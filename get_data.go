package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
)

// getDatum downloads a resource, identified by its hash, from a peer, and give
// it the name name. If an error occurs, returns nil and the error. Else,
// returns the node corresponding to the resource.
func getDatum(peer string, hash []byte, conn net.PacketConn,
name string) (*node, error) {
	if debug {
		fmt.Printf("Requesting datum %v from peer %s\n", hash, peer)
	}
	idLock.Lock()
	if debug {
		fmt.Println("Locked id")
	}
	idDatum := id
	id++
	idLock.Unlock()
	if debug {
		fmt.Println("Unlocked id")
	}
	packet := packet{GetDatum, idDatum, hash}
	for _, addr := range knownPeers[peer].addrs {
		if bufr, err := writeExpBackoff(conn, addr, packet.Bytes());
		err == nil {
			if typeRq := int(bufr[4]); typeRq == NoDatum {
				hashr := bufr[7:39]
				if bytes.Equal(hashr, hash) {
					return nil, errors.New("Peer does not have requested datum")
				} else {
					return nil, errors.New("Peer answered with wrong hash")
				}
			} else if typeRq == Datum {
				lenr := uint16(bufr[5]<<8) | uint16(bufr[6])
				hashr, valuer := bufr[7:39], bufr[39:39 + lenr - 32]
				if !bytes.Equal(hashr, hash) {
					return nil, errors.New("Peer answered with wrong hash")
				}
				if debug {
					fmt.Printf("Peer %s has datum %v, with value %v\n",
					peer, hashr, valuer)
				}
				categoryDatum, valueDatum := int(valuer[0]), valuer[1:]
				var n *node
				if categoryDatum == Chunk {
					if debug {
						fmt.Printf("Received chunk %v\n", valueDatum)
					}
					hashC := sha256.Sum256(valuer)
					if !bytes.Equal(hashC[0:32], hashr) {
						if debug {
							fmt.Printf("%s:\nReceived: %v\nComputed: %v\n",
							name, hashr, hashC)
						}
						return nil,
							errors.New("Hash mismatch, interrupting transfer")
					} else if debug {
						fmt.Printf("Hashes for chunk %v match\n", valueDatum)
					}
					n = &node{Chunk, hashC, nil, name, valueDatum}
				} else if categoryDatum == BigFile {
					if debug {
						fmt.Printf("Received file %v\n", valueDatum)
					}
					var children []*node
					for i := 0; i < len(valueDatum); i += 32 {
						hashRq := valueDatum[i:i+32]
						if debug {
							fmt.Printf("Requesting hash %v\n", hash)
						}
						child, err := getDatum(peer, hashRq, conn, name)
						if err != nil {
							return nil, err
						}
						children = append(children, child)
						if debug {
							fmt.Printf("Added child to node %s\n", name)
						}
					}
					hashC := hashFrom(children)
					if !bytes.Equal(hashC[0:32], hashr) {
						if debug {
							fmt.Printf("%s:\nReceived: %v\nComputed: %v\n",
							name, hashr, hashC)
						}
						return nil,
							errors.New("Hash mismatch, interrupting transfer")
					} else if debug {
						fmt.Printf("Hashes for %s match\n", name)
					}
					n = &node{BigFile, hashC, children, name, nil}
				} else if categoryDatum == Directory {
					if debug {
						fmt.Printf("Received directory %v\n", valueDatum)
					}
					var children []*node
					for i := 0; i < len(valueDatum); i += 64 {
						nameRq := string(valueDatum[i:i+32])
						hashRq := valueDatum[i+32:i+64]
						if debug {
							fmt.Printf("Requesting file %s with hash %v\n",
							nameRq, hashRq)
						}
						child, err := getDatum(peer, hashRq, conn, nameRq)
						if err != nil {
							return nil, err
						}
						children = append(children, child)
						if debug {
							fmt.Printf("Added child %s to node %s\n",
							child.name, name)
						}
					}
					hashC := hashFrom(children)
					if !bytes.Equal(hashC[0:32], hash) {
						if debug {
							fmt.Printf("%s:\nReceived: %v\nComputed: %v\n",
							name, hashr, hashC)
						}
						return nil,
							errors.New("Hash mismatch, interrupting transfer")
					} else if debug {
						fmt.Printf("Hashes for %s match\n", name)
					}
					n = &node{Directory, hashC, children, name, nil}
				} else {
					if debug {
						fmt.Printf("Unknown datum type %d\n", categoryDatum)
					}
					return nil, errors.New("Unknown datum type")
				}
				return n, nil
			}
		} else if debug {
			fmt.Println("Error while writing to peer, trying next address")
		}
	}
	return nil, errors.New("Could not join peer")
}