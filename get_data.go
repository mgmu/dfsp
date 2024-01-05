package main

import (
	"encoding/binary"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
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

	packetDatum := packet{GetDatum, idDatum, hash}

	knownPeersLock.Lock()
	for !knownPeers[peer].handshakeMade {
		if debug {
			fmt.Printf("Handshake with peer %s\n", peer)
		}
		var bufHello []byte
		bufHello = binary.BigEndian.AppendUint32(bufHello, extensions)
		bufHello = append(bufHello, peerName...)
		idLock.Lock()
		idHello := id
		id++
		idLock.Unlock()
		helloRq := packet{
			typ:  uint8(Hello),
			id:   idHello,
			body: bufHello,
		}
		addr := knownPeers[peer].addrs[0]
		if bufr, err := writeExpBackoff(conn,addr, helloRq.Bytes());
		err == nil {
			if idr, _ := toId(bufr[0:4]); idr != idHello {
				go func() {
					if _, err = handleRequest(bufr, addr, conn); err != nil {
						log.Fatal(err)
					}
				}()
				continue
			} else if typeRq := int(bufr[4]); typeRq == HelloReply {
				if debug {
					fmt.Printf("Handshake with %s done\n", peer)
				}
				knownPeers[peer].handshakeMade = true
				updateInteractionTime(addr)
			}
		} else {
			knownPeersLock.Unlock()
			return nil, err
		}
	}
	knownPeersLock.Unlock()
	for _, addr := range knownPeers[peer].addrs {
		for {
			if bufr, err := writeExpBackoff(conn, addr, packetDatum.Bytes());
			err == nil {
				if idr, _ := toId(bufr[0:4]); idr != idDatum {
					if debug {
						fmt.Println("ids differ")
					}
					go func() {
						_, err = handleRequest(bufr, addr, conn)
						if err != nil {
							log.Fatal(err)
						}
					}()
					continue
				}
				if typeRq := int(bufr[4]); typeRq == NoDatum {
					if debug {
						fmt.Println("no datum")
					}
					hashr := bufr[7:39]
					if bytes.Equal(hashr, hash) {
						return nil, errors.New("Peer does not have datum")
					} else {
						return nil, errors.New("Peer answered with wrong hash")
					}
				} else if typeRq == Datum {
					if debug {
						fmt.Println("datum")
					}
					lenr := uint16(bufr[5]) << 8 | uint16(bufr[6])
					hashr, valuer := bufr[7:39], bufr[39:39 + lenr - 32]
					if !bytes.Equal(hashr, hash) {
						if debug {
							fmt.Printf("Received hash %v, expected %v\n",
							hashr, hash)
						}
						continue
					} else if debug {
						fmt.Printf("Peer %s has datum %v\n", peer, hashr)
					}
					if debug {
						fmt.Println("hash of datum matches")
					}
					categoryDatum, valueDatum := int(valuer[0]), valuer[1:]
					var n *node
					if categoryDatum == Chunk {
						if debug {
							fmt.Printf("Received chunk %s\n", name)
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
							fmt.Printf("Hashes for chunk %s match\n", name)
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
								fmt.Printf("Requesting hash %v\n", hashRq)
							}
							child, err := getDatum(peer, hashRq, conn, "")
							if err != nil {
								return nil, err
							}
							children = append(children, child)
							if debug {
								nameRq := fmt.Sprintf("%s-%d", name, i / 32)
								fmt.Printf("Added child %s to node %s\n",
								nameRq, name)
							}
						}
						hashC := hashFrom(children, BigFile)
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
						hashC := hashFrom(children, Directory)
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
				} else if typeRq == Error || typeRq == ErrorReply {
					lenr := uint16(bufr[5]) << 8 | uint16(bufr[6])
					return nil, errors.New(string(bufr[7:7+lenr]))
				} else {
					go func() {
						_, err = handleRequest(bufr, addr, conn)
						if err != nil {
							log.Fatal(err)
						}
					}()
					continue
				}
			} else {
				if debug {
					fmt.Println("getDatum: trying next address")
				}
				break
			}
		}
	}
	return nil, errors.New("Could not join peer")
}
