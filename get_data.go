package main

import (
	"fmt"
	"log"
	"net"
)

// getDatum downloads a resource, identified by its hash, from a peer
func getDatum(peer string, hash []byte, conn net.PacketConn) {
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
		if bufr, err := writeExpBackoff(conn, addr, packet.Bytes()); err == nil {
			if typeRq := int(bufr[4]); typeRq == NoDatum {
				hashr := bufr[7:39]
				if debug {
					fmt.Printf("Peer %s does not have datum %v\n", peer, hashr)
				} else {
					fmt.Printf("Peer %s does not have requested datum", peer)
				}
			} else if typeRq == Datum {
				log.Fatal("todo")
			}
		} else if debug {
			fmt.Println("Error while writing to peer, trying next address")
		}
	}
}