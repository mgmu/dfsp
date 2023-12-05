package main

import (
	"fmt"
	"net"
	"time"
)

// A knownPeer is a representation of a known peer.
type knownPeer struct {
	addrs           []*net.UDPAddr
	key             []byte
	rootHash        []byte
	handshakeMade   bool
	lastInteraction time.Time
}

// newKnownPeer returns a new known host with the given addresses, public key
// and root hash, the handshake is initialized to false and the last interaction
// time is initialized to time.Now(). If key is not 64 bytes long or rootHash is
// not 32 bytes long, returns nil.
func newKnownPeer(addrs []*net.UDPAddr, key []byte,
	rootHash []byte) *knownPeer {
	if len(key) != 64 || len(rootHash) != 32 {
		return nil
	}
	kh := knownPeer{addrs, key, rootHash, false, time.Now()}
	return &kh
}

func (kp *knownPeer) String() string {
	res := " Addresses:\n"
	for _, addr := range kp.addrs {
		res += fmt.Sprintf("  %s\n", addr.String())
	}
	res += fmt.Sprintf(" Public key: %v\n", kp.key)
	res += fmt.Sprintf(" Root hash: %v\n", kp.rootHash)
	res += fmt.Sprintf(" Handshake made: %t\n", kp.handshakeMade)
	res += fmt.Sprintf(" Last interaction time: %s\n", kp.lastInteraction)
	return res
}
