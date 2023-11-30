package main

import (
	"net"
	"time"
)

// A knownPeer is a representation of a known peer.
type knownPeer struct {
	addrs                 []net.UDPAddr
	key                   [64]byte
	rootHash              [32]byte
	handshake_made        bool
	last_interaction_time time.Time
}

// newKnownPeer returns a new known host with the given addresses, public key
// and root hash, the handshake is initialized to false and the last interaction
// time is initialized to time.Now().
func newKnownPeer(addrs []net.UDPAddr, key [64]byte,
	rootHash [32]byte) *knownPeer {
	kh := knownPeer{addrs, key, rootHash, false, time.Now()}
	return &kh
}
