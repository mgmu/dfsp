package main

import (
	"net"
	"time"
)

// A knownPeer is a representation of a known peer.
type knownPeer struct {
	addrs                 []*net.UDPAddr
	key                   []byte
	rootHash              []byte
	handshake_made        bool
	last_interaction_time time.Time
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
