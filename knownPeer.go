package main

import (
	"fmt"
	"net"
	"slices"
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

// Returns true if the given UDP address is at least one the addresses of this
// peer
func (kp *knownPeer) has(other *net.UDPAddr) bool {
	for _, addr := range kp.addrs {
		if addr.IP.Equal(other.IP) && addr.Port == other.Port &&
			addr.Zone == other.Zone {
			return true
		}
	}
	return false
}

// Returns true if the key of this known peer is equal to the given slice.
func (kp *knownPeer) keyMatches(other []byte) bool {
	return slices.Equal(kp.key, other)
}

// Returns true if this known peer has a key, i.e a key that is not a 64 long
// byte slice of zeros.
func (kp *knownPeer) implementsSignatures() bool {
	b := make([]byte, 64)
	return !kp.keyMatches(b)
}
