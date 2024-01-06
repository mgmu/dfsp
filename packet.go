package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

const (
	NoOp = iota
	Error
	Hello
	PublicKey
	Root
	GetDatum
	NatTraversalRequest
	NatTraversal
	ErrorReply     = 128
	HelloReply     = 129
	PublicKeyReply = 130
	RootReply      = 131
	Datum          = 132
	NoDatum        = 133
	minimalHelloPacketLength = 12
)

type packet struct {
	typ  byte
	id   uint32
	body []byte
}

// Transforms this packet into a ready-to-send slice of bytes and returns it.
func (pack *packet) Bytes() []byte {
	var res []byte
	length := pack.Length()
	res = binary.BigEndian.AppendUint32(res, pack.id)
	res = append(res, pack.typ)
	res = binary.BigEndian.AppendUint16(res, length)
	res = append(res, pack.body...)
	switch pack.typ {
	case Hello, HelloReply, PublicKey, PublicKeyReply, Root, RootReply:
		if debug {
			fmt.Println("Computing signature of packet...")
		}
		tmp := Signature(res[:7+length])
		res = append(res, tmp...)
	}
	return res
}

// Computes the length of this packet as a number of bytes and returns it.
// A length of 0 indicates that the type of the packet is unknown.
func (pack *packet) Length() uint16 {
	switch pack.typ {
	case NoOp, Error, ErrorReply:
		return uint16(len(pack.body))
	case Hello, HelloReply:
		return 4 + uint16(len(peerName))
	case PublicKey, PublicKeyReply:
		return 64
	case Root, RootReply:
		return 32
	case GetDatum, Datum:
		return 32
	case NoDatum:
		return 32 + uint16(len(pack.body))
	case NatTraversalRequest:
		return 6
	case NatTraversal:
		return 18
	}
	return 0
}

func Signature(data []byte) []byte {
	hashed := sha256.Sum256(data)
	if privateKey == nil {
		log.Fatal("private key not generated yet")
	}
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	if err != nil {
		log.Fatal("ecdsa.Sign():", err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature
}

// addrToBytes returns the slice of bytes corresponding to the concatenation of
// the ip address and the port number (in NBO order). Returns nil on error.
func addrToBytes(addr *net.UDPAddr) []byte {
	if addr == nil {
		return nil
	}
	res := addr.To4()
	if res == nil {
		res = addr.To6()
	}
	res = binary.BigEndian.AppendUint16(res, uint16(addr.Port))
	return res
}
