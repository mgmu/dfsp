package main

import (
	"encoding/binary"
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
)

type packet struct {
	typeRq uint8
	id     uint32
	body   []byte
}

// Transforms this packet into a ready-to-send slice of bytes and returns it.
func (rq *packet) Bytes() []byte {
	var res []byte
	res = binary.BigEndian.AppendUint32(res, rq.id)
	res = append(res, byte(rq.typeRq))
	res = binary.BigEndian.AppendUint16(res, rq.Length())
	res = append(res, rq.body...)
	return res
}

// Computes the length of this packet as a number of bytes and returns it.
// A length of 0 indicates that the type of the packet is unknown.
func (rq *packet) Length() uint16 {
	switch rq.typeRq {
	case NoOp, Error, ErrorReply:
		return uint16(len(rq.body))
	case Hello, HelloReply:
		return 4 + uint16(len(peerName)) // + signatures
	case PublicKey, PublicKeyReply:
		return 0 // + signatures
	case Root, RootReply:
		return 32 // + signatures
	case GetDatum, Datum:
		return 32
	case NoDatum:
		return 32 + uint16(len(rq.body))
	}
	return 0
}
