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
	ErrorReply = 128
	HelloReply = 129
	PublicKeyReply = 130
	RootReply = 131
	Datum = 132
	NoDatum = 133
)

type request struct {
	typeRq uint8
	id     uint32
	value  []byte
}

// Transforms this request into a ready-to-send slice of bytes and returns it.
func (rq *request) Bytes() []byte {
	var res []byte
	res = binary.BigEndian.AppendUint32(res, rq.id)
	res = append(res, byte(rq.typeRq))
	res = binary.BigEndian.AppendUint16(res, rq.Length())
	res = append(res, rq.value...)
	return res
}

// Computes the length of this request as a number of bytes and returns it.
// A length of 0 indicates that the type of the request is unknown.
func (rq *request) Length() uint16 {
	var length uint16 = 7
	switch rq.typeRq {
	case NoOp, Error, ErrorReply:
		return length + uint16(len(rq.value))
	case Hello, HelloReply:
		return length + 4 + uint16(len(peerName)) // + signatures
	case PublicKey, PublicKeyReply:
		return length // + signatures
	case Root, RootReply:
		return length + 32 // + signatures
	case GetDatum, Datum:
		return length + 32
	case NoDatum:
		return length + 32 + uint16(len(rq.value))
	}
	return 0
}
