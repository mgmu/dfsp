package main

import (
	"crypto/sha256"
	"encoding/binary"
	"log"
	"math/rand"
)

type request struct {
	typeRq uint8
	value  []byte
}

func toBytes(rq *request) []byte {
	// extensions in 'Hello' request
	ext := uint32(0)

	idRq := make([]byte, 4)
	_, err := rand.Read(idRq)
	if err != nil {
		log.Fatal("rand.Read:", err)
	}

	var extRq []byte
	var hashRq []byte
	if rq.typeRq == 2 {
		extRq = binary.BigEndian.AppendUint32(extRq, ext)
	}
	if rq.typeRq == 132 {
		hashRq = make([]byte, 32)

		h := sha256.New()
		h.Write(rq.value)
		hashRq = h.Sum(nil)
	}
	length := len(extRq) + len(rq.value) + len(hashRq)

	var res []byte
	lengthRq := make([]byte, 0)
	lengthRq = binary.BigEndian.AppendUint16(lengthRq, uint16(length))
	res = append(res, idRq...)
	res = append(res, rq.typeRq)
	res = append(res, lengthRq...)
	res = append(res, extRq...)
	// TODO: add extensions if needed
	res = append(res, hashRq...)
	res = append(res, rq.value...)
	return res
}
