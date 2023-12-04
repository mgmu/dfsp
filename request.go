package main

import(
	"crypto/sha256"
	"encoding/binary"
	"log"
	"math/rand"
)

type request struct {
	typeRq     uint8
	value			[]byte
}

func toBytes(rq *request) []byte {
	/* TMP - to be changed when merged */
	id := uint32(0)
	name := "test"
	ext := uint32(0)
	
	idRq := make([]byte, 4)
	binary.BigEndian.AppendUint32(idRq, id)
	_, err := rand.Read(idRq)
	if err != nil {
		log.Fatal("rand.Read:", err)
	}

	nameRq := make([]byte, 0)
	extRq := make([]byte, 0)
	hashRq := make([]byte, 0)
	if rq.typeRq == 2 {
		nameRq = []byte(name)
		extRq := make([]byte, 4)
		binary.BigEndian.AppendUint32(extRq, ext)
	}
	if rq.typeRq == 132 {
		hashRq = make([]byte, 32)

		h := sha256.New()
		h.Write(rq.value)
		hashRq = h.Sum(nil)
	}
	length := len(nameRq) + len(extRq) + len(rq.value) + len(hashRq)
	res := make([]byte, 0)
	lengthRq := make([]byte, 2)
	lengthRq = binary.BigEndian.AppendUint16(lengthRq, uint16(length))
	for i := range idRq {
		res = append(res, idRq[i])
	}
	res = append(res, rq.typeRq)
	for i := range lengthRq {
		res = append(res, lengthRq[i])
	}
	for i := range extRq {
		res = append(res, extRq[i])
	}
	// TODO: add extensions if needed
	for i := range nameRq {
		res = append(res, nameRq[i])
	}
	for i := range hashRq {
		res = append(res, hashRq[i])
	}
	for i := range rq.value {
		res = append(res, rq.value[i])
	}
	return res
}