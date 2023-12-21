package main

import (
	// "errors"
	// "crypto/sha256"
	"fmt"
	"os"
)

// A node of the merkle tree
// category: Chunk = 0 | BigFile = 1 | Directory = 2
// hash: the hash of the concatenation of the children hashes
// children: the child nodes, 0 for Chunk, [2: 32] for BigFile, [0: 16]	Dir
// name: the name of the represented file or directory
// data: a byte slice of at most 1024 bytes
type node struct {
	category byte
	hash     [32]byte
	children []*node
	name     string
	data     []byte
}

// Generates the Merkle tree structure corresponding to the hierarchy denoted by
// name
func from(name string) (*node, error) {
	f, err := os.Open(name)
	check(err)
	fi, err := f.Stat()
	check(err)
	m := fi.Mode()
	if !(m.IsDir() || m.IsRegular()) {
		return nil, fmt.Errorf("node.from(): unsupported file mode %d", m)
	}
	return nil, nil
}
