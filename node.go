package main

import (
	// "errors"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
)

const (
	Chunk = iota
	BigFile
	Directory
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

// Generates the Merkle tree structure corresponding to the tree structure
// denoted by name. If an error occurs, returns nil and the error.
func from(name string) (*node, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	mode := info.Mode()
	size := info.Size()
	if mode.IsRegular() {
		if size > 32 * 1024 {
			data, err := os.ReadFile(name)
			if err != nil {
				return nil, err
			}
			nbChildren := int(size / 1024)
			if size % 1024 != 0 {
				nbChildren++
			}
			childs := make([]*node, nbChildren)
			for i := 0; i < nbChildren; i++ {
				tmp := data[i * 1024: min((i + 1) * 1024, len(data))]
				childs[i] = &node{
					category: Chunk,
					hash: sha256.Sum256(tmp),
					name: info.Name(),
					data: tmp,
				}
			}
			new := &node{
				category: BigFile,
				hash: hashFrom(childs),
				children: childs,
				name: name,
			}
			return new, nil
		} else if size > 1024 {
			log.Fatal("node.from(): File size not yet supported...")
		} else {
			data, err := os.ReadFile(name)
			if err != nil {
				return nil, err
			}
			new := node{
				category: Chunk,
				hash:     sha256.Sum256(data),
				name: name,
				data:     data,
			}
			return &new, nil
		}
	}
	if mode.IsDir() {
		entries, err := os.ReadDir(name)
		if err != nil {
			return nil, err
		}
		if len(entries) > 16 {
			return nil, fmt.Errorf("node.from(): too many entries in dir")
		}
		var children []*node
		for i, child := range entries {
			children[i], err = from(name + child.Name())
			if err != nil {
				return nil, err
			}
		}
		new := &node{
			category: Directory,
			hash: hashFrom(children),
			children: children,
			name: name,
		}
		return new, nil
	}
	return nil, fmt.Errorf("node.from(): unsupported file mode %d", mode)
}

// Computes the hash of the concatenation of the hashes of the nodes in children
func hashFrom(children []*node) [32]byte {
	var hashes []byte
	for i := 0; i < len(children); i++ {
		hashes = append(hashes, children[i].hash[0: 32]...)
	}
	return sha256.Sum256(hashes)
}
