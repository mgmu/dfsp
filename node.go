package main

import (
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
	if debug {
		fmt.Printf("\n\nnode.from()\n")
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	if debug {
		fmt.Println("Open file")
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if debug {
		fmt.Println("Stat file")
	}
	mode := info.Mode()
	size := info.Size()
	if mode.IsRegular() {
		if debug {
			fmt.Println("File is regular")
		}
		if size > 32 * 1024 {
			if debug {
				fmt.Println("File too big, log.Fatal() incoming")
			}
			log.Fatal("node.from(): File size not yet supported...")
		} else if size > 1024 && size <= 32 * 1024 {
			if debug {
				fmt.Printf("Big file of less than %d bytes\n", 32*1024)
			}
			data, err := os.ReadFile(name)
			if err != nil {
				return nil, err
			}
			if debug {
				fmt.Println("Read content of regular file")
			}
			nbChildren := int(size / 1024)
			if size % 1024 != 0 {
				nbChildren++
			}
			if debug {
				fmt.Printf("Size of file %d, number of chunk children %d\n",
					size, nbChildren)
			}
			childs := make([]*node, nbChildren)
			for i := 0; i < nbChildren; i++ {
				if debug {
					fmt.Printf("Creating chunk childs [iter: %d]\n", i)
				}
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
				hash: hashFrom(childs, BigFile),
				children: childs,
				name: name,
			}
			if debug {
				fmt.Println("Returning BigFile")
			}
			return new, nil
		} else {
			if debug {
				fmt.Println("Little file")
			}
			data, err := os.ReadFile(name)
			if err != nil {
				return nil, err
			}
			if debug {
				fmt.Println("Read regular file content")
			}
			new := node{
				category: Chunk,
				hash:     sha256.Sum256(data),
				name: name,
				data:     data,
			}
			if debug {
				fmt.Println("Returning Chunk")
			}
			return &new, nil
		}
	}
	if mode.IsDir() {
		if debug {
			fmt.Println("File is directory")
		}
		entries, err := os.ReadDir(name)
		if err != nil {
			return nil, err
		}
		if debug {
			fmt.Println("Read entries")
		}
		if len(entries) > 16 {
			return nil, fmt.Errorf("node.from(): too many entries in dir")
		}
		if debug {
			fmt.Println("Less than 16 entries")
		}
		var children []*node
		for _, child := range entries {
			if debug {
				fmt.Printf("Rec call to [%s]\n", name + "/" + child.Name())
				
			}
			nd, err := from(name + "/" + child.Name())
			if err != nil {
				return nil, err
			}
			children = append(children, nd)
		}
		new := &node{
			category: Directory,
			hash: hashFrom(children, Directory),
			children: children,
			name: name,
		}
		if debug {
			fmt.Printf("Returning directory with name %s\n", new.name)
		}
		return new, nil
	}
	return nil, fmt.Errorf("node.from(): unsupported file mode %d", mode)
}

// Computes the hash of the concatenation of the hashes of the nodes in children
func hashFrom(children []*node, category byte) [32]byte {
	var hashes []byte
	hashes = append(hashes, []byte{category}...)
	for i := 0; i < len(children); i++ {
		if children[i].name != "" {
			hashes = append(hashes, []byte(children[i].name)...)
		}
		hashes = append(hashes, children[i].hash[0: 32]...)
	}
	return sha256.Sum256(hashes)
}
