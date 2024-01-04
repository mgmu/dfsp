package main

import (
	"bytes"
	"crypto/sha256"
	"log"
	"os"
	"testing"
)

func TestNodeFromUnexistingFileReturnsError(t *testing.T) {
	_, err := from("notafile")
	if err == nil {
		t.Fatal("unexpected success of node creation from not existing file")
	}
}

func TestNodeFromEmptyRegularFileDoesNotReturnsError(t *testing.T) {
	f, err := os.CreateTemp("", "test")
	if err != nil {
		log.Fatal(err)
	}

	_, err = from(f.Name())
	if err != nil {
		t.Fatal("unexpected failure of node creation from empty regular file")
	}
}

func TestNodeFromEmptyRegFileReturnsNonNilNode(t *testing.T) {
	f, err := os.CreateTemp("", "test")
	nd, err := from(f.Name())
	if err != nil {
		t.Fatal("unexpected failure of node creation from empty regular file")
	}
	if nd == nil {
		t.Fatal("unexpected nil value for node from empty regular file")
	}
}

func TestNodeFromEmptyRegFileReturnsNodeOfCategory0(t *testing.T) {
	f, err := os.CreateTemp("", "test")
	nd, err := from(f.Name())
	if err != nil {
		t.Fatal("unexpected failure of node creation from empty regular file")
	}
	if nd.category != 0 {
		t.Fatalf("category %d; want 0", nd.category)
	}
}

func TestNodeFromEmptyRegFileReturnsNodeWithHashOfEmptyString(t *testing.T) {
	f, err := os.CreateTemp("", "test")
	nd, err := from(f.Name())
	if err != nil {
		t.Fatal("unexpected failure of node creation from empty regular file")
	}
	hash := sha256.Sum256([]byte(""))
	if hash != nd.hash {
		t.Fatalf("have %v; want %v", nd.hash, hash)
	}
}

func TestNodeFromExistingExportFolder(t *testing.T) {
	folder := "export"
	nd, err := from(folder)
	if err != nil {
		t.Fatal("unexpected failure of node creation from export folder")
	}
	if nd.category != Directory {
		t.Fatalf("category %d; want %d", nd.category, Directory)
	}
	expectedHash := hashFrom(nd.children, Directory)
	if !bytes.Equal(nd.hash[:], expectedHash[:]) {
		t.Fatalf("have %v; want %v", nd.hash, expectedHash)
	}
}