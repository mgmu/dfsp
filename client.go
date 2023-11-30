package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const serverUrl = "https://jch.irif.fr:8443/"

var knownPeers = make(map[string]knownPeer)

var debug = true

func main() {
	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}

	discoverPeers(client)
}

func discoverPeers(client *http.Client) {
	const peersUrl = "/peers/"

	if debug {
		fmt.Println("Sending GET /peers/")
	}

	resp, err := client.Get(serverUrl + peersUrl)
	defer resp.Body.Close()
	if err != nil {
		log.Fatal("Get:", err)
	}

	if debug {
		fmt.Println("Received GET /peers/ response")
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Get:", err)
	}

	peers := strings.Split(string(buf), "\n")

	for i := 0; i < len(peers); i++ {
		log.Fatal("TODO: get peers' socket addresses")
	}
}
