package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const serverUrl = "https://jch.irif.fr:8443"
const peersUrl = "/peers"
const addressesUrl = "/addresses"
const keyUrl = "/key"
const rootHashUrl = "/root"

var knownPeers = make(map[string]*knownPeer)
var debug = true

func main() {
	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}

	discoverPeers(client)
	if debug {
		fmt.Println("Known peers:")
		for k, v := range knownPeers {
			fmt.Println(k)
			fmt.Println(v)
		}
	}
}

func discoverPeers(client *http.Client) {
	if debug {
		fmt.Println("Sending GET peers")
	}

	resp, err := client.Get(serverUrl + peersUrl)
	if err != nil {
		log.Fatal("Get:", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Fatalf("Server returned status code %d instead of 200",
			resp.StatusCode)
	}

	if debug {
		fmt.Println("Receiving GET /peers response")
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Get:", err)
	}

	peers := strings.Split(string(buf), "\n")
	l := len(peers) - 1 // -1 for empty string caused by last '\n'
	for i := 0; i < l; i++ {
		addrs, err := getPeerSocketAddrs(client, peers[i])
		if err != nil {
			log.Fatal("getPeerSocketAddrs:", err)
		}
		key, err := getPeerPublicKey(client, peers[i])
		if err != nil {
			log.Fatal("getPeerPublicKey:", err)
		}
		rootHash, err := getPeerRootHash(client, peers[i])
		if err != nil {
			log.Fatal("getPeerRootHash:f, err")
		}
		knownPeers[peers[i]] = newKnownPeer(addrs, key, rootHash)
	}
}

// getPeerSocketAddrs returns a list of pointers to UDP socket addresses of the
// peer p. If a socket address can not be resolved, or if the pair is unknown,
// or if the server returned a non-2xx status code, returns nil and the
// corresponding error.
func getPeerSocketAddrs(client *http.Client, p string) ([]*net.UDPAddr, error) {
	if debug {
		fmt.Println("Sending GET /peers/" + p + addressesUrl)
	}

	resp, err := client.Get(serverUrl + peersUrl + "/" + p + addressesUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if debug {
		fmt.Println("Receiving GET /peers/" + p + addressesUrl)
	}

	if resp.StatusCode == 404 {
		err = fmt.Errorf("Peer %q is unknown", p)
		return nil, err
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("Server returned status code %d", resp.StatusCode)
		return nil, err
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if debug {
		fmt.Println("Reading UDP socket addresses of peer " + p)
	}

	addrsAsStr := strings.Split(string(buf), "\n")
	l := len(addrsAsStr) - 1 // for empty string caused by last '\n' in Split
	var addrs = make([]*net.UDPAddr, l)
	for i := 0; i < l; i++ {
		addrs[i], err = net.ResolveUDPAddr("", addrsAsStr[i])
		if err != nil {
			return nil, err
		}
	}

	if debug {
		fmt.Println("Succesfully read UDP socket addresses")
	}

	return addrs, nil
}

// getPeerPublicKey returns the public key of the peer p. If this function
// returns nil as err, it can mean two things: the peer is known and has
// announced a public key or it has not announced any public key yet.
// If an error is encoutered during the process, err is not nil and the byte
// slice is.
func getPeerPublicKey(client *http.Client, p string) ([]byte, error) {
	if debug {
		fmt.Println("Sending GET /peers/" + p + keyUrl)
	}

	resp, err := client.Get(serverUrl + peersUrl + "/" + p + keyUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		if debug {
			fmt.Println("Receiving GET /peers/" + p + keyUrl + " 200")
		}
		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return buf[:64], nil
	case 204:
		if debug {
			fmt.Println("Received GET /peers/" + p + keyUrl + " 204")
		}
		return make([]byte, 64), nil
	case 404:
		err = fmt.Errorf("Peer %q is unknown", p)
		return nil, err
	default:
		err = fmt.Errorf("Server returned status code %d", resp.StatusCode)
		return nil, err
	}
}

// getPeerRootHash returns the root hash of the peer p. If this function returns
// nil as err, it can mean two things: the peer is known and has announced a
// root hash or the it has not announced a root hash yet. If an error is
// encoutered during the process, err is not nil and the byte slice is.
func getPeerRootHash(client *http.Client, p string) ([]byte, error) {
	if debug {
		fmt.Println("Sending GET /peers/" + p + rootHashUrl)
	}

	resp, err := client.Get(serverUrl + peersUrl + "/" + p + rootHashUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		if debug {
			fmt.Println("Received GET /peers/" + p + rootHashUrl + " 200")
		}
		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return buf[:32], nil
	case 204:
		if debug {
			fmt.Println("Received GET /peers/" + p + rootHashUrl + " 204")
		}
		return make([]byte, 32), nil
	case 404:
		err = fmt.Errorf("Peer %q is unknown", p)
		return nil, err
	default:
		err = fmt.Errorf("Server returned status code %d", resp.StatusCode)
		return nil, err
	}
}
