package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net"
	"strings"
	"time"
)

const serverUrl = "https://jch.irif.fr:8443"
const peersUrl = "/peers"
const addressesUrl = "/addresses"
const keyUrl = "/key"

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
	if debug {
		fmt.Println("Sending GET peers")
	}

	resp, err := client.Get(serverUrl + peersUrl + "/")
	if err != nil {
		log.Fatal("Get:", err)
	}
	defer resp.Body.Close()

	if debug {
		fmt.Println("Receiving GET /peers response")
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

// getPeerSocketAddrs returns a list of pointers to UDP socket addresses of the
// peer p. If a socket address can not be resolved, or if the pair is unknowned,
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

	if debug {
		fmt.Println("Receiving GET /peers/" + p + addressesUrl)
	}

	if resp.StatusCode == 404 {
		err = fmt.Errorf("Peer %q is unknown\n", p)
		return nil, err
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("Server returned status code %d\n", resp.StatusCode)
		return nil, err
	}

	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if debug {
		fmt.Println("Reading UDP socket addresses of peer " + p)
	}

	addrsAsStr := strings.Split(string(buf), "\n")
	len := len(addrsAsStr)
	if len > 1 {
		len = len - 1; // because of empty string caused by last '\n' in Split
	}
	var addrs = make([]*net.UDPAddr, len)
	for i := 0; i < len; i++ {
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
// returns nil as err, it can mean two things: if the byte slice is not nil then
// the peer is known and has announced a public key, if the byte slice is nil
// then the peer is known but has not announced any public key yet. If an error
// is encoutered during the process, err is not nil but the byte slice is.
func getPeerPublicKey(client *http.Client, p string) ([]byte, error) {
	if debug {
		fmt.Println("Sent GET /peers/" + p + keyUrl)
	}

	resp, err := client.Get(serverUrl + peersUrl + "/" + p + keyUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		if debug {
			fmt.Println("Received GET /peers/" + p + keyUrl + " 200")
		}
		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		fmt.Println(len(buf))
		return buf[:64], nil
	case 204:
		if debug {
			fmt.Println("Received GET /peers/" + p + keyUrl + " 204")
		}
		return nil, nil
	case 404:
		err = fmt.Errorf("Peer %q is unknown")
		return nil, err
	default:
		err = fmt.Errorf("Server returned status code %i", resp.StatusCode)
		return nil, err
	}
}
