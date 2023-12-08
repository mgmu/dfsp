package main

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	serverUrl       = "https://" + serverName + ":" + serverPort
	serverName      = "jch.irif.fr"
	serverPort      = "8443"
	peersUrl        = "/peers"
	addressesUrl    = "/addresses"
	keyUrl          = "/key"
	rootHashUrl     = "/root"
	peerName        = "Slartibartfast"
	limitExpBackoff = 32
)

var knownPeers = make(map[string]*knownPeer)
var debug = true
var id uint32 = 0
var extensions uint32 = 0

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

	conn, err := net.ListenPacket("udp", "")
	if err != nil {
		log.Fatal("net.ListenPacket:", err)
	}

	if err = serverRegistration(conn); err != nil {
		log.Fatal("Could not register to server:", err)
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

func serverRegistration(conn net.PacketConn) error {
	var buf []byte
	// Hello transfer
	idHello := id
	buf = binary.BigEndian.AppendUint32(buf, id)
	buf = append(buf, byte(2))
	buf = binary.BigEndian.AppendUint16(buf, uint16(4+len(peerName)))
	buf = binary.BigEndian.AppendUint32(buf, extensions)
	buf = append(buf, peerName...)
	server := *knownPeers[serverName]
	addr := server.addrs[0]
	bufr, err := writeExpBackoff(conn, addr, buf)
	if debug {
		fmt.Printf("bufr = %v\n", bufr)
	}
	if err != nil {
		return err
	}
	respId := uint32(bufr[0]<<24 | bufr[1]<<16 | bufr[2]<<8 | bufr[3])
	respType := bufr[4]
	if respType != 129 {
		return fmt.Errorf("TODO: not the right response")
	}
	if respId != idHello {
		return fmt.Errorf("Peer respond with id %d to request id %d", respId,
			idHello)
	}

	// Key transfer
	buf = make([]byte, 7+65536+64+1)
	if debug {
		fmt.Println("Waiting for PublicKey request...")
	}
	n, _, err := conn.ReadFrom(buf)
	if n == len(buf) {
		log.Fatal("Peer packet exceeded maximum length")
	}
	if err != nil {
		return err
	}
	if len(buf) < 7 {
		log.Fatal("Server sent a packet too small")
	}
	idRq := uint32(buf[0]) << 24 | uint32(buf[1]) << 16 | uint32(buf[2]) << 8 |
		uint32(buf[3])
	fmt.Printf("idRq bytes: %v\n", buf[:4])
	typeRq := uint8(buf[4])
	lenRq := uint16(buf[5]<<8 | buf[6])
	if debug {
		fmt.Printf("Received req type %d of length %d with id %d\n", typeRq,
			lenRq, idRq)
		fmt.Printf("Content: %v\n", buf[7:7+lenRq])
	}
	if typeRq == 1 { // Error
		log.Fatal(buf[7: 7+lenRq])
	}
	if typeRq != 3 { // PublicKey
		return fmt.Errorf("TODO: not the expected request type: %d", typeRq)
	}
	server.handshakeMade = true
	server.key = buf[7: 7+lenRq]
	server.lastInteraction = time.Now()
	buf = make([]byte, 0)
	buf = binary.BigEndian.AppendUint32(buf, idRq)
	buf = append(buf, byte(130))
	buf = append(buf, make([]byte, 2)...)
	if debug {
		fmt.Printf("Request to send: %v\n", buf)
	}
	bufr, err = writeExpBackoff(conn, addr, buf)
	if debug {
		fmt.Printf("bytes: %v\n", bufr)
	}
	return nil
}

// Writes to the given socket the given data destined to the given address and
// waits for a response (note that it could be any response, not necessarily the
// one associated to the request just sent). The first write occurs immediatly,
// then if needed 1 second later, and then doubles with every try, until it
// reaches a limit value, at which point the data returned is nil and the error
// is not. Otherwise, returns the packet received and nil as error.
func writeExpBackoff(conn net.PacketConn, addr *net.UDPAddr,
	data []byte) ([]byte, error) {
	wait := 0
	var buf []byte
	buf = make([]byte, 7+65536+64+1) // + 1 for truncation check
	if debug {
		fmt.Println("Write procedure with exponential backoff")
	}
	for wait < limitExpBackoff {
		if debug {
			fmt.Printf("wait time %d\n", wait)
		}
		time.Sleep(time.Duration(wait) * time.Second)
		if debug {
			fmt.Printf("Writing to %s\n", addr.String())
		}
		_, err := conn.WriteTo(data, addr)
		if err != nil {
			log.Fatal("WriteTo:", err)
		}

		err = conn.SetReadDeadline((time.Now()).Add(2 * time.Second))
		if err != nil {
			log.Fatal("SetReadDeadline:", err)
		}

		n, _, err := conn.ReadFrom(buf)
		if n == len(buf) {
			log.Fatal("Peer packet exceeded maximum length")
		}
		if debug {
			fmt.Println("Stopped reading from socket")
		}
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Fatal("ReadFrom:", err)
			}
			if wait == 0 {
				wait++
			} else {
				wait *= 2
			}
		} else {
			length := (buf[5] << 8) | buf[6]
			return buf[:7+length], nil
		}
	}
	return nil, fmt.Errorf("Exponential backoff limit exceeded")
}
