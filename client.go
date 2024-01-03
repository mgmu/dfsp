package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
	"sync"
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
	IdLen           = 4
)

var (
	knownPeers        = make(map[string]*knownPeer)
	debug             = true
	id         uint32 = 0
	idLock     sync.Mutex
	extensions uint32 = 0
	root       *node  = nil
	transport         = &*http.DefaultTransport.(*http.Transport)
	client            = &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}
	privateKey *ecdsa.PrivateKey = nil
	publicKey  *ecdsa.PublicKey  = nil
)

func main() {
	if len(os.Args) > 2 {
		fmt.Printf("Usage: %s [path]\n", os.Args[0])
		return
	}

	if len(os.Args) == 2 {
		tmp, err := from(os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
		root = tmp
	}

	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	discoverPeers()
	conn, err := net.ListenPacket("udp", "")
	if err != nil {
		log.Fatal("net.ListenPacket:", err)
	}

	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("ecdsa.GenerateKey:", err)
	}
	tmp, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("failed to get public key from private key")
	}
	publicKey = tmp

	if err = serverRegistration(conn); err != nil {
		log.Fatal("Could not register to server: ", err)
	}

	// send keepalive periodically
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			time.Sleep(30 * time.Second)
			errKeepalive := sendKeepalive(conn)
			if errKeepalive != nil {
				if debug {
					fmt.Println("Error in keepalive, registering again...")
				}
				if err = serverRegistration(conn); err != nil {
					log.Fatal("Could not register to server: ", err)
				}
			}
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Enter 'p' for peers display, 'd' for downloading a file:")
	for scanner.Scan() {
		input := scanner.Text()
		if len(input) != 1 {
			fmt.Println("Try again.")
		} else {
			switch input {
			case "d":
				log.Fatal("todo")
			case "p":
				for k, v := range knownPeers {
					fmt.Println(k)
					fmt.Println(v)
				}
			default:
				fmt.Println("Try again.")
			}
		}
		fmt.Println("Enter 'p' for peers display, 'd' for downloading a file:")
	}
	if err = scanner.Err(); err != nil {
		log.Fatal("Reading stdin:", err)
	}
	fmt.Println("Exiting...")
}

func discoverPeers() {
	if debug {
		fmt.Println("Discovering peers...")
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
		addrs, err := getPeerSocketAddrs(peers[i])
		if err != nil {
			log.Fatal("getPeerSocketAddrs:", err)
		}
		key, err := getPeerPublicKey(peers[i])
		if err != nil {
			log.Fatal("getPeerPublicKey:", err)
		}
		rootHash, err := getPeerRootHash(peers[i])
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
func getPeerSocketAddrs(p string) ([]*net.UDPAddr, error) {
	if debug {
		fmt.Println("Getting peer socket addresses...")
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
func getPeerPublicKey(p string) ([]byte, error) {
	if debug {
		fmt.Println("Getting " + p + keyUrl + " public key...")
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
// root hash or it has not announced a root hash yet. If an error is
// encoutered during the process, err is not nil and the byte slice is.
func getPeerRootHash(p string) ([]byte, error) {
	if debug {
		fmt.Println("Getting " + p + rootHashUrl + " root hash...")
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
	if debug {
		fmt.Println("Registering to server...")
	}
	var buf []byte
	var bufr []byte
	var err error

	// Hello transfer
	buf = binary.BigEndian.AppendUint32(buf, extensions)
	buf = append(buf, peerName...)
	idLock.Lock()
	idHello := id
	id++
	idLock.Unlock()
	helloRq := packet{
		typ:  uint8(Hello),
		id:   idHello,
		body: buf,
	}
	server := knownPeers[serverName]
	addr := server.addrs[0]

	var rId uint32 = 0
	var rType uint8 = 0
	var rLen uint16 = 0
	for rType != HelloReply {
		if debug {
			fmt.Println("Sending Hello request to server...")
		}
		bufr, err = writeExpBackoff(conn, addr, helloRq.Bytes())
		if debug {
			fmt.Printf("Server response to hello request = %v\n", bufr)
		}
		if err != nil {
			return err
		}
		rId, _ = toId(bufr[:4])
		if rId != helloRq.id {
			go func() {
				if err = handleRequest(bufr, addr, conn); err != nil {
					log.Fatal(err)
				}
			}()
			continue
		}
		rType = bufr[4]
		rLen = uint16(bufr[5]<<8) | uint16(bufr[6])
		if rType == NoOp || rType != HelloReply {
			if debug {
				fmt.Println("Server sent correct id but wrong type")
				fmt.Println("About to try again")
			}
			continue
		}
		if rType == ErrorReply || rType == Error {
			if debug {
				fmt.Println("Server notifies error from this client")
			}
			log.Fatal(string(bufr[7 : 7+rLen]))
		}
	}

	server.handshakeMade = true
	server.lastInteraction = time.Now()

	// Key transfer
	buf = make([]byte, 7+65536+64+1)
	for rType != PublicKey {
		if debug {
			fmt.Println("Waiting for PublicKey packet...")
		}
		n, _, err := conn.ReadFrom(buf)
		if n == len(buf) {
			if debug {
				fmt.Println("Packet truncated, trying again...")
			}
			continue
		}
		if err != nil {
			return err
		}
		if len(buf) < 7 {
			if debug {
				fmt.Println("Packet size too small, trying again...")
			}
			continue
		}
		rId, _ = toId(buf[:4])
		rType = uint8(buf[4])
		rLen := uint16(buf[5])<<8 | uint16(buf[6])
		if rType == ErrorReply || rType == Error {
			if debug {
				fmt.Println("Server notifies error from this client")
			}
			log.Fatal(buf[7 : 7+rLen])
		}
	}

	server.key = buf[7 : 7+rLen]

	formatted := make([]byte, 64)
	publicKey.X.FillBytes(formatted[:32])
	publicKey.Y.FillBytes(formatted[32:])

	pkrPacket := packet{
		typ:  uint8(PublicKeyReply),
		id:   rId,
		body: formatted,
	}

	for rType != Root {
		if debug {
			fmt.Println("Waiting for Root packet...")
		}
		bufr, err = writeExpBackoff(conn, addr, pkrPacket.Bytes())
		rType = uint8(bufr[4])
		if len(bufr) < 7 {
			if debug {
				fmt.Println("Server sent packet too small")
			}
			continue
		}
		if err != nil {
			return err
		}
		if rType == Error || rType == ErrorReply {
			if debug {
				fmt.Println("Server indicates error")
			}
			log.Fatal(string(bufr[7 : 7+uint16(bufr[5])<<8|uint16(bufr[6])]))
		}
		if rType == PublicKey {
			pkrPacket.id = uint32(bufr[0])<<24 | uint32(bufr[1])<<16 |
				uint32(bufr[2])<<8 | uint32(bufr[3])
		}
	}

	// Root hash transfer
	for {
		if debug {
			fmt.Println("Waiting for Root Hash transfer")
		}
		rId, _ = toId(bufr[:4])
		rLen = uint16(bufr[5])<<8 | uint16(bufr[6])
		server.rootHash = bufr[7 : 7+rLen]
		server.lastInteraction = time.Now()

		var rootHash [32]byte
		if root == nil {
			rootHash = sha256.Sum256([]byte(""))
		} else {
			rootHash = root.hash
		}
		packetRoot := packet{
			typ:  uint8(RootReply),
			id:   rId,
			body: rootHash[0:32],
		}
		if debug {
			fmt.Printf("Packet to send: %v\n", packetRoot.Bytes())
		}
		_, err := conn.WriteTo(packetRoot.Bytes(), addr)
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
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Fatal("ReadFrom:", err)
			} else {
				if debug {
					fmt.Println("Read deadline exceeded")
					fmt.Println("Checking if server received root hash")
				}

				_, err = getPeerRootHash(peerName)
				if err == nil {
					break
				}
				if debug {
					fmt.Println(err)
					fmt.Println("Trying again...")
				}
			}
		}
		if debug {
			fmt.Println("Resending RootReply...")
		}
	}
	if debug {
		fmt.Println("Registered to server")
	}
	return nil
}

// sendKeepalive sends hello requests to the server to keep the registration
// alive. It should be called periodically. Errors are handled differently than
// in serverRegistration: if an error is encountered, the function simply checks
// if the registration is still alive, and if it is not, it returns an error.
func sendKeepalive(conn net.PacketConn) error {
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, extensions)
	buf = append(buf, peerName...)
	idLock.Lock()
	if debug {
		fmt.Println("Locked id")
	}
	idKeepalive := id
	id++
	idLock.Unlock()
	if debug {
		fmt.Println("Unlocked id")
	}
	keepaliveRq := packet{
		typ:  uint8(Hello),
		id:   idKeepalive,
		body: buf,
	}
	server := knownPeers[serverName]
	addr := server.addrs[0]
	if debug {
		fmt.Println("Sending keepalive...")
	}
	bufr, err := writeExpBackoff(conn, addr, keepaliveRq.Bytes())
	if debug {
		fmt.Printf("Server response to keepalive = %v\n", bufr)
	}
	if err != nil {
		if debug {
			fmt.Println("Error in keepalive sending, checking registration")
		}
		_, err := getPeerSocketAddrs(peerName)
		if err != nil {
			return err
		} else if debug {
			fmt.Println("Client is still registered")
		}
	}
	rId, _ := toId(bufr[:4])
	rType := bufr[4]
	if rType == ErrorReply ||
		rType != HelloReply ||
		rId != keepaliveRq.id {
		if debug {
			fmt.Println("Error in response, checking registration...")
		}
		_, err := getPeerSocketAddrs(peerName)
		if err != nil {
			return err
		} else if debug {
			fmt.Println("Client is still registered")
		}
	} else {
		server.lastInteraction = time.Now()
		if debug {
			fmt.Printf("Last interaction with server: %v\n",
				server.lastInteraction)
		}
	}
	return nil
}

// Writes to the given socket the given data destined to the given address and
// waits for a response (note that it could be any response, not necessarily the
// one associated to the packet just sent). The first write occurs immediatly,
// then if needed 1 second later, and then doubles with every try, until it
// reaches a limit value, at which point the data returned is nil and the error
// is not. Otherwise, returns the packet received and nil as error.
func writeExpBackoff(conn net.PacketConn, addr *net.UDPAddr,
	data []byte) ([]byte, error) {
	wait := 0
	var buf []byte
	buf = make([]byte, 7+65536+64+1) // + 1 for truncation check
	for wait < limitExpBackoff {
		time.Sleep(time.Duration(wait) * time.Second)
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

// toId converts a slice of bytes of length 4 to an uint32 value and returns it.
// If the slice is not of length 4 it returns 0 and an error. The value in bytes
// is supposed to correspond to a uint32 value storid in NBO.
func toId(bytes []byte) (uint32, error) {
	l := len(bytes)
	if l != IdLen {
		return 0, fmt.Errorf("invalid slice length (%d), expected %d", l, IdLen)
	}
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 |
		uint32(bytes[3]), nil
}

// Returns true if at least one of the known peers has the given UDP address. If
// the given address is nil, returns an error.
func isKnownPeer(addr *net.UDPAddr) (bool, error) {
	if addr == nil {
		return false, fmt.Errorf("isKnownPeer: nil address")
	}
	for _, peer := range knownPeers {
		if peer.has(addr) {
			return true, nil
		}
	}
	return false, nil
}

// Updates the interaction time by setting it to time.Now() to all the known
// peers that have the given UDP address. If none has it, returns an error.
func updateInteractionTime(addr *net.UDPAddr) error {
	fname := "updateInteractionTime"
	if addr == nil {
		return fmt.Errorf(fname + ": nil address")
	}
	known, err := isKnownPeer(addr)
	if err != nil {
		return err
	}
	if !known {
		return fmt.Errorf(fname + ": unknown peer")
	}
	for name, peer := range knownPeers {
		if peer.has(addr) {
			if debug {
				fmt.Println("Updating interaction time of peer " + name)
			}
			peer.lastInteraction = time.Now()
		}
	}
	return nil
}

// handleRequest receives a buffer, an address and a connection and sends a
// response, if needed, to the emitter of the received request. This function
// is meant to be used in a separate thread to respond to an incoming
// communication of different id than the current one
func handleRequest(buf []byte, addr *net.UDPAddr, conn net.PacketConn) error {
	fname := "handleRequest"
	if addr == nil {
		return fmt.Errorf(fname + ": addr is nil")
	}
	if len(buf) < 7 {
		return fmt.Errorf(fname + ": packet received too small")
	}
	id := uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 |
		uint32(buf[3])
	l := uint16(buf[5])<<8 | uint16(buf[6])
	switch buf[4] {
	case Error, ErrorReply:
		log.Fatal("handleRequest:", buf[7:7+l])
	case Hello:
		if debug {
			fmt.Println("Handling Hello request")
		}
		body := make([]byte, 4+len(peerName))
		body = binary.BigEndian.AppendUint32(body, extensions)
		body = append(body, peerName...)
		resp := packet{HelloReply, id, body}
		_, err := conn.WriteTo(resp.Bytes(), addr)
		if err != nil {
			log.Fatal(fname, err)
		}
		known, err := isKnownPeer(addr)
		if err != nil {
			log.Fatal(fname, err)
		}
		if known {
			if err = updateInteractionTime(addr); err != nil {
				log.Fatal(fname, err)
			}
		}
		if debug {
			fmt.Println("Sent HelloReply response")
		}
		// what to do if host is unknown ?
		return nil
	case PublicKey:
		if debug {
			fmt.Println("Handling PublicKey request")
		}
		known, err := isKnownPeer(addr)
		if err != nil {
			log.Fatal(fname, err)
		}
		if !known {
			return nil
		}
		resp := packet{
			typ: PublicKeyReply,
			id:  id,
		}
		_, err = conn.WriteTo(resp.Bytes(), addr)
		if err != nil {
			log.Fatal(fname, err)
		}
		if err = updateInteractionTime(addr); err != nil {
			log.Fatal(fname, err)
		}
		if debug {
			fmt.Println("Sent PublicKeyReply response")
		}
		return nil
	case Root:
		if debug {
			fmt.Println("Handling Root request")
		}
		known, err := isKnownPeer(addr)
		if err != nil {
			log.Fatal(fname, err)
		}
		if !known {
			return nil
		}
		var rootHash []byte
		if root == nil {
			tmp := sha256.Sum256([]byte(""))
			rootHash = tmp[0:32]
		} else {
			rootHash = root.hash[0:32]
		}
		resp := packet{RootReply, id, rootHash}
		_, err = conn.WriteTo(resp.Bytes(), addr)
		if err != nil {
			log.Fatal(fname, err)
		}
		if debug {
			fmt.Println("Sent RootReply response")
		}
		return nil
	case GetDatum:
		if debug {
			fmt.Println("Handling GetDatum request")
		}
		known, err := isKnownPeer(addr)
		if err != nil {
			log.Fatal(fname, err)
		}
		if !known {
			return nil
		}
		hash := buf[7 : 7+l]
		resp := packet{NoDatum, id, hash}
		_, err = conn.WriteTo(resp.Bytes(), addr)
		if err != nil {
			log.Fatal(fname, err)
		}
		if debug {
			fmt.Println("Sent NoDatum response")
		}
		return nil
	default:
		return nil
	}
	if debug {
		fmt.Println(fname + ": Received packet of unknown type")
	}
	return nil
}
