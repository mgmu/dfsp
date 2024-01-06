package main

import (
	"bufio"
	"bytes"
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
	"math/big"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	serverUrl                = "https://" + serverName + ":" + serverPort
	serverName               = "jch.irif.fr"
	serverPort               = "8443"
	peersUrl                 = "/peers"
	addressesUrl             = "/addresses"
	keyUrl                   = "/key"
	rootHashUrl              = "/root"
	peerName                 = "Slartibartfast"
	limitExpBackoff          = 32
	idLen                    = 4
	pkeyFile                 = "private.key"
	natTraversalRequestTries = 3
)

var (
	knownPeers     = make(map[string]*knownPeer)
	knownPeersLock sync.Mutex
	debug                 = true
	id             uint32 = 0
	idLock         sync.Mutex
	extensions     uint32 = 0
	root           *node  = nil
	transport             = &*http.DefaultTransport.(*http.Transport)
	client                = &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}
	privateKey *ecdsa.PrivateKey = nil
	publicKey  *ecdsa.PublicKey  = nil
	enable                       = true
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

	if f, err := os.Open(pkeyFile); err == nil {
		if debug {
			fmt.Printf("Reading private key from %s\n", pkeyFile)
		}
		var priv, pubX, pubY big.Int
		buf := make([]byte, 3*32)
		_, err := f.Read(buf)
		if err != nil {
			log.Fatal("f.Read:", err)
		}
		priv = *big.NewInt(0).SetBytes(buf[:32])
		pubX = *big.NewInt(0).SetBytes(buf[32:64])
		pubY = *big.NewInt(0).SetBytes(buf[64:96])
		publicKey = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     &pubX,
			Y:     &pubY,
		}
		privateKey = &ecdsa.PrivateKey{
			PublicKey: *publicKey,
			D:         &priv,
		}
		if f.Close() != nil {
			log.Fatal("f.Close:", err)
		}
	} else if os.IsNotExist(err) {
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatal("ecdsa.GenerateKey:", err)
		}
		tmp, ok := privateKey.Public().(*ecdsa.PublicKey)
		if !ok {
			log.Fatal("failed to get public key from private key")
		}
		publicKey = tmp

		if f, err := os.Create(pkeyFile); err == nil {
			if debug {
				fmt.Printf("Writing private key to %s\n", pkeyFile)
			}
			priv := privateKey.D.Bytes()
			pubX, pubY := privateKey.X.Bytes(), privateKey.Y.Bytes()
			buf := make([]byte, 0)
			buf = append(buf, priv...)
			buf = append(buf, pubX...)
			buf = append(buf, pubY...)
			if _, err := f.Write(buf); err != nil {
				log.Fatal("f.Write:", err)
			}
			if f.Close() != nil {
				log.Fatal("f.Close:", err)
			}
		} else {
			log.Fatal("os.Create:", err)
		}
	} else {
		log.Fatal("os.Open:", err)
	}

	if err = serverRegistration(conn); err != nil {
		log.Fatal("Could not register to server: ", err)
	}

	// send keepalive periodically & remove peers that have not been seen for
	// more than 3 minutes
	go func() {
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
			knownPeersLock.Lock()
			for _, peer := range knownPeers {
				if time.Since(peer.lastInteraction) > 3*time.Minute {
					peer.handshakeMade = false
				}
			}
			knownPeersLock.Unlock()
		}
	}()

	// listen for requests
	go func() {
		for {
			for enable {
				if debug {
					fmt.Println("Listening...")
				}
				buf := make([]byte, 4+1+2+65536+1)
				err = conn.SetReadDeadline((time.Now()).Add(time.Minute))
				if err != nil {
					fmt.Println(err)
				}
				n, addr, err := conn.ReadFrom(buf)
				if err != nil {
					if !errors.Is(err, os.ErrDeadlineExceeded) {
						if debug {
							fmt.Println("listen thread failed")
						}
						log.Fatal("ReadFrom:", err)
					}
					continue
				}
				if n == len(buf) || n < 7 {
					if debug {
						fmt.Println("packet truncated")
					}
					continue
				}
				udpAddr, err := net.ResolveUDPAddr(addr.Network(),
					addr.String())
				if err != nil {
					if debug {
						fmt.Println(err)
					}
					continue
				}
				_, err = handleRequest(buf[:n], udpAddr, conn)
				if debug {
					fmt.Println("Handled request from listening thread")
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
				fmt.Println("Enter peer name & optionally hash:")
				scanner.Scan()
				input := strings.Split(scanner.Text(), " ")
				peer := input[0]
				if knownPeers[peer] == nil {
					fmt.Println("Unknown peer.")
				} else {
					if strings.Compare(peer, peerName) == 0 {
						fmt.Println("You already have your data...")
						continue
					}
					hashString := ""
					if len(input) > 1 {
						hashString = input[1]
					}
					hash := []byte(hashString)
					if hashString == "" {
						hash = knownPeers[peer].rootHash
					}
					if len(hash) == 32 {
						enable = false
						n, err := getDatum(peer, hash, conn, "data")
						if err != nil {
							fmt.Println(err)
						} else {
							if debug {
								fmt.Println("Beginning write")
							}
							if err := n.Write("./"); err != nil {
								fmt.Printf("Error writing: %v\n", err)
							} else if debug {
								fmt.Println("Write done")
							}
						}
						enable = true
					} else {
						fmt.Println("Error: hash must be 32 bytes long.")
					}
				}
			case "p":
				knownPeersLock.Lock()
				for k, v := range knownPeers {
					fmt.Println(k)
					fmt.Println(v)
				}
				knownPeersLock.Unlock()
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
	if err = conn.Close(); err != nil {
		log.Fatal("Close:", err)
	}
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
		addrs, key, rootHash, err := fetchInfoFor(peers[i])
		if err != nil {
			log.Fatal("fetchInfoFor:", err)
		}
		knownPeersLock.Lock()
		knownPeers[peers[i]] = newKnownPeer(addrs, key, rootHash)
		knownPeersLock.Unlock()
	}
}

// Fetches the socket addresses, the public key and the root hash of a peer of
// given name.
func fetchInfoFor(name string) ([]*net.UDPAddr, []byte, []byte, error) {
	addrs, err := getPeerSocketAddrs(name)
	if err != nil {
		return nil, []byte{}, []byte{}, err
	}
	key, err := getPeerPublicKey(name)
	if err != nil {
		return nil, []byte{}, []byte{}, err
	}
	rootHash, err := getPeerRootHash(name)
	if err != nil {
		return nil, []byte{}, []byte{}, err
	}
	return addrs, key, rootHash, nil
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
	knownPeersLock.Lock()
	server := knownPeers[serverName]
	addr := server.addrs[0]
	knownPeersLock.Unlock()

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
				if _, err = handleRequest(bufr, addr, conn); err != nil {
					log.Fatal(err)
				}
			}()
			continue
		}
		rType = bufr[4]
		rLen = uint16(bufr[5])<<8 | uint16(bufr[6])
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

	knownPeersLock.Lock()
	server = knownPeers[serverName]
	server.handshakeMade = true
	server.lastInteraction = time.Now()
	knownPeersLock.Unlock()

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

	knownPeersLock.Lock()
	server = knownPeers[serverName]
	server.key = buf[7 : 7+rLen]
	knownPeersLock.Unlock()

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
			pkrPacket.id, _ = toId(bufr[:4])
		}
	}

	// Root hash transfer
	for {
		if debug {
			fmt.Println("Waiting for Root Hash transfer")
		}
		rId, _ = toId(bufr[:4])
		rLen = uint16(bufr[5])<<8 | uint16(bufr[6])
		knownPeersLock.Lock()
		server = knownPeers[serverName]
		server.rootHash = bufr[7 : 7+rLen]
		server.lastInteraction = time.Now()
		knownPeersLock.Unlock()

		var rootHash [32]byte
		if root == nil {
			rootHash = sha256.Sum256([]byte(""))
		} else {
			rootHash = root.hash
		}
		packetRoot := packet{
			typ:  uint8(RootReply),
			id:   rId,
			body: rootHash[:],
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
	knownPeersLock.Lock()
	if debug {
		fmt.Println("Locked knownPeers")
	}
	if debug {
		fmt.Println("Copying server addresses")
	}
	server := knownPeers[serverName]
	addr := *server.addrs[0]
	knownPeersLock.Unlock()
	if debug {
		fmt.Println("Unlocked knownPeers")
	}
	if debug {
		fmt.Println("Sending keepalive...")
	}
	for {
		bufr, err := writeExpBackoff(conn, &addr, keepaliveRq.Bytes())
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
			return nil
		}
		rId, _ := toId(bufr[:4])
		rType := bufr[4]
		if rType != HelloReply || rId != keepaliveRq.id {
			go func() {
				if _, err := handleRequest(bufr, &addr, conn); err != nil {
					log.Fatal(err)
				}
			}()
			continue
		} else {
			updateInteractionTime(&addr)
			if debug {
				fmt.Printf("Last interaction with server: %v\n",
					server.lastInteraction)
			}
			return nil
		}
	}
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
		if debug {
			fmt.Printf("write sleep for %d seconds\n", wait)
		}
		time.Sleep(time.Duration(wait) * time.Second)
		if debug {
			fmt.Println("done sleeping")
		}
		_, err := conn.WriteTo(data, addr)
		if err != nil {
			log.Fatal("WriteTo:", err)
		}
		if debug {
			fmt.Println("sent packet")
		}

		err = conn.SetReadDeadline((time.Now()).Add(2 * time.Second))
		if err != nil {
			log.Fatal("SetReadDeadline:", err)
		}

		n, _, err := conn.ReadFrom(buf)
		if debug {
			fmt.Println("read packet")
		}

		if n == len(buf) {
			log.Fatal("Peer packet exceeded maximum length")
		}
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				if debug {
					fmt.Println("error from read")
				}
				log.Fatal("ReadFrom:", err)
			}
			if wait == 0 {
				if debug {
					fmt.Println("first send, increment")
				}
				wait++
			} else {
				if debug {
					fmt.Println("after first send, double wait time")
				}
				wait *= 2
			}
		} else {
			if debug {
				fmt.Println("error is nil, update interaction time")
			}
			updateInteractionTime(addr)
			if debug {
				fmt.Println("about to return the received data")
			}
			return buf[:n], nil
		}
	}
	return nil, fmt.Errorf("Exponential backoff limit exceeded")
}

// toId converts a slice of bytes of length 4 to an uint32 value and returns it.
// If the slice is not of length 4 it returns 0 and an error. The value in bytes
// is supposed to correspond to a uint32 value storid in NBO.
func toId(bytes []byte) (uint32, error) {
	l := len(bytes)
	if l != idLen {
		return 0, fmt.Errorf("invalid slice length (%d), expected %d", l, idLen)
	}
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 |
		uint32(bytes[3]), nil
}

// Returns true if at least one of the known peers has the given UDP address. If
// the given address is nil, returns an error.
func isKnownPeer(addr *net.UDPAddr) (bool, error) {
	if debug {
		fmt.Println("checking is peer is known")
	}
	if addr == nil {
		return false, fmt.Errorf("isKnownPeer: nil address")
	}
	for _, peer := range knownPeers {
		if peer.has(addr) {
			if debug {
				fmt.Println("check finished")
			}
			return true, nil
		}
	}
	if debug {
		fmt.Println("check finished")
	}
	return false, nil
}

// Updates the interaction time by setting it to time.Now() to all the known
// peers that have the given UDP address. If none has it, returns an error.
func updateInteractionTime(addr *net.UDPAddr) error {
	if debug {
		fmt.Println("updating interaction time")
	}
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
	if debug {
		fmt.Println("updated interaction time")
	}
	return nil
}

// handleRequest receives a buffer, an address and a connection and sends a
// response, if needed, to the emitter of the received request. Returns true if
// a response was sent, false if not, and a non nil error if something went
// wrong.
func handleRequest(buf []byte, addr *net.UDPAddr,
	conn net.PacketConn) (bool, error) {
	fname := "handleRequest"
	if addr == nil {
		return false, fmt.Errorf(fname + ": addr is nil")
	}
	if len(buf) < 7 {
		return false, fmt.Errorf(fname + ": packet received too small")
	}
	id, _ := toId(buf[:4])
	l := uint16(buf[5])<<8 | uint16(buf[6])
	if len(buf) < int(7+l) {
		return false, fmt.Errorf(fname + ": packet size does not match")
	}
	switch buf[4] {
	case Error, ErrorReply:
		log.Fatal("handleRequest:", buf[7:7+l])
	case Hello:
		if debug {
			fmt.Println("Handling Hello request")
			fmt.Println("Checking format of message")
		}

		if l < 5 {
			if debug {
				fmt.Println("Packet truncated -> ignore request")
			}
			return false, nil
		}

		name := string(buf[11 : 7+l])
		knownPeersLock.Lock()
		peer, prs := knownPeers[name]
		if prs {
			if debug {
				fmt.Println("Peer " + name + " is known")
			}
			if peer.implementsSignatures() {
				if int(7+l) > len(buf) {
					if debug {
						fmt.Println("packet does not contain signature")
					}
					return false, nil
				}
				if !checkSignature(buf[:7+l], buf[7+l:], peer.key) {
					if debug {
						fmt.Println("Signature invalid -> ignore request")
					}
					knownPeersLock.Unlock()
					return false, nil
				}
				if debug {
					fmt.Println("Signature of " + name + " checks out")
				}
			}
			if err := updateInteractionTime(addr); err != nil {
				log.Fatal(fname, err)
			}
		} else {
			if debug {
				fmt.Println("Peer " + name + " is unknown")
			}
			addrs, key, rootHash, err := fetchInfoFor(name)
			if err != nil {
				return false, err
			}
			if !slices.Equal(key, make([]byte, 64)) {
				if int(7+l) > len(buf) {
					if debug {
						fmt.Println("packet does not contain signature")
					}
					return false, nil
				}
				if !checkSignature(buf[:7+l], buf[7+l:], key) {
					if debug {
						fmt.Println("Signature invalid -> ignore request")
					}
					knownPeersLock.Unlock()
					return false, nil
				}
				if debug {
					fmt.Println("Signature of " + name + " checks out")
				}
			}
			knownPeers[name] = newKnownPeer(addrs, key, rootHash)
			knownPeersLock.Unlock()
		}

		body := make([]byte, 4+len(peerName))
		body = binary.BigEndian.AppendUint32(body, extensions)
		body = append(body, peerName...)
		resp := packet{HelloReply, id, body}
		data := resp.Bytes()
		n, err := conn.WriteTo(data, addr)
		if n != len(data) {
			return false, nil
		}
		if err != nil {
			log.Fatal(fname, err)
		}
		if debug {
			fmt.Println("Sent HelloReply response")
		}
		return true, nil
	case PublicKey:
		if debug {
			fmt.Println("Handling PublicKey request")
		}
		knownPeersLock.Lock()
		defer knownPeersLock.Unlock()
		known, err := isKnownPeer(addr)
		if err != nil {
			log.Fatal(fname, err)
		}
		if !known {
			knownPeersLock.Unlock()
			return false, nil
		}
		name, peer, _ := getPeerWith(addr)

		if peer.handshakeMade {
			if peer.implementsSignatures() {
				if int(7+l) > len(buf) {
					if debug {
						fmt.Println("packet does not contain signature")
					}
					return false, nil
				}
				if !checkSignature(buf[:7+l], buf[7+l:], peer.key) {
					if debug {
						fmt.Println("Signature invalid -> ignore request")
					}
					return false, nil
				}
				if debug {
					fmt.Println("Signature of " + name + " checks out")
				}
			}

			formatted := make([]byte, 64)
			publicKey.X.FillBytes(formatted[:32])
			publicKey.Y.FillBytes(formatted[32:])
			resp := packet{
				typ:  PublicKeyReply,
				id:   id,
				body: formatted,
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
		}
		return true, nil
	case Root:
		if debug {
			fmt.Println("Handling Root request")
		}
		knownPeersLock.Lock()
		defer knownPeersLock.Unlock()
		known, err := isKnownPeer(addr)
		if err != nil {
			log.Fatal(fname, err)
		}
		if !known {
			return false, nil
		}

		name, peer, _ := getPeerWith(addr)
		if peer.handshakeMade {
			if peer.implementsSignatures() {
				if int(7+l) > len(buf) {
					if debug {
						fmt.Println("packet does not contain signature")
					}
					return false, nil
				}
				if !checkSignature(buf[:7+l], buf[7+l:], peer.key) {
					if debug {
						fmt.Println("Signature invalid -> ignore request")
					}
					return false, nil
				}
				if debug {
					fmt.Println("Signature of " + name + " checks out")
				}
			}

			var rootHash []byte
			if root == nil {
				tmp := sha256.Sum256([]byte(""))
				rootHash = tmp[:]
			} else {
				rootHash = root.hash[:]
			}
			resp := packet{RootReply, id, rootHash}
			_, err = conn.WriteTo(resp.Bytes(), addr)
			if err != nil {
				log.Fatal(fname, err)
			}
			if debug {
				fmt.Println("Sent RootReply response")
			}
		}
		knownPeersLock.Lock()
		updateInteractionTime(addr)
		knownPeersLock.Unlock()
		return true, nil
	case GetDatum:
		if debug {
			fmt.Println("Handling GetDatum request")
		}
		knownPeersLock.Lock()
		if debug {
			fmt.Println("Locked knownPeers")
		}
		known, err := isKnownPeer(addr)
		knownPeersLock.Unlock()
		if debug {
			fmt.Println("Unlocked knownPeers")
		}
		if err != nil {
			log.Fatal(fname, err)
		}
		if !known {
			return false, nil
		}
		knownPeersLock.Lock()
		_, peer, err := getPeerWith(addr)
		knownPeersLock.Unlock()
		if err != nil {
			return false, err
		} else if peer.handshakeMade {
			hash := buf[7 : 7+l]
			resp := packet{NoDatum, id, hash}
			_, err = conn.WriteTo(resp.Bytes(), addr)
			if err != nil {
				log.Fatal(fname, err)
			}
			if debug {
				fmt.Println("Sent NoDatum response")
			}
		}
		knownPeersLock.Lock()
		updateInteractionTime(addr)
		knownPeersLock.Unlock()
		return true, nil
	case NatTraversal:
		if debug {
			fmt.Println("Received NatTraversal")
		}
		if l != 6 && l != 18 {
			if debug {
				fmt.Println("Received NatTraversal has invalid size")
			}
			return false, fmt.Errorf("packet truncated")
		}
		knownPeersLock.Lock()
		if debug {
			fmt.Println("Locked knownPeers")
		}
		server := knownPeers[serverName]
		found := false
		for _, other := range server.addrs {
			if bytes.Equal(addr.IP, other.IP) && addr.Port == other.Port {
				found = true
			}
		}
		if !found {
			knownPeersLock.Unlock()
			if debug {
				fmt.Println("Unlocked knownPeers")
				fmt.Println("Ignore NatTraversal from other than server")
			}
			return false, nil
		}
		knownPeersLock.Unlock()
		if debug {
			fmt.Println("Unlocked knownPeers")
		}

		// send Hello to p
		var ip []byte
		var port uint16
		if l == 6 {
			ip = buf[7:11]
			port = uint16(buf[11])<<8 | uint16(buf[12])
		} else {
			ip = buf[7:23]
			port = uint16(buf[23])<<8 | uint16(buf[24])
		}

		pAddr := net.UDPAddr{
			IP: ip,
			Port: int(port),
		}

		idLock.Lock()
		if debug {
			fmt.Println("Locked id")
		}
		idPack := id
		id++
		idLock.Unlock()
		if debug {
			fmt.Println("Unlocked id")
		}
		var body []byte
		body = binary.BigEndian.AppendUint32(body, extensions)
		body = append(body, peerName...)
		pack := packet{
			typ:  Hello,
			id:   idPack,
			body: body,
		}
		data := pack.Bytes()
		if debug {
			fmt.Println("NatTraversal: Sending hello request")
			fmt.Println("%v\n", data)
		}
		n, err := conn.WriteTo(data, &pAddr)
		if n != len(data) {
			log.Fatal("packet truncated")
		}
		if err != nil {
			log.Fatal("WriteTo:", err)
		}

		// wait hello reply from p
		// TODO: factorize
		err = conn.SetReadDeadline((time.Now()).Add(time.Second))
		if err != nil {
			log.Fatal("SetReadDeadline:", err)
		}
		buf := make([]byte, 4+1+2+65536+1)
		n, _, err = conn.ReadFrom(buf)
		if n == len(buf) || n < minimalHelloPacketLength {
			if debug {
				fmt.Println("NatTraversal: packet truncated")
			}
			return false, nil
		}
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Fatal("ReadFrom:", err)
			}
			if debug {
				fmt.Println("NatTraversal: deadline exceeded, abort")
			}
			return false, nil
		}
		idBuf, _ := toId(buf[:4])
		if pack.id != idBuf || buf[5] != HelloReply {
			go func() {
				if _, err = handleRequest(buf, addr, conn); err != nil {
					log.Fatal(err)
				}
			}()
			return false, nil
		}
		length := uint16(buf[5])<<8 | uint16(buf[6])
		name := string(buf[11 : 11+length])

		// check hello reply
		// TODO: factorize
		knownPeersLock.Lock()
		if debug {
			fmt.Println("Locked knownPeers")
		}
		peer, prs := knownPeers[name]
		if prs {
			if debug {
				fmt.Println("Peer " + name + " is known")
			}
			if peer.implementsSignatures() {
				if int(7+length) > len(buf) {
					if debug {
						fmt.Println("packet does not contain signature")
					}
					return false, nil
				}
				if !checkSignature(buf[:7+length], buf[7+length:], peer.key) {
					if debug {
						fmt.Println("Signature invalid -> ignore request")
					}
					knownPeersLock.Unlock()
					if debug {
						fmt.Println("Unlocked knownPeers")
					}
					return false, nil
				}
				if debug {
					fmt.Println("Signature of " + name + " checks out")
				}
			}
			if err = updateInteractionTime(&pAddr); err != nil {
				log.Fatal(err)
			}
		} else {
			if debug {
				fmt.Println("Peer " + name + " is unknown")
			}
			addrs, key, rootHash, err := fetchInfoFor(name)
			if err != nil {
				return false, err
			}
			if !slices.Equal(key, make([]byte, 64)) {
				if int(7+length) > len(buf) {
					if debug {
						fmt.Println("packet does not contain signature")
					}
					return false, nil
				}
				if !checkSignature(buf[:7+length], buf[7+length:], key) {
					if debug {
						fmt.Println("Signature invalid -> ignore request")
					}
					knownPeersLock.Unlock()
					if debug {
						fmt.Println("Unlocked knownPeers")
					}
					return false, nil
				}
				if debug {
					fmt.Println("Signature of " + name + " checks out")
				}
			}
			knownPeers[name] = newKnownPeer(addrs, key, rootHash)
			knownPeersLock.Unlock()
			if debug {
				fmt.Println("Unlocked knownPeers")
			}
		}

		// let p verify our signature
		time.Sleep(time.Second)

		// wait for hello from p
		err = conn.SetReadDeadline((time.Now()).Add(time.Second))
		if err != nil {
			log.Fatal("SetReadDeadline:", err)
		}
		buf = make([]byte, 4+1+2+65536+1)
		n, oAddr, err := conn.ReadFrom(buf)
		if n == len(buf) || n < minimalHelloPacketLength {
			if debug {
				fmt.Println("packet truncated")
			}
			return false, nil
		}
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Fatal("ReadFrom:", err)
			}
			if debug {
				fmt.Println("Deadline exceeded")
			}
			return false, nil
		}

		idBuf, _ = toId(buf[:4])
		if pack.id != idBuf || buf[5] != Hello {
			if strings.Compare(oAddr.Network(), "udp") != 0 {
				fmt.Println("wrong network")
				return false, nil
			}
			udpAddr, err := net.ResolveUDPAddr(oAddr.Network(),
				oAddr.String())
			if err != nil {
				return false, err
			}
			go func() {
				if _, err = handleRequest(buf, udpAddr, conn); err != nil {
					log.Fatal(err)
				}
			}()
			return false, nil
		}

		ok, err := handleRequest(buf, &pAddr, conn)
		if err != nil {
			return false, err
		}
		if !ok {
			if debug {
				fmt.Println("Failed nat traversal")
			}
			return false, nil
		}
		if debug {
			fmt.Println("Nat traversal success")
		}

		return true, nil
	default:
		return false, nil
	}
	if debug {
		fmt.Println(fname + ": Received packet of unknown type")
	}
	return false, nil
}

// Checks if the data was correctly signed
func checkSignature(data, signature, key []byte) bool {
	if len(key) != 64 || len(signature) != 64 {
		return false
	}
	var x, y big.Int
	x.SetBytes(key[:32])
	y.SetBytes(key[32:])
	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     &x,
		Y:     &y,
	}
	var r, s big.Int
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])
	hashed := sha256.Sum256(data)
	return ecdsa.Verify(publicKey, hashed[:], &r, &s)
}

// getPeerWith returns the name and the peer information of one of the peers
// that have the given address.
func getPeerWith(addr *net.UDPAddr) (string, *knownPeer, error) {
	if addr == nil {
		return "", nil, fmt.Errorf("invalid nil argument")
	}
	for name, peer := range knownPeers {
		if peer.has(addr) {
			return name, peer, nil
		}
	}
	return "", nil, fmt.Errorf("peer with given address not found")
}

// natTraversalRequest starts a NAT traversal procedure. Use this function if
// a peer can not be reached.
func natTraversalRequest(addr *net.UDPAddr, conn net.PacketConn) error {
	// addr is q
	body := addrToBytes(addr)
	if body == nil {
		return fmt.Errorf("failed to build nat traversal request packet")
	}

	noOpToPeer := true
	// needed if we also are behind a NAT
	go func() {
		for noOpToPeer {
			idLock.Lock()
			idNoOp := id
			id++
			idLock.Unlock()
			pack := packet{
				typ: NoOp,
				id:  idNoOp,
			}
			conn.WriteTo(pack.Bytes(), addr)
			if debug {
				fmt.Println("Sent NoOp to peer")
			}
			time.Sleep(time.Second)
		}
	}()

	for i := 0; i < natTraversalRequestTries; i++ {
		if debug {
			fmt.Printf("Try #%d of nat traversal\n", i)
		}
		// send NTR to server
		idLock.Lock()
		if debug {
			fmt.Println("Locking id")
		}
		idPack := id
		id++
		idLock.Unlock()
		if debug {
			fmt.Println("Unlocking id")
		}
		pack := packet{
			typ:  NatTraversalRequest,
			id:   idPack,
			body: body,
		}
		data := pack.Bytes()
		if debug {
			fmt.Println("Sending nat traversal request")
			fmt.Println("%v\n", data)
		}
		knownPeersLock.Lock()
		server := knownPeers[serverName]
		servAddr := server.addrs[0]
		knownPeersLock.Unlock()
		n, err := conn.WriteTo(data, servAddr)
		if n != len(data) {
			noOpToPeer = false
			log.Fatal("packet truncated")
		}
		if err != nil {
			noOpToPeer = false
			log.Fatal("WriteTo:", err)
		}

		// wait a certain amount of time a hello from addr
		err = conn.SetReadDeadline((time.Now()).Add(time.Second))
		if err != nil {
			noOpToPeer = false
			log.Fatal("SetReadDeadline:", err)
		}
		buf := make([]byte, 4+1+2+65536+1)
		n, _, err = conn.ReadFrom(buf)
		if n == len(buf) || n < minimalHelloPacketLength {
			if debug {
				fmt.Println("packet truncated")
			}
			continue
		}
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Fatal("ReadFrom:", err)
			}
			// if deadline exceeded, try again
			continue
		}
		idBuf, _ := toId(buf[:4])
		if pack.id != idBuf || buf[5] != Hello {
			go func() {
				if _, err = handleRequest(buf, addr, conn); err != nil {
					log.Fatal(err)
				}
			}()
			continue
		}
		ok, err := handleRequest(buf, addr, conn)
		if err != nil {
			noOpToPeer = false
			log.Fatal(err)
		}
		if !ok {
			continue
		}
		length := uint16(buf[5])<<8 | uint16(buf[6])
		name := string(buf[11 : 11+length])

		// wait a little bit to let addr verify our signature if needed
		time.Sleep(time.Second)

		// send a hello to addr
		buf = make([]byte, 4+len(peerName))
		buf = binary.BigEndian.AppendUint32(buf, extensions)
		buf = append(buf, peerName...)
		idLock.Lock()
		idPack = id
		id++
		idLock.Unlock()
		pack = packet{
			typ:  Hello,
			id:   idPack,
			body: buf,
		}
		data = pack.Bytes()
		n, err = conn.WriteTo(data, addr)
		if n != len(data) {
			noOpToPeer = false
			log.Fatal("packet truncated")
		}
		if err != nil {
			noOpToPeer = false
			log.Fatal(err)
		}

		// wait a certain amount of time the hello reply
		err = conn.SetReadDeadline((time.Now()).Add(time.Second))
		if err != nil {
			noOpToPeer = false
			log.Fatal("SetReadDeadline:", err)
		}
		buf = make([]byte, 4+1+2+65536+1)
		n, _, err = conn.ReadFrom(buf)
		if n == len(buf) || n < minimalHelloPacketLength {
			if debug {
				fmt.Println("packet truncated")
			}
			continue
		}
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				noOpToPeer = false
				log.Fatal("ReadFrom:", err)
			}
			// if deadline exceeded, try again
			continue
		}

		idBuf, _ = toId(buf[:4])
		if pack.id != idBuf || buf[5] != Hello {
			go func() {
				if _, err = handleRequest(buf, addr, conn); err != nil {
					log.Fatal(err)
				}
			}()
			continue
		}

		length = uint16(buf[5])<<8 | uint16(buf[6])
		knownPeersLock.Lock()
		peer := knownPeers[name]
		if peer.implementsSignatures() {
			if !checkSignature(buf[:7+length], buf[7+length:], peer.key) {
				if debug {
					fmt.Println("Signature invalid -> ignore request")
				}
				knownPeersLock.Unlock()
				continue
			}
			if debug {
				fmt.Println("Signature of " + name + " checks out")
			}
		}
		if err = updateInteractionTime(addr); err != nil {
			noOpToPeer = false
			log.Fatal(err)
		}
		knownPeersLock.Unlock()
		noOpToPeer = false
		return nil
	}
	noOpToPeer = false
	return fmt.Errorf("Failed NAT traversal")
}
