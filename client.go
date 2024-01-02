package main

import (
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
	"bufio"
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
	IdLen = 4
)

var (
	knownPeers        = make(map[string]*knownPeer)
	debug             = true
	id         uint32 = 0
	idLock     sync.Mutex
	extensions uint32 = 0
	root *node = nil
	transport         = &*http.DefaultTransport.(*http.Transport)
	client            = &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}
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

	discoverPeers(client)
	conn, err := net.ListenPacket("udp", "")
	if err != nil {
		log.Fatal("net.ListenPacket:", err)
	}

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
			errKeepalive := sendKeepalive(client, conn)
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

func discoverPeers(client *http.Client) {
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
func getPeerPublicKey(client *http.Client, p string) ([]byte, error) {
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
// root hash or the it has not announced a root hash yet. If an error is
// encoutered during the process, err is not nil and the byte slice is.
func getPeerRootHash(client *http.Client, p string) ([]byte, error) {
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
	// Hello transfer
	buf = binary.BigEndian.AppendUint32(buf, extensions)
	buf = append(buf, peerName...)
	idLock.Lock()
	if debug {
		fmt.Println("Locked id")
	}
	idHello := id
	id++
	idLock.Unlock()
	if debug {
		fmt.Println("Unlocked id")
	}
	helloRq := packet{
		typeRq: uint8(Hello),
		id:     idHello,
		body:   buf,
	}
	server := knownPeers[serverName]
	addr := server.addrs[0]
	if debug {
		fmt.Println("Sending Hello request...")
	}
	bufr, err := writeExpBackoff(conn, addr, helloRq.Bytes())
	if debug {
		fmt.Printf("Server response to hello request = %v\n", bufr)
	}
	if err != nil {
		return err
	}
	respId := uint32(bufr[0])<<24 | uint32(bufr[1])<<16 | uint32(bufr[2])<<8 |
		uint32(bufr[3])
	respType := bufr[4]
	respLen := uint16(bufr[5]<<8) | uint16(bufr[6])
	if respType == NoOp {
		log.Fatal("Server sent NoOp and we don't know what to do")
	}
	if respType == ErrorReply {
		fmt.Println("Error reply")
		log.Fatal(string(bufr[7 : 7+respLen]))
	}
	if respType == Error {
		fmt.Println("Error reply")
		log.Fatal(string(buf[7 : 7+respLen]))
	}
	if respType != HelloReply {
		return fmt.Errorf("not the right response to hello rq %d", respType)
	}
	if respId != helloRq.id {
		return fmt.Errorf("Peer respond with id %d to packet id %d", respId,
			helloRq.id)
	}

	// Key transfer
	buf = make([]byte, 7+65536+64+1)
	if debug {
		fmt.Println("Waiting for PublicKey packet...")
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
	idPublicKeyPacket := uint32(buf[0])<<24 | uint32(buf[1])<<16 |
		uint32(buf[2])<<8 | uint32(buf[3])
	typeRq := uint8(buf[4])
	lenRq := uint16(buf[5])<<8 | uint16(buf[6])
	if debug {
		fmt.Printf("Received type %d of length %d with id %d\n", typeRq,
			lenRq, idPublicKeyPacket)
		fmt.Printf("Content: %v\n", buf[7:7+lenRq])
	}
	if typeRq == ErrorReply {
		log.Fatal(buf[7 : 7+lenRq])
	}
	if typeRq != PublicKey {
		return fmt.Errorf("TODO: not the expected packet type: %d", typeRq)
	}
	server.handshakeMade = true
	server.key = buf[7 : 7+lenRq]
	server.lastInteraction = time.Now()
	publicKeyReplyPacket := packet{
		typeRq: uint8(PublicKeyReply),
		id:     idPublicKeyPacket,
		body:   make([]byte, 0),
	}
	if debug {
		fmt.Printf("Packet to send: %v\n", publicKeyReplyPacket.Bytes())
	}
	for typeRq != Root && typeRq == PublicKey {
		bufr, err = writeExpBackoff(conn, addr, publicKeyReplyPacket.Bytes())
		typeRq = uint8(bufr[4])
		publicKeyReplyPacket.id = uint32(bufr[0])<<24 | uint32(bufr[1])<<16 |
			uint32(bufr[2])<<8 | uint32(bufr[3])
		if debug {
			fmt.Printf("bytes received after publicKeyReplyPacket: %v\n", bufr)
			fmt.Printf("new id of reply: %d\n", publicKeyReplyPacket.id)
			fmt.Printf("Packet to send: %v\n", publicKeyReplyPacket.Bytes())
		}
		if err != nil {
			return err
		}
		if typeRq == Error || typeRq == ErrorReply {
			fmt.Println("Server indicates error")
			log.Fatal(string(bufr[7 : 7+uint16(bufr[5])<<8|uint16(bufr[6])]))
		}
	}

	// Root hash transfer
	for {
		if debug {
			fmt.Println("Waiting for Root Hash transfer")
		}
		if len(bufr) < 7 {
			log.Fatal("Server sent a packet too small")
		}
		idRq := uint32(bufr[0])<<24 | uint32(bufr[1])<<16 | uint32(bufr[2])<<8 |
			uint32(bufr[3])
		typeRq := uint8(bufr[4])
		lenRq := uint16(bufr[5])<<8 | uint16(bufr[6])
		if debug {
			fmt.Printf("Received req type %d of length %d with id %d\n", typeRq,
				lenRq, idRq)
			fmt.Printf("idRq bytes: %v\n", bufr[:4])
		}
		if typeRq == ErrorReply {
			log.Fatal(bufr[7 : 7+lenRq])
		}
		if typeRq != Root {
			return fmt.Errorf("Expected type 4 but got %d", typeRq)
		}
		server.rootHash = bufr[7 : 7+lenRq]
		server.lastInteraction = time.Now()

		var rootHash [32]byte
		if root == nil {
			rootHash = sha256.Sum256([]byte(""))
		} else {
			rootHash = root.hash
		}
		packetRoot := packet{
			typeRq: uint8(RootReply),
			id: uint32(bufr[0])<<24 | uint32(bufr[1])<<16 | uint32(bufr[2])<<8 |
				uint32(bufr[3]),
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

		bufr = make([]byte, 7+65536+64+1)
		n, _, err := conn.ReadFrom(bufr)
		if n == len(buf) {
			log.Fatal("Peer packet exceeded maximum length")
		}
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Fatal("ReadFrom:", err)
			} else {
				if debug {
					fmt.Println("Deadline exceeded")
				}

				resp, err := client.Get(serverUrl + peersUrl + "/" + peerName +
					rootHashUrl)
				if err != nil {
					log.Fatal("Get:", err)
				}

				if resp.StatusCode == 200 {
					fmt.Println("Root hash transfer done")
					break
				} else if resp.StatusCode == 404 {
					if debug {
						log.Fatal("Error during RootReply: unknown peer")
					}
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
func sendKeepalive(client *http.Client, conn net.PacketConn) error {
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
		typeRq: uint8(Hello),
		id:     idKeepalive,
		body:   buf,
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
		_, err := getPeerSocketAddrs(client, peerName)
		if err != nil {
			return err
		} else if debug {
			fmt.Println("Client is still registered")
		}
	}
	respId := uint32(bufr[0])<<24 | uint32(bufr[1])<<16 |
		uint32(bufr[2])<<8 | uint32(bufr[3])
	respType := bufr[4]
	if respType == ErrorReply ||
		respType != HelloReply ||
		respId != keepaliveRq.id {
		if debug {
			fmt.Println("Error in response, checking registration...")
		}
		_, err := getPeerSocketAddrs(client, peerName)
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
	// if debug {
	// 	fmt.Println("Write procedure with exponential backoff")
	// }
	for wait < limitExpBackoff {
		// if debug {
		// 	fmt.Printf("wait time %d\n", wait)
		// }
		time.Sleep(time.Duration(wait) * time.Second)
		// if debug {
		// 	fmt.Printf("Writing to %s\n", addr.String())
		// }
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
		// if debug {
		// 	fmt.Println("Stopped reading from socket")
		// }
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
