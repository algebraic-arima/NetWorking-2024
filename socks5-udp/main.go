package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	tcpListenPort = 1081
)

func handleConnection(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 256)
	n, err := conn.Read(buffer)
	fmt.Println(string(buffer))
	if err != nil {
		fmt.Println("Error reading from connection:", err)
		return
	}

	if n < 3 || buffer[0] != 5 {
		fmt.Println("Invalid SOCKS5 version identifier/method selection message")
		return
	}

	methods := buffer[2:n]
	var methodSelected byte = 0
	methodAccepted := false

	for _, method := range methods {
		if method == 0 {
			methodAccepted = true
			break
		}
	}

	if !methodAccepted {
		methodSelected = 0xff
	}

	// send method selection response
	_, err = conn.Write([]byte{5, methodSelected})
	if err != nil {
		fmt.Println("Error writing method selection message:", err)
		return
	}

	if methodSelected == 0xff {
		fmt.Println("No acceptable authentication methods")
		return
	}

	_, err = conn.Read(buffer)
	if err != nil {
		fmt.Println("Error reading from connection:", err)
		return
	}

	fmt.Println(buffer)

	if buffer[0] != 5 || buffer[1] != 3 {
		fmt.Println("Invalid SOCKS5 UDP ASSOCIATE request")
		return
	}
	fmt.Println("UDP ASSOCIATE")

	var bindAddr *net.UDPAddr
	switch buffer[3] {
	case 1:
		bindAddr = &net.UDPAddr{
			IP:   net.IPv4(buffer[4], buffer[5], buffer[6], buffer[7]),
			Port: int(binary.BigEndian.Uint16(buffer[8:10])),
		}
	case 4:
		bindAddr = &net.UDPAddr{
			IP:   net.IP(buffer[4:20]),
			Port: int(binary.BigEndian.Uint16(buffer[20:22])),
		}
	case 3:
		domainLength := int(buffer[4])
		domain := string(buffer[5 : 5+domainLength])
		port := int(binary.BigEndian.Uint16(buffer[5+domainLength : 5+domainLength+2]))
		ipAddr, err := net.ResolveIPAddr("ip", domain)
		if err != nil {
			fmt.Println("Error resolving domain name:", err)
			return
		}
		bindAddr = &net.UDPAddr{
			IP:   ipAddr.IP,
			Port: port,
		}
	default:
		fmt.Println("Unsupported address type")
		return
	}
	fmt.Println(bindAddr)
	// Listen on a random UDP port
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		fmt.Println("Error listening on UDP port:", err)
		return
	}
	fmt.Printf("Listening on UDP port: %d\n", udpConn.LocalAddr().(*net.UDPAddr).Port)
	defer udpConn.Close()

	// Send response to client
	bndAddr := udpConn.LocalAddr().(*net.UDPAddr)
	response := []byte{
		5, 0x00, 0x00, 1,
		0, 0, 0, 0,
		byte(bndAddr.Port >> 8), byte(bndAddr.Port & 0xff),
	}
	copy(response[4:8], bndAddr.IP.To4())
	_, err = conn.Write(response)
	if err != nil {
		fmt.Println("Error writing to connection:", err)
		return
	}

	buffer = make([]byte, 4096)
	for {
		udpConn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// Read UDP packet from the random port
		n, addr, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error reading from UDP:", err)
			break
		}

		fmt.Printf("Received %d bytes from %s\n", n, addr)
		if n < 10 {
			fmt.Println("Invalid UDP packet")
			continue
		}

		dstAddr := parseSocks5Address(buffer[3:])
		if dstAddr == nil {
			fmt.Println("Invalid destination address")
			continue
		}

		// Send UDP packet to destination port
		targetAddr, err := net.ResolveUDPAddr("udp", dstAddr.String())
		if err != nil {
			fmt.Println("Error resolving target address:", err)
			continue
		}
		_, err = udpConn.WriteToUDP(buffer[10:n], targetAddr)
		if err != nil {
			fmt.Println("Error writing to target address:", err)
			continue
		}

		fmt.Println("Sent to server:", string(buffer))

		// Receive response from destination port
		n, addr, err = udpConn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error reading from target server:", err)
			continue
		}

		// Send response back to client
		socksHeader := make([]byte, 10)
		socksHeader[0] = 0
		socksHeader[1] = 0
		socksHeader[2] = 0
		socksHeader[3] = 1
		copy(socksHeader[4:8], addr.IP.To4())
		binary.BigEndian.PutUint16(socksHeader[8:10], uint16(addr.Port))
		response = append(socksHeader, buffer[:n]...)
		_, err = udpConn.WriteToUDP(response, addr)
		if err != nil {
			fmt.Println("Error writing to client address:", err)
			continue
		}
		fmt.Println("Received from target server:", response)
	}
}

func parseSocks5Address(buffer []byte) net.Addr {
	switch buffer[0] {
	case 1:
		if len(buffer) < 7 {
			return nil
		}
		ip := net.IPv4(buffer[1], buffer[2], buffer[3], buffer[4])
		port := int(binary.BigEndian.Uint16(buffer[5:7]))
		return &net.UDPAddr{IP: ip, Port: port}
	case 3:
		domainLength := int(buffer[1])
		if len(buffer) < 2+domainLength+2 {
			return nil
		}
		domain := string(buffer[2 : 2+domainLength])
		port := int(binary.BigEndian.Uint16(buffer[2+domainLength : 2+domainLength+2]))
		ipAddr, err := net.ResolveIPAddr("ip", domain)
		if err != nil {
			fmt.Println("Error resolving domain:", err)
			return nil
		}
		return &net.UDPAddr{IP: ipAddr.IP, Port: port}
	case 4:
		if len(buffer) < 19 {
			return nil
		}
		ip := net.IP(buffer[1:17])
		port := int(binary.BigEndian.Uint16(buffer[17:19]))
		return &net.UDPAddr{IP: ip, Port: port}
	default:
		return nil
	}
}

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:1081")
	if err != nil {
		fmt.Println("Error starting TCP server:", err)
		return
	}
	fmt.Println("Listening on TCP port:", "127.0.0.1:1081")
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go handleConnection(conn)
	}
}
