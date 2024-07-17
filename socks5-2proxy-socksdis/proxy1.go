package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"regexp"
)

const (
	proxy1ListenPort = 1081
	proxyDialPort    = 1080
)

// 0 for direct, 1 for proxy, -1 for forbidden
func diffIP(dest []byte) int {
	directCIDR := []string{
		"192.168.1.0/24", "10.0.0.0/8",
	}
	forbiddenCIDR := []string{
		"39.156.66.10/1",
	}
	for _, cidr := range directCIDR {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			fmt.Println("Failed to parse CIDR:", err)
			return -1
		}
		if ipNet.Contains(dest) {
			return 0
		}
	}
	for _, cidr := range forbiddenCIDR {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			fmt.Println("Failed to parse CIDR:", err)
			return -1
		}
		if ipNet.Contains(dest) {
			return -1
		}
	}
	return 1
}

func diffDomain(dest []byte) int {
	directDomainPattern := []string{
		`^.*\.sjtu\.edu\.cn$`,
	}
	forbiddenDomainPattern := []string{
		`^.*\.baidu\.com$`,
	}
	for _, p := range directDomainPattern {
		match, err := regexp.MatchString(p, string(dest))
		if match {
			return 0
		}
		if err != nil {
			fmt.Println("Failed to match pattern:", err)
			return -1
		}
	}
	for _, p := range forbiddenDomainPattern {
		match, err := regexp.MatchString(p, string(dest))
		if match {
			return -1
		}
		if err != nil {
			fmt.Println("Failed to match pattern:", err)
			return -1
		}
	}
	return 1
}

func SOCKS5Handshake(conn net.Conn) (string, error) {
	buf := make([]byte, 262)
	err := fmt.Errorf("")

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		fmt.Println("Failed to read version and number of methods:", err)
		return "", err
	}

	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		fmt.Println("Failed to read methods:", err)
		return "", err
	}

	// No AUTH
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		fmt.Println("Failed to write method selection response:", err)
		return "", err
	}

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		fmt.Println("Failed to read request header:", err)
		return "", err
	}

	if buf[1] != 0x01 {
		fmt.Println("Unsupported command:", buf[1])
		return "", err
	}

	var host string
	var port uint16
	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, buf[:4+2]); err != nil {
			fmt.Println("Failed to read IPv4 address and port:", err)
			return "", err
		}
		host = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		port = binary.BigEndian.Uint16(buf[4:6])
	case 0x03:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			fmt.Println("Failed to read domain length:", err)
			return "", err
		}
		domainLength := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domainLength+2]); err != nil {
			fmt.Println("Failed to read domain name and port:", err)
			return "", err
		}
		host = string(buf[:domainLength])
		port = binary.BigEndian.Uint16(buf[domainLength : domainLength+2])
	case 0x04:
		if _, err := io.ReadFull(conn, buf[:16+2]); err != nil {
			fmt.Println("Failed to read IPv6 address and port:", err)
			return "", err
		}
		host = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]",
			binary.BigEndian.Uint16(buf[0:2]), binary.BigEndian.Uint16(buf[2:4]),
			binary.BigEndian.Uint16(buf[4:6]), binary.BigEndian.Uint16(buf[6:8]),
			binary.BigEndian.Uint16(buf[8:10]), binary.BigEndian.Uint16(buf[10:12]),
			binary.BigEndian.Uint16(buf[12:14]), binary.BigEndian.Uint16(buf[14:16]))
		port = binary.BigEndian.Uint16(buf[16:18])
	default:
		fmt.Println("Unsupported address type:", buf[3])
		return "", err
	}

	targetAddr := fmt.Sprintf("%s:%d", host, port)

	fmt.Println("Target address:", targetAddr)

	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x3f, 0, 0, 0, byte(1080 >> 8), byte(1080 & 0xff)}); err != nil {
		fmt.Println("Failed to write connection success response:", err)
		return "", err
	}

	return targetAddr, nil
}

func handleClient(conn net.Conn) {
	targetAddr, err := SOCKS5Handshake(conn)
	if err != nil {
		fmt.Println("SOCKS5: Failed to handshake with client:", err)
		return
	}

	proxy2Conn, err := connect(targetAddr)
	if err != nil {
		fmt.Println("Failed to connect to Proxy 2:", err)
		return
	}

	forward := func(src, dest net.Conn) {

		if _, err := io.Copy(dest, src); err != nil {
			return
		}
	}

	go forward(conn, proxy2Conn)
	forward(proxy2Conn, conn)

	defer func(src net.Conn) {
		if err := src.Close(); err != nil {
			fmt.Println("Failed to close source connection:", err)
		}
	}(conn)
	defer func(dest net.Conn) {
		if err := dest.Close(); err != nil {
			fmt.Println("Failed to close destination connection:", err)
		}
	}(proxy2Conn)
}

func connect(targetAddr string) (net.Conn, error) {

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid target address: %v", err)
	}

	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", err)
	}

	ip := net.ParseIP(host)
	var addrType byte
	var addrBody []byte

	if ip == nil {
		addrType = 0x03 // Domain name
		addrBody = append([]byte{byte(len(host))}, []byte(host)...)
		fmt.Println("Domain name:", host)
		fmt.Println(addrBody)
	} else if ip.To4() != nil {
		addrType = 0x01 // IPv4
		addrBody = ip.To4()
		fmt.Println("IPv4 address:", addrBody)
	} else {
		addrType = 0x04 // IPv6
		addrBody = ip.To16()
		fmt.Println("IPv6 address:", addrBody)
	}

	req := []byte{0x05, 0x01, 0x00, addrType}
	req = append(req, addrBody...)
	req = append(req, byte(port>>8), byte(port&0xff))

	fmt.Println("Request:", string(addrBody))

	d := -1
	if addrType == 0x03 {
		d = diffDomain(addrBody)
	} else if addrType == 0x01 || addrType == 0x04 {
		d = diffIP(addrBody)
	}

	if d == 1 {
		conn, err := connectProxy2(req)
		return conn, err
	} else if d == 0 {
		conn, err := net.Dial("tcp", targetAddr)
		return conn, err
	}
	return nil, fmt.Errorf("connect forbidden to %s", host)
}

func connectProxy2(req []byte) (net.Conn, error) {
	conn, err := net.DialTCP("tcp",
		nil,
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxyDialPort})
	//conn, err := net.Dial("tcp", fmt.Sprintf(":%d", proxy2Addr))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Proxy 2: %v", err)
	}

	fmt.Println(conn.LocalAddr())

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, fmt.Errorf("failed to send handshake to Proxy 2: %v", err)
	}

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("failed to read handshake response from Proxy 2: %v", err)
	}

	if buf[1] != 0x00 {
		return nil, fmt.Errorf("no acceptable authentication method from Proxy 2")
	}

	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("failed to send connect request to Proxy 2: %v", err)
	}

	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("failed to read connect response from Proxy 2: %v", err)
	}

	if resp[1] != 0x00 {
		return nil, fmt.Errorf("connection request to Proxy 2 failed, response code: %d", resp[1])
	}

	return conn, nil
}

func runProxyClient() {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", proxy1ListenPort))
	if err != nil {
		fmt.Println("Failed to start server:", err)
		return
	}
	defer func(listener net.Listener) {
		if err := listener.Close(); err != nil {
			fmt.Println("Failed to close listener:", err)
		}
	}(listener)

	fmt.Println("SOCKS5 proxy client is running on port", proxy1ListenPort)

	cnt := 0
	for {
		fmt.Println("\033[32mConnection\033[0m", fmt.Sprintf("%d", cnt))
		cnt++
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Failed to accept connection:", err)
			continue
		} else {
			fmt.Println("Local", conn.LocalAddr(), "connected to", conn.RemoteAddr())
		}
		go handleClient(conn)
	}
}
