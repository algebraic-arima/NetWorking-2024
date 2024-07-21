package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
)

const (
	proxyListenPort = 1081
	proxyDialPort   = 1080
)

var dirDomain = []string{
	`^.*\.sjtu\.edu\.cn$`,
}
var forbDomain = []string{
	`^example\.com$`,
}
var dirCIDR = []string{
	"192.168.1.0/24", "10.0.0.0/8",
}
var forbCIDR = []string{
	"39.156.66.10",
}

// 0 for direct, 1 for proxy, -1 for forbidden
func diffIP(dest []byte) int {

	for _, cidr := range dirCIDR {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			fmt.Println("Failed to parse CIDR:", err)
			return -1
		}
		if ipNet.Contains(dest) {
			return 0
		}
	}
	for _, cidr := range forbCIDR {
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

func diffDomain(dest string) int {
	for _, p := range dirDomain {
		match, err := regexp.MatchString(p, dest)
		if match {
			return 0
		}
		if err != nil {
			fmt.Println("Failed to match pattern:", err)
			return -1
		}
	}
	for _, p := range forbDomain {
		match, err := regexp.MatchString(p, dest)
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

func handleClient(conn net.Conn) {
	buf := make([]byte, 262)

	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Println("Failed to close connection from usr to proxy1:", err)
		}
	}(conn)

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		fmt.Println("Failed to read version and number of methods:", err)
		return
	}

	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		fmt.Println("Failed to read methods:", err)
		return
	}

	// No AUTH
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		fmt.Println("Failed to write method selection response:", err)
		return
	}

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		fmt.Println("Failed to read request header:", err)
		return
	}

	if buf[1] != 0x01 {
		fmt.Println("Unsupported command:", buf[1])
		return
	}

	var host string
	var port uint16
	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, buf[:4+2]); err != nil {
			fmt.Println("Failed to read IPv4 address and port:", err)
			return
		}
		host = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		port = binary.BigEndian.Uint16(buf[4:6])
	case 0x03:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			fmt.Println("Failed to read domain length:", err)
			return
		}
		domainLength := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domainLength+2]); err != nil {
			fmt.Println("Failed to read domain name and port:", err)
			return
		}
		host = string(buf[:domainLength])
		port = binary.BigEndian.Uint16(buf[domainLength : domainLength+2])
	case 0x04:
		if _, err := io.ReadFull(conn, buf[:16+2]); err != nil {
			fmt.Println("Failed to read IPv6 address and port:", err)
			return
		}
		host = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]",
			binary.BigEndian.Uint16(buf[0:2]), binary.BigEndian.Uint16(buf[2:4]),
			binary.BigEndian.Uint16(buf[4:6]), binary.BigEndian.Uint16(buf[6:8]),
			binary.BigEndian.Uint16(buf[8:10]), binary.BigEndian.Uint16(buf[10:12]),
			binary.BigEndian.Uint16(buf[12:14]), binary.BigEndian.Uint16(buf[14:16]))
		port = binary.BigEndian.Uint16(buf[16:18])
	default:
		fmt.Println("Unsupported address type:", buf[3])
		return
	}

	targetAddr := fmt.Sprintf("%s:%d", host, port)

	fmt.Println("Target address:", targetAddr)

	proxy2Conn, err := connect(targetAddr)

	if err != nil {
		fmt.Println("Failed to connect to Proxy 2:", err)
		return
	}

	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x3f, 0, 0, 0, byte(1080 >> 8), byte(1080 & 0xff)}); err != nil {
		fmt.Println("Failed to write connection success response:", err)
		return
	}

	err = handleHttp(conn, proxy2Conn)
	if err != nil {
		fmt.Println("Failed to handle HTTP/TLS request:", err)
		return
	}

	forward := func(src, dest net.Conn) {
		defer func(src net.Conn) {
			if err := src.Close(); err != nil {
				fmt.Println("Failed to close source connection:", err)
			}
		}(src)
		defer func(dest net.Conn) {
			if err := dest.Close(); err != nil {
				fmt.Println("Failed to close destination connection:", err)
			}
		}(dest)

		if _, err := io.Copy(dest, src); err != nil {
			fmt.Println(err)
			return
		}
	}
	go forward(conn, proxy2Conn)
	forward(proxy2Conn, conn)
}

func handleHttp(backConn net.Conn, frontConn net.Conn) error {
	buf := make([]byte, 4096)
	bufLen, err := backConn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read HTTP/TLS request: %s", err)
	}

	//req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf)))
	host, err := ParseHTTP(buf)

	if err == nil {
		fmt.Println("Host:", host)

		//fmt.Printf("Received HTTP request:\n%+v\n", req)

		fmt.Printf("Received HTTP request from host %s\n", host)

		d := diffDomain(host)
		if d == -1 {
			return fmt.Errorf("forbidden to access %s", host)
		}

		if host == "example.com" {
			return fmt.Errorf("forbidden to access example.com")
		}

		if _, err := frontConn.Write(buf[:bufLen]); err != nil {
			return fmt.Errorf("failed to write HTTP request to Proxy 2: %s", err)
		}

		fmt.Println("HTTP:", string(buf))
	} else {
		//fmt.Println("TLS(maybe):", string(buf))

		str, err := ParseTLS(buf)

		if err != nil {
			return fmt.Errorf("failed to parse TLS request: %s", err)
		}

		d := diffDomain(str)
		if d == -1 {
			return fmt.Errorf("forbidden to access %s", str)
		}

		if str == "example.com" {
			return fmt.Errorf("forbidden to access example.com")
		}

		if _, err := frontConn.Write(buf[:bufLen]); err != nil {
			return fmt.Errorf("failed to write TLS request to Proxy 2: %s", err)
		}
	}
	return nil
}

func ParseTLS(tlsBytes []byte) (string, error) {
	buffer := bytes.NewBuffer(tlsBytes)

	var contentType uint8
	if err := binary.Read(buffer, binary.BigEndian, &contentType); err != nil {
		return "", err
	}
	if contentType != 0x16 {
		return "", fmt.Errorf("not a ClientHello")
	}

	// 读取ProtocolVersion
	var protocolVersion uint16
	if err := binary.Read(buffer, binary.BigEndian, &protocolVersion); err != nil {
		return "", err
	}

	var length uint16
	if err := binary.Read(buffer, binary.BigEndian, &length); err != nil {
		return "", err
	}

	var handshakeType uint8
	if err := binary.Read(buffer, binary.BigEndian, &handshakeType); err != nil {
		return "", err
	}
	if handshakeType != 0x01 {
		return "", fmt.Errorf("not a ClientHello")
	}

	buffer.Next(3) // handshakeLength = 3 bytes

	var legacyVersion uint16
	if err := binary.Read(buffer, binary.BigEndian, &legacyVersion); err != nil {
		return "", err
	}

	random := make([]byte, 32)
	if _, err := buffer.Read(random); err != nil {
		return "", err
	}

	var legacySessionIDLength uint8
	if err := binary.Read(buffer, binary.BigEndian, &legacySessionIDLength); err != nil {
		return "", err
	}

	buffer.Next(int(legacySessionIDLength))

	var cipherSuitesLength uint16
	if err := binary.Read(buffer, binary.BigEndian, &cipherSuitesLength); err != nil {
		return "", err
	}

	buffer.Next(int(cipherSuitesLength))

	var compressionMethodsLength uint8
	if err := binary.Read(buffer, binary.BigEndian, &compressionMethodsLength); err != nil {
		return "", err
	}

	buffer.Next(int(compressionMethodsLength))

	var extensionsLength uint16
	if err := binary.Read(buffer, binary.BigEndian, &extensionsLength); err != nil {
		return "", err
	}

	extensionsData := make([]byte, extensionsLength)
	if _, err := buffer.Read(extensionsData); err != nil {
		return "", err
	}

	//fmt.Println("Extensions:", string(extensionsData))

	sniHostname := ""
	for i := 0; i < len(extensionsData); {
		extensionType := uint16(extensionsData[i])<<8 | uint16(extensionsData[i+1])
		i += 2
		extensionDataLength := int(extensionsData[i])<<8 | int(extensionsData[i+1])
		i += 2

		if extensionType == 0x0000 {
			sniHostname = string(extensionsData[i+5 : i+extensionDataLength])
			break
		}
		i += extensionDataLength
	}

	if sniHostname != "" {
		fmt.Println("SNI hostname:", sniHostname)
		return sniHostname, nil
	} else {
		return "", fmt.Errorf("SNI extension not found in TLS ClientHello")
	}
}

func ParseHTTP(httpBytes []byte) (string, error) {
	reader := bytes.NewReader(httpBytes)
	bufReader := bufio.NewReader(reader)

	_, err := bufReader.ReadString('\n')
	if err != nil {
		return "", errors.New("failed to read request line")
	}

	for {
		line, err := bufReader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("failed to read headers")
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {
			if parts[0] == "Host" {
				return parts[1], nil
			}
		}
	}

	return "", errors.New("host header not found")
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

	//if d == 1 {
	conn, err := connectProxy2(req)
	return conn, err
	//} else if d == 0 {
	//	conn, err := net.Dial("tcp", targetAddr)
	//	return conn, err
	//}
	//return nil, fmt.Errorf("not allowed to connect to %s", host)
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

func client() {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", proxyListenPort))
	if err != nil {
		fmt.Println("Failed to start server:", err)
		return
	}
	defer func(listener net.Listener) {
		if err := listener.Close(); err != nil {
			fmt.Println("Failed to close listener:", err)
		}
	}(listener)

	fmt.Println("SOCKS5 proxy client is running on port", proxyListenPort)

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
