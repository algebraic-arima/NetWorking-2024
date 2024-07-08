package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

const (
	proxyListenPort = 1080
	logPath         = "log/"
	certPath        = "server.pem"
	keyPath         = "server.key"
)

func handleClient(conn net.Conn, n int) {
	gologPath := logPath + fmt.Sprintf("%d.log", n)
	logFile, err := os.Create(gologPath)
	defer func(logFile *os.File) {
		if err := logFile.Close(); err != nil {
			fmt.Println("Failed to close log file:", err)
		}
	}(logFile)
	log.SetOutput(logFile)

	buf := make([]byte, 262)

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		fmt.Println("Failed to read version and number of methods:", err)
		return
	}

	//fmt.Printf("Received: %v\n", conn.RemoteAddr())

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
	switch buf[3] {
	case 0x01:
		fmt.Println("IPv4 address")
		if _, err := io.ReadFull(conn, buf[:4+2]); err != nil {
			fmt.Println("Failed to read IPv4 address and port:", err)
			return
		}
		host = fmt.Sprintf("%d.%d.%d.%d:%d", buf[0], buf[1], buf[2], buf[3], binary.BigEndian.Uint16(buf[4:6]))
	case 0x03:
		fmt.Println("Domain address")
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			fmt.Println("Failed to read domain length:", err)
			return
		}
		domainLength := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domainLength+2]); err != nil {
			fmt.Println("Failed to read domain name and port:", err)
			return
		}
		host = fmt.Sprintf("%s:%d", string(buf[:domainLength]), binary.BigEndian.Uint16(buf[domainLength:domainLength+2]))
	case 0x04:
		fmt.Println("IPv6 address")
		if _, err := io.ReadFull(conn, buf[:16+2]); err != nil {
			fmt.Println("Failed to read IPv6 address and port:", err)
			return
		}
		host = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			binary.BigEndian.Uint16(buf[0:2]), binary.BigEndian.Uint16(buf[2:4]),
			binary.BigEndian.Uint16(buf[4:6]), binary.BigEndian.Uint16(buf[6:8]),
			binary.BigEndian.Uint16(buf[8:10]), binary.BigEndian.Uint16(buf[10:12]),
			binary.BigEndian.Uint16(buf[12:14]), binary.BigEndian.Uint16(buf[14:16]),
			binary.BigEndian.Uint16(buf[16:18]))
	default:
		fmt.Println("Unsupported address type:", buf[3])
		return
	}

	fmt.Println("Host:", host)

	tcpAddr, err := net.ResolveTCPAddr("tcp", host)
	if err != nil {
		fmt.Println("Failed to resolve address:", err)
		return
	}

	fmt.Println("TCPAddr:", tcpAddr)

	targetConn, err := net.Dial("tcp", host)

	if err != nil {
		fmt.Println("Failed to connect to target:", err)
		return
	}

	fmt.Println("TargetConn from", targetConn.LocalAddr(), "to", targetConn.RemoteAddr())

	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, buf[0], buf[1], buf[2], buf[3], 0, 0}); err != nil {
		fmt.Println("Failed to write connection success response:", err)
		return
	}

	fmt.Println("Connected to target:", host)

	err = handleHttp(conn, targetConn)
	if err != nil {
		fmt.Println("Failed to handle HTTP request:", err)
		return
	}

	forward := func(src, dest net.Conn) {
		defer func(src net.Conn) {
			if err := src.Close(); err != nil {
				fmt.Println("Failed to close source:", err)
			}
		}(src)
		defer func(dest net.Conn) {
			if err := dest.Close(); err != nil {
				fmt.Println("Failed to close destination:", err)
			}
		}(dest)
		if _, err := io.Copy(src, dest); err != nil {
			return
		}
	}
	go forward(targetConn, conn)
	forward(conn, targetConn)
}

func handleHttp(backConn net.Conn, frontConn net.Conn) error {
	buf := make([]byte, 65536)
	n, err := backConn.Read(buf)
	// the first package
	if err != nil {
		return fmt.Errorf("failed to read HTTP/TLS request: %s", err)
	}

	//req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf)))
	host, err := ParseHTTP(buf)

	if err == nil {
		//host := req.Host
		fmt.Println("Host:", host)

		//fmt.Printf("Received HTTP request:\n%+v\n", req)

		fmt.Printf("Received HTTP request from host %s\n", host)

		fmt.Println("HTTP Request:\n", string(buf))
		reqStr := trimHTTPReq(string(buf[:n]))
		//resStr := string(buf[:n])
		fmt.Println("Trimmed HTTP Request:\n", reqStr)
		buf = []byte(reqStr)
		n = len(buf)

		if _, err := frontConn.Write(buf[:n]); err != nil {
			return fmt.Errorf("failed to write HTTP request to Proxy 2: %s", err)
		}

		log.Println("HTTP Request:\n", string(buf))

		if n, err = frontConn.Read(buf); err != nil {
			fmt.Println("Failed to read from frontConn:", err)
			return err
		}

		log.Println("HTTP Response:\n", string(buf))

		resStr := string(buf[:n])
		resStr = strings.ReplaceAll(resStr, "PKU JudgeOnline", "SJTU ACMOJ")
		buf = []byte(resStr)
		n = len(buf)

		if _, err := backConn.Write(buf[:n]); err != nil {
			fmt.Println("Failed to write to backConn:", err)
			return err
		}

	} else {
		str, err := ParseTLS(buf)

		if err != nil {
			return fmt.Errorf("failed to parse TLS request: %s", err)
		}

		//if str == "www.example.com" {
		//	return fmt.Errorf("forbidden to access www.example.com")
		//}

		fmt.Println("SNI hostname:", str)

		if _, err := frontConn.Write(buf[:n]); err != nil {
			return fmt.Errorf("failed to write TLS request to Proxy 2: %s", err)
		}
	}
	return nil
}

func trimHTTPReq(httpRequest string) string {
	parts := strings.SplitN(httpRequest, "\r\n\r\n", 2)
	headersPart := parts[0]
	body := ""
	if len(parts) > 1 {
		body = parts[1]
	}

	lines := strings.Split(headersPart, "\r\n")
	var filteredHeaders strings.Builder
	for _, line := range lines {
		//if strings.HasPrefix(line, "Accept-Encoding:") {
		//	continue
		//} else if strings.HasPrefix(line, "Content-Encoding:") {
		//	continue
		//} else if strings.HasPrefix(line, "Transfer-Encoding:") {
		//	continue
		//} else if strings.HasPrefix(line, "Set-Cookie") {
		//	continue
		//}
		filteredHeaders.WriteString(line + "\r\n")
	}

	filteredHeaders.WriteString("\r\n\r\n")
	filteredHeaders.WriteString(body)

	return filteredHeaders.String()
}

func responseToBytes(res *http.Response) []byte {
	var buf bytes.Buffer

	// Write status line
	statusLine := fmt.Sprintf("HTTP/%d.%d %s\r\n", res.ProtoMajor, res.ProtoMinor, res.Status)
	buf.WriteString(statusLine)

	// Write headers
	res.Header.Write(&buf)
	buf.WriteString("\r\n")

	// Write body
	bodyBytes, _ := io.ReadAll(res.Body)
	buf.Write(bodyBytes)

	return buf.Bytes()
}

func responseToString(res *http.Response) string {
	var buf bytes.Buffer

	// Write status line
	statusLine := fmt.Sprintf("HTTP/%d.%d %s\r\n", res.ProtoMajor, res.ProtoMinor, res.Status)
	buf.WriteString(statusLine)

	// Write headers
	res.Header.Write(&buf)
	buf.WriteString("\r\n")

	// Write body
	bodyBytes, _ := io.ReadAll(res.Body)
	buf.Write(bodyBytes)

	return buf.String()
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

func main() {
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

	fmt.Println("SOCKS5 proxy server is running on", proxyListenPort)
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
		go handleClient(conn, cnt)
	}
}
