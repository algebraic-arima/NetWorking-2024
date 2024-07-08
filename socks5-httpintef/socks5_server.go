package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
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

func socks5Handshake(conn net.Conn) (net.Conn, string, int, error) {
	err := fmt.Errorf("failed to handshake")
	buf := make([]byte, 262)

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		fmt.Println("Failed to read version and number of methods:", err)
		return nil, "", -1, err
	}

	//fmt.Printf("Received: %v\n", conn.RemoteAddr())

	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		fmt.Println("Failed to read methods:", err)
		return nil, "", -1, err
	}

	// No AUTH
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		fmt.Println("Failed to write method selection response:", err)
		return nil, "", -1, err
	}

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		fmt.Println("Failed to read request header:", err)
		return nil, "", -1, err
	}

	if buf[1] != 0x01 {
		fmt.Println("Unsupported command:", buf[1])
		return nil, "", -1, err
	}

	var host string
	switch buf[3] {
	case 0x01:
		//fmt.Println("IPv4 address")
		if _, err := io.ReadFull(conn, buf[:4+2]); err != nil {
			fmt.Println("Failed to read IPv4 address and port:", err)
			return nil, "", -1, err
		}
		host = fmt.Sprintf("%d.%d.%d.%d:%d", buf[0], buf[1], buf[2], buf[3], binary.BigEndian.Uint16(buf[4:6]))
	case 0x03:
		//fmt.Println("Domain address")
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			fmt.Println("Failed to read domain length:", err)
			return nil, "", -1, err
		}
		domainLength := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domainLength+2]); err != nil {
			fmt.Println("Failed to read domain name and port:", err)
			return nil, "", -1, err
		}
		host = fmt.Sprintf("%s:%d", string(buf[:domainLength]), binary.BigEndian.Uint16(buf[domainLength:domainLength+2]))
	case 0x04:
		//fmt.Println("IPv6 address")
		if _, err := io.ReadFull(conn, buf[:16+2]); err != nil {
			fmt.Println("Failed to read IPv6 address and port:", err)
			return nil, "", -1, err
		}
		host = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			binary.BigEndian.Uint16(buf[0:2]), binary.BigEndian.Uint16(buf[2:4]),
			binary.BigEndian.Uint16(buf[4:6]), binary.BigEndian.Uint16(buf[6:8]),
			binary.BigEndian.Uint16(buf[8:10]), binary.BigEndian.Uint16(buf[10:12]),
			binary.BigEndian.Uint16(buf[12:14]), binary.BigEndian.Uint16(buf[14:16]),
			binary.BigEndian.Uint16(buf[16:18]))
	default:
		fmt.Println("Unsupported address type:", buf[3])
		return nil, "", -1, err
	}

	fmt.Println("Host:", host)

	tcpAddr, err := net.ResolveTCPAddr("tcp", host)
	if err != nil {
		fmt.Println("Failed to resolve address:", err)
		return nil, "", -1, err
	}
	port := tcpAddr.Port

	fmt.Println("TCPAddr:", tcpAddr)

	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, buf[0], buf[1], buf[2], buf[3], 0, 0}); err != nil {
		fmt.Println("Failed to write connection success response:", err)
		return nil, "", -1, err
	}
	return conn, host, port, nil
}

func handleClient(conn net.Conn, n int) {
	gologPath := logPath + fmt.Sprintf("%d.log", n)
	logFile, err := os.Create(gologPath)
	defer func(logFile *os.File) {
		if err := logFile.Close(); err != nil {
			fmt.Println("Failed to close log file:", err)
		}
	}(logFile)
	log.SetOutput(logFile)

	_, host, port, err := socks5Handshake(conn)
	if err != nil {
		fmt.Println("Failed to handshake:", err)
		return
	}

	if port == 443 {
		fmt.Println("HTTPS: ")
	} else if port == 80 {
		fmt.Println("HTTP: ")
	}
	fmt.Println("SOCKS5 Connected to target:", host)

	targetConn, err := net.Dial("tcp", host)

	if err != nil {
		fmt.Println("Failed to connect to target:", err)
		return
	}

	fmt.Println("TargetConn from", targetConn.LocalAddr(), "to", targetConn.RemoteAddr())

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

func replaceString(str string) string {
	str = strings.ReplaceAll(str, "PKU JudgeOnline", "FDU ACMOJ")
	str = strings.ReplaceAll(str, "Example Domain", "SJTU ACMOJ")
	str = strings.ReplaceAll(str, "blue", "purple")
	str = strings.ReplaceAll(str, "images/logo0.gif", "https://vi.sjtu.edu.cn/uploads/files/22fc9c46e0998e2454d64f7eda901595-d2c02ba527abb94ad97653e36bbac8a1.png")
	str = strings.ReplaceAll(str, "images/logo3.gif", "https://acm.sjtu.edu.cn/w/images/acm_logo_135x135.png")
	str = strings.ReplaceAll(str, "images/fengmian_2.jpg", "https://ts1.cn.mm.bing.net/th/id/R-C.3acef4f3beb3ea4d530f73628e31143c?rik=aU9DHFaxeIVLCw&riu=http%3a%2f%2fabook.hep.com.cn%2fICourseFiles%2fMaterialsLibCovers%2fgroup2%2fM00%2f3A%2fD8%2fwKhLoFop7KeAJ5CbAALJStVLIyY76..jpg&ehk=Bt9HyUKC9jAzQNrLKZmltDv4z%2f17mYV06269kAD4f%2fM%3d&risl=&pid=ImgRaw&r=0")
	return str
}

func decGZip(data []byte) ([]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()

	decompressedData, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, err
	}

	return decompressedData, nil
}

func handleHttp(backConn net.Conn, frontConn net.Conn) error {

	buf := make([]byte, 65536)
	n, err := backConn.Read(buf)

	if err != nil {
		return fmt.Errorf("failed to read HTTP/TLS request: %s", err)
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf)))

	if err == nil {
		host := req.Host
		fmt.Println("Host:", host)

		//fmt.Printf("Received HTTP request:\n%+v\n", req)

		fmt.Printf("Received HTTP request from host %s\n", host)

		if _, err := frontConn.Write(buf[:n]); err != nil {
			return fmt.Errorf("failed to write HTTP request to Proxy 2: %s", err)
		}

		log.Println("HTTP Request:\n", string(buf))

		res, err := http.ReadResponse(bufio.NewReader(frontConn), req)
		if err != nil {
			return fmt.Errorf("failed to read HTTP response: %s", err)
		}

		resBodyBytes, err := io.ReadAll(res.Body)
		fmt.Println("Response body:", string(resBodyBytes))
		if err != nil {
			fmt.Println("Failed to read response body:", err)
			return err
		}

		res.Body = ioutil.NopCloser(bytes.NewReader(resBodyBytes))

		var resDe http.Response
		resDe.Header = res.Header

		var decResBodyBytes []byte
		if res.Header.Get("Content-Encoding") == "gzip" {
			decResBodyBytes, err = decGZip(resBodyBytes)
			resDe.Header.Del("Content-Encoding")
			resDe.Header.Del("Transfer-Encoding")
		} else {
			decResBodyBytes = resBodyBytes
		}
		if err != nil {
			fmt.Println("Failed to decompress response body:", err)
			return err
		}

		decResBodyBytes = []byte(replaceString(string(decResBodyBytes)))

		fmt.Println("Decompressed response body:\n", string(decResBodyBytes))

		res.Body = ioutil.NopCloser(bytes.NewReader(decResBodyBytes))

		res.Header.Set("Content-Length", fmt.Sprintf("%d", len(resBodyBytes)))

		res.ContentLength = int64(len(decResBodyBytes))

		//log.Println("HTTP response:\n", responseToString(res))

		fmt.Println(res)
		if err := res.Write(backConn); err != nil {
			fmt.Println("Failed to write to backConn:", err)
			return err
		}

	} else {
		str, err := ParseTLS(buf)

		if err != nil {
			return fmt.Errorf("failed to parse TLS request: %s", err)
		}

		fmt.Println("SNI hostname:", str)

		if _, err := frontConn.Write(buf[:n]); err != nil {
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
		return sniHostname, nil
	} else {
		return "", fmt.Errorf("SNI extension not found in TLS ClientHello")
	}
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
