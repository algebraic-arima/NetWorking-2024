package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
)

var proxyListenPort = 1080

func handleClient(conn net.Conn) {
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
		//fmt.Println("IPv4 address")
		if _, err := io.ReadFull(conn, buf[:4+2]); err != nil {
			fmt.Println("Failed to read IPv4 address and port:", err)
			return
		}
		host = fmt.Sprintf("%d.%d.%d.%d:%d", buf[0], buf[1], buf[2], buf[3], binary.BigEndian.Uint16(buf[4:6]))
	case 0x03:
		//fmt.Println("Domain address")
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
		//fmt.Println("IPv6 address")
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

	targetConn, err := net.DialTCP("tcp", nil, tcpAddr)

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

	//io.Copy(targetConn, conn)
	//io.Copy(conn, targetConn)
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

func server() {
	Port := flag.Int("port", 1080, "Port to listen on")
	flag.Parse()
	proxyListenPort = *Port

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
		go handleClient(conn)
	}
}
