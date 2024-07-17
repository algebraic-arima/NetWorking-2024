package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"unsafe"
)

func proxy() {
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	fmt.Println("TProxy server listening on port 8080...")

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		go handleClientRequest(clientConn)
	}
}

func handleClientRequest(clientConn net.Conn) {
	defer clientConn.Close()
	dest, dType := getOriginalDestination(clientConn.(*net.TCPConn))
	if dType == 0 {
		fmt.Println("Failed to get original destination or format illegal")
		return
	}
	// fmt.Println(string(dest))
	newConn, err := net.Dial("tcp", "localhost:1080")
	if err != nil {
		fmt.Println("Failed to connect to port", 1080)
		return
	}
	defer newConn.Close()

	// first handshake
	newConn.Write([]byte{5, 1, 0})

	// response to 1080
	buf := make([]byte, 4096)
	_, err = io.ReadFull(newConn, buf[:2])
	if err != nil {
		fmt.Println("Error reading handshake response:", err)
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		fmt.Println("Unsupported SOCKS version or authentication method")
		return
	}

	var response []byte
	if dType == 0x01 {
		response = []byte{5, 1, 0, 1}
		response = append(response, dest...)
	} else if dType == 0x04 {
		response = []byte{5, 1, 0, 4}
		response = append(response, dest...)
	} else {
		fmt.Println("Unsupported address type")
		return
	}
	newConn.Write(response)
	fmt.Println("Response:", response)

	n, err := newConn.Read(buf)
	if err != nil || n < 10 || buf[1] != 0x00 {
		fmt.Println("Target SOCKS5 server connection failed")
		return
	}

	// _, err = io.ReadFull(newConn, buf[:4])
	// if err != nil {
	// 	fmt.Println("Error reading addr response:", err)
	// 	return
	// }
	// if buf[0] != 0x05 || buf[1] != 0x00 || buf[2] != 0x00 {
	// 	fmt.Println("Unsupported SOCKS version or command")
	// 	return
	// }
	// switch buf[4] {
	// case 0x01:
	// 	if _, err := io.ReadFull(newConn, buf[:4+2]); err != nil {
	// 		fmt.Println("Failed to read IPv4 address and port:", err)
	// 		return
	// 	}
	// case 0x04:
	// 	if _, err := io.ReadFull(newConn, buf[:16+2]); err != nil {
	// 		fmt.Println("Failed to read IPv6 address and port:", err)
	// 		return
	// 	}
	// case 0x03:
	// 	if _, err := io.ReadFull(newConn, buf[:1]); err != nil {
	// 		fmt.Println("Failed to read domain length:", err)
	// 		return
	// 	}
	// 	domainLength := int(buf[0])
	// 	if _, err := io.ReadFull(newConn, buf[:domainLength+2]); err != nil {
	// 		fmt.Println("Failed to read domain name and port:", err)
	// 		return
	// 	}
	// }

	forward := func(src, dest net.Conn) {
		if _, err := io.Copy(src, dest); err != nil {
			return
		}
	}

	go forward(newConn, clientConn)
	forward(clientConn, newConn)

}

func getOriginalDestination(conn *net.TCPConn) ([]byte, int) {
	// Get underlying file descriptor
	connFile, err := conn.File()
	if err != nil {
		return nil, 0
	}
	defer connFile.Close()

	// Get file descriptor from file
	fd := int(connFile.Fd())

	// Prepare structure for syscall
	var addr unix.RawSockaddrAny
	addrLen := uint32(unsafe.Sizeof(addr))

	// Call syscall to get original destination
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_IP),
		uintptr(unix.SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&addrLen)),
		0,
	)
	if errno != 0 {
		return nil, 0
	}

	// Check address family and handle accordingly
	switch addr.Addr.Family {
	case unix.AF_INET:
		// IPv4
		sockaddr := (*unix.RawSockaddrInet4)(unsafe.Pointer(&addr))
		ip := sockaddr.Addr[:]
		port := []byte{byte(sockaddr.Port & 0xff), byte(sockaddr.Port >> 8)}
		dest := append(ip, port...)
		return dest, 1
	case unix.AF_INET6:
		// IPv6
		sockaddr := (*unix.RawSockaddrInet6)(unsafe.Pointer(&addr))
		ip := sockaddr.Addr[:]
		port := []byte{byte(sockaddr.Port & 0xff), byte(sockaddr.Port >> 8)}
		dest := append(ip, port...)
		return dest, 4
	default:
		return nil, 0
	}
}
