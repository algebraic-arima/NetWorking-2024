package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	// "syscall"
	"unsafe"
)

func tproxy() {
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
	dest, err := getOriginalDestination(clientConn.(*net.TCPConn))
	if err != nil {
		fmt.Println("Failed to get original destination:", err)
		return
	}
	// fmt.Println(string(dest))
	newConn, err := net.Dial("tcp", "localhost:1080")
	if err != nil {
		fmt.Println("Failed to connect to port", 1080)
		return
	}
	// first handshake
	newConn.Write([]byte{5, 1, 0})

	defer clientConn.Close()
	defer newConn.Close()

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

	response := []byte{5, 1, 0, 1, dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]}
	newConn.Write(response)
	fmt.Println("Response:", response)

	_, err = io.ReadFull(newConn, buf[:4])
	if err != nil {
		fmt.Println("Error reading addr response:", err)
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x00 || buf[2] != 0x00 {
		fmt.Println("Unsupported SOCKS version or command")
		return
	}
	switch buf[4] {
	case 0x01:
		if _, err := io.ReadFull(newConn, buf[:4+2]); err != nil {
			fmt.Println("Failed to read IPv4 address and port:", err)
			return
		}
	case 0x04:
		if _, err := io.ReadFull(newConn, buf[:16+2]); err != nil {
			fmt.Println("Failed to read IPv6 address and port:", err)
			return
		}
	case 0x03:
		if _, err := io.ReadFull(newConn, buf[:1]); err != nil {
			fmt.Println("Failed to read domain length:", err)
			return
		}
		domainLength := int(buf[0])
		if _, err := io.ReadFull(newConn, buf[:domainLength+2]); err != nil {
			fmt.Println("Failed to read domain name and port:", err)
			return
		}
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
	go forward(newConn, clientConn)
	forward(clientConn, newConn)
}

func getOriginalDestination(conn *net.TCPConn) ([]byte, error) {
	// Get underlying file descriptor
	connFile, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer connFile.Close()

	// Get file descriptor from file
	fd := int(connFile.Fd())

	// Prepare structure for syscall
	var addr unix.RawSockaddrInet4
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
		return nil, errno
	}

	// Format IP and port from sockaddr structure into []byte
	ip := []byte{addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3]}
	port := []byte{byte(addr.Port), byte(addr.Port >> 8)}

	// Concatenate IP and port bytes
	dest := append(ip, port...)

	fmt.Println(dest)

	return dest, nil
}
