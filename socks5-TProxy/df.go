package main

import (
	"fmt"
	// "io"
	"net"
)

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// 读取客户端发送的数据
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Error reading:", err)
		return
	}

	fmt.Println(string(buf[:n]))

	// TODO: 根据需要处理数据包，可以进行代理或直连逻辑
	fmt.Printf("Received data from %s: %s\n", conn.RemoteAddr(), string(buf[:n]))

	// 例如，简单地将收到的数据发送回客户端
	_, err = conn.Write(buf[:n])
	if err != nil {
		fmt.Println("Error writing:", err)
		return
	}
}

func ma() {
	listener, err := net.Listen("tcp", "127.0.0.1:8888")
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}
	defer listener.Close()

	fmt.Println("Listening on 127.0.0.1:8888")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting:", err)
			return
		}

		go handleConnection(conn)
	}
}
