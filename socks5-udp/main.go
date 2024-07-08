package main

import (
	"fmt"
	"log"
	"net"
)

const (
	ProxyPort = "15001"
)

var adore = map[string][]string{
	"Les grandes eaux qu'elle avait veillées": {
		"Mellow Alize",
		"Songe de la plus haute tour",
		"Le commencement de la fin",
		"Dream Anamnesis",
	},
	"Galliard of Brass and Iron": {
		"Clockwork Waltz",
		"The Rotating Realm",
		"Welcome to the Industry",
		"Le duc sous l'eau",
		"The Faded Idyll",
		"The Drifting Beauty",
		"Huldra's Retreat",
		"Whispering Dewdrops",
	},
	"Versi di Petrichor": {
		"Regali Teneri",
		"Ed e subito sera",
	},
}

func m() {
	fmt.Println(adore)
	go udpclient()
	udpserver()
}

func handleClient(clientConn net.Conn) {
	defer clientConn.Close()

	// 读取客户端发送的数据
	buf := make([]byte, 1024)
	n, err := clientConn.Read(buf)
	if err != nil {
		log.Printf("Error reading from client: %v", err)
		return
	}
	log.Printf("Received from client: %s", buf[:n])

	// 在这里可以对接收到的数据进行处理或转发到实际的目标服务器
	// 这里仅示例将数据回传给客户端
	_, err = clientConn.Write([]byte("Hello from proxy server"))
	if err != nil {
		log.Printf("Error writing to client: %v", err)
		return
	}
	log.Printf("Sent response to client")

	log.Printf("Closed connection with %s", clientConn.RemoteAddr())
}
