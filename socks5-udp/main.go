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
	"Chanson of Justice and Impartiality": {
		"Le Souvenir avec le crepuscule",
		"Ballad of Many Waters",
		"Leisurely Days in Fontaine",
		"Poesy of Chrysolite",
		"Pluie sur la ville",
		"Romaritime Recollection",
		"Pilot's Rest",
		"Limpide est le sanglot d'eau",
		"Clair de lune",
		"Where all Waters Converge",
		"Raven Gloss of Darkness",
		"Le spectacle doit continuer",
	},
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
