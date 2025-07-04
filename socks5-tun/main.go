package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	// "strconv"
	"syscall"

	"github.com/songgao/water"
)

const (
	TUN_DEVICE_NAME = "tun0"
	MTU             = 65536
)

var pool map[string]net.Conn

func main() {
	for k := range pool {
		delete(pool, k)
	}
	ifce, err := setup()
	if err != nil {
		log.Println("Open tun error")
		return
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cleanup()
		os.Exit(0)
	}()

	// Buffer for reading packets
	packet := make([]byte, MTU) // Adjust buffer size as needed

	for {
		n, err := ifce.Read(packet)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Received packet from TUN device (%d bytes):\n%s\n", n, []byte(packet))

		if packet[0]&0xf0 != 0x40 {
			log.Println("Not an IPv4 packet")
			return
		}
		go handlePacket(ifce, packet, n)
	}
}

func handlePacket(ifce *water.Interface, packet []byte, length int) {
	// Parse IPv4 header to extract destination IP address and port
	destinationIP := net.IPv4(packet[16], packet[17], packet[18], packet[19]).String()
	destinationPort := binary.BigEndian.Uint16(packet[22:24])

	dest := fmt.Sprintf("%s:%d", destinationIP, destinationPort)
	// vConn, ok := pool[dest]
	// if ok {
	// 	_, err := vConn.Write(packet[:length])
	// 	if err != nil {
	// 		log.Println("Failed to write to server:", err)
	// 		return
	// 	}
	// 	log.Println("Sent packet to server")
	// 	return
	// }

	conn, err := net.Dial("tcp", dest)
	if err != nil {
		log.Printf("Failed to connect to server %s:%d: %v", destinationIP, destinationPort, err)
		return
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr)
	log.Printf("Local port automatically assigned: %d", localAddr.Port)

	_, err = conn.Write(packet[:length]) // sending processed packet
	if err != nil {
		log.Println("Failed to write to server:", err)
		return
	}

	log.Println("Sent packet to server")

	// Read server response
	response := make([]byte, MTU) // adjust buffer size as needed
	_, err = conn.Read(response)
	if err != nil {
		log.Println("Failed to read server response:", err)
		return
	}

	log.Printf("Received %d bytes from server", len(response))

	// Write server response back to tun0 device
	_, err = ifce.Write(response)
	if err != nil {
		log.Println("Failed to write to tun0 device:", err)
		return
	}

	log.Println("Sent response to tun0")
}

func setup() (*water.Interface, error) {
	pid := os.Getpid()
	fmt.Printf("PID: %d\n", pid)

	config := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: "tun0",
		},
	}
	ifce, err := water.New(config)
	if err != nil {
		log.Fatalf("Failed to create TUN device: %v", err)
		return nil, err
	}

	ipCmd := exec.Command("ip", "addr", "add", "10.0.0.1/24", "dev", "tun0")
	if err := ipCmd.Run(); err != nil {
		log.Fatalf("Failed to set IP address for tun0: %v", err)
		return nil, err
	}

	linkCmd := exec.Command("ip", "link", "set", "dev", "tun0", "up")
	if err := linkCmd.Run(); err != nil {
		log.Fatalf("Failed to bring up tun0: %v", err)
		return nil, err
	}

	iprouteCmds := []string{
		"ip rule add from 10.0.0.1/24 table local",
		"sudo ip rule add from all lookup tun0",
		"sudo ip route add default dev tun0 table tun0",
	}

	for _, cmd := range iprouteCmds {
		iptablesCmd := exec.Command("bash", "-c", cmd)
		if err := iptablesCmd.Run(); err != nil {
			log.Printf("Failed to run iptables command '%s': %v", cmd, err)
		}
	}

	log.Println("Configured tun0 device and traffic rules")
	return ifce, nil
}

func cleanup() {
	clearCmd := []string{
		"sudo ip rule del from 10.0.0.1/24 table local",
		"sudo ip rule del from all table tun0",
		"sudo ip route del default dev tun0 table tun0",
	}

	for _, cmd := range clearCmd {
		iptablesCmd := exec.Command("bash", "-c", cmd)
		if err := iptablesCmd.Run(); err != nil {
			log.Printf("Failed to run cleanup command '%s': %v", cmd, err)
		}
	}

	log.Println("Cleaned up tun0 device and traffic rules")
}

// package main
