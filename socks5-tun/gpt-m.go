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
	MTU             = 1024
)

func main() {

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

		log.Printf("Received packet from TUN device (%d bytes):\n%s\n", n, packet)

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

	// // Establish TCP connection to the parsed destination address and port
	// localAddr, err := getLocalIPAddress()
	// if err != nil {
	// 	log.Println("Failed to get local IP address:", err)
	// 	return
	// }

	// localTCPAddr := &net.TCPAddr{
	// 	IP: localAddr,
	// }

	// conn, err := net.DialTCP("tcp", localTCPAddr, &net.TCPAddr{
	// 	IP:   net.ParseIP(destinationIP),
	// 	Port: int(destinationPort),
	// })
	// if err != nil {
	// 	log.Println("Failed to connect to server:", err)
	// 	return
	// }
	// defer conn.Close()

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", destinationIP, destinationPort))
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

	routeCmd := exec.Command("ip", "route", "add", "default", "dev", "tun0", "table", "tun0")
	if err := routeCmd.Run(); err != nil {
		log.Fatalf("Failed to add default route for tun0: %v", err)
		return nil, err
	}

	iptablesCmds := []string{
		"iptables -t mangle -N tun0",
		"iptables -t mangle -A OUTPUT -o lo -p tcp -j MARK --set-mark 1",
		"iptables -t mangle -A OUTPUT -p tcp --sport 8080 -j MARK --set-mark 2",
		"ip rule add fwmark 1 table tun0",
		"ip route add default dev tun0 table tun0",
		"ip rule add fwmark 2 table proxy",
		"ip route add default via 10.180.0.1 dev eth2 table proxy",
		"iptables -t mangle -A OUTPUT -o tun0 -j ACCEPT",
	}

	for _, cmd := range iptablesCmds {
		iptablesCmd := exec.Command("bash", "-c", cmd)
		if err := iptablesCmd.Run(); err != nil {
			log.Printf("Failed to run iptables command '%s': %v", cmd, err)
		}
	}

	log.Println("Configured tun0 device and traffic rules")
	return ifce, nil
}

func cleanup() {
	cmds := []string{
		"ip link set dev tun0 down",
		"ip link del dev tun0",
		"iptables -t mangle -D OUTPUT -p tcp --dport 80 -j MARK --set-mark 1",
		"ip rule del fwmark 1 table tun0",
		"iptables -t mangle -F PROXY_BYPASS",
		"iptables -t mangle -X PROXY_BYPASS",
		"iptables -t mangle -D OUTPUT -j PROXY_BYPASS",
	}

	for _, cmd := range cmds {
		iptablesCmd := exec.Command("bash", "-c", cmd)
		if err := iptablesCmd.Run(); err != nil {
			log.Printf("Failed to run cleanup command '%s': %v", cmd, err)
		}
	}

	log.Println("Cleaned up tun0 device and traffic rules")
}

func getLocalIPAddress() (net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			ip = ip.To4()
			if ip != nil {
				return ip, nil
			}
		}
	}
	return nil, fmt.Errorf("no IP address found")
}
