package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

const (
	proxyListenPort = 1081
)

var allowedCIDR = []string{
	"192.168.1.0/24",
	"10.0.0.0/8",
}
var directPattern = []string{
	`^.*\.sjtu\.edu\.cn$`,
}
var forbiddenPattern = []string{
	`^.*\.baidu\.com$`,
}

// 0 for direct, 1 for proxy, -1 for forbidden
func diffIP(dest []byte) int {
	for _, cidr := range allowedCIDR {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			fmt.Println("Failed to parse CIDR:", err)
			return -1
		}
		if ipNet.Contains(dest) {
			return 0
		}
	}
	return 1
}

func diffDomain(dest []byte) int {
	for _, p := range directPattern {
		match, err := regexp.MatchString(p, string(dest))
		if match {
			return 0
		}
		if err != nil {
			fmt.Println("Failed to match pattern:", err)
			return -1
		}
	}
	for _, p := range forbiddenPattern {
		match, err := regexp.MatchString(p, string(dest))
		if match {
			return -1
		}
		if err != nil {
			fmt.Println("Failed to match pattern:", err)
			return -1
		}
	}
	return 1
}

func getPID(conn net.Conn) (map[string]int, error) {
	var table = make(map[string]int)
	clientAddr := conn.RemoteAddr().(*net.TCPAddr)
	//clientIP:=clientAddr.IP.String()
	clientPort := clientAddr.Port
	fmt.Println("Port:", clientPort)
	cms := exec.Command("lsof", "-i", fmt.Sprintf(":%d", clientPort))

	var output bytes.Buffer
	cms.Stdout = &output
	err := cms.Run()
	if err != nil {
		fmt.Println("Error executing command:", err)
		return nil, err
	}

	fmt.Println("Output:", output.String())

	lines := strings.Split(output.String(), "\n")

	for _, line := range lines {
		if strings.Contains(line, "LISTEN") || strings.Contains(line, "ESTABLISHED") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				n, f := strconv.Atoi(fields[1])
				if f != nil {
					fmt.Println("Failed to convert PID:", f)
					continue
				}
				table[fields[0]] = n
			}
		}
	}
	if len(table) == 0 {
		return nil, fmt.Errorf("no process found")
	}
	return table, nil
}

func handleClient(conn net.Conn) {

	buf := make([]byte, 262)

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		fmt.Println("Failed to read version and number of methods:", err)
		return
	}

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
	var port uint16
	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, buf[:4+2]); err != nil {
			fmt.Println("Failed to read IPv4 address and port:", err)
			return
		}
		host = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		port = binary.BigEndian.Uint16(buf[4:6])
	case 0x03:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			fmt.Println("Failed to read domain length:", err)
			return
		}
		domainLength := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domainLength+2]); err != nil {
			fmt.Println("Failed to read domain name and port:", err)
			return
		}
		host = string(buf[:domainLength])
		port = binary.BigEndian.Uint16(buf[domainLength : domainLength+2])
	case 0x04:
		if _, err := io.ReadFull(conn, buf[:16+2]); err != nil {
			fmt.Println("Failed to read IPv6 address and port:", err)
			return
		}
		host = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]",
			binary.BigEndian.Uint16(buf[0:2]), binary.BigEndian.Uint16(buf[2:4]),
			binary.BigEndian.Uint16(buf[4:6]), binary.BigEndian.Uint16(buf[6:8]),
			binary.BigEndian.Uint16(buf[8:10]), binary.BigEndian.Uint16(buf[10:12]),
			binary.BigEndian.Uint16(buf[12:14]), binary.BigEndian.Uint16(buf[14:16]))
		port = binary.BigEndian.Uint16(buf[16:18])
	default:
		fmt.Println("Unsupported address type:", buf[3])
		return
	}

	targetAddr := fmt.Sprintf("%s:%d", host, port)

	fmt.Println("Target address:", targetAddr)

	pidtab, err := getPID(conn)
	if err != nil {
		fmt.Println("Failed to get PID:", err)
		return
	}
	pid := pidtab["curl"]

	if pid != 0 {
		exePath, err := getExecPath(pid)
		if err != nil {
			fmt.Println("Failed to get ExecPath of PID", pid, ":", err)
			return
		}
		cmd, err := getCommand(pid)
		if err != nil {
			fmt.Println("Failed to get Command of PID", pid, ":", err)
			return
		}

		fmt.Printf("PID: %d, ExecPath: %s, Command: %s\n", pid, exePath, cmd)

		cmdTokens := strings.Split(cmd, " ")

		dom := cmdTokens[1]
		fmt.Println("Domain:", dom)
		matched, err := regexp.MatchString(`^.*\\.baidu\\.com$`, dom)
		if err != nil {
			return
		}
		if matched || strings.Contains(dom, "baidu") {
			fmt.Println("Blocked")
			return
		}
	}

	proxy2Conn, err := connect(targetAddr)

	if err != nil {
		fmt.Println("Failed to connect to Proxy 2:", err)
		return
	}

	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x3f, 0, 0, 0, byte(1080 >> 8), byte(1080 & 0xff)}); err != nil {
		fmt.Println("Failed to write connection success response:", err)
		return
	}

	forward := func(src, dest net.Conn) {
		defer func(src net.Conn) {
			if err := src.Close(); err != nil {
				fmt.Println("Failed to close source connection:", err)
			}
		}(src)
		defer func(dest net.Conn) {
			if err := dest.Close(); err != nil {
				fmt.Println("Failed to close destination connection:", err)
			}
		}(dest)

		if _, err := io.Copy(dest, src); err != nil {
			return
		}
	}

	go forward(conn, proxy2Conn)
	forward(proxy2Conn, conn)
}

func getExecPath(pid int) (string, error) {
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}
	return exePath, nil
}

func getCommand(pid int) (string, error) {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	cmdlineBytes, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return "", fmt.Errorf("failed to read command line: %v", err)
	}
	cmdline := strings.Join(strings.Split(string(cmdlineBytes), "\x00"), " ")
	return cmdline, nil
}

func connect(targetAddr string) (net.Conn, error) {

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid target address: %v", err)
	}

	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", err)
	}

	ip := net.ParseIP(host)
	var addrType byte
	var addrBody []byte

	if ip == nil {
		addrType = 0x03 // Domain name
		addrBody = append([]byte{byte(len(host))}, []byte(host)...)
		fmt.Println("Domain name:", host)
		fmt.Println(string(addrBody))
	} else if ip.To4() != nil {
		addrType = 0x01 // IPv4
		addrBody = ip.To4()
		fmt.Println("IPv4 address:", addrBody)
	} else {
		addrType = 0x04 // IPv6
		addrBody = ip.To16()
		fmt.Println("IPv6 address:", addrBody)
	}

	req := []byte{0x05, 0x01, 0x00, addrType}
	req = append(req, addrBody...)
	req = append(req, byte(port>>8), byte(port&0xff))

	fmt.Println("Request:", string(addrBody))

	d := -1
	if addrType == 0x03 {
		d = diffDomain(addrBody)
	} else if addrType == 0x01 || addrType == 0x04 {
		d = diffIP(addrBody)
	}

	if d == 1 {
		conn, err := connectProxy2(req)
		return conn, err
	} else if d == 0 {
		conn, err := net.Dial("tcp", targetAddr)
		return conn, err
	}
	return nil, fmt.Errorf("not allowed to connect to %s", host)
}

func connectProxy2(req []byte) (net.Conn, error) {
	conn, err := net.DialTCP("tcp",
		nil,
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: clientListenPort})
	//conn, err := net.Dial("tcp", fmt.Sprintf(":%d", proxy2Addr))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Proxy 2: %v", err)
	}

	fmt.Println("dial conn:", conn.LocalAddr())

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, fmt.Errorf("failed to send handshake to Proxy 2: %v", err)
	}

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("failed to read handshake response from Proxy 2: %v", err)
	}

	if buf[1] != 0x00 {
		return nil, fmt.Errorf("no acceptable authentication method from Proxy 2")
	}

	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("failed to send connect request to Proxy 2: %v", err)
	}

	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("failed to read connect response from Proxy 2: %v", err)
	}

	if resp[1] != 0x00 {
		return nil, fmt.Errorf("connection request to Proxy 2 failed, response code: %d", resp[1])
	}

	return conn, nil
}

func client() {
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

	fmt.Println("SOCKS5 proxy client is running on port", proxyListenPort)

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

func main() {
	go server()
	client()
}
