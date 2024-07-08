package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	logDir          = "log/"
	proxyListenPort = 1081
	certFilePath    = "ca.crt"
	keyFilePath     = "ca.key"
	replaceTokenNum = 5
	filename        = "replace.txt"
)

var rtCert *x509.Certificate
var rtKey crypto.PrivateKey
var replace = [replaceTokenNum][2]string{
	{`PKU JudgeOnline`, `<a href="https://acm.sjtu.edu.cn/OnlineJudge/">SJTU ACMOJ</a>`},
	{`百度`, `<a href="https://mzh.moegirl.org.cn/%E5%8F%8C%E5%8F%B6%E7%90%86%E5%A4%AE">双叶</a>`},
	{`Example Domain`, `<a href="https://en.wikipedia.org/wiki/Principal_ideal_domain">Principal Ideal Domain</a>`},
	{`代理`, `代数`},
	{`原神`, `鸣潮`},
}

// var f = "xx45 72x4 572x 4572 1754 3216 7"

func loadRootCA() (*x509.Certificate, crypto.PrivateKey, error) {
	rootCertBytes, err := os.ReadFile(certFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("1%v", err)
	}
	rootCertBlock, _ := pem.Decode(rootCertBytes)
	if rootCertBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode root certificate")
	}
	rootCA, err := x509.ParseCertificate(rootCertBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("2%v", err)
	}

	rootKeyBytes, err := os.ReadFile(keyFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("3%v", err)
	}
	rootKeyBlock, _ := pem.Decode(rootKeyBytes)
	if rootKeyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode root key")
	}
	rootKey, err := x509.ParsePKCS8PrivateKey(rootKeyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("4%v", err)
	}

	return rootCA, rootKey, nil
}

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

func generateDynamicCert(rootCA *x509.Certificate, rootKey crypto.PrivateKey, domain string) ([]byte, []byte, error) {

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %v", err)
	}

	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, rootCA, &priv.PublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	return certPEM, privPEM, nil
}

func tlsHandshake(conn net.Conn, host string) (*tls.Conn, error) {
	domain := strings.Split(host, ":")[0]
	certPEM, privPEM, err := generateDynamicCert(rtCert, rtKey, domain)
	if err != nil {
		fmt.Println("Failed to generate dynamic certificate:", err)
		return nil, err
	}
	tmpCert, err := tls.X509KeyPair(certPEM, privPEM)
	if err != nil {
		fmt.Println("Failed to load key pair:", err)
		return nil, err
	}
	tmpConfig := &tls.Config{
		Certificates: []tls.Certificate{tmpCert},
		GetConfigForClient: func(clientHelloInfo *tls.ClientHelloInfo) (*tls.Config, error) {
			fmt.Println("Received client hello from host:", clientHelloInfo.ServerName)
			return nil, nil
		},
		MinVersion: tls.VersionTLS11,
		MaxVersion: tls.VersionTLS13,
	}
	tlsConn := tls.Server(conn, tmpConfig)

	if err := tlsConn.Handshake(); err != nil {
		fmt.Println("Failed to handshake with client:", err)
		return nil, err
	}
	return tlsConn, nil
}

func openLog(n int) {
	logTxtDir := logDir + fmt.Sprintf("%d.log", n)
	logFile, err := os.Create(logTxtDir)
	if err != nil {
		fmt.Println("Failed to create log file:", err)
		return
	}
	defer func(logFile *os.File) {
		if err := logFile.Close(); err != nil {
			fmt.Println("Failed to close log file:", err)
		}
	}(logFile)
	log.SetOutput(logFile)
}

func handleClient(conn net.Conn, n int) {
	openLog(n)
	_, host, port, err := socks5Handshake(conn)
	if err != nil {
		fmt.Println("Socks5: Failed to handshake with client:", err)
		return
	}

	fmt.Println("Socks5 connecting to target:", host)

	var backConn net.Conn
	var forwardConn net.Conn

	if port == 443 {
		fmt.Println("\033[34mHTTPS\033[0m")

		backConn, err = tlsHandshake(conn, host)
		if err != nil {
			fmt.Println("TLS: Failed to handshake with client:", err)
			return
		}

		fmt.Println("TLS handshake successful with target:", host)

		forwardConn, err = tls.Dial("tcp", host, nil)
		if err != nil {
			fmt.Println("Failed to connect to target:", err)
			return
		}

	} else if port == 80 {
		fmt.Println("\033[34mHTTP\033[0m")

		backConn = conn
		forwardConn, err = net.Dial("tcp", host)

		if err != nil {
			fmt.Println("Failed to connect to target:", err)
			return
		}
	}

	forward := func(src, dest net.Conn, dir string) {
		var a net.Conn
		fmt.Println(a)
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
		for {
			if dir == "forward" {
				req, err := http.ReadRequest(bufio.NewReader(src))
				if err != nil {
					if err != io.EOF {
						fmt.Println("Failed to read request:", err)
					}
					return
				}
				req.Header.Del("Accept-Encoding")
				dump, err := httputil.DumpRequest(req, true)
				if err != nil {
					fmt.Println("Failed to dump request:", err)
					return
				}
				fmt.Println("Request:", string(dump))
				if err := req.Write(dest); err != nil {
					fmt.Println("Failed to write request:", err)
					return
				}
			} else if dir == "backward" {
				resp, err := http.ReadResponse(bufio.NewReader(src), nil)
				if err != nil {
					if err != io.EOF {
						fmt.Println("Failed to read response:", err)
					}
					return
				}
				dump, err := httputil.DumpResponse(resp, true)
				if err != nil {
					fmt.Println("Failed to dump response:", err)
					return
				}
				fmt.Println("Response:", string(dump))
				err = replaceResponseBody(resp, replace)
				if err != nil {
					fmt.Println("Failed to replace response body:", err)
					return
				}

				if err := resp.Write(dest); err != nil {
					fmt.Println("Failed to write response:", err)
					return
				}
			}
		}
	}
	go forward(backConn, forwardConn, "forward")
	forward(forwardConn, backConn, "backward")
}

func replaceResponseBody(resp *http.Response, oldNewPairs [replaceTokenNum][2]string) error {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if err := resp.Body.Close(); err != nil {
		return err
	}

	bodyString := string(bodyBytes)
	for _, pair := range oldNewPairs {
		olds := pair[0]
		news := pair[1]
		re, err := regexp.Compile(olds)
		// re, err := regexp.Compile(`\b` + regexp.QuoteMeta(olds) + `\b`)
		if err != nil {
			return fmt.Errorf("failed to compile regular expression: %v", err)
		}

		bodyString = re.ReplaceAllString(bodyString, news)
	}

	resp.Body = io.NopCloser(bytes.NewReader([]byte(bodyString)))
	resp.ContentLength = int64(len(bodyString))
	resp.Header.Set("Content-Length", fmt.Sprint(len(bodyString)))

	return nil
}

func main() {
	var err error

	rtCert, rtKey, err = loadRootCA()
	if err != nil {
		fmt.Println("Failed to load key pair:", err)
		return
	}

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
