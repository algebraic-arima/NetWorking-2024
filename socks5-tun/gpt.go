package main

import (
	"log"
	// "os"
	"syscall"
	"unsafe"
)

const ()

type Ifreq struct {
	Name  [syscall.IFNAMSIZ]byte
	Flags short
}

type short int16

func min() {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		log.Fatalf("Failed to open TUN device: %v", err)
	}
	defer syscall.Close(fd)

	ifr := &Ifreq{}
	ifr.Flags = syscall.IFF_TUN | syscall.IFF_NO_PI
	copy(ifr.Name[:syscall.IFNAMSIZ-1], []byte(TUN_DEVICE_NAME))

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(ifr)))
	if errno != 0 {
		log.Fatalf("Failed to set TUN device parameters: %v", errno)
	}

	log.Printf("TUN device %s opened\n", TUN_DEVICE_NAME)

	buffer := make([]byte, MTU)

	for {
		n, err := syscall.Read(fd, buffer)
		if err != nil {
			log.Fatalf("Failed to read from TUN device: %v", err)
		}
		packet := buffer[:n]

		// parse
		log.Printf("Received packet from TUN device (%d bytes):\n%s\n", n, packet)
	}
}
