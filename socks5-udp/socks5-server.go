package main

import (
	"github.com/armon/go-socks5"
	"log"
)

func socks5Server() {
	conf := &socks5.Config{}
	server, err := socks5.New(conf)
	if err != nil {
		log.Fatal(err)
	}

	addr := "10.180.92.161:1080"
	log.Println("Starting SOCKS5 proxy server on", addr)
	if err := server.ListenAndServe("tcp", addr); err != nil {
		log.Fatal(err)
	}
}
