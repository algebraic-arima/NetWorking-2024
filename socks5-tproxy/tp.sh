#!/bin/bash

sysctl -w net.ipv4.ip_forward=1

sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner 1001 -j REDIRECT --to-port 8080

go build

./socks5-TProxy
