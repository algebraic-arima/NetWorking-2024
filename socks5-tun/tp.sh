#!/bin/bash

sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner 1001 -j REDIRECT --to-port 8080

go build

./socks5-TProxy
sudo ip tuntap add dev tun0 mode tun
sudo ip link set dev tun0 up
sudo ip addr add 10.0.0.1/24 dev tun0
sudo nano /etc/iproute2/rt_tables
sudo ip route add default dev tun0 table tun0
sudo iptables -t mangle -A OUTPUT -p tcp --dport 80 -j MARK --set-mark 1
sudo ip rule add fwmark 1 table tun0
sudo iptables -t mangle -N PROXY_BYPASS
sudo iptables -t mangle -A PROXY_BYPASS -p tcp --sport 8080 -j RETURN
sudo iptables -t mangle -A PROXY_BYPASS -p tcp --dport 8080 -j RETURN
sudo iptables -t mangle -A PROXY_BYPASS -j MARK --set-mark 1
sudo iptables -t mangle -A OUTPUT -j PROXY_BYPASS
ip route show table tun0
ip rule show

echo "Hel547lnkko" | socat - UDP-DATAGRAM:192.168.1.100:12345
sudo tcpdump -i tun0 -vv -X


iptables -t mangle -N TUN0
iptables -t mangle -A OUTPUT -o lo -p tcp -j MARK --set-mark 1
iptables -t mangle -A OUTPUT -p tcp --dport 8080 -j MARK --set-mark 2
ip rule add fwmark 1 table tun0
ip route add default dev tun0 table tun0
ip rule add fwmark 2 table proxy
ip route add default via 10.180.0.1 dev eth2 table proxy
iptables -t mangle -A OUTPUT -o tun0 -j ACCEPT