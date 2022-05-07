# vtun

A simple VPN written in golang.

[EN](https://github.com/net-byte/vtun/blob/master/README.md) | [中文](https://github.com/net-byte/vtun/blob/master/README_CN.md)

[![Travis](https://travis-ci.com/net-byte/vtun.svg?branch=master)](https://github.com/net-byte/vtun)
[![Go Report Card](https://goreportcard.com/badge/github.com/net-byte/vtun)](https://goreportcard.com/report/github.com/net-byte/vtun)
![image](https://img.shields.io/badge/License-MIT-orange)
![image](https://img.shields.io/badge/License-Anti--996-red)

# Features
* VPN over tcp
* VPN over udp
* VPN over websocket

# Usage

```
Usage of ./vtun:
  -S    server mode
  -c string
        tun interface cidr (default "172.16.0.10/24")
  -d string
        dns address (default "8.8.8.8:53")
  -g    client global mode
  -k string
        key (default "freedom@2022")
  -l string
        local address (default ":3000")
  -mtu int
        tun mtu (default 1500)
  -obfs
        enable data obfuscation
  -p string
        protocol tcp/udp/ws/wss (default "wss")
  -path string
        websocket path (default "/freedom")
  -s string
        server address (default ":3001")
  -t int
        dial timeout in seconds (default 30)

```

## Build

```
sh scripts/build.sh
```

## Client

```
sudo ./vtun-linux-amd64 -l=:3000 -s=server-addr:3001 -c=172.16.0.10/24 -k=123456

```

## Client with global mode(routing all your traffic to server)

```
sudo ./vtun-linux-amd64 -l=:3000 -s=server-addr:3001 -c=172.16.0.10/24 -k=123456 -g

```

## Server

```
sudo ./vtun-linux-amd64 -S -l=:3001 -c=172.16.0.1/24 -k=123456

```

## Server setup on Linux

1. Add TLS for websocket,reverse proxy server(3001) via nginx/caddy(443)

2. Enable IP forwarding on server

```
  sudo echo 1 > /proc/sys/net/ipv4/ip_forward
  sudo sysctl -p
  # Masquerade outgoing traffic
  iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
  # Allow return traffic
  iptables -A INPUT -i eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -A INPUT -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
  # Forward everything
  iptables -A FORWARD -j ACCEPT
```

## Docker
[docker image](https://hub.docker.com/r/netbyte/vtun)

### Run client
```
docker run  -d --privileged --restart=always --net=host --name vtun-client netbyte/vtun -l :3000 -s server-addr:3001 -c 172.16.0.10/24 -k 123456
```

### Run client with global mode
```
docker run  -d --privileged --restart=always --net=host --name vtun-client netbyte/vtun -l :3000 -s server-addr:3001 -c 172.16.0.10/24 -k 123456 -g
```

### Run server
```
docker run  -d --privileged --restart=always --net=host --name vtun-server netbyte/vtun -S -l :3001 -c 172.16.0.1/24 -k 123456
```

## Mobile client

### [Android](https://github.com/net-byte/vTunnel)

## TODO (help wanted)
1. Support windows
2. Develop iOS app

# License
[The MIT License (MIT)](https://raw.githubusercontent.com/net-byte/vtun/master/LICENSE)
