# vtun

A simple VPN written in golang.

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
  -c string
        tun interface CIDR (default "172.16.0.10/24")
  -k string
        key (default "6w9z$C&F)J@NcRfWjXn3r4u7x!A%D*G-")
  -l string
        local address (default ":3000")
  -p string
        protocol tcp/udp/ws/wss (default "wss")
  -s string
        server address (default ":3001")
  -d string
        dns address (default "8.8.8.8:53")
  -path string
        websocket path (default "/freedom")
  -P    enable pporf server on :6060
  -S    server mode
  -g    client global mode
  -obfs enable obfuscation

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
  // eth0 is the name of your public network interface
  sudo iptables -t nat -A POSTROUTING -s 172.16.0.0/24 -o eth0 -j MASQUERADE
```

## Docker

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
2. Support IPv6
3. Develop iOS app

# License
[The MIT License (MIT)](https://raw.githubusercontent.com/net-byte/vtun/master/LICENSE)
