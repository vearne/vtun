package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/tcp"
	"github.com/net-byte/vtun/udp"
	"github.com/net-byte/vtun/ws"
)

func main() {
	config := config.Config{}
	flag.StringVar(&config.CIDR, "c", "172.16.0.10/24", "tun interface CIDR")
	flag.StringVar(&config.LocalAddr, "l", ":3000", "local address")
	flag.StringVar(&config.ServerAddr, "s", ":3001", "server address")
	flag.StringVar(&config.Key, "k", "6w9z$C&F)J@NcRfWjXn3r4u7x!A%D*G-", "key")
	flag.StringVar(&config.Protocol, "p", "wss", "protocol tcp/udp/ws/wss")
	flag.StringVar(&config.DNS, "d", "8.8.8.8:53", "dns address")
	flag.StringVar(&config.WebSocketPath, "path", "/freedom", "websocket path")
	flag.BoolVar(&config.ServerMode, "S", false, "server mode")
	flag.BoolVar(&config.GlobalMode, "g", false, "client global mode")
	flag.BoolVar(&config.Obfuscate, "obfs", false, "enable obfuscation")
	flag.BoolVar(&config.Pprof, "P", false, "enable pporf server on :6060")
	flag.Parse()
	config.Init()
	if config.Pprof {
		go func() {
			log.Printf("pprof server on :6060")
			if err := http.ListenAndServe(":6060", nil); err != nil {
				log.Printf("pprof failed: %v", err)
			}
		}()
	}
	switch config.Protocol {
	case "udp":
		if config.ServerMode {
			udp.StartServer(config)
		} else {
			udp.StartClient(config)
		}
	case "tcp":
		if config.ServerMode {
			tcp.StartServer(config)
		} else {
			tcp.StartClient(config)
		}
	case "ws":
		if config.ServerMode {
			ws.StartServer(config)
		} else {
			ws.StartClient(config)
		}
	default:
		if config.ServerMode {
			ws.StartServer(config)
		} else {
			ws.StartClient(config)
		}
	}
}
