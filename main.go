package main

import (
	"flag"

	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/udp"
	"github.com/net-byte/vtun/ws"
)

func main() {
	config := config.Config{}
	flag.StringVar(&config.CIDR, "c", "172.16.0.2/24", "tun interface CIDR")
	flag.StringVar(&config.LocalAddr, "l", "0.0.0.0:3000", "local address")
	flag.StringVar(&config.ServerAddr, "s", "0.0.0.0:3001", "server address")
	flag.StringVar(&config.Key, "k", "6w9z$C&F)J@NcRfWjXn3r4u7x!A%D*G-", "key")
	flag.StringVar(&config.Gateway, "g", "172.16.0.1", "gateway")
	flag.StringVar(&config.Route, "r", "", "route")
	flag.StringVar(&config.Protocol, "p", "wss", "protocol ws/wss/udp")
	flag.BoolVar(&config.ServerMode, "S", false, "server mode")
	flag.BoolVar(&config.Obfuscate, "o", false, "obfuscate data")
	flag.BoolVar(&config.Pprof, "P", false, "enable pporf server on :6060")
	flag.Parse()
	config.Init()
	switch config.Protocol {
	case "udp":
		if config.ServerMode {
			udp.StartServer(config)
		} else {
			udp.StartClient(config)
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
