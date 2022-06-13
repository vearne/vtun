package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/net-byte/vtun/grpc"

	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/tls"
	"github.com/net-byte/vtun/tun"
	"github.com/net-byte/vtun/udp"
	"github.com/net-byte/vtun/ws"
)

func main() {
	config := config.Config{}
	flag.StringVar(&config.DeviceName, "dn", "", "device name")
	flag.StringVar(&config.CIDR, "c", "172.16.0.10/24", "tun interface cidr")
	flag.StringVar(&config.CIDRv6, "c6", "fced:9999::9999/64", "tun interface ipv6 cidr")
	flag.IntVar(&config.MTU, "mtu", 1500, "tun mtu")
	flag.StringVar(&config.LocalAddr, "l", ":3000", "local address")
	flag.StringVar(&config.ServerAddr, "s", ":3001", "server address")
	flag.StringVar(&config.IntranetServerIP, "sip", "172.16.0.1", "intranet server ip")
	flag.StringVar(&config.IntranetServerIPv6, "sip6", "fced:9999::1", "intranet server ipv6")
	flag.StringVar(&config.DNSServerIP, "dip", "8.8.8.8", "dns server ip")
	flag.StringVar(&config.Key, "k", "freedom@2022", "key")
	flag.StringVar(&config.Protocol, "p", "udp", "protocol udp/tls/grpc/ws/wss")
	flag.StringVar(&config.WebSocketPath, "path", "/freedom", "websocket path")
	flag.BoolVar(&config.ServerMode, "S", false, "server mode")
	flag.BoolVar(&config.GlobalMode, "g", false, "client global mode")
	flag.BoolVar(&config.Obfs, "obfs", false, "enable data obfuscation")
	flag.IntVar(&config.Timeout, "t", 30, "dial timeout in seconds")
	flag.StringVar(&config.TLSCertificateFilePath, "certificate", "./certs/server.pem", "tls certificate file path")
	flag.StringVar(&config.TLSCertificateKeyFilePath, "privatekey", "./certs/server.key", "tls certificate key file path")
	flag.StringVar(&config.TLSSni, "sni", "", "tls handshake sni")
	flag.BoolVar(&config.TLSInsecureSkipVerify, "isv", false, "tls insecure skip verify")
	flag.Parse()
	initConfig(&config)
	go startApp(config)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	stopApp(config)
}

// initConfig initializes the config
func initConfig(config *config.Config) {
	if !config.ServerMode && config.GlobalMode {
		host, _, err := net.SplitHostPort(config.ServerAddr)
		if err != nil {
			log.Panic("error server address")
		}
		serverIP := netutil.LookupIP(host)
		switch runtime.GOOS {
		case "linux":
			config.LocalGateway = netutil.GetLocalGatewayOnLinux(serverIP.To4() != nil)
		case "darwin":
			config.LocalGateway = netutil.GetLocalGatewayOnMac(serverIP.To4() != nil)
		}
	}
	cipher.SetKey(config.Key)
	json, _ := json.Marshal(config)
	log.Printf("init config:%s", string(json))
}

// startApp starts the app
func startApp(config config.Config) {
	switch config.Protocol {
	case "udp":
		if config.ServerMode {
			udp.StartServer(config)
		} else {
			udp.StartClient(config)
		}
	case "ws", "wss":
		if config.ServerMode {
			ws.StartServer(config)
		} else {
			ws.StartClient(config)
		}
	case "tls":
		if config.ServerMode {
			tls.StartServer(config)
		} else {
			tls.StartClient(config)
		}
	case "grpc":
		if config.ServerMode {
			grpc.StartServer(config)
		} else {
			grpc.StartClient(config)
		}
	default:
		if config.ServerMode {
			udp.StartServer(config)
		} else {
			udp.StartClient(config)
		}
	}
}

// stopApp stops the app
func stopApp(config config.Config) {
	tun.ResetTun(config)
	log.Printf("vtun stopped")
}
