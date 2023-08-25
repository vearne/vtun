package main

import (
	"flag"
	"github.com/net-byte/vtun/common"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/net-byte/vtun/app"
	"github.com/net-byte/vtun/common/config"
)

var cfg = config.Config{}
var configFile string

func init() {
	flag.StringVar(&configFile, "f", "", "config file")
	flag.StringVar(&cfg.DeviceName, "dn", config.DefaultConfig.DeviceName, "device name")
	flag.StringVar(&cfg.CIDR, "c", config.DefaultConfig.CIDR, "tun interface cidr")
	flag.StringVar(&cfg.CIDRv6, "c6", config.DefaultConfig.CIDRv6, "tun interface ipv6 cidr")
	flag.IntVar(&cfg.MTU, "mtu", config.DefaultConfig.MTU, "tun mtu")
	flag.StringVar(&cfg.LocalAddr, "l", config.DefaultConfig.LocalAddr, "local address")
	flag.StringVar(&cfg.ServerAddr, "s", config.DefaultConfig.ServerAddr, "server address")
	flag.StringVar(&cfg.ServerIP, "sip", config.DefaultConfig.ServerIP, "server ip")
	flag.StringVar(&cfg.ServerIPv6, "sip6", config.DefaultConfig.ServerIPv6, "server ipv6")
	flag.StringVar(&cfg.Key, "k", config.DefaultConfig.Key, "key")
	flag.StringVar(&cfg.Protocol, "p", config.DefaultConfig.Protocol, "protocol udp/tls/grpc/quic/utls/dtls/h2/http/tcp/https/ws/wss")
	flag.StringVar(&cfg.Path, "path", config.DefaultConfig.Path, "path")
	flag.BoolVar(&cfg.ServerMode, "S", config.DefaultConfig.ServerMode, "server mode")
	flag.BoolVar(&cfg.GlobalMode, "g", config.DefaultConfig.GlobalMode, "client global mode")
	flag.BoolVar(&cfg.Obfs, "obfs", config.DefaultConfig.Obfs, "enable data obfuscation")
	flag.BoolVar(&cfg.Compress, "compress", config.DefaultConfig.Compress, "enable data compression")
	flag.IntVar(&cfg.Timeout, "t", config.DefaultConfig.Timeout, "dial timeout in seconds")
	flag.StringVar(&cfg.TLSCertificateFilePath, "certificate", config.DefaultConfig.TLSCertificateFilePath, "tls certificate file path")
	flag.StringVar(&cfg.TLSCertificateKeyFilePath, "privatekey", config.DefaultConfig.TLSCertificateKeyFilePath, "tls certificate key file path")
	flag.StringVar(&cfg.TLSSni, "sni", config.DefaultConfig.TLSSni, "tls handshake sni")
	flag.BoolVar(&cfg.TLSInsecureSkipVerify, "isv", config.DefaultConfig.TLSInsecureSkipVerify, "tls insecure skip verify")
	flag.BoolVar(&cfg.Verbose, "v", config.DefaultConfig.Verbose, "enable verbose output")
	flag.BoolVar(&cfg.PSKMode, "psk", config.DefaultConfig.PSKMode, "enable psk mode (dtls only)")
	flag.StringVar(&cfg.Host, "host", config.DefaultConfig.Host, "http host")
	flag.Parse()
}

func main() {
	common.DisplayVersionInfo()
	if configFile != "" {
		err := cfg.LoadConfig(configFile)
		if err != nil {
			log.Fatalf("Failed to load config from file: %s", err)
		}
	}
	app := app.NewApp(&cfg)
	app.InitConfig()
	go app.StartApp()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	app.StopApp()
}
