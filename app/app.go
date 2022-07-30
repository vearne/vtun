package app

import (
	"log"
	"net"
	"runtime"

	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/grpc"
	"github.com/net-byte/vtun/tls"
	"github.com/net-byte/vtun/tun"
	"github.com/net-byte/vtun/udp"
	"github.com/net-byte/vtun/ws"
)

var SrcUrl = "https://github.com/net-byte/vtun"
var Banner = `
_                 
__ __ | |_   _  _   _ _  
\ V / |  _| | || | | ' \ 
 \_/   \__|  \_,_| |_||_|
						 
A simple VPN written in Go. %s
`

// vtun app struct
type Vtun struct {
	Config  *config.Config
	Version string
}

// InitConfig initializes the config
func (app *Vtun) InitConfig() {
	log.Printf(Banner, SrcUrl)
	log.Printf("vtun version:%s", app.Version)
	log.Printf("vtun starting...")
	if !app.Config.ServerMode && app.Config.GlobalMode {
		host, _, err := net.SplitHostPort(app.Config.ServerAddr)
		if err != nil {
			log.Panic("error server address")
		}
		serverIP := netutil.LookupIP(host)
		switch runtime.GOOS {
		case "linux":
			app.Config.LocalGateway = netutil.GetLocalGatewayOnLinux(serverIP.To4() != nil)
		case "darwin":
			app.Config.LocalGateway = netutil.GetLocalGatewayOnMac(serverIP.To4() != nil)
		case "windows":
			app.Config.LocalGateway = netutil.GetLocalGateway()
		}
	}
	cipher.SetKey(app.Config.Key)
	log.Printf("initialized config:%+v\n", app.Config)
}

// StartApp starts the app
func (app *Vtun) StartApp() {
	switch app.Config.Protocol {
	case "udp":
		if app.Config.ServerMode {
			udp.StartServer(*app.Config)
		} else {
			udp.StartClient(*app.Config)
		}
	case "ws", "wss":
		if app.Config.ServerMode {
			ws.StartServer(*app.Config)
		} else {
			ws.StartClient(*app.Config)
		}
	case "tls":
		if app.Config.ServerMode {
			tls.StartServer(*app.Config)
		} else {
			tls.StartClient(*app.Config)
		}
	case "grpc":
		if app.Config.ServerMode {
			grpc.StartServer(*app.Config)
		} else {
			grpc.StartClient(*app.Config)
		}
	default:
		if app.Config.ServerMode {
			udp.StartServer(*app.Config)
		} else {
			udp.StartClient(*app.Config)
		}
	}
}

// StopApp stops the app
func (app *Vtun) StopApp() {
	tun.ResetTun(*app.Config)
	log.Printf("vtun stopped")
}
