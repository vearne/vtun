package ws

import (
	"log"
	"net"
	"time"

	"github.com/gobwas/ws/wsutil"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/tun"
	"github.com/songgao/water"
)

// StartClient starts the ws client
func StartClient(config config.Config) {
	log.Printf("vtun websocket client started on %v", config.LocalAddr)
	iface := tun.CreateTun(config)
	go tunToWs(config, iface)
	for {
		conn := netutil.ConnectServer(config)
		if conn == nil {
			time.Sleep(3 * time.Second)
			continue
		}
		cache.GetCache().Set("wsconn", conn, 24*time.Hour)
		wsToTun(config, conn, iface)
		cache.GetCache().Delete("wsconn")
	}
}

// wsToTun sends packets from ws to tun
func wsToTun(config config.Config, wsconn net.Conn, iface *water.Interface) {
	defer wsconn.Close()
	for {
		wsconn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
		packet, err := wsutil.ReadServerBinary(wsconn)
		if err != nil {
			break
		}
		if config.Obfs {
			packet = cipher.XOR(packet)
		}
		_, err = iface.Write(packet)
		if err != nil {
			break
		}
	}
}

// tunToWs sends packets from tun to ws
func tunToWs(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.MTU)
	for {
		n, err := iface.Read(packet)
		if err != nil || n == 0 {
			continue
		}
		if v, ok := cache.GetCache().Get("wsconn"); ok {
			b := packet[:n]
			if config.Obfs {
				b = cipher.XOR(b)
			}
			wsconn := v.(net.Conn)
			wsconn.SetWriteDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
			if err = wsutil.WriteClientBinary(wsconn, b); err != nil {
				continue
			}
		}
	}
}
