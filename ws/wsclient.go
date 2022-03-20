package ws

import (
	"io"
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
	"github.com/songgao/water/waterutil"
)

// Start websocket client
func StartClient(config config.Config) {
	log.Printf("vtun websocket client started on %v", config.LocalAddr)
	iface := tun.CreateTun(config)
	// read data from tun
	packet := make([]byte, config.MTU)
	for {
		n, err := iface.Read(packet)
		if err != nil || n == 0 {
			continue
		}
		b := packet[:n]
		if !waterutil.IsIPv4(b) {
			continue
		}
		srcIPv4, dstIPv4 := netutil.GetIPv4(b)
		if srcIPv4 == "" || dstIPv4 == "" {
			continue
		}
		key := dstIPv4
		var conn net.Conn
		if v, ok := cache.GetCache().Get(key); ok {
			conn = v.(net.Conn)
		} else {
			conn = netutil.ConnectServer(config)
			if conn == nil {
				continue
			}
			cache.GetCache().Set(key, conn, 10*time.Minute)
			go wsToTun(config, key, conn, iface)
		}
		if config.Obfs {
			b = cipher.XOR(b)
		}
		wsutil.WriteClientBinary(conn, b)
	}
}

func wsToTun(config config.Config, key string, wsconn net.Conn, iface *water.Interface) {
	defer wsconn.Close()
	for {
		wsconn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
		b, err := wsutil.ReadServerBinary(wsconn)
		if err != nil || err == io.EOF {
			break
		}
		if config.Obfs {
			b = cipher.XOR(b)
		}
		if !waterutil.IsIPv4(b) {
			continue
		}
		iface.Write(b)
	}
	cache.GetCache().Delete(key)
}
