package ws

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/gobwas/ws/wsutil"
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
	for {
		if conn := netutil.ConnectServer(config); conn != nil {
			var wg sync.WaitGroup
			wg.Add(2)
			go wsToTun(&wg, config, conn, iface)
			go tunToWs(&wg, config, conn, iface)
			wg.Wait()
			conn.Close()
		}
	}
}

func wsToTun(wg *sync.WaitGroup, config config.Config, wsconn net.Conn, iface *water.Interface) {
	defer wg.Done()
	for {
		var packet []byte
		var err error
		wsconn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
		packet, err = wsutil.ReadServerBinary(wsconn)
		if err != nil {
			break
		}
		if config.Obfs {
			packet = cipher.XOR(packet)
		}
		if !waterutil.IsIPv4(packet) {
			continue
		}
		iface.Write(packet)
	}
}

func tunToWs(wg *sync.WaitGroup, config config.Config, wsconn net.Conn, iface *water.Interface) {
	defer wg.Done()
	packet := make([]byte, 0, config.MTU)
	for {
		n, err := iface.Read(packet)
		if err != nil || n == 0 {
			break
		}
		packet = packet[:n]
		if !waterutil.IsIPv4(packet) {
			continue
		}
		srcIPv4, dstIPv4 := netutil.GetIPv4(packet)
		if srcIPv4 == "" || dstIPv4 == "" {
			continue
		}
		if config.Obfs {
			packet = cipher.XOR(packet)
		}
		wsconn.SetWriteDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
		err = wsutil.WriteClientBinary(wsconn, packet)
		if err != nil {
			break
		}
	}
}
