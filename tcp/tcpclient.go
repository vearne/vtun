package tcp

import (
	"io"
	"log"
	"net"
	"time"

	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/tun"
	"github.com/songgao/water"
)

// Start tcp client
func StartClient(config config.Config) {
	log.Printf("vtun tcp client started on %v", config.LocalAddr)
	iface := tun.CreateTun(config)
	go tunToTcp(config, iface)
	for {
		conn, err := net.DialTimeout("tcp", config.ServerAddr, time.Duration(config.Timeout)*time.Second)
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		cache.GetCache().Set("tcpconn", conn, 24*time.Hour)
		tcpToTun(config, conn, iface)
		cache.GetCache().Delete("tcpconn")

	}
}

func tunToTcp(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.MTU)
	for {
		n, err := iface.Read(packet)
		if err != nil || n == 0 {
			continue
		}
		if v, ok := cache.GetCache().Get("tcpconn"); ok {
			b := packet[:n]
			if config.Obfs {
				packet = cipher.XOR(packet)
			}
			tcpconn := v.(net.Conn)
			tcpconn.SetWriteDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
			_, err = tcpconn.Write(b)
			if err != nil {
				continue
			}
		}
	}
}

func tcpToTun(config config.Config, tcpconn net.Conn, iface *water.Interface) {
	defer tcpconn.Close()
	packet := make([]byte, config.MTU)
	for {
		tcpconn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
		n, err := tcpconn.Read(packet)
		if err != nil || err == io.EOF {
			break
		}
		b := packet[:n]
		if config.Obfs {
			b = cipher.XOR(b)
		}
		_, err = iface.Write(b)
		if err != nil {
			break
		}
	}
}
