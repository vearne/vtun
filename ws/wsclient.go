package ws

import (
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/gobwas/ws/wsutil"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/tun"
	"github.com/patrickmn/go-cache"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
)

// StartClient starts ws client
func StartClient(config config.Config) {
	iface := tun.CreateTun(config)
	c := cache.New(30*time.Minute, 10*time.Minute)
	log.Printf("vtun ws client started,CIDR is %v", config.CIDR)
	// read data from tun
	packet := make([]byte, 1500)
	for {
		n, err := iface.Read(packet)
		if err != nil || n == 0 {
			continue
		}
		b := packet[:n]
		if !waterutil.IsIPv4(b) {
			continue
		}
		srcAddr, dstAddr := netutil.GetAddr(b)
		if srcAddr == "" || dstAddr == "" {
			continue
		}
		key := strings.Join([]string{dstAddr, srcAddr}, "->")
		var conn net.Conn
		if v, ok := c.Get(key); ok {
			conn = v.(net.Conn)
		} else {
			conn = netutil.ConnectServer(config)
			if conn == nil {
				continue
			}
			c.Set(key, conn, cache.DefaultExpiration)
			go wsToTun(config, c, key, conn, iface)
		}
		if config.Obfuscate {
			b = cipher.XOR(b)
		}
		wsutil.WriteClientBinary(conn, b)
	}
}

func wsToTun(config config.Config, c *cache.Cache, key string, wsconn net.Conn, iface *water.Interface) {
	defer wsconn.Close()
	for {
		wsconn.SetReadDeadline(time.Now().Add(time.Duration(30) * time.Second))
		b, err := wsutil.ReadServerBinary(wsconn)
		if err != nil || err == io.EOF {
			break
		}
		if config.Obfuscate {
			b = cipher.XOR(b)
		}
		if !waterutil.IsIPv4(b) {
			continue
		}
		iface.Write(b[:])
	}
	c.Delete(key)
}
