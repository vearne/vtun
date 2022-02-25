package tcp

import (
	"io"
	"log"
	"net"
	"time"

	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/tun"
	"github.com/patrickmn/go-cache"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
)

// Start a tcp client
func StartClient(config config.Config) {
	iface := tun.CreateTun(config)
	c := cache.New(30*time.Minute, 10*time.Minute)
	log.Printf("vtun tcp client started on %v", config.LocalAddr)
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
		srcIPv4, dstIPv4 := netutil.GetIPv4(b)
		if srcIPv4 == "" || dstIPv4 == "" {
			continue
		}
		key := dstIPv4
		var conn net.Conn
		if v, ok := c.Get(key); ok {
			conn = v.(net.Conn)
		} else {
			conn, err = net.DialTimeout("tcp", config.ServerAddr, 30*time.Second)
			if conn == nil || err != nil {
				continue
			}
			c.Set(key, conn, cache.DefaultExpiration)
			go tcpToTun(config, c, key, conn, iface)
		}
		if config.Obfuscate {
			b = cipher.XOR(b)
		}
		conn.Write(b)
	}
}

func tcpToTun(config config.Config, c *cache.Cache, key string, tcpconn net.Conn, iface *water.Interface) {
	defer tcpconn.Close()
	buffer := make([]byte, 1500)
	for {
		tcpconn.SetReadDeadline(time.Now().Add(time.Duration(30) * time.Second))
		n, err := tcpconn.Read(buffer)
		if err != nil || err == io.EOF {
			break
		}
		b := buffer[:n]
		if config.Obfuscate {
			b = cipher.XOR(b)
		}
		if !waterutil.IsIPv4(b) {
			continue
		}
		iface.Write(b)
	}
	c.Delete(key)
}
