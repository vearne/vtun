package tcp

import (
	"io"
	"log"
	"net"
	_ "net/http/pprof"
	"strings"
	"time"

	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/tun"
	"github.com/patrickmn/go-cache"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
)

// Start a tcp server
func StartServer(config config.Config) {
	iface := tun.CreateTun(config)
	c := cache.New(30*time.Minute, 10*time.Minute)
	// server -> client
	go toClient(config, iface, c)
	ln, err := net.Listen("tcp", config.LocalAddr)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("vtun tcp server started on %v", config.LocalAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		// client -> server
		go toServer(config, conn, iface, c)
	}

}

func toClient(config config.Config, iface *water.Interface, c *cache.Cache) {
	buffer := make([]byte, 1500)
	for {
		n, err := iface.Read(buffer)
		if err != nil || err == io.EOF || n == 0 {
			continue
		}
		b := buffer[:n]
		if !waterutil.IsIPv4(b) {
			continue
		}
		srcAddr, dstAddr := netutil.GetAddr(b)
		if srcAddr == "" || dstAddr == "" {
			continue
		}
		key := strings.Join([]string{dstAddr, srcAddr}, "->")
		if v, ok := c.Get(key); ok {
			if config.Obfuscate {
				b = cipher.XOR(b)
			}
			counter.IncrWriteByte(n)
			v.(net.Conn).Write(b)
		}
	}
}

func toServer(config config.Config, tcpconn net.Conn, iface *water.Interface, c *cache.Cache) {
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
		srcAddr, dstAddr := netutil.GetAddr(b)
		if srcAddr == "" || dstAddr == "" {
			continue
		}
		key := strings.Join([]string{srcAddr, dstAddr}, "->")
		c.Set(key, tcpconn, cache.DefaultExpiration)
		counter.IncrReadByte(len(b))
		iface.Write(b)
	}
}
