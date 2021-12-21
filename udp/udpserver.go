package udp

import (
	"log"
	"net"
	"strings"
	"time"

	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/tun"
	"github.com/patrickmn/go-cache"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
)

// Start an udp server
func StartServer(config config.Config) {
	iface := tun.CreateTun(config)
	localAddr, err := net.ResolveUDPAddr("udp", config.LocalAddr)
	if err != nil {
		log.Fatalln("failed to get udp socket:", err)
	}
	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		log.Fatalln("failed to listen on udp socket:", err)
	}
	defer conn.Close()
	log.Printf("vtun udp server started on %v", config.LocalAddr)
	// server -> client
	reply := &Reply{localConn: conn, connCache: cache.New(30*time.Minute, 10*time.Minute)}
	go reply.toClient(config, iface, conn)
	// client -> server
	buf := make([]byte, 1500)
	for {
		n, cliAddr, err := conn.ReadFromUDP(buf)
		if err != nil || n == 0 {
			continue
		}
		var b []byte
		if config.Obfuscate {
			b = cipher.XOR(buf[:n])
		} else {
			b = buf[:n]
		}
		if !waterutil.IsIPv4(b) {
			continue
		}
		iface.Write(b)
		srcAddr, dstAddr := netutil.GetAddr(b)
		if srcAddr == "" || dstAddr == "" {
			continue
		}
		key := strings.Join([]string{srcAddr, dstAddr}, "->")
		reply.connCache.Set(key, cliAddr, cache.DefaultExpiration)
	}
}

type Reply struct {
	localConn *net.UDPConn
	connCache *cache.Cache
}

func (r *Reply) toClient(config config.Config, iface *water.Interface, conn *net.UDPConn) {
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
		if v, ok := r.connCache.Get(key); ok {
			if config.Obfuscate {
				b = cipher.XOR(b)
			}
			r.localConn.WriteToUDP(b, v.(*net.UDPAddr))
		}
	}
}
