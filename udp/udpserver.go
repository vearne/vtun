package udp

import (
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

// Start udp server
func StartServer(config config.Config) {
	log.Printf("vtun udp server started on %v", config.LocalAddr)
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
	// server -> client
	reply := &Reply{localConn: conn, connCache: cache.New(30*time.Minute, 10*time.Minute)}
	go reply.toClient(config, iface, conn)
	// client -> server
	buf := make([]byte, config.MTU)
	for {
		n, cliAddr, err := conn.ReadFromUDP(buf)
		if err != nil || n == 0 {
			continue
		}
		var b []byte
		if config.Obfs {
			b = cipher.XOR(buf[:n])
		} else {
			b = buf[:n]
		}
		if !waterutil.IsIPv4(b) {
			continue
		}
		srcIPv4, dstIPv4 := netutil.GetIPv4(b)
		if srcIPv4 == "" || dstIPv4 == "" {
			continue
		}
		iface.Write(b)
		reply.connCache.Set(srcIPv4, cliAddr, cache.DefaultExpiration)
	}
}

type Reply struct {
	localConn *net.UDPConn
	connCache *cache.Cache
}

func (r *Reply) toClient(config config.Config, iface *water.Interface, conn *net.UDPConn) {
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
		if v, ok := r.connCache.Get(dstIPv4); ok {
			if config.Obfs {
				b = cipher.XOR(b)
			}
			r.localConn.WriteToUDP(b, v.(*net.UDPAddr))
		}
	}
}
