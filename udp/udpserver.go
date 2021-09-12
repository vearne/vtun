package udp

import (
	"fmt"
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

// StartServer starts udp server
func StartServer(config config.Config) {
	iface := tun.CreateTun(config)
	localAddr, err := net.ResolveUDPAddr("udp", config.LocalAddr)
	if err != nil {
		log.Fatalln("failed to get UDP socket:", err)
	}
	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		log.Fatalln("failed to listen on UDP socket:", err)
	}
	defer conn.Close()
	log.Printf("vtun udp server started on %v,CIDR is %v", config.LocalAddr, config.CIDR)
	// write data to client
	f := &Forward{localConn: conn, connCache: cache.New(30*time.Minute, 10*time.Minute)}
	go f.tunToUDP(iface, conn)
	// read data from client
	buf := make([]byte, 1500)
	for {
		n, cliAddr, err := conn.ReadFromUDP(buf)
		if err != nil || n == 0 {
			continue
		}
		b := cipher.XOR(buf[:n])
		if !waterutil.IsIPv4(b) {
			continue
		}
		iface.Write(b)
		srcAddr, dstAddr := netutil.GetAddr(b)
		if srcAddr == "" || dstAddr == "" {
			continue
		}
		key := fmt.Sprintf("%v->%v", srcAddr, dstAddr)
		f.connCache.Set(key, cliAddr, cache.DefaultExpiration)
	}
}

type Forward struct {
	localConn *net.UDPConn
	connCache *cache.Cache
}

func (f *Forward) tunToUDP(iface *water.Interface, conn *net.UDPConn) {
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
		key := fmt.Sprintf("%v->%v", dstAddr, srcAddr)
		v, ok := f.connCache.Get(key)
		if ok {
			b = cipher.XOR(b)
			f.localConn.WriteToUDP(b, v.(*net.UDPAddr))
		}
	}
}
