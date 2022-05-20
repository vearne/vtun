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
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
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
	if localAddr.IP.To4() != nil {
		p := ipv4.NewPacketConn(conn)
		if err := p.SetTOS(0xb8); err != nil { // DSCP EF
			log.Fatalln("failed to set conn tos:", err)
		}
	} else {
		p := ipv6.NewPacketConn(conn)
		if err := p.SetTrafficClass(0xb8); err != nil { // DSCP EF
			log.Fatalln("failed to set conn tos:", err)
		}
	}
	defer conn.Close()
	s := &Server{config: config, iface: iface, localConn: conn, connCache: cache.New(30*time.Minute, 10*time.Minute)}
	go s.tunToUdp()
	s.udpToTun()
}

type Server struct {
	config    config.Config
	iface     *water.Interface
	localConn *net.UDPConn
	connCache *cache.Cache
}

func (s *Server) tunToUdp() {
	packet := make([]byte, s.config.MTU)
	for {
		n, err := s.iface.Read(packet)
		if err != nil || n == 0 {
			continue
		}
		b := packet[:n]
		if key := netutil.GetDstKey(b); key != "" {
			if v, ok := s.connCache.Get(key); ok {
				if s.config.Obfs {
					b = cipher.XOR(b)
				}
				s.localConn.WriteToUDP(b, v.(*net.UDPAddr))
			}
		}
	}
}

func (s *Server) udpToTun() {
	packet := make([]byte, s.config.MTU)
	for {
		n, cliAddr, err := s.localConn.ReadFromUDP(packet)
		if err != nil || n == 0 {
			continue
		}
		b := packet[:n]
		if s.config.Obfs {
			b = cipher.XOR(b)
		}
		if key := netutil.GetSrcKey(b); key != "" {
			s.iface.Write(b)
			s.connCache.Set(key, cliAddr, cache.DefaultExpiration)
		}
	}
}
