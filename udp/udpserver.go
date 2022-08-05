package udp

import (
	"log"
	"net"
	"time"

	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
	"github.com/patrickmn/go-cache"
)

// StartServer starts the udp server
func StartServer(iface *water.Interface, config config.Config) {
	log.Printf("vtun udp server started on %v", config.LocalAddr)
	localAddr, err := net.ResolveUDPAddr("udp", config.LocalAddr)
	if err != nil {
		log.Fatalln("failed to get udp socket:", err)
	}
	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		log.Fatalln("failed to listen on udp socket:", err)
	}
	defer conn.Close()
	s := &Server{config: config, iface: iface, localConn: conn, connCache: cache.New(30*time.Minute, 10*time.Minute)}
	go s.tunToUdp()
	s.udpToTun()
}

// the server struct
type Server struct {
	config    config.Config
	iface     *water.Interface
	localConn *net.UDPConn
	connCache *cache.Cache
}

// tunToUdp sends packets from tun to udp
func (s *Server) tunToUdp() {
	packet := make([]byte, 4096)
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
				if s.config.Compress {
					b = snappy.Encode(nil, b)
				}
				s.localConn.WriteToUDP(b, v.(*net.UDPAddr))
				counter.IncrWrittenBytes(n)
			}
		}
	}
}

// udpToTun sends packets from udp to tun
func (s *Server) udpToTun() {
	packet := make([]byte, 4096)
	for {
		n, cliAddr, err := s.localConn.ReadFromUDP(packet)
		if err != nil || n == 0 {
			continue
		}
		b := packet[:n]
		if s.config.Compress {
			b, err = snappy.Decode(nil, b)
			if err != nil {
				continue
			}
		}
		if s.config.Obfs {
			b = cipher.XOR(b)
		}
		if key := netutil.GetSrcKey(b); key != "" {
			s.iface.Write(b)
			s.connCache.Set(key, cliAddr, cache.DefaultExpiration)
			counter.IncrReadBytes(n)
		}
	}
}
