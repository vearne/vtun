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

// Server the server struct
type Server struct {
	config    config.Config
	iFace     *water.Interface
	localConn *net.UDPConn
	connCache *cache.Cache
}

// StartServer starts the udp server
func StartServer(iFace *water.Interface, config config.Config) {
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
	s := &Server{config: config, iFace: iFace, localConn: conn, connCache: cache.New(30*time.Minute, 10*time.Minute)}
	go s.tunToUdp()
	s.udpToTun()
}

// tunToUdp sends packets from tun to udp
func (s *Server) tunToUdp() {
	packet := make([]byte, s.config.BufferSize)
	for {
		n, err := s.iFace.Read(packet)
		if err != nil {
			netutil.PrintErr(err, s.config.Verbose)
			break
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
				_, err := s.localConn.WriteToUDP(b, v.(*net.UDPAddr))
				if err != nil {
					s.connCache.Delete(key)
					continue
				}
				counter.IncrWrittenBytes(n)
			}
		}
	}
}

// udpToTun sends packets from udp to tun
func (s *Server) udpToTun() {
	packet := make([]byte, s.config.BufferSize)
	for {
		n, cliAddr, err := s.localConn.ReadFromUDP(packet)
		if err != nil || n == 0 {
			netutil.PrintErr(err, s.config.Verbose)
			continue
		}
		b := packet[:n]
		if s.config.Compress {
			b, err = snappy.Decode(nil, b)
			if err != nil {
				netutil.PrintErr(err, s.config.Verbose)
				continue
			}
		}
		if s.config.Obfs {
			b = cipher.XOR(b)
		}

		cidrIP, _, err := net.ParseCIDR(s.config.CIDR)
		if err != nil {
			netutil.PrintErr(err, s.config.Verbose)
			return
		}

		if dstKey := netutil.GetDstKey(b); dstKey != "" {
			// the package come from vtun udp client in-code ping operation
			if dstKey == "0.0.0.0" {
				srcKey := netutil.GetSrcKey(b)
				s.connCache.Set(srcKey, cliAddr, 24*time.Hour)
				continue
			}

			// the package come from vtun udp client, send to this vtun udp server
			if dstKey == cidrIP.String() {
				if key := netutil.GetSrcKey(b); key != "" {
					s.iFace.Write(b)
					s.connCache.Set(key, cliAddr, 24*time.Hour)
					counter.IncrReadBytes(n)
				}
				continue
			}

			// the package come from vtun udp client, send to another client
			if v, ok := s.connCache.Get(dstKey); ok {
				_, err := s.localConn.WriteToUDP(b, v.(*net.UDPAddr))
				if err != nil {
					s.connCache.Delete(dstKey)
					continue
				}
				counter.IncrWrittenBytes(n)
			}
		}
	}
}
