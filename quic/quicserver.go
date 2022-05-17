package quic

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/tun"
	"github.com/songgao/water"
)

//Start quic server
func StartServer(config config.Config) {
	log.Printf("vtun quic server started on %v", config.LocalAddr)
	iface := tun.CreateTun(config)
	cert, err := tls.LoadX509KeyPair(config.TLSCertificateFilePath, config.TLSCertificateKeyFilePath)
	if err != nil {
		log.Panic(err)
	}
	tlsconfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"vtun/1.0"},
	}
	l, err := quic.ListenAddr(config.LocalAddr, tlsconfig, nil)
	if err != nil {
		log.Panic(err)
	}
	// server -> client
	go toClient(config, iface)
	// client -> server
	for {
		session, err := l.Accept(context.Background())
		if err != nil {
			continue
		}
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			continue
		}
		go toServer(config, stream, iface)
	}
}

func toClient(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.MTU)
	for {
		n, err := iface.Read(packet)
		if err != nil || err == io.EOF || n == 0 {
			continue
		}
		b := packet[:n]
		if key := netutil.GetDstKey(b); key != "" {
			if v, ok := cache.GetCache().Get(key); ok {
				if config.Obfs {
					b = cipher.XOR(b)
				}
				v.(quic.Stream).Write(b)
			}
		}
	}
}

func toServer(config config.Config, stream quic.Stream, iface *water.Interface) {
	defer stream.Close()
	packet := make([]byte, config.MTU)
	for {
		stream.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
		n, err := stream.Read(packet)
		if err != nil || err == io.EOF {
			break
		}
		b := packet[:n]
		if config.Obfs {
			b = cipher.XOR(b)
		}
		if key := netutil.GetSrcKey(b); key != "" {
			cache.GetCache().Set(key, stream, 10*time.Minute)
			iface.Write(b)
		}
	}
}
