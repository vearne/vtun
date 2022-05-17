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
	"github.com/net-byte/vtun/tun"
	"github.com/songgao/water"
)

// Start quic client
func StartClient(config config.Config) {
	log.Printf("vtun quic client started on %v", config.LocalAddr)
	iface := tun.CreateTun(config)
	go tunToQuic(config, iface)
	for {
		tlsconfig := &tls.Config{
			InsecureSkipVerify: config.TLSInsecureSkipVerify,
			NextProtos:         []string{"vtun/1.0"},
		}
		if config.TLSSni != "" {
			tlsconfig.ServerName = config.TLSSni
		}
		quicConfig := &quic.Config{
			ConnectionIDLength:   12,
			HandshakeIdleTimeout: time.Second * 10,
			MaxIdleTimeout:       time.Second * 30,
			KeepAlive:            true,
		}
		session, err := quic.DialAddr(config.ServerAddr, tlsconfig, quicConfig)
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		stream, err := session.OpenStreamSync(context.Background())
		if err != nil {
			continue
		}
		cache.GetCache().Set("quicconn", stream, 24*time.Hour)
		quicToTun(config, stream, iface)
		cache.GetCache().Delete("quicconn")
	}
}

func tunToQuic(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.MTU)
	for {
		n, err := iface.Read(packet)
		if err != nil || n == 0 {
			continue
		}
		if v, ok := cache.GetCache().Get("quicconn"); ok {
			b := packet[:n]
			if config.Obfs {
				packet = cipher.XOR(packet)
			}
			stream := v.(quic.Stream)
			stream.SetWriteDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
			_, err = stream.Write(b)
			if err != nil {
				continue
			}
		}
	}
}

func quicToTun(config config.Config, stream quic.Stream, iface *water.Interface) {
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
		_, err = iface.Write(b)
		if err != nil {
			break
		}
	}
}
