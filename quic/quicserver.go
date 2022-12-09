package quic

import (
	"context"
	"crypto/tls"
	"github.com/golang/snappy"
	"github.com/lucas-clemente/quic-go"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
	"io"
	"log"
	"time"
)

// StartServer starts the quic server
func StartServer(iface *water.Interface, config config.Config) {
	log.Printf("start quic server started on %v", config.LocalAddr)
	tlsCert, err := tls.LoadX509KeyPair(config.TLSCertificateFilePath, config.TLSCertificateKeyFilePath)
	if err != nil {
		log.Panic(err)
	}
	var tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"vtun"},
	}
	listener, err := quic.ListenAddr(config.LocalAddr, tlsConfig, nil)
	if err != nil {
		log.Panic(err)
	}
	//server -> client
	go toClient(config, iface)
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			continue
		}
		go func() {
			for {
				stream, err := conn.AcceptStream(context.Background())
				if err != nil {
					netutil.PrintErr(err, config.Verbose)
					return
				}
				//client -> server
				toServer(config, stream, iface)
			}
		}()
	}
}

// toClient sends packets from iface to quicconn
func toClient(config config.Config, iFace *water.Interface) {
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	for {
		shn, err := iFace.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		shb[0] = byte(shn >> 8 & 0xff)
		shb[1] = byte(shn & 0xff)
		b := packet[:shn]
		if key := netutil.GetDstKey(b); key != "" {
			if v, ok := cache.GetCache().Get(key); ok {
				if config.Obfs {
					b = cipher.XOR(b)
				}
				if config.Compress {
					b = snappy.Encode(nil, b)
				}
				stream := v.(quic.Stream)
				b = append(shb, b...)
				n, err := stream.Write(b)
				if err != nil {
					netutil.PrintErr(err, config.Verbose)
					break
				}
				counter.IncrWrittenBytes(n)
			}
		}
	}
}

// toServer sends packets from quicConn to iface
func toServer(config config.Config, stream quic.Stream, iface *water.Interface) {
	var packet []byte
	shb := make([]byte, 2)
	for {
		n, err := stream.Read(shb)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if n < 2 {
			continue
		}
		shn := 0
		shn = ((shn & 0x00) | int(shb[0])) << 8
		shn = shn | int(shb[1])
		packet = make([]byte, shn)
		n, err = stream.Read(packet)
		if err == io.EOF || err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		b := packet[:n]
		if config.Compress {
			b, err = snappy.Decode(nil, b)
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				break
			}
		}
		if config.Obfs {
			b = cipher.XOR(b)
		}
		if key := netutil.GetSrcKey(b); key != "" {
			cache.GetCache().Set(key, stream, 24*time.Hour)
			n, err = iface.Write(b)
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				break
			}
			counter.IncrReadBytes(n)
		}
	}
}
