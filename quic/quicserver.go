package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/common/xproto"
	"github.com/net-byte/water"
	"github.com/quic-go/quic-go"
	"log"
	"time"
)

// StartServer starts the quic server
func StartServer(iFace *water.Interface, config config.Config) {
	log.Printf("vtun quic server started on %v", config.LocalAddr)
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
	go toClient(config, iFace)
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		go func() {
			for {
				stream, err := conn.AcceptStream(context.Background())
				if err != nil {
					netutil.PrintErr(err, config.Verbose)
					break
				}
				//client -> server
				toServer(config, stream, iFace)
			}
			err := conn.CloseWithError(quic.ApplicationErrorCode(0x01), "closed")
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				return
			}
		}()
	}
}

// toClient sends packets from iFace to quic
func toClient(config config.Config, iFace *water.Interface) {
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	for {
		shn, err := iFace.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		xproto.WriteLength(shb, shn)
		b := packet[:shn]
		if key := netutil.GetDstKey(b); key != "" {
			if v, ok := cache.GetCache().Get(key); ok {
				if config.Obfs {
					b = cipher.XOR(b)
				}
				if config.Compress {
					b = snappy.Encode(nil, b)
				}
				copy(packet[len(shb):len(shb)+len(b)], b)
				copy(packet[:len(shb)], shb)
				stream := v.(quic.Stream)
				n, err := stream.Write(packet[:len(shb)+len(b)])
				if err != nil {
					cache.GetCache().Delete(key)
					netutil.PrintErr(err, config.Verbose)
					continue
				}
				counter.IncrWrittenBytes(n)
			}
		}
	}
}

// toServer sends packets from quic to iFace
func toServer(config config.Config, stream quic.Stream, iFace *water.Interface) {
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	defer stream.Close()
	for {
		n, err := stream.Read(shb)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if n < 2 {
			break
		}
		shn := xproto.ReadLength(shb)
		count, err := splitRead(stream, shn, packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if count != shn || count <= 0 {
			netutil.PrintErr(errors.New("count read error"), config.Verbose)
			break
		}
		b := packet[:count]
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
			n, err = iFace.Write(b)
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				break
			}
			counter.IncrReadBytes(n)
		}
	}
}
