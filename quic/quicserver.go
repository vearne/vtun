package quic

import (
	"context"
	"crypto/tls"
	"log"
	"time"

	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
	"github.com/quic-go/quic-go"
)

// StartServer starts the quic server
func StartServer(iface *water.Interface, config config.Config) {
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
	go toClient(config, iface)
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
				toServer(config, stream, iface)
			}
			conn.CloseWithError(quic.ApplicationErrorCode(0x01), "closed")
		}()
	}
}

// toClient sends packets from iface to quicconn
func toClient(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	for {
		shn, err := iface.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
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

// toServer sends packets from quicConn to iface
func toServer(config config.Config, stream quic.Stream, iface *water.Interface) {
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
		shn := 0
		shn = ((shn & 0x00) | int(shb[0])) << 8
		shn = shn | int(shb[1])
		splitSize := 99
		var count = 0
		if shn < splitSize {
			n, err = stream.Read(packet[:shn])
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				break
			}
			count = n
		} else {
			for count < shn {
				receiveSize := splitSize
				if shn-count < splitSize {
					receiveSize = shn - count
				}
				n, err = stream.Read(packet[count : count+receiveSize])
				if err != nil {
					netutil.PrintErr(err, config.Verbose)
					break
				}
				count += n
			}
		}
		b := packet[:shn]
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
