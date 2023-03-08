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

// StartClient starts the quic client
func StartClient(iface *water.Interface, config config.Config) {
	log.Println("vtun quic client started")
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.TLSInsecureSkipVerify,
		NextProtos:         []string{"vtun"},
	}
	if config.TLSSni != "" {
		tlsConfig.ServerName = config.TLSSni
	}
	go tunToQuic(config, iface)
	for {
		conn, err := quic.DialAddr(config.ServerAddr, tlsConfig, nil)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			time.Sleep(3 * time.Second)
			continue
		}
		stream, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			conn.CloseWithError(quic.ApplicationErrorCode(0x01), "closed")
			continue
		}
		cache.GetCache().Set("quicstream", stream, 24*time.Hour)
		quicToTun(config, stream, iface)
		cache.GetCache().Delete("quicstream")
	}
}

// tunToQuic sends packets from tun to quic
func tunToQuic(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	for {
		shn, err := iface.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		b := packet[:shn]
		if config.Obfs {
			b = cipher.XOR(b)
		}
		if config.Compress {
			b = snappy.Encode(nil, b)
		}
		shb[0] = byte(shn >> 8 & 0xff)
		shb[1] = byte(shn & 0xff)
		copy(packet[len(shb):len(shb)+len(b)], b)
		copy(packet[:len(shb)], shb)
		if v, ok := cache.GetCache().Get("quicstream"); ok {
			stream := v.(quic.Stream)
			n, err := stream.Write(packet[:len(shb)+len(b)])
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			counter.IncrWrittenBytes(n)
		}
	}
}

// quicToTun sends packets from quic to tun
func quicToTun(config config.Config, stream quic.Stream, iface *water.Interface) {
	defer stream.Close()
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
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
		n, err = iface.Write(b)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		counter.IncrReadBytes(n)
	}
}
