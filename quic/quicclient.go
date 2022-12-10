package quic

import (
	"context"
	"crypto/tls"
	"github.com/golang/snappy"
	"github.com/lucas-clemente/quic-go"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
	"log"
)

// StartClient starts the quic client
func StartClient(iFace *water.Interface, config config.Config) {
	log.Println("vtun quic client started")
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.TLSInsecureSkipVerify,
		NextProtos:         []string{"vtun"},
	}
	if config.TLSSni != "" {
		tlsConfig.ServerName = config.TLSSni
	}
	for {
		conn, err := quic.DialAddr(config.ServerAddr, tlsConfig, nil)
		if err != nil {
			log.Panic(err)
		}
		stream, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		go tunToQuic(config, stream, iFace)
		quicToTun(config, stream, iFace)
	}
}

// tunToQuic sends packets from tun to quic
func tunToQuic(config config.Config, stream quic.Stream, iFace *water.Interface) {
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	for {
		shn, err := iFace.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
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
		b = append(shb, b...)
		n, err := stream.Write(b)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		counter.IncrWrittenBytes(n)
	}
}

// quicToTun sends packets from quic to tun
func quicToTun(config config.Config, stream quic.Stream, iFace *water.Interface) {
	var packet []byte
	var shb = make([]byte, 2)
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
		splitSize := 64
		var count = 0
		if shn < splitSize {
			n, err = stream.Read(packet)
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
				buffer := make([]byte, receiveSize)
				n, err = stream.Read(buffer)
				if err != nil {
					netutil.PrintErr(err, config.Verbose)
					break
				}
				copy(packet[count:count+n], buffer[:n])
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
		n, err = iFace.Write(b)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		counter.IncrReadBytes(n)
	}
}
