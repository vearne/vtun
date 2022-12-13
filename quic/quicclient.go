package quic

import (
	"context"
	"crypto/tls"
	"log"
	"sync"
	"time"

	"github.com/golang/snappy"
	"github.com/lucas-clemente/quic-go"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
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
	var wg sync.WaitGroup
	for {
		conn, err := quic.DialAddr(config.ServerAddr, tlsConfig, nil)
		if err != nil {
			log.Panic(err)
		}
		for {
			stream, err := conn.OpenStreamSync(context.Background())
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				break
			}
			go tunToQuic(config, stream, iFace, &wg)
			quicToTun(config, stream, iFace, &wg)
		}
		wg.Wait()
	}
}

// tunToQuic sends packets from tun to quic
func tunToQuic(config config.Config, stream quic.Stream, iFace *water.Interface, wg *sync.WaitGroup) {
	wg.Add(1)
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	defer func() {
		stream.Close()
		wg.Done()
	}()
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
		copy(packet[len(shb):len(shb)+len(b)], b)
		copy(packet[:len(shb)], shb)
		stream.SetWriteDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
		n, err := stream.Write(packet[:len(shb)+len(b)])
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		counter.IncrWrittenBytes(n)
	}
}

// quicToTun sends packets from quic to tun
func quicToTun(config config.Config, stream quic.Stream, iFace *water.Interface, wg *sync.WaitGroup) {
	wg.Add(1)
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	defer func() {
		stream.Close()
		wg.Done()
	}()
	for {
		stream.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
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
			stream.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
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
				stream.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
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
		n, err = iFace.Write(b)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		counter.IncrReadBytes(n)
	}
}
