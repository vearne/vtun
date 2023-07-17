package quic

import (
	"context"
	"crypto/tls"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/xproto"
	"github.com/net-byte/vtun/common/xtun"
	"log"
	"time"

	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
	"github.com/quic-go/quic-go"
)

const ConnTag = "stream"

var _ctx context.Context
var cancel context.CancelFunc

func StartClientForApi(config config.Config, outputStream <-chan []byte, inputStream chan<- []byte, writeCallback, readCallback func(int), _ctx context.Context) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.TLSInsecureSkipVerify,
		NextProtos:         []string{"vtun"},
	}
	if config.TLSSni != "" {
		tlsConfig.ServerName = config.TLSSni
	}
	go tunToStream(config, outputStream, _ctx, writeCallback)
	for xtun.ContextOpened(_ctx) {
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
		cache.GetCache().Set(ConnTag, stream, 24*time.Hour)
		streamToTun(config, stream, inputStream, _ctx, readCallback)
		cache.GetCache().Delete(ConnTag)
	}
}

// StartClient starts the quic client
func StartClient(iFace *water.Interface, config config.Config) {
	log.Println("vtun quic client started")
	_ctx, cancel = context.WithCancel(context.Background())
	outputStream := make(chan []byte)
	go xtun.ReadFromTun(iFace, config, outputStream, _ctx)
	inputStream := make(chan []byte)
	go xtun.WriteToTun(iFace, config, inputStream, _ctx)
	StartClientForApi(
		config, outputStream, inputStream,
		func(n int) { counter.IncrWrittenBytes(n) },
		func(n int) { counter.IncrReadBytes(n) },
		_ctx,
	)
}

// tunToStream sends packets from tun to quic
func tunToStream(config config.Config, outputStream <-chan []byte, _ctx context.Context, callback func(int)) {
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	for xtun.ContextOpened(_ctx) {
		b := <-outputStream
		n := len(b)
		if config.Obfs {
			b = cipher.XOR(b)
		}
		if config.Compress {
			b = snappy.Encode(nil, b)
		}
		xproto.WriteLength(shb, n)
		copy(packet[len(shb):len(shb)+n], b)
		copy(packet[:len(shb)], shb)
		if v, ok := cache.GetCache().Get(ConnTag); ok {
			session := v.(quic.Stream)
			n, err := session.Write(packet[:len(shb)+n])
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			callback(len(shb) + n)
		}
	}
}

// streamToTun sends packets from quic to tun
func streamToTun(config config.Config, stream quic.Stream, inputStream chan<- []byte, _ctx context.Context, callback func(int)) {
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	defer stream.Close()
	for xtun.ContextOpened(_ctx) {
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
		inputStream <- b[:]
		callback(n)
	}
}

func Close() {
	cancel()
}
