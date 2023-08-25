package utls

import (
	"context"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/x/xtun"
	"github.com/net-byte/vtun/transport/protocol/tcp"
	utls "github.com/refraction-networking/utls"
	"log"
	"net"
	"time"

	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
)

var _ctx context.Context
var cancel context.CancelFunc

func StartClientForApi(config config.Config, outputStream <-chan []byte, inputStream chan<- []byte, writeCallback, readCallback func(int), _ctx context.Context) {
	tlsConfig := &utls.Config{
		InsecureSkipVerify: config.TLSInsecureSkipVerify,
	}
	if config.TLSSni != "" {
		tlsConfig.ServerName = config.TLSSni
	}
	go tcp.Tun2Conn(config, outputStream, _ctx, readCallback)
	for xtun.ContextOpened(_ctx) {
		tcpConn, err := net.Dial("tcp", config.ServerAddr)
		if err != nil {
			time.Sleep(3 * time.Second)
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		conn := utls.UClient(tcpConn, tlsConfig, utls.HelloRandomized)
		err = conn.Handshake()
		if err != nil {
			time.Sleep(3 * time.Second)
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		err = tcp.Handshake(config, conn)
		if err != nil {
			time.Sleep(3 * time.Second)
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		cache.GetCache().Set(tcp.ConnTag, conn, 24*time.Hour)
		tcp.Conn2Tun(config, conn, inputStream, _ctx, writeCallback)
		cache.GetCache().Delete(tcp.ConnTag)
	}
}

// StartClient starts the utls client
func StartClient(iFace *water.Interface, config config.Config) {
	log.Println("vtun utls client started")
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

func Close() {
	cancel()
}
