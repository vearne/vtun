package h1

import (
	"context"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/xtun"
	"github.com/net-byte/vtun/transport/protocol/tcp"
	"log"
	"time"

	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
)

var _ctx context.Context
var cancel context.CancelFunc

func StartClientForApi(config config.Config, outputStream <-chan []byte, inputStream chan<- []byte, writeCallback, readCallback func(int), _ctx context.Context) {
	var cl *Client
	tcA := RandomStringByStringNonce(16, config.Key, 123)
	tcB := RandomStringByStringNonce(32, config.Key, 456)
	tcC := RandomStringByStringNonce(64, config.Key, 789)
	ua := RandomUserAgent(config.Key)
	if config.Protocol == "https" {
		cl = NewTLSClient(config)
	} else {
		cl = NewClient(config.ServerAddr, config.Host)
	}
	cl.TokenCookieA = tcA
	cl.TokenCookieB = tcB
	cl.TokenCookieC = tcC
	cl.Path = "/" + RandomStringByInt64(32, time.Now().UnixMilli())
	cl.UserAgent = ua
	go tcp.Tun2Conn(config, outputStream, _ctx, readCallback)
	for xtun.ContextOpened(_ctx) {
		conn, err := cl.Dial()
		if err != nil {
			time.Sleep(3 * time.Second)
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		err = tcp.Handshake(config, conn)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		cache.GetCache().Set(tcp.ConnTag, conn, 24*time.Hour)
		tcp.Conn2Tun(config, conn, inputStream, _ctx, writeCallback)
		cache.GetCache().Delete(tcp.ConnTag)
	}
}

// StartClient starts the h1 client
func StartClient(iFace *water.Interface, config config.Config) {
	log.Println("vtun h1 client started")
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
