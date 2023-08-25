package tls

import (
	"context"
	"crypto/tls"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/common/xtun"
	"github.com/net-byte/vtun/transport/protocol/tcp"
	"github.com/net-byte/water"
	"log"
	"time"
)

var _ctx context.Context
var cancel context.CancelFunc

func StartClientForApi(config config.Config, outputStream <-chan []byte, inputStream chan<- []byte, writeCallback, readCallback func(int), _ctx context.Context) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.TLSInsecureSkipVerify,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
	}
	if config.TLSSni != "" {
		tlsConfig.ServerName = config.TLSSni
	}
	go tcp.Tun2Conn(config, outputStream, _ctx, readCallback)
	for xtun.ContextOpened(_ctx) {
		conn, err := tls.Dial("tcp", config.ServerAddr, tlsConfig)
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

// StartClient starts the tls client
func StartClient(iFace *water.Interface, config config.Config) {
	log.Println("vtun tls client started")
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
