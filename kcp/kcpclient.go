package kcp

import (
	"context"
	"crypto/sha1"
	"errors"
	"github.com/net-byte/vtun/common/xproto"
	"github.com/net-byte/vtun/common/xtun"
	"log"
	"runtime"
	"strings"
	"time"

	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
)

const ConnTag = "stream"

var _ctx context.Context
var cancel context.CancelFunc

func StartClientForApi(config config.Config, outputStream <-chan []byte, inputStream chan<- []byte, writeCallback, readCallback func(int), _ctx context.Context) {
	key := pbkdf2.Key([]byte(config.Key), []byte("default_salt"), 1024, 32, sha1.New)
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		netutil.PrintErr(err, config.Verbose)
		return
	}
	go tunToKcp(config, outputStream, _ctx, writeCallback)
	for xtun.ContextOpened(_ctx) {
		if session, err := kcp.DialWithOptions(config.ServerAddr, block, 10, 3); err == nil {
			go CheckKCPSessionAlive(session, config)
			cache.GetCache().Set(ConnTag, session, 24*time.Hour)
			kcpToTun(config, session, inputStream, _ctx, readCallback)
			cache.GetCache().Delete(ConnTag)
		} else {
			netutil.PrintErr(err, config.Verbose)
			time.Sleep(3 * time.Second)
			continue
		}
	}
}

func StartClient(iFace *water.Interface, config config.Config) {
	log.Println("vtun kcp client started")
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

func tunToKcp(config config.Config, outputStream <-chan []byte, _ctx context.Context, callback func(int)) {
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
			session := v.(*kcp.UDPSession)
			n, err := session.Write(packet[:len(shb)+n])
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			callback(len(shb) + n)
		}
	}
}

func kcpToTun(config config.Config, session *kcp.UDPSession, inputStream chan<- []byte, _ctx context.Context, callback func(int)) {
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	defer session.Close()
	for xtun.ContextOpened(_ctx) {
		n, err := session.Read(shb)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if n < 2 {
			break
		}
		shn := xproto.ReadLength(shb)
		count, err := splitRead(session, shn, packet)
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

func CheckKCPSessionAlive(session *kcp.UDPSession, config config.Config) {
	os := runtime.GOOS
	for {
		time.Sleep(time.Duration(config.Timeout) * time.Second)

		if os == "windows" {
			result := netutil.ExecCmd("ping", "-n", "4", config.ServerIP)
			if strings.Contains(result, `100%`) {
				session.Close()
				netutil.PrintErr(errors.New("ping server failed, reconnecting"), config.Verbose)
				break
			}
			continue
		} else if os == "linux" || os == "darwin" {
			result := netutil.ExecCmd("ping", "-c", "4", config.ServerIP)
			// macos return "100.0% packet loss",  linux return "100% packet loss"
			if strings.Contains(result, `100.0%`) || strings.Contains(result, `100%`) {
				session.Close()
				netutil.PrintErr(errors.New("ping server failed, reconnecting"), config.Verbose)
				break
			}
			continue
		}

	}
}

func Close() {
	cancel()
}
