package kcp

import (
	"context"
	"crypto/sha1"
	"errors"
	"github.com/net-byte/vtun/common/x/xproto"
	"github.com/net-byte/vtun/common/x/xtun"
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
	key := pbkdf2.Key([]byte(config.Key), []byte(SALT), 4096, 32, sha1.New)
	block, err := kcp.NewAESBlockCrypt(key[:16])
	if err != nil {
		netutil.PrintErr(err, config.Verbose)
		return
	}
	go tunToKcp(config, outputStream, _ctx, writeCallback)
	for xtun.ContextOpened(_ctx) {
		if session, err := kcp.DialWithOptions(config.ServerAddr, block, 10, 3); err == nil {
			session.SetWindowSize(SndWnd, RcvWnd)
			session.SetACKNoDelay(false)
			session.SetStreamMode(true)
			if err := session.SetDSCP(DSCP); err != nil {
				netutil.PrintErr(err, config.Verbose)
				return
			}
			if err := session.SetReadBuffer(SockBuf); err != nil {
				netutil.PrintErr(err, config.Verbose)
				return
			}
			if err := session.SetWriteBuffer(SockBuf); err != nil {
				netutil.PrintErr(err, config.Verbose)
				return
			}
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
	header := make([]byte, xproto.HeaderLength)
	for xtun.ContextOpened(_ctx) {
		b := <-outputStream
		if v, ok := cache.GetCache().Get(ConnTag); ok {
			if config.Obfs {
				b = cipher.XOR(b)
			}
			if config.Compress {
				b = snappy.Encode(nil, b)
			}
			xproto.WriteLength(header, len(b))
			session := v.(*kcp.UDPSession)
			n, err := session.Write(xproto.Merge(header, b))
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			callback(len(b) + n)
		}
	}
}

func kcpToTun(config config.Config, session *kcp.UDPSession, inputStream chan<- []byte, _ctx context.Context, callback func(int)) {
	buffer := make([]byte, config.BufferSize)
	header := make([]byte, xproto.HeaderLength)
	defer session.Close()
	for xtun.ContextOpened(_ctx) {
		n, err := session.Read(header)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if n != xproto.HeaderLength {
			netutil.PrintErrF(config.Verbose, "n %d != header_length %d\n", n, xproto.HeaderLength)
			break
		}
		length := xproto.ReadLength(header)
		count, err := splitRead(session, length, buffer)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if count != length || count <= 0 {
			netutil.PrintErrF(config.Verbose, "count %d != length %d\n", count, length)
			break
		}
		b := buffer[:count]
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
		inputStream <- xproto.Copy(b)
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
