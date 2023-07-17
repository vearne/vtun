package dtls

import (
	"context"
	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/xproto"
	"github.com/net-byte/vtun/common/xtun"
	"github.com/pion/dtls/v2"
	"log"
	"net"
	"time"

	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
)

const ConnTag = "conn"

var _ctx context.Context
var cancel context.CancelFunc

func StartClientForApi(config config.Config, outputStream <-chan []byte, inputStream chan<- []byte, writeCallback, readCallback func(int), _ctx context.Context) {
	var tlsConfig *dtls.Config
	if config.PSKMode {
		tlsConfig = &dtls.Config{
			PSK: func(bytes []byte) ([]byte, error) {
				return []byte{0x09, 0x46, 0x59, 0x02, 0x49}, nil
			},
			PSKIdentityHint:      []byte(config.Key),
			CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_GCM_SHA256, dtls.TLS_PSK_WITH_AES_128_CCM_8},
			ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		}
	} else {
		tlsConfig = &dtls.Config{
			ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
			InsecureSkipVerify:   config.TLSInsecureSkipVerify,
		}
		if config.TLSSni != "" {
			tlsConfig.ServerName = config.TLSSni
		}
	}
	go tun2Conn(config, outputStream, _ctx, readCallback)
	for xtun.ContextOpened(_ctx) {
		ctx, cancel := context.WithTimeout(_ctx, 30*time.Second)
		defer cancel()
		addr, err := net.ResolveUDPAddr("udp", config.ServerAddr)
		if err != nil {
			time.Sleep(3 * time.Second)
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		conn, err := dtls.DialWithContext(ctx, "udp", addr, tlsConfig)
		if err != nil {
			time.Sleep(3 * time.Second)
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		cache.GetCache().Set(ConnTag, conn, 24*time.Hour)
		conn2Tun(config, conn, inputStream, _ctx, writeCallback)
		cache.GetCache().Delete(ConnTag)
		conn.Close()
	}
}

// StartClient starts the dtls client
func StartClient(iFace *water.Interface, config config.Config) {
	log.Println("vtun dtls client started")
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

// tun2Conn sends packets from tun to conn
func tun2Conn(config config.Config, outputStream <-chan []byte, _ctx context.Context, callback func(int)) {
	for xtun.ContextOpened(_ctx) {
		b := <-outputStream
		if v, ok := cache.GetCache().Get(ConnTag); ok {
			if config.Obfs {
				b = cipher.XOR(b)
			}
			if config.Compress {
				b = snappy.Encode(nil, b)
			}
			conn := v.(*dtls.Conn)
			n, err := conn.Write(xproto.Copy(b))
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			callback(n)
		}
	}
}

// conn2Tun sends packets from conn to tun
func conn2Tun(config config.Config, conn *dtls.Conn, inputStream chan<- []byte, _ctx context.Context, callback func(int)) {
	defer conn.Close()
	buffer := make([]byte, config.BufferSize)
	for xtun.ContextOpened(_ctx) {
		count, err := conn.Read(buffer)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
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
		callback(len(b))
	}
}

func Close() {
	cancel()
}
