package tcp

import (
	"context"
	"errors"
	"fmt"
	"github.com/net-byte/vtun/common/xcrypto"
	"github.com/net-byte/vtun/common/xproto"
	"github.com/net-byte/vtun/common/xtun"
	"log"
	"net"
	"time"

	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
)

const ConnTag = "conn"
const HandshakeTag = "handshake"

var _ctx context.Context
var cancel context.CancelFunc

func StartClientForApi(config config.Config, outputStream <-chan []byte, inputStream chan<- []byte, writeCallback, readCallback func(int), _ctx context.Context) {
	go Tun2Conn(config, outputStream, _ctx, readCallback)
	for xtun.ContextOpened(_ctx) {
		conn, err := net.Dial("tcp", config.ServerAddr)
		if err != nil {
			time.Sleep(3 * time.Second)
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		err = Handshake(config, conn)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		cache.GetCache().Set(ConnTag, conn, 24*time.Hour)
		Conn2Tun(config, conn, inputStream, _ctx, writeCallback)
		cache.GetCache().Delete(ConnTag)
	}
}

// StartClient starts the tcp client
func StartClient(iFace *water.Interface, config config.Config) {
	log.Println("vtun tcp client started")
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

func Handshake(config config.Config, conn net.Conn) error {
	var obj *xproto.ClientHandshakePacket
	var err error
	if v, ok := cache.GetCache().Get(HandshakeTag); ok {
		obj = v.(*xproto.ClientHandshakePacket)
	} else {
		obj, err = xproto.GenClientHandshakePacket(config)
		if err != nil {
			conn.Close()
			return err
		}
		cache.GetCache().Set(HandshakeTag, obj, 24*time.Hour)
	}
	_, err = conn.Write(obj.Bytes())
	if err != nil {
		conn.Close()
		return err
	}

	return nil
}

// Tun2Conn sends packets from tun to conn
func Tun2Conn(config config.Config, outputStream <-chan []byte, _ctx context.Context, callback func(int)) {
	authKey := xproto.ParseAuthKeyFromString(config.Key)
	xp := &xcrypto.XCrypto{}
	err := xp.Init(config.Key)
	if err != nil {
		netutil.PrintErr(err, config.Verbose)
		return
	}
	for xtun.ContextOpened(_ctx) {
		b := <-outputStream
		if v, ok := cache.GetCache().Get(ConnTag); ok {
			if config.Obfs {
				b = cipher.XOR(b)
			}
			b, err = xp.Encode(b)
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				break
			}
			if config.Compress {
				b = snappy.Encode(nil, b)
			}
			ph := &xproto.ClientSendPacketHeader{
				ProtocolVersion: xproto.ProtocolVersion,
				Key:             authKey,
				Length:          len(b),
			}
			conn := v.(net.Conn)
			_, err = conn.Write(ph.Bytes())
			if err != nil {
				conn.Close()
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			n, err := conn.Write(b[:])
			if err != nil {
				conn.Close()
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			callback(n)
		}
	}
}

// Conn2Tun sends packets from conn to tun
func Conn2Tun(config config.Config, conn net.Conn, inputStream chan<- []byte, _ctx context.Context, callback func(int)) {
	defer conn.Close()
	header := make([]byte, xproto.ServerSendPacketHeaderLength)
	packet := make([]byte, config.BufferSize)
	xp := &xcrypto.XCrypto{}
	err := xp.Init(config.Key)
	if err != nil {
		netutil.PrintErr(err, config.Verbose)
		return
	}
	for xtun.ContextOpened(_ctx) {
		n, err := conn.Read(header)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if n != xproto.ServerSendPacketHeaderLength {
			netutil.PrintErr(errors.New(fmt.Sprintf("received length <%d> not equals <%d>!", n, xproto.ServerSendPacketHeaderLength)), config.Verbose)
			break
		}
		ph := xproto.ParseServerSendPacketHeader(header[:n])
		if ph == nil {
			netutil.PrintErr(errors.New("ph == nil"), config.Verbose)
			break
		}
		n, err = splitRead(conn, ph.Length, packet[:ph.Length])
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if n != ph.Length {
			netutil.PrintErr(errors.New(fmt.Sprintf("received length <%d> not equals <%d>!", n, ph.Length)), config.Verbose)
			break
		}
		b := packet[:n]
		if config.Compress {
			b, err = snappy.Decode(nil, b)
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				break
			}
		}
		b, err = xp.Decode(b)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if config.Obfs {
			b = cipher.XOR(b)
		}
		inputStream <- b[:]
		callback(xproto.ServerSendPacketHeaderLength + ph.Length)
	}
}

func Close() {
	cancel()
}
