package tcp

import (
	"errors"
	"fmt"
	"github.com/net-byte/vtun/common/xcrypto"
	"github.com/net-byte/vtun/common/xproto"
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

// StartClient starts the tcp client
func StartClient(iFace *water.Interface, config config.Config) {
	log.Println("vtun h1 client started")
	go tunToTcp(config, iFace)
	for {
		conn, err := net.Dial("tcp", config.ServerAddr)
		if err != nil {
			time.Sleep(3 * time.Second)
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		err = handshake(config, conn)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		cache.GetCache().Set("conn", conn, 24*time.Hour)
		tcpToTun(config, conn, iFace)
		cache.GetCache().Delete("conn")
	}
}

func handshake(config config.Config, conn net.Conn) error {
	var obj *xproto.ClientHandshakePacket
	var err error
	if v, ok := cache.GetCache().Get("handshake"); ok {
		obj = v.(*xproto.ClientHandshakePacket)
	} else {
		obj, err = xproto.GenClientHandshakePacket(config)
		if err != nil {
			conn.Close()
			return err
		}
		cache.GetCache().Set("handshake", obj, 24*time.Hour)
	}

	_, err = conn.Write(obj.Bytes())
	if err != nil {
		conn.Close()
		return err
	}

	return nil
}

// tunToTcp sends packets from tun to tcp
func tunToTcp(config config.Config, iFace *water.Interface) {
	authKey := xproto.ParseAuthKeyFromString(config.Key)
	buffer := make([]byte, config.BufferSize)
	xp := &xcrypto.XCrypto{}
	err := xp.Init(config.Key)
	if err != nil {
		netutil.PrintErr(err, config.Verbose)
		return
	}
	for {
		n, err := iFace.Read(buffer)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		b := buffer[:n]
		if v, ok := cache.GetCache().Get("conn"); ok {
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
			conn := v.(net.Conn)
			ph := &xproto.ClientSendPacketHeader{
				ProtocolVersion: xproto.ProtocolVersion,
				Key:             authKey,
				Length:          len(b),
			}
			_, err := conn.Write(ph.Bytes())
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
			counter.IncrWrittenBytes(n)
		}
	}
}

// tcpToTun sends packets from tcp to tun
func tcpToTun(config config.Config, conn net.Conn, iFace *water.Interface) {
	defer conn.Close()
	header := make([]byte, xproto.ServerSendPacketHeaderLength)
	packet := make([]byte, config.BufferSize)
	xp := &xcrypto.XCrypto{}
	err := xp.Init(config.Key)
	if err != nil {
		netutil.PrintErr(err, config.Verbose)
		return
	}
	for {
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
		n, err = iFace.Write(b)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		counter.IncrReadBytes(n)
	}
}
