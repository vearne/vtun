package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/net-byte/vtun/common/xproto"
	"log"
	"time"

	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
	"github.com/quic-go/quic-go"
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
	go tunToQuic(config, iFace)
	for {
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
		err = handshake(config, stream)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		cache.GetCache().Set("quicStream", stream, 24*time.Hour)
		quicToTun(config, stream, iFace)
		cache.GetCache().Delete("quicStream")
	}
}

func handshake(config config.Config, stream quic.Stream) error {
	var obj *xproto.ClientHandshakePacket
	var err error
	if v, ok := cache.GetCache().Get("handshake"); ok {
		obj = v.(*xproto.ClientHandshakePacket)
	} else {
		obj, err = xproto.GenClientHandshakePacket(config)
		if err != nil {
			stream.Close()
			return err
		}
		cache.GetCache().Set("handshake", obj, 24*time.Hour)
	}

	_, err = stream.Write(obj.Bytes())
	if err != nil {
		stream.Close()
		return err
	}

	return nil
}

// tunToQuic sends packets from tun to quic
func tunToQuic(config config.Config, iFace *water.Interface) {
	authKey := xproto.ParseAuthKeyFromString(config.Key)
	buffer := make([]byte, config.BufferSize)
	for {
		n, err := iFace.Read(buffer)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		b := buffer[:n]
		if v, ok := cache.GetCache().Get("quicStream"); ok {
			if config.Obfs {
				b = cipher.XOR(b)
			}
			if config.Compress {
				b = snappy.Encode(nil, b)
			}
			stream := v.(quic.Stream)
			ph := &xproto.ClientSendPacketHeader{
				ProtocolVersion: xproto.ProtocolVersion,
				Key:             authKey,
				Length:          len(b),
			}
			_, err := stream.Write(ph.Bytes())
			if err != nil {
				stream.Close()
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			n, err := stream.Write(b[:])
			if err != nil {
				stream.Close()
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			counter.IncrWrittenBytes(n)
		}
	}
}

// quicToTun sends packets from quic to tun
func quicToTun(config config.Config, stream quic.Stream, iFace *water.Interface) {
	defer stream.Close()
	header := make([]byte, xproto.ServerSendPacketHeaderLength)
	packet := make([]byte, config.BufferSize)
	for {
		n, err := stream.Read(header)
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
		n, err = splitRead(stream, ph.Length, packet[:ph.Length])
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
		if config.Obfs {
			b = cipher.XOR(b)
		}
		n, err = iFace.Write(b)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
	}
}
