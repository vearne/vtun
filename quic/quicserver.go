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

// StartServer starts the quic server
func StartServer(iFace *water.Interface, config config.Config) {
	log.Printf("vtun quic server started on %v", config.LocalAddr)
	tlsCert, err := tls.LoadX509KeyPair(config.TLSCertificateFilePath, config.TLSCertificateKeyFilePath)
	if err != nil {
		log.Panic(err)
	}
	var tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"vtun"},
	}
	listener, err := quic.ListenAddr(config.LocalAddr, tlsConfig, nil)
	if err != nil {
		log.Panic(err)
	}
	//server -> client
	go toClient(config, iFace)
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		go func() {
			for {
				stream, err := conn.AcceptStream(context.Background())
				if err != nil {
					netutil.PrintErr(err, config.Verbose)
					break
				}
				//client -> server
				toServer(config, stream, iFace)
			}
			err := conn.CloseWithError(quic.ApplicationErrorCode(0x01), "closed")
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				return
			}
		}()
	}
}

// toClient sends packets from iFace to quic
func toClient(config config.Config, iFace *water.Interface) {
	buffer := make([]byte, config.BufferSize)
	for {
		n, err := iFace.Read(buffer)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		b := buffer[:n]
		if key := netutil.GetDstKey(b); key != "" {
			if v, ok := cache.GetCache().Get(key); ok {
				if config.Obfs {
					b = cipher.XOR(b)
				}
				if config.Compress {
					b = snappy.Encode(nil, b)
				}
				ph := &xproto.ServerSendPacketHeader{
					ProtocolVersion: xproto.ProtocolVersion,
					Length:          len(b),
				}
				stream := v.(quic.Stream)
				_, err := stream.Write(ph.Bytes())
				if err != nil {
					netutil.PrintErr(err, config.Verbose)
					cache.GetCache().Delete(key)
					stream.Close()
					continue
				}
				n, err := stream.Write(b[:])
				if err != nil {
					netutil.PrintErr(err, config.Verbose)
					cache.GetCache().Delete(key)
					stream.Close()
					continue
				}
				counter.IncrWrittenBytes(n)
			}
		}
	}
}

// toServer sends packets from quic to iFace
func toServer(config config.Config, stream quic.Stream, iFace *water.Interface) {
	defer stream.Close()
	handshake := make([]byte, xproto.ClientHandshakePacketLength)
	header := make([]byte, xproto.ClientSendPacketHeaderLength)
	packet := make([]byte, config.BufferSize)
	authKey := xproto.ParseAuthKeyFromString(config.Key)
	n, err := stream.Read(handshake)
	if err != nil {
		netutil.PrintErr(err, config.Verbose)
		return
	}
	if n != xproto.ClientHandshakePacketLength {
		netutil.PrintErr(errors.New(fmt.Sprintf("received handshake length <%d> not equals <%d>!", n, xproto.ClientHandshakePacketLength)), config.Verbose)
		return
	}
	hs := xproto.ParseClientHandshakePacket(handshake[:n])
	if hs == nil {
		netutil.PrintErr(errors.New("hs == nil"), config.Verbose)
		return
	}
	if !hs.Key.Equals(authKey) {
		netutil.PrintErr(errors.New("authentication failed"), config.Verbose)
		return
	}
	cache.GetCache().Set(hs.CIDRv4.String(), stream, 24*time.Hour)
	cache.GetCache().Set(hs.CIDRv6.String(), stream, 24*time.Hour)
	for {
		n, err := stream.Read(header)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if n != xproto.ClientSendPacketHeaderLength {
			netutil.PrintErr(errors.New(fmt.Sprintf("received length <%d> not equals <%d>!", n, xproto.ClientSendPacketHeaderLength)), config.Verbose)
			break
		}
		ph := xproto.ParseClientSendPacketHeader(header[:n])
		if ph == nil {
			netutil.PrintErr(errors.New("ph == nil"), config.Verbose)
			break
		}
		if !ph.Key.Equals(authKey) {
			netutil.PrintErr(errors.New("authentication failed"), config.Verbose)
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
		counter.IncrReadBytes(n)
	}
}
