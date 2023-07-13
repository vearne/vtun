package h1

import (
	"errors"
	"fmt"
	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/common/xproto"
	"github.com/net-byte/water"
	"log"
	"net"
	"net/http"
	"time"
)

// StartServer starts the h1 server
func StartServer(iFace *water.Interface, config config.Config) {
	log.Printf("vtun h1 server started on %v", config.LocalAddr)
	websrv := NewHandle(http.NotFoundHandler())
	http.Handle("/", websrv)
	srv := &http.Server{Addr: config.LocalAddr, Handler: nil}
	go func(*http.Server) {
		err := srv.ListenAndServe()
		if err != nil {
			panic(err)
		}
	}(srv)
	// server -> client
	go toClient(config, iFace)
	// client -> server
	for {
		conn, err := websrv.Accept()
		if err != nil {
			continue
		}
		go toServer(config, conn, iFace)
	}
}

// toClient sends packets from iFace to conn
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
				conn := v.(net.Conn)
				_, err := conn.Write(ph.Bytes())
				if err != nil {
					netutil.PrintErr(err, config.Verbose)
					cache.GetCache().Delete(key)
					conn.Close()
					continue
				}
				n, err := conn.Write(b[:])
				if err != nil {
					netutil.PrintErr(err, config.Verbose)
					cache.GetCache().Delete(key)
					conn.Close()
					continue
				}
				counter.IncrWrittenBytes(n)
			}
		}
	}
}

// toServer sends packets from conn to iFace
func toServer(config config.Config, conn net.Conn, iFace *water.Interface) {
	defer conn.Close()
	handshake := make([]byte, xproto.ClientHandshakePacketLength)
	header := make([]byte, xproto.ClientSendPacketHeaderLength)
	packet := make([]byte, config.BufferSize)
	authKey := xproto.ParseAuthKeyFromString(config.Key)
	n, err := conn.Read(handshake)
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
	cache.GetCache().Set(hs.CIDRv4.String(), conn, 24*time.Hour)
	cache.GetCache().Set(hs.CIDRv6.String(), conn, 24*time.Hour)
	for {
		n, err := conn.Read(header)
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
