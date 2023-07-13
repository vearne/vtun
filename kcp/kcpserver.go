package kcp

import (
	"crypto/sha1"
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
	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
)

func StartServer(iFace *water.Interface, config config.Config) {
	log.Printf("vtun kcp server started on %v", config.LocalAddr)
	key := pbkdf2.Key([]byte(config.Key), []byte("default_salt"), 1024, 32, sha1.New)
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		netutil.PrintErr(err, config.Verbose)
		return
	}
	if listener, err := kcp.ListenWithOptions(config.LocalAddr, block, 10, 3); err == nil {
		go toClient(iFace, config)
		for {
			session, err := listener.AcceptKCP()
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			go toServer(iFace, session, config)
		}
	} else {
		log.Fatal(err)
	}
}

func toServer(iFace *water.Interface, session *kcp.UDPSession, config config.Config) {
	defer session.Close()
	handshake := make([]byte, xproto.ClientHandshakePacketLength)
	header := make([]byte, xproto.ClientSendPacketHeaderLength)
	packet := make([]byte, config.BufferSize)
	authKey := xproto.ParseAuthKeyFromString(config.Key)
	n, err := session.Read(handshake)
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
	cache.GetCache().Set(hs.CIDRv4.String(), session, 24*time.Hour)
	cache.GetCache().Set(hs.CIDRv6.String(), session, 24*time.Hour)
	for {
		n, err := session.Read(header)
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
		n, err = splitRead(session, ph.Length, packet[:ph.Length])
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

func toClient(iFace *water.Interface, config config.Config) {
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
				session := v.(*kcp.UDPSession)
				_, err := session.Write(ph.Bytes())
				if err != nil {
					cache.GetCache().Delete(key)
					netutil.PrintErr(err, config.Verbose)
					session.Close()
					continue
				}
				n, err := session.Write(b[:])
				if err != nil {
					cache.GetCache().Delete(key)
					netutil.PrintErr(err, config.Verbose)
					session.Close()
					continue
				}
				counter.IncrWrittenBytes(n)
			}
		}
	}
}
