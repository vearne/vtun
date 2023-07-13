package kcp

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"github.com/net-byte/vtun/common/xproto"
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

func StartClient(iFace *water.Interface, config config.Config) {
	log.Println("vtun kcp client started")
	key := pbkdf2.Key([]byte(config.Key), []byte("default_salt"), 1024, 32, sha1.New)
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		netutil.PrintErr(err, config.Verbose)
		return
	}
	go tunToKcp(config, iFace)
	for {
		if session, err := kcp.DialWithOptions(config.ServerAddr, block, 10, 3); err == nil {
			go CheckKCPSessionAlive(session, config)
			err = handshake(config, session)
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			cache.GetCache().Set("kcpConn", session, 24*time.Hour)
			kcpToTun(config, session, iFace)
			cache.GetCache().Delete("kcpConn")
		} else {
			netutil.PrintErr(err, config.Verbose)
			time.Sleep(3 * time.Second)
			continue
		}
	}
}

func handshake(config config.Config, session *kcp.UDPSession) error {
	var obj *xproto.ClientHandshakePacket
	var err error
	if v, ok := cache.GetCache().Get("handshake"); ok {
		obj = v.(*xproto.ClientHandshakePacket)
	} else {
		obj, err = xproto.GenClientHandshakePacket(config)
		if err != nil {
			session.Close()
			return err
		}
		cache.GetCache().Set("handshake", obj, 24*time.Hour)
	}

	_, err = session.Write(obj.Bytes())
	if err != nil {
		session.Close()
		return err
	}

	return nil
}

func tunToKcp(config config.Config, iFace *water.Interface) {
	authKey := xproto.ParseAuthKeyFromString(config.Key)
	buffer := make([]byte, config.BufferSize)
	for {
		n, err := iFace.Read(buffer)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		b := buffer[:n]
		if v, ok := cache.GetCache().Get("kcpConn"); ok {
			if config.Obfs {
				b = cipher.XOR(b)
			}
			if config.Compress {
				b = snappy.Encode(nil, b)
			}
			ph := &xproto.ClientSendPacketHeader{
				ProtocolVersion: xproto.ProtocolVersion,
				Key:             authKey,
				Length:          len(b),
			}
			session := v.(*kcp.UDPSession)
			_, err = session.Write(ph.Bytes())
			if err != nil {
				session.Close()
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			n, err = session.Write(b[:])
			if err != nil {
				session.Close()
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			counter.IncrWrittenBytes(n)
		}
	}
}

func kcpToTun(config config.Config, session *kcp.UDPSession, iFace *water.Interface) {
	defer session.Close()
	header := make([]byte, xproto.ServerSendPacketHeaderLength)
	packet := make([]byte, config.BufferSize)
	for {
		n, err := session.Read(header)
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
