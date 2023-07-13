package h1

import (
	"errors"
	"fmt"
	"github.com/net-byte/vtun/common/xproto"
	"log"
	"net"
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
)

// StartClient starts the h1 client
func StartClient(iFace *water.Interface, config config.Config) {
	log.Println("vtun h1 client started")
	go tunToH1(config, iFace)
	for {
		cl := NewClient(config.ServerAddr)
		conn, err := cl.Dial()
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
		//go checkH1SessionAlive(conn, config)
		cache.GetCache().Set("conn", conn, 24*time.Hour)
		h1ToTun(config, conn, iFace)
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

// tunToH1 sends packets from tun to tls
func tunToH1(config config.Config, iFace *water.Interface) {
	authKey := xproto.ParseAuthKeyFromString(config.Key)
	buffer := make([]byte, config.BufferSize)
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
			n, err = conn.Write(b[:])
			if err != nil {
				conn.Close()
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			counter.IncrWrittenBytes(n)
		}
	}
}

// h1ToTun sends packets from tls to tun
func h1ToTun(config config.Config, conn net.Conn, iFace *water.Interface) {
	defer conn.Close()
	header := make([]byte, xproto.ServerSendPacketHeaderLength)
	packet := make([]byte, config.BufferSize)
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

func checkH1SessionAlive(conn net.Conn, config config.Config) {
	os := runtime.GOOS
	defer conn.Close()
	for {
		if os == "windows" {
			result := netutil.ExecCmd("ping", "-n", "2", "-l", "21", "-w", "1200", config.ServerIP)
			if strings.Contains(result, `100%`) {
				netutil.PrintErr(errors.New("ping server failed, reconnecting"), config.Verbose)
				break
			}
			continue
		} else if os == "linux" || os == "darwin" {
			result := netutil.ExecCmd("ping", "-c", "2", "-s", "21", "-w", "1200", config.ServerIP)
			// macos return "100.0% packet loss",  linux return "100% packet loss"
			if strings.Contains(result, `100.0%`) || strings.Contains(result, `100%`) {
				netutil.PrintErr(errors.New("ping server failed, reconnecting"), config.Verbose)
				break
			}
			continue
		}
	}
}
