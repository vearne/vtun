package kcp

import (
	"crypto/sha1"
	"errors"
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

func StartClient(iface *water.Interface, config config.Config) {
	log.Println("vtun kcp client started")
	key := pbkdf2.Key([]byte(config.Key), []byte("default_salt"), 1024, 32, sha1.New)
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		netutil.PrintErr(err, config.Verbose)
		return
	}
	go tunToKcp(config, iface)
	for {
		if session, err := kcp.DialWithOptions(config.ServerAddr, block, 10, 3); err == nil {
			go CheckKCPSessionAlive(session, config)
			cache.GetCache().Set("kcpconn", session, 24*time.Hour)
			kcpToTun(config, session, iface)
			cache.GetCache().Delete("kcpconn")
		} else {
			netutil.PrintErr(err, config.Verbose)
			time.Sleep(3 * time.Second)
			continue
		}
	}
}

func tunToKcp(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	for {
		shn, err := iface.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		b := packet[:shn]
		if config.Obfs {
			b = cipher.XOR(b)
		}
		if config.Compress {
			b = snappy.Encode(nil, b)
		}
		shb[0] = byte(shn >> 8 & 0xff)
		shb[1] = byte(shn & 0xff)
		copy(packet[len(shb):len(shb)+len(b)], b)
		copy(packet[:len(shb)], shb)
		if v, ok := cache.GetCache().Get("kcpconn"); ok {
			session := v.(*kcp.UDPSession)
			n, err := session.Write(packet[:len(shb)+len(b)])
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			counter.IncrWrittenBytes(n)
		}
	}
}

func kcpToTun(config config.Config, session *kcp.UDPSession, iface *water.Interface) {
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	defer session.Close()
	for {
		n, err := session.Read(shb)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if n < 2 {
			break
		}
		shn := 0
		shn = ((shn & 0x00) | int(shb[0])) << 8
		shn = shn | int(shb[1])
		splitSize := 99
		var count = 0
		if shn < splitSize {
			n, err = session.Read(packet[:shn])
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				break
			}
			count = n
		} else {
			for count < shn {
				receiveSize := splitSize
				if shn-count < splitSize {
					receiveSize = shn - count
				}
				n, err = session.Read(packet[count : count+receiveSize])
				if err != nil {
					netutil.PrintErr(err, config.Verbose)
					break
				}
				count += n
			}
		}
		b := packet[:shn]
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
		n, err = iface.Write(b)
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
