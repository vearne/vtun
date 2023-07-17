package kcp

import (
	"crypto/sha1"
	"errors"
	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/common/xproto"
	"github.com/net-byte/water"
	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
	"log"
	"time"
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
		shn := xproto.ReadLength(shb)
		count, err := splitRead(session, shn, packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if count != shn || count <= 0 {
			netutil.PrintErr(errors.New("count read error"), config.Verbose)
			break
		}
		b := packet[:count]
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
		if key := netutil.GetSrcKey(b); key != "" {
			cache.GetCache().Set(key, session, 24*time.Hour)
			n, err = iFace.Write(b)
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				break
			}
			counter.IncrReadBytes(n)
		}
	}
}

func toClient(iFace *water.Interface, config config.Config) {
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	for {
		shn, err := iFace.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		xproto.WriteLength(shb, shn)
		b := packet[:shn]
		if key := netutil.GetDstKey(b); key != "" {
			if v, ok := cache.GetCache().Get(key); ok {
				if config.Obfs {
					b = cipher.XOR(b)
				}
				if config.Compress {
					b = snappy.Encode(nil, b)
				}
				copy(packet[len(shb):len(shb)+len(b)], b)
				copy(packet[:len(shb)], shb)
				session := v.(*kcp.UDPSession)
				n, err := session.Write(packet[:len(shb)+len(b)])
				if err != nil {
					cache.GetCache().Delete(key)
					netutil.PrintErr(err, config.Verbose)
					continue
				}
				counter.IncrWrittenBytes(n)
			}
		}
	}
}
