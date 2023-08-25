package kcp

import (
	"crypto/sha1"
	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/common/x/xproto"
	"github.com/net-byte/water"
	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
	"log"
	"time"
)

func StartServer(iFace *water.Interface, config config.Config) {
	log.Printf("vtun kcp server started on %v", config.LocalAddr)
	key := pbkdf2.Key([]byte(config.Key), []byte(SALT), 4096, 32, sha1.New)
	block, err := kcp.NewAESBlockCrypt(key[:16])
	if err != nil {
		netutil.PrintErr(err, config.Verbose)
		return
	}
	if listener, err := kcp.ListenWithOptions(config.LocalAddr, block, 10, 3); err == nil {
		if err := listener.SetDSCP(DSCP); err != nil {
			netutil.PrintErr(err, config.Verbose)
			return
		}
		if err := listener.SetReadBuffer(SockBuf); err != nil {
			netutil.PrintErr(err, config.Verbose)
			return
		}
		if err := listener.SetWriteBuffer(SockBuf); err != nil {
			netutil.PrintErr(err, config.Verbose)
			return
		}
		go toClient(iFace, config)
		for {
			session, err := listener.AcceptKCP()
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			session.SetWindowSize(SndWnd, RcvWnd)
			session.SetACKNoDelay(false)
			session.SetStreamMode(true)
			go toServer(iFace, session, config)
		}
	} else {
		log.Fatal(err)
	}
}

func toServer(iFace *water.Interface, session *kcp.UDPSession, config config.Config) {
	packet := make([]byte, config.BufferSize)
	header := make([]byte, xproto.HeaderLength)
	defer session.Close()
	for {
		n, err := session.Read(header)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if n < xproto.HeaderLength {
			netutil.PrintErrF(config.Verbose, "%d < header_length %d\n", n, xproto.HeaderLength)
			break
		}
		length := xproto.ReadLength(header)
		count, err := splitRead(session, length, packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if count != length || count <= 0 {
			netutil.PrintErrF(config.Verbose, "count %d != length %d\n", count, length)
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
	header := make([]byte, xproto.HeaderLength)
	for {
		n, err := iFace.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		b := packet[:n]
		if key := netutil.GetDstKey(b); key != "" {
			if v, ok := cache.GetCache().Get(key); ok {
				if config.Obfs {
					b = cipher.XOR(b)
				}
				if config.Compress {
					b = snappy.Encode(nil, b)
				}
				xproto.WriteLength(header, len(b))
				session := v.(*kcp.UDPSession)
				n, err = session.Write(xproto.Merge(header, b))
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
