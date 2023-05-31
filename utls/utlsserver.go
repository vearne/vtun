package utls

import (
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
	utls "github.com/refraction-networking/utls"
)

// StartServer starts the utls server
func StartServer(iface *water.Interface, config config.Config) {
	log.Printf("vtun utls server started on %v", config.LocalAddr)
	cert, err := utls.LoadX509KeyPair(config.TLSCertificateFilePath, config.TLSCertificateKeyFilePath)
	if err != nil {
		log.Panic(err)
	}
	tlsConfig := &utls.Config{
		Certificates: []utls.Certificate{cert},
	}
	ln, err := utls.Listen("tcp", config.LocalAddr, tlsConfig)
	if err != nil {
		log.Panic(err)
	}
	// server -> client
	go toClient(config, iface)
	// client -> server
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		sniffConn := NewPeekPreDataConn(conn)
		switch sniffConn.Type {
		case TypeHttp:
			if sniffConn.Handle() {
				continue
			}
		case TypeHttp2:
			if sniffConn.Handle() {
				continue
			}
		}
		go toServer(config, sniffConn, iface)
	}
}

// toClient sends packets from iface to conn
func toClient(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.BufferSize)
	for {
		n, err := iface.Read(packet)
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
				_, err := v.(net.Conn).Write(b)
				if err != nil {
					cache.GetCache().Delete(key)
					continue
				}
				counter.IncrWrittenBytes(n)
			}
		}
	}
}

// toServer sends packets from conn to iface
func toServer(config config.Config, conn net.Conn, iface *water.Interface) {
	defer conn.Close()
	packet := make([]byte, config.BufferSize)
	for {
		n, err := conn.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
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
		if key := netutil.GetSrcKey(b); key != "" {
			cache.GetCache().Set(key, conn, 24*time.Hour)
			iface.Write(b)
			counter.IncrReadBytes(n)
		}
	}
}
