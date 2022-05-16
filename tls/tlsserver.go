package tls

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"time"

	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/tun"
	"github.com/songgao/water"
)

//Start tls server
func StartServer(config config.Config) {
	log.Printf("vtun tls server started on %v", config.LocalAddr)
	iface := tun.CreateTun(config)
	cert, err := tls.LoadX509KeyPair(config.TLSCertificateFilePath, config.TLSCertificateKeyFilePath)
	if err != nil {
		log.Println(err)
		return
	}
	tlsconfig := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	ln, err := tls.Listen("tcp", config.LocalAddr, tlsconfig)
	if err != nil {
		log.Println(err)
		return
	}
	// server -> client
	go toClient(config, iface)
	// client -> server
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go toServer(config, conn, iface)
	}
}

func toClient(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.MTU)
	for {
		n, err := iface.Read(packet)
		if err != nil || err == io.EOF || n == 0 {
			continue
		}
		b := packet[:n]
		if key := netutil.GetDstKey(b); key != "" {
			if v, ok := cache.GetCache().Get(key); ok {
				if config.Obfs {
					b = cipher.XOR(b)
				}
				v.(net.Conn).Write(b)
			}
		}
	}
}

// todo fallback to http
func toServer(config config.Config, tlsconn net.Conn, iface *water.Interface) {
	defer tlsconn.Close()
	packet := make([]byte, config.MTU)
	for {
		tlsconn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
		n, err := tlsconn.Read(packet)
		if err != nil || err == io.EOF {
			break
		}
		b := packet[:n]
		if config.Obfs {
			b = cipher.XOR(b)
		}
		if key := netutil.GetSrcKey(b); key != "" {
			cache.GetCache().Set(key, tlsconn, 10*time.Minute)
			iface.Write(b)
		}
	}
}
