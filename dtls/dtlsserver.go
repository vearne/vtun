package dtls

import (
	"crypto/tls"
	"errors"
	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/common/xproto"
	"github.com/net-byte/water"
	"github.com/pion/dtls/v2"
	"log"
	"net"
	"time"
)

// StartServer starts the dtls server
func StartServer(iFace *water.Interface, config config.Config) {
	log.Printf("vtun dtls server started on %v", config.LocalAddr)
	var tlsConfig *dtls.Config
	if config.PSKMode {
		tlsConfig = &dtls.Config{
			PSK: func(bytes []byte) ([]byte, error) {
				return []byte{0x09, 0x46, 0x59, 0x02, 0x49}, nil
			},
			PSKIdentityHint:      []byte(config.Key),
			CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_GCM_SHA256, dtls.TLS_PSK_WITH_AES_128_CCM_8},
			ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		}
	} else {
		certificate, err := tls.LoadX509KeyPair(config.TLSCertificateFilePath, config.TLSCertificateKeyFilePath)
		if err != nil {
			log.Panic(err)
		}
		tlsConfig = &dtls.Config{
			Certificates:         []tls.Certificate{certificate},
			ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
			ClientAuth:           dtls.NoClientCert,
		}
	}
	addr, err := net.ResolveUDPAddr("udp", config.LocalAddr)
	if err != nil {
		log.Panic(err)
	}
	ln, err := dtls.Listen("udp", addr, tlsConfig)
	if err != nil {
		log.Panic(err)
	}
	// server -> client
	go toClient(config, iFace)
	// client -> server
	for {
		conn, err := ln.Accept()
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		go toServer(config, conn, iFace)
	}
}

// toClient sends packets from iFace to dtls
func toClient(config config.Config, iFace *water.Interface) {
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
				conn := v.(*dtls.Conn)
				n, err := conn.Write(packet[:len(shb)+len(b)])
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

// toServer sends packets from dtls to iFace
func toServer(config config.Config, conn net.Conn, iFace *water.Interface) {
	packet := make([]byte, config.BufferSize)
	shb := make([]byte, 2)
	defer conn.Close()
	for {
		n, err := conn.Read(shb)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if n < 2 {
			break
		}
		shn := xproto.ReadLength(shb)
		count, err := splitRead(conn, shn, packet)
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
			cache.GetCache().Set(key, conn, 24*time.Hour)
			n, err = iFace.Write(b)
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				break
			}
			counter.IncrReadBytes(n)
		}
	}
}
