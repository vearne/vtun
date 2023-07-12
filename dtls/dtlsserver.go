package dtls

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/net-byte/vtun/common/xproto"
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
	"github.com/pion/dtls/v2"
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
			continue
		}
		go toServer(config, conn, iFace)
	}
}

// toClient sends packets from iFace to conn
func toClient(config config.Config, iFace *water.Interface) {
	packet := make([]byte, config.BufferSize)
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
				ph := &xproto.ServerSendPacketHeader{
					ProtocolVersion: xproto.ProtocolVersion,
					Length:          len(b),
				}
				_, err := v.(net.Conn).Write(ph.Bytes())
				if err != nil {
					cache.GetCache().Delete(key)
					continue
				}
				n, err = v.(net.Conn).Write(b[:])
				if err != nil {
					cache.GetCache().Delete(key)
					continue
				}
				counter.IncrWrittenBytes(n)
			}
		}
	}
}

// toServer sends packets from conn to iFace
func toServer(config config.Config, conn net.Conn, iFace *water.Interface) {
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
		}
	}(conn)
	header := make([]byte, xproto.ClientSendPacketHeaderLength)
	packet := make([]byte, config.BufferSize)
	authKey := xproto.ParseAuthKeyFromString(config.Key)
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
		n, err = conn.Read(packet)
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
		if key := netutil.GetSrcKey(b); key != "" {
			cache.GetCache().Set(key, conn, 24*time.Hour)
			_, err := iFace.Write(b)
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				break
			}
			counter.IncrReadBytes(n)
		}
	}
}
