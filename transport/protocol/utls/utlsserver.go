package utls

import (
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/transport/protocol/tcp"
	"github.com/net-byte/vtun/transport/protocol/tls"
	"github.com/net-byte/water"
	utls "github.com/refraction-networking/utls"
	"log"
)

// StartServer starts the utls server
func StartServer(iFace *water.Interface, config config.Config) {
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
	go tcp.ToClient(config, iFace)
	// client -> server
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		sniffConn := tls.NewPeekPreDataConn(conn)
		switch sniffConn.Type {
		case tls.TypeHttp:
			if sniffConn.Handle() {
				continue
			}
		case tls.TypeHttp2:
			if sniffConn.Handle() {
				continue
			}
		}
		go tcp.ToServer(config, sniffConn, iFace)
	}
}
