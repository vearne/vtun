package h1

import (
	"crypto/tls"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/transport/protocol/tcp"
	"github.com/net-byte/water"
	"log"
	"net/http"
)

// StartServer starts the h1 server
func StartServer(iFace *water.Interface, config config.Config) {
	log.Printf("vtun h1 server started on %v", config.LocalAddr)
	webSrv := NewHandle(netutil.GetDefaultHttpHandleFunc())
	webSrv.TokenCookieA = RandomStringByStringNonce(16, config.Key, 123)
	webSrv.TokenCookieB = RandomStringByStringNonce(32, config.Key, 456)
	webSrv.TokenCookieC = RandomStringByStringNonce(64, config.Key, 789)
	http.Handle("/", webSrv)
	srv := &http.Server{Addr: config.LocalAddr, Handler: nil}
	go func(srv *http.Server) {
		var err error
		if config.Protocol == "https" {
			tlsConfig := &tls.Config{
				MinVersion:       tls.VersionTLS13,
				CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				},
			}
			srv.TLSConfig = tlsConfig
			err = srv.ListenAndServeTLS(config.TLSCertificateFilePath, config.TLSCertificateKeyFilePath)
		} else {
			err = srv.ListenAndServe()
		}
		if err != http.ErrServerClosed {
			panic(err)
		}
	}(srv)
	// server -> client
	go tcp.ToClient(config, iFace)
	// client -> server
	for {
		conn, err := webSrv.Accept()
		if err != nil {
			continue
		}
		go tcp.ToServer(config, conn, iFace)
	}
}
