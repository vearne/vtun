package utls

import (
	utls "github.com/refraction-networking/utls"
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
)

// StartClient starts the utls client
func StartClient(iface *water.Interface, config config.Config) {
	log.Println("vtun utls client started")
	go tunToTLS(config, iface)
	tlsconfig := &utls.Config{
		InsecureSkipVerify: config.TLSInsecureSkipVerify,
	}
	if config.TLSSni != "" {
		tlsconfig.ServerName = config.TLSSni
	}
	for {
		tcpConn, err := net.Dial("tcp", config.ServerAddr)
		if err != nil {
			time.Sleep(3 * time.Second)
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		conn := utls.UClient(tcpConn, tlsconfig, utls.HelloRandomized)
		err = conn.Handshake()
		if err != nil {
			time.Sleep(3 * time.Second)
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		cache.GetCache().Set("utlsconn", conn, 24*time.Hour)
		tlsToTun(config, conn, iface)
		cache.GetCache().Delete("utlsconn")
	}
}

// tunToTLS sends packets from tun to tls
func tunToTLS(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.BufferSize)
	for {
		n, err := iface.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if v, ok := cache.GetCache().Get("utlsconn"); ok {
			b := packet[:n]
			if config.Obfs {
				b = cipher.XOR(b)
			}
			if config.Compress {
				b = snappy.Encode(nil, b)
			}
			utlsconn := v.(*utls.UConn)
			_, err = utlsconn.Write(b)
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			counter.IncrWrittenBytes(n)
		}
	}
}

// tlsToTun sends packets from tls to tun
func tlsToTun(config config.Config, conn *utls.UConn, iface *water.Interface) {
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
		_, err = iface.Write(b)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		counter.IncrReadBytes(n)
	}
}
