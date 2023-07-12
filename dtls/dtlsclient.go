package dtls

import (
	"errors"
	"fmt"
	"github.com/net-byte/vtun/common/xproto"
	"github.com/pion/dtls/v2"
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

// StartClient starts the dtls client
func StartClient(iFace *water.Interface, config config.Config) {
	log.Println("vtun dtls client started")
	go tunToTLS(config, iFace)
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
		tlsConfig = &dtls.Config{
			ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
			InsecureSkipVerify:   config.TLSInsecureSkipVerify,
		}
		if config.TLSSni != "" {
			tlsConfig.ServerName = config.TLSSni
		}
	}
	for {
		addr, err := net.ResolveUDPAddr("udp", config.ServerAddr)
		if err != nil {
			time.Sleep(3 * time.Second)
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		conn, err := dtls.Dial("udp", addr, tlsConfig)
		if err != nil {
			time.Sleep(3 * time.Second)
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		cache.GetCache().Set("dtlsConn", conn, 24*time.Hour)
		tlsToTun(config, conn, iFace)
		cache.GetCache().Delete("dtlsConn")
	}
}

// tunToTLS sends packets from tun to tls
func tunToTLS(config config.Config, iFace *water.Interface) {
	authKey := xproto.ParseAuthKeyFromString(config.Key)
	buffer := make([]byte, config.BufferSize)
	for {
		n, err := iFace.Read(buffer)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		fmt.Printf("iface read: %v", buffer[:n])
		if v, ok := cache.GetCache().Get("dtlsConn"); ok {
			b := buffer[:n]
			if config.Obfs {
				b = cipher.XOR(b)
			}
			if config.Compress {
				b = snappy.Encode(nil, b)
			}
			conn := v.(net.Conn)
			ph := &xproto.ClientSendPacketHeader{
				ProtocolVersion: xproto.ProtocolVersion,
				Key:             authKey,
				Length:          len(b),
			}
			_, err = conn.Write(ph.Bytes())
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			n, err = v.(net.Conn).Write(b[:])
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			counter.IncrWrittenBytes(n)
		}
	}
}

// tlsToTun sends packets from tls to tun
func tlsToTun(config config.Config, conn net.Conn, iFace *water.Interface) {
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
		}
	}(conn)
	header := make([]byte, xproto.ServerSendPacketHeaderLength)
	packet := make([]byte, config.BufferSize)
	for {
		n, err := conn.Read(header)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if n != xproto.ServerSendPacketHeaderLength {
			netutil.PrintErr(errors.New(fmt.Sprintf("received length <%d> not equals <%d>!", n, xproto.ServerSendPacketHeaderLength)), config.Verbose)
			break
		}
		ph := xproto.ParseServerSendPacketHeader(header[:n])
		if ph == nil {
			netutil.PrintErr(errors.New("ph == nil"), config.Verbose)
			break
		}
		n, err = conn.Read(packet[:ph.Length])
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
		_, err = iFace.Write(b)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		counter.IncrReadBytes(n)
	}
}
