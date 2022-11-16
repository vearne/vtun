package ws

import (
	"log"
	"net"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
)

// StartClient starts the ws client
func StartClient(iface *water.Interface, config config.Config) {
	log.Println("vtun websocket client started")
	go tunToWs(config, iface)
	for {
		conn := netutil.ConnectServer(config)
		if conn == nil {
			time.Sleep(3 * time.Second)
			continue
		}
		cache.GetCache().Set("wsconn", conn, 24*time.Hour)
		go wsToTun(config, conn, iface)
		ping(conn, config)
		cache.GetCache().Delete("wsconn")
	}
}

func ping(wsconn net.Conn, config config.Config) {
	defer wsconn.Close()
	for {
		wsconn.SetWriteDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
		err := wsutil.WriteClientMessage(wsconn, ws.OpText, []byte("ping"))
		if err != nil {
			break
		}
		time.Sleep(3 * time.Second)
	}
}

// wsToTun sends packets from ws to tun
func wsToTun(config config.Config, wsconn net.Conn, iface *water.Interface) {
	defer wsconn.Close()
	for {
		wsconn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
		packet, err := wsutil.ReadServerBinary(wsconn)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if config.Compress {
			packet, _ = snappy.Decode(nil, packet)
		}
		if config.Obfs {
			packet = cipher.XOR(packet)
		}
		_, err = iface.Write(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		counter.IncrReadBytes(len(packet))
	}
}

// tunToWs sends packets from tun to ws
func tunToWs(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.BufferSize)
	for {
		n, err := iface.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if v, ok := cache.GetCache().Get("wsconn"); ok {
			b := packet[:n]
			if config.Obfs {
				b = cipher.XOR(b)
			}
			if config.Compress {
				b = snappy.Encode(nil, b)
			}
			wsconn := v.(net.Conn)
			wsconn.SetWriteDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
			if err = wsutil.WriteClientBinary(wsconn, b); err != nil {
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			counter.IncrWrittenBytes(n)
		}
	}
}
