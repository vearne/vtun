package tcp

import (
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/tun"
	"github.com/songgao/water"
)

// Start tcp client
func StartClient(config config.Config) {
	log.Printf("vtun tcp client started on %v", config.LocalAddr)
	iface := tun.CreateTun(config)
	for {
		if conn, err := net.DialTimeout("tcp", config.ServerAddr, time.Duration(config.Timeout)*time.Second); conn != nil && err == nil {
			defer conn.Close()
			var wg sync.WaitGroup
			wg.Add(2)
			go tcpToTun(&wg, config, conn, iface)
			go tunToTcp(&wg, config, conn, iface)
			wg.Wait()
		}
	}
}

func tunToTcp(wg *sync.WaitGroup, config config.Config, tcpconn net.Conn, iface *water.Interface) {
	defer wg.Done()
	packet := make([]byte, config.MTU)
	for {
		n, err := iface.Read(packet)
		if err != nil || n == 0 {
			break
		}
		b := packet[:n]
		if config.Obfs {
			b = cipher.XOR(b)
		}
		tcpconn.Write(b)
	}
}
func tcpToTun(wg *sync.WaitGroup, config config.Config, tcpconn net.Conn, iface *water.Interface) {
	defer wg.Done()
	packet := make([]byte, config.MTU)
	for {
		tcpconn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
		n, err := tcpconn.Read(packet)
		if err != nil || err == io.EOF {
			break
		}
		b := packet[:n]
		if config.Obfs {
			b = cipher.XOR(b)
		}
		iface.Write(b)
	}
}
