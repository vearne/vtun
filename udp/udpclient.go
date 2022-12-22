package udp

import (
	"log"
	"net"

	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
)

// StartClient starts the udp client
func StartClient(iface *water.Interface, config config.Config) {
	serverAddr, err := net.ResolveUDPAddr("udp", config.ServerAddr)
	if err != nil {
		log.Fatalln("failed to resolve server addr:", err)
	}
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		log.Fatalln("failed to dial udp server:", err)
	}
	defer conn.Close()
	log.Println("vtun udp client started")
	c := &Client{config: config, iface: iface, conn: conn}
	go c.udpToTun()
	c.tunToUdp()
}

// The client struct
type Client struct {
	config config.Config
	iface  *water.Interface
	conn   *net.UDPConn
}

// udpToTun sends packets from udp to tun
func (c *Client) udpToTun() {
	packet := make([]byte, c.config.BufferSize)
	for {
		n, err := c.conn.Read(packet)
		if err != nil {
			netutil.PrintErr(err, c.config.Verbose)
			continue
		}
		b := packet[:n]
		if c.config.Compress {
			b, err = snappy.Decode(nil, b)
			if err != nil {
				netutil.PrintErr(err, c.config.Verbose)
				continue
			}
		}
		if c.config.Obfs {
			b = cipher.XOR(b)
		}
		c.iface.Write(b)
		counter.IncrReadBytes(n)
	}
}

// tunToUdp sends packets from tun to udp
func (c *Client) tunToUdp() {
	packet := make([]byte, c.config.BufferSize)
	for {
		n, err := c.iface.Read(packet)
		if err != nil {
			netutil.PrintErr(err, c.config.Verbose)
			break
		}
		b := packet[:n]
		if c.config.Obfs {
			b = cipher.XOR(b)
		}
		if c.config.Compress {
			b = snappy.Encode(nil, b)
		}
		_, err = c.conn.Write(b)
		if err != nil {
			netutil.PrintErr(err, c.config.Verbose)
			continue
		}
		counter.IncrWrittenBytes(n)
	}
}
