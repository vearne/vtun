package udp

import (
	"log"
	"net"
	"time"

	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
)

// Client The client struct
type Client struct {
	config config.Config
	iFace  *water.Interface
	conn   *net.UDPConn
}

// StartClient starts the udp client
func StartClient(iFace *water.Interface, config config.Config) {
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
	c := &Client{config: config, iFace: iFace, conn: conn}
	go c.udpToTun()
	go c.keepAlive()
	c.tunToUdp()
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
		c.iFace.Write(b)
		counter.IncrReadBytes(n)
	}
}

// tunToUdp sends packets from tun to udp
func (c *Client) tunToUdp() {
	packet := make([]byte, c.config.BufferSize)
	for {
		n, err := c.iFace.Read(packet)
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

func (c *Client) keepAlive() {
	srcIp, _, err := net.ParseCIDR(c.config.CIDR)
	if err != nil {
		netutil.PrintErr(err, c.config.Verbose)
		return
	}

	// dst ip(pingIpPacket[12:16]): 0.0.0.0, src ip(pingIpPacket[16:20]): 0.0.0.0
	pingIpPacket := []byte{0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00}
	copy(pingIpPacket[12:16], srcIp[12:16]) // modify ping packet src ip to client CIDR ip

	if c.config.Obfs {
		pingIpPacket = cipher.XOR(pingIpPacket)
	}
	if c.config.Compress {
		pingIpPacket = snappy.Encode(nil, pingIpPacket)
	}

	for {
		time.Sleep(time.Second * 10)

		_, err := c.conn.Write(pingIpPacket)
		if err != nil {
			netutil.PrintErr(err, c.config.Verbose)
			continue
		}
	}
}
