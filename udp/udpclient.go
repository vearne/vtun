package udp

import (
	"log"
	"net"

	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/tun"
	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

// Start udp client
func StartClient(config config.Config) {
	log.Printf("vtun udp client started on %v", config.LocalAddr)
	iface := tun.CreateTun(config)
	serverAddr, err := net.ResolveUDPAddr("udp", config.ServerAddr)
	if err != nil {
		log.Fatalln("failed to resolve server addr:", err)
	}
	localAddr, err := net.ResolveUDPAddr("udp", config.LocalAddr)
	if err != nil {
		log.Fatalln("failed to get udp socket:", err)
	}
	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		log.Fatalln("failed to listen on udp socket:", err)
	}
	p := ipv4.NewPacketConn(conn)
	if err := p.SetTOS(0xb8); err != nil { // DSCP EF
		log.Fatalln("failed to set conn tos:", err)
	}
	defer conn.Close()
	c := &Client{config: config, iface: iface, localConn: conn, serverAddr: serverAddr}
	go c.udpToTun()
	c.tunToUdp()
}

type Client struct {
	config     config.Config
	iface      *water.Interface
	localConn  *net.UDPConn
	serverAddr *net.UDPAddr
}

func (c *Client) udpToTun() {
	packet := make([]byte, c.config.MTU)
	for {
		n, _, err := c.localConn.ReadFromUDP(packet)
		if err != nil || n == 0 {
			continue
		}
		b := packet[:n]
		if c.config.Obfs {
			b = cipher.XOR(b)
		}
		c.iface.Write(b)
	}
}
func (c *Client) tunToUdp() {
	packet := make([]byte, c.config.MTU)
	for {
		n, err := c.iface.Read(packet)
		if err != nil || n == 0 {
			continue
		}
		b := packet[:n]
		if c.config.Obfs {
			b = cipher.XOR(b)
		}
		c.localConn.WriteToUDP(b, c.serverAddr)
	}
}
