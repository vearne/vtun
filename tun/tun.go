package tun

import (
	"log"
	"net"
	"runtime"
	"strconv"

	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
)

// CreateTun creates a tun interface
func CreateTun(config config.Config) (iface *water.Interface) {
	c := water.Config{DeviceType: water.TUN}
	if config.DeviceName != "" {
		c.PlatformSpecificParams = water.PlatformSpecificParams{Name: config.DeviceName, Network: config.CIDR}
	} else {
		os := runtime.GOOS
		if os == "windows" {
			c.PlatformSpecificParams = water.PlatformSpecificParams{Name: "vtun", Network: config.CIDR}
		} else {
			c.PlatformSpecificParams = water.PlatformSpecificParams{Network: config.CIDR}
		}
	}
	iface, err := water.New(c)
	if err != nil {
		log.Fatalln("failed to create tun interface:", err)
	}
	log.Printf("interface created %v", iface.Name())
	configTun(config, iface)
	return iface
}

// ConfigTun configures the tun interface
func configTun(config config.Config, iface *water.Interface) {
	os := runtime.GOOS
	ip, _, err := net.ParseCIDR(config.CIDR)
	if err != nil {
		log.Panicf("error cidr %v", config.CIDR)
	}
	ipv6, _, err := net.ParseCIDR(config.CIDRv6)
	if err != nil {
		log.Panicf("error ipv6 cidr %v", config.CIDRv6)
	}
	if os == "linux" {
		netutil.ExecCmd("/sbin/ip", "link", "set", "dev", iface.Name(), "mtu", strconv.Itoa(config.MTU))
		netutil.ExecCmd("/sbin/ip", "addr", "add", config.CIDR, "dev", iface.Name())
		netutil.ExecCmd("/sbin/ip", "-6", "addr", "add", config.CIDRv6, "dev", iface.Name())
		netutil.ExecCmd("/sbin/ip", "link", "set", "dev", iface.Name(), "up")
		if !config.ServerMode && config.GlobalMode {
			physicalIface := netutil.GetInterface()
			host, _, err := net.SplitHostPort(config.ServerAddr)
			if err != nil {
				log.Panic("error server address")
			}
			serverIP := netutil.LookupIP(host)
			if physicalIface != "" && serverIP != nil {
				netutil.ExecCmd("/sbin/ip", "route", "add", "0.0.0.0/1", "dev", iface.Name())
				netutil.ExecCmd("/sbin/ip", "-6", "route", "add", "::/1", "dev", iface.Name())
				netutil.ExecCmd("/sbin/ip", "route", "add", "128.0.0.0/1", "dev", iface.Name())
				netutil.ExecCmd("/sbin/ip", "route", "add", config.DNSIP+"/32", "via", config.LocalGateway, "dev", physicalIface)
				if serverIP.To4() != nil {
					netutil.ExecCmd("/sbin/ip", "route", "add", serverIP.To4().String()+"/32", "via", config.LocalGateway, "dev", physicalIface)
				} else {
					netutil.ExecCmd("/sbin/ip", "-6", "route", "add", serverIP.To16().String()+"/64", "via", config.LocalGateway, "dev", physicalIface)
				}
			}
		}

	} else if os == "darwin" {
		gateway := config.ServerIP
		gateway6 := config.ServerIPv6
		netutil.ExecCmd("ifconfig", iface.Name(), "inet", ip.String(), gateway, "up")
		netutil.ExecCmd("ifconfig", iface.Name(), "inet6", ipv6.String(), gateway6, "up")
		if !config.ServerMode && config.GlobalMode {
			physicalIface := netutil.GetInterface()
			host, _, err := net.SplitHostPort(config.ServerAddr)
			if err != nil {
				log.Panic("error server address")
			}
			serverIP := netutil.LookupIP(host)
			if physicalIface != "" && serverIP != nil {
				if serverIP.To4() != nil {
					netutil.ExecCmd("route", "add", serverIP.To4().String(), config.LocalGateway)
				} else {
					netutil.ExecCmd("route", "add", "-inet6", serverIP.To16().String(), config.LocalGateway)
				}
				netutil.ExecCmd("route", "add", config.DNSIP, config.LocalGateway)
				netutil.ExecCmd("route", "add", "-inet6", "::/1", "-interface", iface.Name())
				netutil.ExecCmd("route", "add", "0.0.0.0/1", "-interface", iface.Name())
				netutil.ExecCmd("route", "add", "128.0.0.0/1", "-interface", iface.Name())
				netutil.ExecCmd("route", "add", "default", gateway)
				netutil.ExecCmd("route", "change", "default", gateway)
			}
		}
	} else if os == "windows" {
		if !config.ServerMode && config.GlobalMode {
			gateway := config.ServerIP
			host, _, err := net.SplitHostPort(config.ServerAddr)
			if err != nil {
				log.Panic("error server address")
			}
			serverIP := netutil.LookupIP(host)
			if serverIP != nil {
				netutil.ExecCmd("cmd", "/C", "route", "delete", "0.0.0.0", "mask", "0.0.0.0")
				netutil.ExecCmd("cmd", "/C", "route", "add", "0.0.0.0", "mask", "0.0.0.0", gateway, "metric", "6")
				netutil.ExecCmd("cmd", "/C", "route", "add", serverIP.To4().String(), config.LocalGateway, "metric", "5")
				netutil.ExecCmd("cmd", "/C", "route", "add", config.DNSIP, config.LocalGateway, "metric", "5")
			}
		}
	} else {
		log.Printf("not support os %v", os)
	}
	log.Printf("interface configured %v", iface.Name())
}

// ResetTun resets the tun interface
func ResetTun(config config.Config) {
	// reset gateway
	if !config.ServerMode && config.GlobalMode {
		os := runtime.GOOS
		if os == "darwin" {
			netutil.ExecCmd("route", "add", "default", config.LocalGateway)
			netutil.ExecCmd("route", "change", "default", config.LocalGateway)
		} else if os == "windows" {
			netutil.ExecCmd("cmd", "/C", "route", "delete", "0.0.0.0", "mask", "0.0.0.0")
			netutil.ExecCmd("cmd", "/C", "route", "add", "0.0.0.0", "mask", "0.0.0.0", config.LocalGateway, "metric", "6")
		}
	}
}
