package tun

import (
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"

	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/songgao/water"
)

func CreateTun(config config.Config) (iface *water.Interface) {
	c := water.Config{DeviceType: water.TUN}
	if config.DeviceName != "" {
		c = water.Config{DeviceType: water.TUN, PlatformSpecificParams: water.PlatformSpecificParams{Name: config.DeviceName}}
	}
	iface, err := water.New(c)
	if err != nil {
		log.Fatalln("failed to create tun interface:", err)
	}
	log.Println("interface created:", iface.Name())
	configTun(config, iface)
	return iface
}

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
			serverIP := netutil.LookupIP(strings.Split(config.ServerAddr, ":")[0])
			if physicalIface != "" && serverIP != "" {
				netutil.ExecCmd("/sbin/ip", "route", "add", "0.0.0.0/1", "dev", iface.Name())
				netutil.ExecCmd("/sbin/ip", "-6", "route", "add", "::/1", "dev", iface.Name())
				netutil.ExecCmd("/sbin/ip", "route", "add", "128.0.0.0/1", "dev", iface.Name())
				netutil.ExecCmd("/sbin/ip", "route", "add", "8.8.8.8/32", "via", config.LocalGateway, "dev", physicalIface)
				netutil.ExecCmd("/sbin/ip", "route", "add", strings.Join([]string{serverIP, "32"}, "/"), "via", config.LocalGateway, "dev", physicalIface)
			}
		}

	} else if os == "darwin" {
		gateway := config.IntranetServerIP
		gateway6 := config.IntranetServerIPv6
		netutil.ExecCmd("ifconfig", iface.Name(), "inet", ip.String(), gateway, "up")
		netutil.ExecCmd("ifconfig", iface.Name(), "inet6", ipv6.String(), gateway6, "up")
		if !config.ServerMode && config.GlobalMode {
			physicalIface := netutil.GetInterface()
			serverIP := netutil.LookupIP(strings.Split(config.ServerAddr, ":")[0])
			if physicalIface != "" && serverIP != "" {
				netutil.ExecCmd("route", "add", serverIP, config.LocalGateway)
				netutil.ExecCmd("route", "add", "8.8.8.8", config.LocalGateway)
				netutil.ExecCmd("route", "add", "-inet6", "::/1", "-interface", iface.Name())
				netutil.ExecCmd("route", "add", "0.0.0.0/1", "-interface", iface.Name())
				netutil.ExecCmd("route", "add", "128.0.0.0/1", "-interface", iface.Name())
				netutil.ExecCmd("route", "add", "default", gateway)
				netutil.ExecCmd("route", "change", "default", gateway)
			}
		}
	} else {
		log.Printf("not support os:%v", os)
	}
}

func Reset(config config.Config) {
	os := runtime.GOOS
	if os == "darwin" && !config.ServerMode && config.GlobalMode {
		netutil.ExecCmd("route", "add", "default", config.LocalGateway)
		netutil.ExecCmd("route", "change", "default", config.LocalGateway)
	}
}
