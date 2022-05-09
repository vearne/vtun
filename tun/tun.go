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
	ip, ipNet, err := net.ParseCIDR(config.CIDR)
	if err != nil {
		log.Panicf("error cidr %v", config.CIDR)
	}
	if os == "linux" {
		netutil.ExecCmd("bash", "-c", "ip", "link", "set", "dev", iface.Name(), "mtu", strconv.Itoa(config.MTU))
		netutil.ExecCmd("bash", "-c", "ip", "addr", "add", config.CIDR, "dev", iface.Name())
		netutil.ExecCmd("bash", "-c", "ip", "link", "set", "dev", iface.Name(), "up")
		if config.GlobalMode {
			physicalIface := netutil.GetPhysicalInterface()
			serverIP := netutil.LookupIP(strings.Split(config.ServerAddr, ":")[0])
			if physicalIface != "" && serverIP != "" {
				netutil.ExecCmd("bash", "-c", "ip", "route", "add", "0.0.0.0/1", "dev", iface.Name())
				netutil.ExecCmd("bash", "-c", "ip", "route", "add", "128.0.0.0/1", "dev", iface.Name())
				netutil.ExecCmd("bash", "-c", "ip", "route", "add", strings.Join([]string{serverIP, "32"}, "/"), "via", config.DefaultGateway, "dev", physicalIface)
				netutil.ExecCmd("bash", "-c", "ip", "route", "add", strings.Join([]string{strings.Split(config.DNS, ":")[0], "32"}, "/"), "via", config.DefaultGateway, "dev", physicalIface)
			}
		}

	} else if os == "darwin" {
		gateway := ipNet.IP.To4()
		gateway[3]++
		netutil.ExecCmd("ifconfig", iface.Name(), "inet", ip.String(), gateway.String(), "up")
		physicalIface := netutil.GetPhysicalInterface()
		if config.GlobalMode {
			serverIP := netutil.LookupIP(strings.Split(config.ServerAddr, ":")[0])
			if physicalIface != "" && serverIP != "" {
				netutil.ExecCmd("route", "add", serverIP, config.DefaultGateway)
				netutil.ExecCmd("route", "add", strings.Split(config.DNS, ":")[0], config.DefaultGateway)
				netutil.ExecCmd("route", "add", "0.0.0.0/1", "-interface", iface.Name())
				netutil.ExecCmd("route", "add", "128.0.0.0/1", "-interface", iface.Name())
				netutil.ExecCmd("route", "add", "default", gateway.String())
				netutil.ExecCmd("route", "change", "default", gateway.String())
			}
		}
	} else {
		log.Printf("not support os:%v", os)
	}
}

func Reset(config config.Config) {
	os := runtime.GOOS
	if os == "darwin" && config.GlobalMode {
		netutil.ExecCmd("route", "change", "default", config.DefaultGateway)
	}
}
