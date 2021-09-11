package tun

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"

	"github.com/net-byte/vtun/common/config"
	"github.com/songgao/water"
)

func CreateTun(config config.Config) (iface *water.Interface) {
	c := water.Config{DeviceType: water.TUN}
	iface, err := water.New(c)
	if err != nil {
		log.Fatalln("failed to allocate TUN interface:", err)
	}
	log.Println("interface allocated:", iface.Name())
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
		execCmd("/sbin/ip", "link", "set", "dev", iface.Name(), "mtu", "1500")
		execCmd("/sbin/ip", "addr", "add", config.CIDR, "dev", iface.Name())
		execCmd("/sbin/ip", "link", "set", "dev", iface.Name(), "up")
		if config.Route != "" {
			addRoute := fmt.Sprintf("route add %s dev %s", config.Route, iface.Name())
			execCmd("/sbin/ip", addRoute)
		}
	} else if os == "darwin" {
		execCmd("ifconfig", iface.Name(), "inet", ip.String(), config.Gateway, "up")
		if config.Route != "" {
			addRoute := fmt.Sprintf("add -net %s -interface %s", config.Route, iface.Name())
			execCmd("route", addRoute)
		}
	} else if os == "windows" {
		setAddress := fmt.Sprintf("set address name=%s source=static addr=%s mask=%s gateway=none", iface.Name(), ip.String(), ipMask(ipNet.Mask))
		execCmd("netsh interface ip", setAddress)
		if config.Route != "" {
			deleteRoute := fmt.Sprintf("delete route prefix=%s interface=%s store=active", config.Route, iface.Name())
			addRoute := fmt.Sprintf("add route prefix=%s interface=%s store=active", config.Route, iface.Name())
			execCmd("netsh interface ip", deleteRoute)
			execCmd("netsh interface ip", addRoute)
		}
	} else {
		log.Printf("not support os:%v", os)
	}
}

func execCmd(c string, args ...string) {
	cmd := exec.Command(c, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if err != nil {
		log.Fatalln("failed to exec cmd:", err)
	}
}

func ipMask(mask net.IPMask) string {
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}
