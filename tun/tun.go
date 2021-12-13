package tun

import (
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
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
	ip, _, err := net.ParseCIDR(config.CIDR)
	if err != nil {
		log.Panicf("error cidr %v", config.CIDR)
	}
	physicalIface, gatewayIP, localNetwork := netutil.GetPhysicalInterface()
	if os == "linux" {
		execCmd("/sbin/ip", "link", "set", "dev", iface.Name(), "mtu", "1500")
		execCmd("/sbin/ip", "addr", "add", config.CIDR, "dev", iface.Name())
		execCmd("/sbin/ip", "link", "set", "dev", iface.Name(), "up")
		if config.Route != "" {
			execCmd("/sbin/ip", "route", "add", config.Route, "dev", iface.Name())
		}
		serverIP := netutil.LookupIP(strings.Split(config.ServerAddr, ":")[0])
		execCmd("/sbin/ip", "route", "add", "0.0.0.0/1", "dev", iface.Name())
		execCmd("/sbin/ip", "route", "add", "128.0.0.0/1", "dev", iface.Name())
		execCmd("/sbin/ip", "delete", strings.Join([]string{serverIP, "32"}, "/"), "via", gatewayIP, "dev", physicalIface)
		execCmd("/sbin/ip", "add", strings.Join([]string{serverIP, "32"}, "/"), "via", gatewayIP, "dev", physicalIface)
	} else if os == "darwin" {
		execCmd("ifconfig", iface.Name(), "inet", ip.String(), config.Gateway, "up")
		if config.Route != "" {
			execCmd("route", "add", "-net", config.Route, "-interface", iface.Name())
			execCmd("route", "add", "0.0.0.0/0", "-interface", iface.Name())
			execCmd("route", "add", localNetwork, "-interface", config.Route)
		}
	} else {
		log.Printf("not support os:%v", os)
	}
}

func execCmd(c string, args ...string) {
	log.Printf("exec cmd: %v %v:", c, args)
	cmd := exec.Command(c, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if err != nil {
		log.Println("failed to exec cmd:", err)
	}
}
