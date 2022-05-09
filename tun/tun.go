package tun

import (
	"log"
	"net"
	"os"
	"os/exec"
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
		execCmd("/sbin/ip", "link", "set", "dev", iface.Name(), "mtu", strconv.Itoa(config.MTU))
		execCmd("/sbin/ip", "addr", "add", config.CIDR, "dev", iface.Name())
		execCmd("/sbin/ip", "link", "set", "dev", iface.Name(), "up")
		if config.GlobalMode {
			physicalIface, gateway, _ := netutil.GetPhysicalInterface()
			serverIP := netutil.LookupIP(strings.Split(config.ServerAddr, ":")[0])
			if physicalIface != "" && serverIP != "" {
				execCmd("/sbin/ip", "route", "add", "0.0.0.0/1", "dev", iface.Name())
				execCmd("/sbin/ip", "route", "add", "128.0.0.0/1", "dev", iface.Name())
				execCmd("/sbin/ip", "route", "add", strings.Join([]string{serverIP, "32"}, "/"), "via", gateway, "dev", physicalIface)
				execCmd("/sbin/ip", "route", "add", strings.Join([]string{strings.Split(config.DNS, ":")[0], "32"}, "/"), "via", gateway, "dev", physicalIface)
			}
		}

	} else if os == "darwin" {
		gateway := ipNet.IP.To4()
		gateway[3]++
		execCmd("ifconfig", iface.Name(), "inet", ip.String(), gateway.String(), "up")
		physicalIface, localGateway, _ := netutil.GetPhysicalInterface()
		if config.GlobalMode {
			serverIP := netutil.LookupIP(strings.Split(config.ServerAddr, ":")[0])
			if physicalIface != "" && serverIP != "" {
				execCmd("route", "add", serverIP, localGateway)
				execCmd("route", "add", strings.Split(config.DNS, ":")[0], localGateway)
				execCmd("route", "add", "0.0.0.0/1", "-interface", iface.Name())
				execCmd("route", "add", "128.0.0.0/1", "-interface", iface.Name())
				execCmd("route", "add", "default", gateway.String())
				execCmd("route", "change", "default", gateway.String())
			}
		}
	} else {
		log.Printf("not support os:%v", os)
	}
}

func Reset(config config.Config) {
	os := runtime.GOOS
	if os == "darwin" && config.GlobalMode {
		_, localGateway, _ := netutil.GetPhysicalInterface()
		execCmd("route", "add", "default", localGateway)
		execCmd("route", "change", "default", localGateway)
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
