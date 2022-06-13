package register

import (
	"log"
	"net"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
)

// The global cache for register
var _register *cache.Cache

func init() {
	_register = cache.New(30*time.Minute, 3*time.Minute)
}

// AddClientIP adds a client ip to the register
func AddClientIP(ip string) {
	_register.Add(ip, 0, cache.DefaultExpiration)
}

// DeleteClientIP deletes a client ip from the register
func DeleteClientIP(ip string) {
	_register.Delete(ip)
}

// ExistClientIP checks if the client ip is in the register
func ExistClientIP(ip string) bool {
	_, ok := _register.Get(ip)
	return ok
}

// keepAlive keeps the client ip alive
func KeepAliveClientIP(ip string) {
	if ExistClientIP(ip) {
		_register.Increment(ip, 1)
	} else {
		AddClientIP(ip)
	}
}

// PickClientIP picks a client ip from the register
func PickClientIP(cidr string) (clientIP string, prefixLength string) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Panicf("error cidr %v", cidr)
	}
	total := addressCount(ipNet) - 3
	index := uint64(0)
	//skip first ip
	ip = incr(ipNet.IP.To4())
	for {
		ip = incr(ip)
		index++
		if index >= total {
			break
		}
		if !ExistClientIP(ip.String()) {
			AddClientIP(ip.String())
			return ip.String(), strings.Split(cidr, "/")[1]
		}
	}
	return "", ""
}

// ListClientIPs returns the client ips in the register
func ListClientIPs() []string {
	result := []string{}
	for k := range _register.Items() {
		result = append(result, k)
	}
	return result
}

// addressCount returns the number of addresses in a CIDR network.
func addressCount(network *net.IPNet) uint64 {
	prefixLen, bits := network.Mask.Size()
	return 1 << (uint64(bits) - uint64(prefixLen))
}

// incr increments the ip by 1
func incr(IP net.IP) net.IP {
	IP = checkIPv4(IP)
	incIP := make([]byte, len(IP))
	copy(incIP, IP)
	for j := len(incIP) - 1; j >= 0; j-- {
		incIP[j]++
		if incIP[j] > 0 {
			break
		}
	}
	return incIP
}

// checkIPv4 checks if the ip is IPv4
func checkIPv4(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}
