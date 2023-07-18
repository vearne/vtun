package netutil

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"tailscale.com/net/interfaces"
	"time"

	"github.com/gobwas/ws"
	"github.com/net-byte/go-gateway"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
)

// ConnectServer connects to the server with the given address.
func ConnectServer(config config.Config) net.Conn {
	scheme := "ws"
	host := config.ServerAddr
	if config.Protocol == "wss" {
		scheme = "wss"
		if config.TLSSni != "" {
			host = config.TLSSni
		}
	}
	u := url.URL{Scheme: scheme, Host: host, Path: config.Path}
	header := make(http.Header)
	header.Set("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36")
	if config.Key != "" {
		header.Set("key", config.Key)
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.TLSInsecureSkipVerify,
	}
	if config.TLSSni != "" {
		tlsConfig.ServerName = config.TLSSni
	}
	dialer := ws.Dialer{
		Header:    ws.HandshakeHeaderHTTP(header),
		Timeout:   time.Duration(config.Timeout) * time.Second,
		TLSConfig: tlsConfig,
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, config.ServerAddr)
		},
	}
	c, _, _, err := dialer.Dial(context.Background(), u.String())
	if err != nil {
		log.Printf("[client] failed to dial websocket %s %v", u.String(), err)
		return nil
	}
	return c
}

// GetInterface returns the name of interface
func GetInterface() (name string) {
	ifaces := getAllInterfaces()
	if len(ifaces) == 0 {
		return ""
	}
	netAddrs, _ := ifaces[0].Addrs()
	for _, addr := range netAddrs {
		ip, ok := addr.(*net.IPNet)
		if ok && ip.IP.To4() != nil && !ip.IP.IsLoopback() {
			name = ifaces[0].Name
			break
		}
	}
	return name
}

// getAllInterfaces returns all interfaces
func getAllInterfaces() []net.Interface {
	iFaceList, err := net.Interfaces()
	if err != nil {
		log.Println(err)
		return nil
	}

	var outInterfaces []net.Interface
	for _, iFace := range iFaceList {
		if iFace.Flags&net.FlagLoopback == 0 && iFace.Flags&net.FlagUp == 1 && isPhysicalInterface(iFace.Name) {
			netAddrList, _ := iFace.Addrs()
			if len(netAddrList) > 0 {
				outInterfaces = append(outInterfaces, iFace)
			}
		}
	}
	return outInterfaces
}

// isPhysicalInterface returns true if the interface is physical
func isPhysicalInterface(addr string) bool {
	prefixArray := []string{"ens", "enp", "enx", "eno", "eth", "en0", "wlan", "wlp", "wlo", "wlx", "wifi0", "lan0"}
	for _, pref := range prefixArray {
		if strings.HasPrefix(strings.ToLower(addr), pref) {
			return true
		}
	}
	return false
}

// LookupIP Lookup IP address of the given hostname
func LookupIP(domain string) net.IP {
	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		log.Println(err)
		return nil
	}
	return ips[0]
}

// IsIPv4 returns true if the packet is IPv4s
func IsIPv4(packet []byte) bool {
	flag := packet[0] >> 4
	return flag == 4
}

// IsIPv6 returns true if the packet is IPv6s
func IsIPv6(packet []byte) bool {
	flag := packet[0] >> 4
	return flag == 6
}

// GetIPv4Src returns the IPv4 source address of the packet
func GetIPv4Src(packet []byte) net.IP {
	return net.IPv4(packet[12], packet[13], packet[14], packet[15])
}

// GetIPv4Dst returns the IPv4 destination address of the packet
func GetIPv4Dst(packet []byte) net.IP {
	return net.IPv4(packet[16], packet[17], packet[18], packet[19])
}

// GetIPv6Src returns the IPv6 source address of the packet
func GetIPv6Src(packet []byte) net.IP {
	return net.IP(packet[8:24])
}

// GetIPv6Dst returns the IPv6 destination address of the packet
func GetIPv6Dst(packet []byte) net.IP {
	return net.IP(packet[24:40])
}

// GetSrcKey returns the source key of the packet
func GetSrcKey(packet []byte) string {
	key := ""
	if IsIPv4(packet) && len(packet) >= 20 {
		key = GetIPv4Src(packet).To4().String()
	} else if IsIPv6(packet) && len(packet) >= 40 {
		key = GetIPv6Src(packet).To16().String()
	}
	return key
}

// GetDstKey returns the destination key of the packets
func GetDstKey(packet []byte) string {
	key := ""
	if IsIPv4(packet) && len(packet) >= 20 {
		key = GetIPv4Dst(packet).To4().String()
	} else if IsIPv6(packet) && len(packet) >= 40 {
		key = GetIPv6Dst(packet).To16().String()
	}
	return key
}

// ExecCmd executes the given command
func ExecCmd(c string, args ...string) string {
	//log.Printf("exec %v %v", c, args)
	cmd := exec.Command(c, args...)
	out, err := cmd.Output()
	if err != nil {
		log.Println("failed to exec cmd:", err)
	}
	if len(out) == 0 {
		return ""
	}
	s := string(out)
	return strings.ReplaceAll(s, "\n", "")
}

// DiscoverGateway returns the local gateway IP address
func DiscoverGateway(ipv4 bool) string {
	var ip net.IP
	var err error
	if ipv4 {
		ip, err = gateway.DiscoverGatewayIPv4()
	} else {
		ip, err = gateway.DiscoverGatewayIPv6()
	}
	if err != nil {
		log.Println(err)
		return ""
	}
	return ip.String()
}

// LookupServerAddrIP returns the IP of server address
func LookupServerAddrIP(serverAddr string) net.IP {
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		log.Panic("error server address")
		return nil
	}
	ip := LookupIP(host)
	return ip
}

// GetDefaultHttpResponse returns the default http response
func GetDefaultHttpResponse() []byte {
	return []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nCF-Cache-Status: DYNAMIC\r\nServer: cloudflare\r\n\r\nfollow")
}

func GetDefaultHttpHandleFunc() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "6")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("CF-Cache-Status", "DYNAMIC")
		w.Header().Set("Server", "cloudflare")
		w.Write([]byte("follow"))
	})
}

// PrintErr returns the error log
func PrintErr(err error, enableVerbose bool) {
	if !enableVerbose {
		return
	}
	log.Printf("error:%v", err)
}

// PrintErrF returns the error log
func PrintErrF(enableVerbose bool, formatString string, args ...any) {
	if !enableVerbose {
		return
	}
	log.Printf("error: "+formatString, args...)
}

// PrintStats returns the stats info
func PrintStats(enableVerbose bool, serverMode bool) {
	if !enableVerbose {
		return
	}
	go func() {
		for {
			time.Sleep(30 * time.Second)
			log.Printf("stats:%v", counter.PrintBytes(serverMode))
		}
	}()
}

func DefaultRouteInterface() (string, error) {
	return interfaces.DefaultRouteInterface()
}
