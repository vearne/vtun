package netutil

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gobwas/ws"
	"github.com/net-byte/vtun/common/config"
	"github.com/songgao/water/waterutil"
)

func GetAddr(b []byte) (srcAddr string, dstAddr string) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("failed to get addr:%v", err)
			srcAddr = ""
			dstAddr = ""
		}
	}()
	if waterutil.IPv4Protocol(b) == waterutil.TCP || waterutil.IPv4Protocol(b) == waterutil.UDP {
		srcIp := waterutil.IPv4Source(b)
		dstIp := waterutil.IPv4Destination(b)
		srcPort := waterutil.IPv4SourcePort(b)
		dstPort := waterutil.IPv4DestinationPort(b)
		src := strings.Join([]string{srcIp.To4().String(), strconv.FormatUint(uint64(srcPort), 10)}, ":")
		dst := strings.Join([]string{dstIp.To4().String(), strconv.FormatUint(uint64(dstPort), 10)}, ":")
		//log.Printf("%s->%v", src, dst)
		return src, dst
	} else if waterutil.IPv4Protocol(b) == waterutil.ICMP {
		srcIp := waterutil.IPv4Source(b)
		dstIp := waterutil.IPv4Destination(b)
		return srcIp.To4().String(), dstIp.To4().String()
	}
	return "", ""
}

func ConnectServer(config config.Config) net.Conn {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, config.DNS)
		},
	}
	scheme := "ws"
	if config.Protocol == "wss" {
		scheme = "wss"
	}
	u := url.URL{Scheme: scheme, Host: config.ServerAddr, Path: config.WebSocketPath}
	header := make(http.Header)
	header.Set("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36")
	header.Set("key", config.Key)
	dialer := ws.Dialer{
		Header: ws.HandshakeHeaderHTTP(header),
	}
	c, _, _, err := dialer.Dial(context.Background(), u.String())
	if err != nil {
		log.Printf("[client] failed to dial websocket %s %v", u.String(), err)
		return nil
	}
	return c
}

func GetPhysicalInterface() (name string, gateway string, network string) {
	ifaces := getAllPhysicalInterfaces()
	if len(ifaces) == 0 {
		return "", "", ""
	}
	netAddrs, _ := ifaces[0].Addrs()
	for _, addr := range netAddrs {
		ip, ok := addr.(*net.IPNet)
		if ok && ip.IP.To4() != nil && !ip.IP.IsLoopback() {
			ipNet := ip.IP.To4().Mask(ip.IP.DefaultMask()).To4()
			network = strings.Join([]string{ipNet.String(), strings.Split(ip.String(), "/")[1]}, "/")
			ipNet[3]++
			gateway = ipNet.String()
			name = ifaces[0].Name
			log.Printf("physical interface %v gateway %v network %v", name, gateway, network)
			break
		}
	}
	return name, gateway, network
}

func getAllPhysicalInterfaces() []net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Println(err)
		return nil
	}

	var outInterfaces []net.Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp == 1 && isPhysicalInterface(iface.Name) {
			netAddrs, _ := iface.Addrs()
			if len(netAddrs) > 0 {
				outInterfaces = append(outInterfaces, iface)
			}
		}
	}
	return outInterfaces
}

func isPhysicalInterface(addr string) bool {
	prefixArray := []string{"ens", "enp", "enx", "eno", "eth", "en0", "wlan", "wlp", "wlo", "wlx", "wifi0", "lan0"}
	for _, pref := range prefixArray {
		if strings.HasPrefix(strings.ToLower(addr), pref) {
			return true
		}
	}
	return false
}

func LookupIP(domain string) string {
	ips, err := net.LookupIP(domain)
	if err != nil {
		log.Println(err)
		return ""
	}
	for _, ip := range ips {
		return ip.To4().String()
	}
	return ""
}
