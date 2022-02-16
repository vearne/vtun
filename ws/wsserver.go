package ws

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"strings"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/inhies/go-bytesize"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/register"
	"github.com/net-byte/vtun/tun"
	"github.com/patrickmn/go-cache"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
)

// Start a ws server
func StartServer(config config.Config) {
	iface := tun.CreateTun(config)
	c := cache.New(30*time.Minute, 10*time.Minute)
	// server -> client
	go toClient(config, iface, c)
	// client -> server
	http.HandleFunc(config.WebSocketPath, func(w http.ResponseWriter, r *http.Request) {
		if !checkPermission(w, r, config) {
			return
		}
		wsconn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			log.Printf("[server] failed to upgrade http %v", err)
			return
		}
		toServer(config, wsconn, iface, c)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "Hello，世界！")
	})

	http.HandleFunc("/ip", func(w http.ResponseWriter, req *http.Request) {
		ip := req.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip = strings.Split(req.RemoteAddr, ":")[0]
		}
		resp := fmt.Sprintf("%v", ip)
		io.WriteString(w, resp)
	})

	http.HandleFunc("/register/pick/ip", func(w http.ResponseWriter, r *http.Request) {
		if !checkPermission(w, r, config) {
			return
		}
		ip, pl := register.PickClientIP(config.CIDR)
		resp := fmt.Sprintf("%v/%v", ip, pl)
		io.WriteString(w, resp)
	})

	http.HandleFunc("/register/delete/ip", func(w http.ResponseWriter, r *http.Request) {
		if !checkPermission(w, r, config) {
			return
		}
		ip := r.URL.Query().Get("ip")
		if ip != "" {
			register.DeleteClientIP(ip)
		}
		io.WriteString(w, "OK")
	})

	http.HandleFunc("/register/keepalive/ip", func(w http.ResponseWriter, r *http.Request) {
		if !checkPermission(w, r, config) {
			return
		}
		ip := r.URL.Query().Get("ip")
		if ip != "" {
			register.KeepAliveClientIP(ip)
		}
		io.WriteString(w, "OK")
	})

	http.HandleFunc("/register/list/ip", func(w http.ResponseWriter, r *http.Request) {
		if !checkPermission(w, r, config) {
			return
		}
		io.WriteString(w, strings.Join(register.ListClientIP(), "\r\n"))
	})

	http.HandleFunc("/stats", func(w http.ResponseWriter, req *http.Request) {
		resp := fmt.Sprintf("download %v upload %v", bytesize.New(float64(counter.TotalWriteByte)).String(), bytesize.New(float64(counter.TotalReadByte)).String())
		io.WriteString(w, resp)
	})

	log.Printf("vtun ws server started on %v", config.LocalAddr)
	http.ListenAndServe(config.LocalAddr, nil)
}
func checkPermission(w http.ResponseWriter, req *http.Request, config config.Config) bool {
	key := req.Header.Get("key")
	if key != config.Key {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("No permission"))
		return false
	}
	return true
}

func toClient(config config.Config, iface *water.Interface, c *cache.Cache) {
	buffer := make([]byte, 1500)
	for {
		n, err := iface.Read(buffer)
		if err != nil || err == io.EOF || n == 0 {
			continue
		}
		b := buffer[:n]
		if !waterutil.IsIPv4(b) {
			continue
		}
		srcAddr, dstAddr := netutil.GetAddr(b)
		if srcAddr == "" || dstAddr == "" {
			continue
		}
		key := strings.Join([]string{dstAddr, srcAddr}, "->")
		if v, ok := c.Get(key); ok {
			if config.Obfuscate {
				b = cipher.XOR(b)
			}
			counter.IncrWriteByte(n)
			wsutil.WriteServerBinary(v.(net.Conn), b)
		}
	}
}

func toServer(config config.Config, wsconn net.Conn, iface *water.Interface, c *cache.Cache) {
	defer wsconn.Close()
	for {
		wsconn.SetReadDeadline(time.Now().Add(time.Duration(30) * time.Second))
		b, err := wsutil.ReadClientBinary(wsconn)
		if err != nil || err == io.EOF {
			break
		}
		if config.Obfuscate {
			b = cipher.XOR(b)
		}
		if !waterutil.IsIPv4(b) {
			continue
		}
		srcAddr, dstAddr := netutil.GetAddr(b)
		if srcAddr == "" || dstAddr == "" {
			continue
		}
		key := strings.Join([]string{srcAddr, dstAddr}, "->")
		c.Set(key, wsconn, cache.DefaultExpiration)
		counter.IncrReadByte(len(b))
		iface.Write(b)
	}
}
