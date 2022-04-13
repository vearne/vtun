package ws

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/inhies/go-bytesize"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/register"
	"github.com/net-byte/vtun/tun"
	"github.com/songgao/water"
)

// Start websocket server
func StartServer(config config.Config) {
	iface := tun.CreateTun(config)
	// server -> client
	go toClient(config, iface)
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
		toServer(config, wsconn, iface)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "Hello,世界!")
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

	log.Printf("vtun websocket server started on %v", config.LocalAddr)
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

func toClient(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.MTU)
	for {
		n, err := iface.Read(packet)
		if err != nil || err == io.EOF || n == 0 {
			continue
		}
		b := packet[:n]
		key := netutil.GetDestinationKey(b)
		if key == "" {
			continue
		}
		if v, ok := cache.GetCache().Get(key); ok {
			if config.Obfs {
				b = cipher.XOR(b)
			}
			counter.IncrWriteByte(n)
			wsutil.WriteServerBinary(v.(net.Conn), b)
		}
	}
}

func toServer(config config.Config, wsconn net.Conn, iface *water.Interface) {
	defer wsconn.Close()
	for {
		wsconn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
		b, err := wsutil.ReadClientBinary(wsconn)
		if err != nil || err == io.EOF {
			break
		}
		if config.Obfs {
			b = cipher.XOR(b)
		}
		key := netutil.GetSourceKey(b)
		if key == "" {
			continue
		}
		cache.GetCache().Set(key, wsconn, 10*time.Minute)
		counter.IncrReadByte(len(b))
		iface.Write(b)
	}
}
