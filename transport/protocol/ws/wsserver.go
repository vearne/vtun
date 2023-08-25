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
	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/register"
	"github.com/net-byte/water"
)

// StartServer starts the ws server
func StartServer(iFace *water.Interface, config config.Config) {
	// server -> client
	go toClient(config, iFace)
	// client -> server
	http.HandleFunc(config.Path, func(w http.ResponseWriter, r *http.Request) {
		if !checkPermission(w, r, config) {
			return
		}
		wsconn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			log.Printf("[server] failed to upgrade http %v", err)
			return
		}
		toServer(config, wsconn, iFace)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "6")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("CF-Cache-Status", "DYNAMIC")
		w.Header().Set("Server", "cloudflare")
		w.Write([]byte(`follow`))
	})

	http.HandleFunc("/ip", func(w http.ResponseWriter, req *http.Request) {
		ip := req.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip, _, _ = net.SplitHostPort(req.RemoteAddr)
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
		io.WriteString(w, strings.Join(register.ListClientIPs(), "\r\n"))
	})

	http.HandleFunc("/register/prefix/ipv4", func(w http.ResponseWriter, r *http.Request) {
		if !checkPermission(w, r, config) {
			return
		}
		_, ipv4Net, err := net.ParseCIDR(config.CIDR)
		var resp string
		if err != nil {
			resp = "error"
		} else {
			resp = ipv4Net.String()
		}
		io.WriteString(w, resp)
	})

	http.HandleFunc("/register/prefix/ipv6", func(w http.ResponseWriter, r *http.Request) {
		if !checkPermission(w, r, config) {
			return
		}
		_, ipv6Net, err := net.ParseCIDR(config.CIDRv6)
		var resp string
		if err != nil {
			resp = "error"
		} else {
			resp = ipv6Net.String()
		}
		io.WriteString(w, resp)
	})

	http.HandleFunc("/stats", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, counter.PrintBytes(true))
	})

	log.Printf("vtun websocket server started on %v", config.LocalAddr)
	if config.Protocol == "wss" && config.TLSCertificateFilePath != "" && config.TLSCertificateKeyFilePath != "" {
		http.ListenAndServeTLS(config.LocalAddr, config.TLSCertificateFilePath, config.TLSCertificateKeyFilePath, nil)
	} else {
		http.ListenAndServe(config.LocalAddr, nil)
	}

}

// checkPermission checks the permission of the request
func checkPermission(w http.ResponseWriter, req *http.Request, config config.Config) bool {
	if config.Key == "" {
		return true
	}
	key := req.Header.Get("key")
	if key != config.Key {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("No permission"))
		return false
	}
	return true
}

// toClient sends data to client
func toClient(config config.Config, iFace *water.Interface) {
	packet := make([]byte, config.BufferSize)
	for {
		n, err := iFace.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		b := packet[:n]
		if key := netutil.GetDstKey(b); key != "" {
			if v, ok := cache.GetCache().Get(key); ok {
				if config.Obfs {
					b = cipher.XOR(b)
				}
				if config.Compress {
					b = snappy.Encode(nil, b)
				}
				err := wsutil.WriteServerBinary(v.(net.Conn), b)
				if err != nil {
					cache.GetCache().Delete(key)
					continue
				}
				counter.IncrWrittenBytes(n)
			}
		}
	}
}

// toServer sends data to server
func toServer(config config.Config, wsconn net.Conn, iFace *water.Interface) {
	defer wsconn.Close()
	for {
		b, op, err := wsutil.ReadClientData(wsconn)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if op == ws.OpText {
			if config.Verbose {
				log.Println(string(b[:]))
			}
			wsutil.WriteServerMessage(wsconn, op, b)
		} else if op == ws.OpBinary {
			if config.Compress {
				b, _ = snappy.Decode(nil, b)
			}
			if config.Obfs {
				b = cipher.XOR(b)
			}
			if key := netutil.GetSrcKey(b); key != "" {
				cache.GetCache().Set(key, wsconn, 24*time.Hour)
				counter.IncrReadBytes(len(b))
				iFace.Write(b)
			}
		}
	}
}
