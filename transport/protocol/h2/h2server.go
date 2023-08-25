package h2

import (
	"fmt"
	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/common/x/xproto"
	"github.com/net-byte/water"
	"io"
	"log"
	"net/http"
	"time"
)

// StartServer starts the h2 server
func StartServer(iFace *water.Interface, config config.Config) {
	log.Printf("vtun h2 server started on %v", config.LocalAddr)
	mux := http.NewServeMux()
	mux.Handle(config.Path, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ServeHTTP(writer, request, config, iFace)
	}))
	srv := &http.Server{
		Addr:    config.LocalAddr,
		Handler: mux,
	}
	go toClient(config, iFace)
	log.Fatal(srv.ListenAndServeTLS(config.TLSCertificateFilePath, config.TLSCertificateKeyFilePath))
}

func ServeHTTP(w http.ResponseWriter, r *http.Request, config config.Config, iFace *water.Interface) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	conn, err := Accept(w, r)
	if err != nil {
		log.Printf("Failed creating connection from %s: %s", r.RemoteAddr, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	toServer(conn, config, iFace)
}

// toClient sends packets from tun to h2
func toClient(config config.Config, iFace *water.Interface) {
	packet := make([]byte, config.BufferSize)
	header := make([]byte, xproto.HeaderLength)
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
				xproto.WriteLength(header, len(b))
				n, err = v.(*Conn).Write(xproto.Merge(header, b))
				if err != nil {
					cache.GetCache().Delete(key)
					continue
				}
				counter.IncrWrittenBytes(n)
			}
		}
	}
}

// toServer sends packets from h2 to tun
func toServer(conn *Conn, config config.Config, iFace *water.Interface) {
	defer conn.Close()
	buffer := make([]byte, config.BufferSize)
	header := make([]byte, xproto.HeaderLength)
	for {
		n, err := conn.Read(header)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if n != xproto.HeaderLength {
			netutil.PrintErrF(config.Verbose, "n %d != header_length %d\n", n, xproto.HeaderLength)
			break
		}
		length := xproto.ReadLength(header)
		count, err := conn.Read(buffer[:length])
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if count != length {
			netutil.PrintErrF(config.Verbose, "count %d != length %d\n", count, length)
			break
		}
		b := buffer[:count]
		if config.Compress {
			b, err = snappy.Decode(nil, b)
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				break
			}
		}
		if config.Obfs {
			b = cipher.XOR(b)
		}
		if key := netutil.GetSrcKey(b); key != "" {
			cache.GetCache().Set(key, conn, 24*time.Hour)
			_, err := iFace.Write(b)
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				return
			}
			counter.IncrReadBytes(xproto.HeaderLength + n)
		}
	}
}

var ErrHTTP2NotSupported = fmt.Errorf("HTTP2 not supported")

type Server struct {
	StatusCode int
}

func (u *Server) Accept(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if !r.ProtoAtLeast(2, 0) {
		return nil, ErrHTTP2NotSupported
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, ErrHTTP2NotSupported
	}
	c, ctx := newConn(r.Context(), r.Body, &flushWrite{w: w, f: flusher})
	*r = *r.WithContext(ctx)
	w.WriteHeader(u.StatusCode)
	flusher.Flush()

	return c, nil
}

var defaultUpgrade = Server{
	StatusCode: http.StatusOK,
}

func Accept(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	return defaultUpgrade.Accept(w, r)
}

type flushWrite struct {
	w io.Writer
	f http.Flusher
}

func (w *flushWrite) Write(data []byte) (int, error) {
	n, err := w.w.Write(data)
	w.f.Flush()
	return n, err
}

func (w *flushWrite) Close() error {
	return nil
}
