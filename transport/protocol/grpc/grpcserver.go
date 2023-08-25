package grpc

import (
	"github.com/net-byte/vtun/transport/protocol/grpc/proto"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang/snappy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
)

// The StreamService is the implementation of the StreamServer interface
type StreamService struct {
	proto.UnimplementedGrpcServeServer
	config config.Config
	iface  *water.Interface
}

// Tunnel implements the StreamServer interface
func (s *StreamService) Tunnel(srv proto.GrpcServe_TunnelServer) error {
	toServer(srv, s.config, s.iface)
	return nil
}

// GetHTTPServeMux common HTTP Server
func GetHTTPServeMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("follow"))
	})
	return mux
}

// StartServer starts the grpc server
func StartServer(iface *water.Interface, config config.Config) {
	log.Printf("vtun grpc server started on %v", config.LocalAddr)
	creds, err := credentials.NewServerTLSFromFile(config.TLSCertificateFilePath, config.TLSCertificateKeyFilePath)
	if err != nil {
		log.Panic(err)
	}
	mux := GetHTTPServeMux()
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	proto.RegisterGrpcServeServer(grpcServer, &StreamService{config: config, iface: iface})
	go toClient(config, iface)
	err = http.ListenAndServeTLS(config.LocalAddr, config.TLSCertificateFilePath, config.TLSCertificateKeyFilePath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			mux.ServeHTTP(w, r)
		}
		return
	}))
	if err != nil {
		log.Fatalf("grpc server error: %v", err)
	}
}

// toClient sends packets from tun to grpc
func toClient(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.BufferSize)
	for {
		n, err := iface.Read(packet)
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
				err := v.(proto.GrpcServe_TunnelServer).Send(&proto.PacketData{Data: b})
				if err != nil {
					cache.GetCache().Delete(key)
					continue
				}
				counter.IncrWrittenBytes(n)
			}
		}
	}
}

// toServer sends packets from grpc to tun
func toServer(srv proto.GrpcServe_TunnelServer, config config.Config, iface *water.Interface) {
	for {
		packet, err := srv.Recv()
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		b := packet.Data[:]
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
			cache.GetCache().Set(key, srv, 24*time.Hour)
			iface.Write(b)
			counter.IncrReadBytes(len(b))
		}
	}
}
