package grpc

import (
	"context"
	"crypto/tls"
	"log"
	"time"

	"github.com/golang/snappy"
	"github.com/net-byte/vtun/grpc/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/water"
)

// StartClient starts the grpc client
func StartClient(iface *water.Interface, config config.Config) {
	log.Printf("vtun grpc client started on %v", config.LocalAddr)
	go tunToGrpc(config, iface)
	tlsconfig := &tls.Config{
		InsecureSkipVerify: config.TLSInsecureSkipVerify,
	}
	if config.TLSSni != "" {
		tlsconfig.ServerName = config.TLSSni
	}
	creds := credentials.NewTLS(tlsconfig)
	for {
		conn, err := grpc.Dial(config.ServerAddr, grpc.WithBlock(), grpc.WithTransportCredentials(creds))
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		streamClient := proto.NewGrpcServeClient(conn)
		stream, err := streamClient.Tunnel(context.Background())
		if err != nil {
			conn.Close()
			continue
		}
		cache.GetCache().Set("grpcconn", stream, 24*time.Hour)
		grpcToTun(config, stream, iface)
		cache.GetCache().Delete("grpcconn")
		conn.Close()
	}
}

// tunToGrpc sends packets from tun to grpc
func tunToGrpc(config config.Config, iface *water.Interface) {
	packet := make([]byte, 4096)
	for {
		n, err := iface.Read(packet)
		if err != nil || n == 0 {
			continue
		}
		if v, ok := cache.GetCache().Get("grpcconn"); ok {
			b := packet[:n]
			if config.Obfs {
				b = cipher.XOR(b)
			}
			if config.Compress {
				b = snappy.Encode(nil, b)
			}
			grpcconn := v.(proto.GrpcServe_TunnelClient)
			err = grpcconn.Send(&proto.PacketData{Data: b})
			if err != nil {
				continue
			}
			counter.IncrWrittenBytes(n)
		}
	}
}

// grpcToTun sends packets from grpc to tun
func grpcToTun(config config.Config, stream proto.GrpcServe_TunnelClient, iface *water.Interface) {
	for {
		packet, err := stream.Recv()
		if err != nil {
			break
		}
		b := packet.Data[:]
		if config.Compress {
			b, err = snappy.Decode(nil, b)
			if err != nil {
				break
			}
		}
		if config.Obfs {
			b = cipher.XOR(b)
		}
		_, err = iface.Write(b)
		if err != nil {
			break
		}
		counter.IncrReadBytes(len(b))
	}
}
