package grpc

import (
	"context"
	"crypto/tls"
	"github.com/net-byte/vtun/grpc/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io"
	"log"
	"time"

	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/tun"
	"github.com/songgao/water"
)

func StartClient(config config.Config) {
	log.Printf("vtun grpc client started on %v", config.LocalAddr)
	tlsconfig := &tls.Config{
		InsecureSkipVerify: config.TLSInsecureSkipVerify,
	}
	if config.TLSSni != "" {
		tlsconfig.ServerName = config.TLSSni
	}
	creds := credentials.NewTLS(tlsconfig)
	iface := tun.CreateTun(config)
	conn, err := grpc.Dial(config.ServerAddr, grpc.WithBlock(), grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Panic(err)
	}
	defer conn.Close()
	streamClient := proto.NewGrpcServeClient(conn)
	stream, err := streamClient.Tunnel(context.Background())
	if err != nil {
		log.Panic(err)
	}
	go tunToGrpc(config, iface)
	for {
		cache.GetCache().Set("grpcconn", stream, 24*time.Hour)
		grpcToTun(config, stream, iface)
		cache.GetCache().Delete("grpcconn")
	}
}

func tunToGrpc(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.MTU)
	for {
		n, err := iface.Read(packet)
		if err != nil || n == 0 {
			continue
		}
		if v, ok := cache.GetCache().Get("grpcconn"); ok {
			b := packet[:n]
			if config.Obfs {
				packet = cipher.XOR(packet)
			}
			grpcconn := v.(proto.GrpcServe_TunnelClient)
			err = grpcconn.Send(&proto.PacketData{Data: b})
			if err != nil {
				continue
			}
		}
	}
}

func grpcToTun(config config.Config, stream proto.GrpcServe_TunnelClient, iface *water.Interface) {
	for {
		packet, err := stream.Recv()
		if err != nil || err == io.EOF {
			break
		}
		b := packet.Data[:]
		if config.Obfs {
			b = cipher.XOR(b)
		}
		_, err = iface.Write(b)
		if err != nil {
			break
		}
	}
}
