package grpc

import (
	"context"
	"crypto/tls"
	"log"
	"time"

	"github.com/net-byte/vtun/transport/protocol/grpc/proto"

	"github.com/golang/snappy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
)

// StartClient starts the grpc client
func StartClient(iface *water.Interface, config config.Config) {
	log.Println("vtun grpc client started")
	go tunToGrpc(config, iface)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.TLSInsecureSkipVerify,
	}
	if config.TLSSni != "" {
		tlsConfig.ServerName = config.TLSSni
	}

	creds := credentials.NewTLS(tlsConfig)

	var heartbeat = keepalive.ClientParameters{
		Time:                10 * time.Second, // send pings every 10 seconds if there is no activity
		Timeout:             10 * time.Second, // wait 10 second for ping ack before considering the connection dead
		PermitWithoutStream: true,             // send pings even without active streams
	}
	for {
		conn, err := grpc.Dial(config.ServerAddr,
			grpc.WithBlock(),
			grpc.WithTransportCredentials(creds),
			grpc.WithKeepaliveParams(heartbeat),
		)
		if err != nil {
			time.Sleep(3 * time.Second)
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		streamClient := proto.NewGrpcServeClient(conn)
		stream, err := streamClient.Tunnel(context.Background())
		if err != nil {
			conn.Close()
			netutil.PrintErr(err, config.Verbose)
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
	packet := make([]byte, config.BufferSize)
	for {
		n, err := iface.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
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
				netutil.PrintErr(err, config.Verbose)
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
		_, err = iface.Write(b)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		counter.IncrReadBytes(len(b))
	}
}
