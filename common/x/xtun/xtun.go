package xtun

import (
	"context"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/common/x/xproto"
	"github.com/net-byte/water"
)

func ReadFromTun(iFace *water.Interface, config config.Config, out chan<- []byte, _ctx context.Context) {
	packet := make([]byte, config.BufferSize)
	for ContextOpened(_ctx) {
		n, err := iFace.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		out <- xproto.Copy(packet[:n])
	}
}

func WriteToTun(iFace *water.Interface, config config.Config, in <-chan []byte, _ctx context.Context) {
	for ContextOpened(_ctx) {
		b := <-in
		_, err := iFace.Write(b)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
	}
}

func ContextOpened(_ctx context.Context) bool {
	select {
	case <-_ctx.Done():
		return false
	default:
		return true
	}
}
