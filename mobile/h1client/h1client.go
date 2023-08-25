package h1client

import (
	"context"
	"github.com/net-byte/vtun/common/x/xchan"
	kc "github.com/net-byte/vtun/mobile/config"
	"github.com/net-byte/vtun/transport/protocol/h1"
)

var _ctx context.Context
var cancel context.CancelFunc

var _chR *xchan.UnboundedChan[[]byte]
var _chW *xchan.UnboundedChan[[]byte]

func Init() {
	_ctx, cancel = context.WithCancel(context.Background())
	_chR = xchan.NewUnboundedChan[[]byte](_ctx, 1000)
	_chW = xchan.NewUnboundedChan[[]byte](_ctx, 1000)
}

func StartClient() {
	h1.StartClientForApi(
		kc.Config, _chW.Out, _chR.In,
		func(n int) {},
		func(n int) {},
		_ctx,
	)
}

func Read(bts []byte) int {
	r := <-_chR.Out
	n := len(r)
	copy(bts[:n], r)
	return n
}

func Write(bts []byte) int {
	n := len(bts)
	var buf = make([]byte, n)
	copy(buf[:], bts[:])
	_chW.In <- bts
	return n
}

func Close() {
	cancel()
}
