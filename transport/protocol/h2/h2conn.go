package h2

import (
	"context"
	"io"
	"sync"
)

type Conn struct {
	r      io.Reader
	wc     io.WriteCloser
	cancel context.CancelFunc
	wLock  sync.Mutex
	rLock  sync.Mutex
}

func newConn(ctx context.Context, r io.Reader, wc io.WriteCloser) (*Conn, context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	return &Conn{
		r:      r,
		wc:     wc,
		cancel: cancel,
	}, ctx
}

func (c *Conn) Write(data []byte) (int, error) {
	c.wLock.Lock()
	defer c.wLock.Unlock()
	return c.wc.Write(data)
}

func (c *Conn) Read(data []byte) (int, error) {
	c.rLock.Lock()
	defer c.rLock.Unlock()
	return c.r.Read(data)
}

func (c *Conn) Close() error {
	c.cancel()
	return c.wc.Close()
}
