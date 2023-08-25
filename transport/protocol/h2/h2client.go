package h2

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/common/xproto"
	"github.com/net-byte/vtun/common/xtun"
	"github.com/net-byte/water"
	"golang.org/x/net/http2"
	"io"
	"log"
	"net/http"
	"time"
)

const ConnTag = "h2conn"

var _ctx context.Context
var cancel context.CancelFunc

func StartClientForApi(config config.Config, outputStream <-chan []byte, inputStream chan<- []byte, writeCallback, readCallback func(int), _ctx context.Context) {
	go tunToH2(config, outputStream, _ctx, readCallback)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.TLSInsecureSkipVerify,
	}
	if config.TLSSni != "" {
		tlsConfig.ServerName = config.TLSSni
	}
	httpHeader := http.Header{}
	httpHeader.Add("Accept-Encoding", "identity")
	client := &Client{
		Client: &http.Client{
			Transport: &http2.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
		Header: httpHeader,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for xtun.ContextOpened(_ctx) {
		conn, resp, err := client.Connect(ctx, fmt.Sprintf("https://%s%s", config.ServerAddr, config.Path))
		if err != nil {
			time.Sleep(3 * time.Second)
			netutil.PrintErrF(config.Verbose, "Initiate conn: %s\n", err)
			continue
		}
		defer conn.Close()
		if resp.StatusCode != http.StatusOK {
			time.Sleep(3 * time.Second)
			netutil.PrintErrF(config.Verbose, "bad status code: %d\n", resp.StatusCode)
			continue
		}
		cache.GetCache().Set(ConnTag, conn, 24*time.Hour)
		h2ToTun(config, conn, inputStream, _ctx, writeCallback)
		cache.GetCache().Delete(ConnTag)
		conn.Close()
	}
}

// StartClient starts the h2 client
func StartClient(iFace *water.Interface, config config.Config) {
	log.Println("vtun h2 client started")
	_ctx, cancel = context.WithCancel(context.Background())
	outputStream := make(chan []byte, 1000)
	go xtun.ReadFromTun(iFace, config, outputStream, _ctx)
	inputStream := make(chan []byte, 1000)
	go xtun.WriteToTun(iFace, config, inputStream, _ctx)
	StartClientForApi(
		config, outputStream, inputStream,
		func(n int) { counter.IncrWrittenBytes(n) },
		func(n int) { counter.IncrReadBytes(n) },
		_ctx,
	)
}

// tunToH2 sends packets from tun to h2
func tunToH2(config config.Config, outputStream <-chan []byte, _ctx context.Context, callback func(int)) {
	header := make([]byte, xproto.HeaderLength)
	for xtun.ContextOpened(_ctx) {
		b := <-outputStream
		if v, ok := cache.GetCache().Get(ConnTag); ok {
			if config.Obfs {
				b = cipher.XOR(b)
			}
			if config.Compress {
				b = snappy.Encode(nil, b)
			}
			xproto.WriteLength(header, len(b))
			conn := v.(*Conn)
			n, err := conn.Write(xproto.Merge(header, b))
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			callback(n)
		}
	}
}

// h2ToTun sends packets from h2 to tun
func h2ToTun(config config.Config, conn *Conn, inputStream chan<- []byte, _ctx context.Context, callback func(int)) {
	defer conn.Close()
	buffer := make([]byte, config.BufferSize)
	header := make([]byte, xproto.HeaderLength)
	for xtun.ContextOpened(_ctx) {
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
		inputStream <- xproto.Copy(b)
		callback(n)
	}
}

type Client struct {
	Method string
	Header http.Header
	Client *http.Client
}

func (c *Client) Connect(ctx context.Context, urlStr string) (*Conn, *http.Response, error) {
	reader, writer := io.Pipe()
	req, err := http.NewRequest(c.Method, urlStr, reader)
	if err != nil {
		return nil, nil, err
	}
	req.Proto = "HTTP/2"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	if c.Header != nil {
		req.Header = c.Header
	}
	req = req.WithContext(ctx)
	httpClient := c.Client
	if httpClient == nil {
		httpClient = defaultClient.Client
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		reader.Close()
		writer.Close()
		return nil, nil, err
	}
	conn, ctx := newConn(req.Context(), resp.Body, writer)
	resp.Request = req.WithContext(ctx)
	return conn, resp, nil
}

var defaultClient = Client{
	Method: http.MethodPost,
	Client: &http.Client{Transport: &http2.Transport{}},
}

func Close() {
	cancel()
}
