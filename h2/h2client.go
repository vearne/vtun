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
	"github.com/net-byte/water"
	"golang.org/x/net/http2"
	"io"
	"log"
	"net/http"
	"time"
)

// StartClient starts the h2 client
func StartClient(iFace *water.Interface, config config.Config) {
	log.Println("vtun h2 client started")
	go tunToH2(config, iFace)
	tlsconfig := &tls.Config{
		InsecureSkipVerify: config.TLSInsecureSkipVerify,
	}
	if config.TLSSni != "" {
		tlsconfig.ServerName = config.TLSSni
	}
	client := &Client{
		Client: &http.Client{
			Transport: &http2.Transport{
				TLSClientConfig: tlsconfig,
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for {
		conn, resp, err := client.Connect(ctx, fmt.Sprintf("https://%s%s", config.ServerAddr, config.WebSocketPath))
		if err != nil {
			log.Fatalf("Initiate conn: %s\n", err)
		}
		defer conn.Close()
		if resp.StatusCode != http.StatusOK {
			log.Fatalf("bad status code: %d\n", resp.StatusCode)
		}
		cache.GetCache().Set("h2conn", conn, 24*time.Hour)
		h2ToTun(config, conn, iFace)
		cache.GetCache().Delete("h2conn")
		conn.Close()
	}
}

// tunToH2 sends packets from tun to h2
func tunToH2(config config.Config, iFace *water.Interface) {
	packet := make([]byte, config.BufferSize)
	for {
		n, err := iFace.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		if v, ok := cache.GetCache().Get("h2conn"); ok {
			b := packet[:n]
			if config.Obfs {
				b = cipher.XOR(b)
			}
			if config.Compress {
				b = snappy.Encode(nil, b)
			}
			conn := v.(*Conn)
			n, err = conn.Write(b)
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				continue
			}
			counter.IncrWrittenBytes(n)
		}
	}
}

// h2ToTun sends packets from h2 to tun
func h2ToTun(config config.Config, conn *Conn, iFace *water.Interface) {
	packet := make([]byte, config.BufferSize)
	for {
		n, err := conn.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		b := packet[:n]
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
		_, err = iFace.Write(b)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		counter.IncrReadBytes(len(b))
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
