package h1

import (
	"crypto/tls"
	"github.com/net-byte/vtun/common/config"
	"net"
	"net/http"
	"time"
)

type dialerT struct {
	Transport *http.Transport
	TLSConfig *tls.Config
}

func (dl *dialerT) GetProto() string {
	return "https://"
}

func (dl *dialerT) Do(req *http.Request, timeout time.Duration) (*http.Response, error) {
	client := &http.Client{
		Timeout: timeout,
	}
	client.Transport = dl.Transport
	return client.Do(req)
}

func (dl *dialerT) DialTimeout(host string, timeout time.Duration) (net.Conn, error) {
	tx, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		return nil, err
	}
	tx = tls.Client(tx, dl.TLSConfig)
	return tx, nil
}

func NewTLSClient(config config.Config) *Client {
	cl := NewClient(config.ServerAddr)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.TLSInsecureSkipVerify,
	}

	if config.TLSSni != "" {
		tlsConfig.ServerName = config.TLSSni
	}

	Transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	cl.Dialer = &dialerT{
		TLSConfig: tlsConfig,
		Transport: Transport,
	}

	return cl
}
