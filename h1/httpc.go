package h1

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

var (
	ErrNotServer    = errors.New("may not tunnel server")
	ErrTokenTimeout = errors.New("token may timeout")
)

type NetDialer interface {
	GetProto() string
	Do(req *http.Request, timeout time.Duration) (*http.Response, error)
	DialTimeout(host string, timeout time.Duration) (net.Conn, error)
}

type dialer Client

func (dl dialer) GetProto() string {
	return "http://"
}
func (dl dialer) Do(req *http.Request, timeout time.Duration) (*http.Response, error) {
	client := &http.Client{
		Timeout: timeout,
	}
	return client.Do(req)
}
func (dl dialer) DialTimeout(serverAddr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", serverAddr, timeout)
}

type Client struct {
	TxMethod     string
	RxMethod     string
	TxFlag       string
	RxFlag       string
	TokenCookieA string
	TokenCookieB string
	TokenCookieC string
	UserAgent    string
	Path         string
	Timeout      time.Duration
	Host         string
	ServerAddr   string

	Dialer NetDialer
}

func (cl *Client) getURL() string {
	url := cl.ServerAddr + cl.Path
	return cl.Dialer.GetProto() + url
}

func (cl *Client) getToken() (string, error) {
	req, err := http.NewRequest("GET", cl.getURL(), nil)
	if err != nil {

		return "", err
	}
	if cl.Host != "" {
		req.Header.Set("Host", cl.Host)
	}
	req.Header.Set("User-Agent", cl.UserAgent)
	req.Close = true
	res, err := cl.Dialer.Do(req, cl.Timeout)
	if err != nil {

		return "", err
	}
	defer res.Body.Close()

	_, err = io.ReadAll(res.Body)
	if err != nil {

	}

	return cl.checkToken(res)
}

func (cl *Client) checkToken(res *http.Response) (string, error) {
	cookies := res.Cookies()

	for _, cookie := range cookies {

		if cookie.Name == cl.TokenCookieA {
			return cookie.Value, nil
		}
	}

	return "", ErrNotServer
}

func (cl *Client) getTx(token string) (net.Conn, []byte, error) { //io.WriteCloser
	req, err := http.NewRequest(cl.TxMethod, cl.getURL(), nil)
	if err != nil {

		return nil, nil, err
	}
	if cl.Host != "" {
		req.Header.Set("Host", cl.Host)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "private, no-store, no-cache, max-age=0")
	req.Header.Set("User-Agent", cl.UserAgent)
	req.Header.Set("Cookie", fmt.Sprintf("Tag=follow; %s=%s; %s=%s", cl.TokenCookieB, token, cl.TokenCookieC, cl.TxFlag))

	tx, err := cl.Dialer.DialTimeout(cl.ServerAddr, cl.Timeout)
	if err != nil {
		return nil, nil, err
	}

	req.Write(tx)

	txBuf := bufio.NewReaderSize(tx, 1024)
	res, err := http.ReadResponse(txBuf, req)
	if err != nil {
		tx.Close()
		return nil, nil, err
	}

	_, err = cl.checkToken(res)
	if err == nil {
		tx.Close()
		return nil, nil, ErrTokenTimeout
	}

	txBuf.Buffered()

	return tx, nil, nil
}

func (cl *Client) getRx(token string) (net.Conn, []byte, error) { //io.ReadCloser
	req, err := http.NewRequest(cl.RxMethod, cl.getURL(), nil)
	if err != nil {
		return nil, nil, err
	}
	if cl.Host != "" {
		req.Header.Set("Host", cl.Host)
	}
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "private, no-store, no-cache, max-age=0")
	req.Header.Set("User-Agent", cl.UserAgent)
	req.Header.Set("Cookie", fmt.Sprintf("Tag=follow; %s=%s; %s=%s", cl.TokenCookieB, token, cl.TokenCookieC, cl.RxFlag))
	rx, err := cl.Dialer.DialTimeout(cl.ServerAddr, cl.Timeout)
	if err != nil {
		return nil, nil, err
	}
	req.Write(rx)
	rxBuf := bufio.NewReaderSize(rx, 1024)
	res, err := http.ReadResponse(rxBuf, req)
	if err != nil {
		rx.Close()
		return nil, nil, err
	}

	_, err = cl.checkToken(res)
	if err == nil {
		rx.Close()
		return nil, nil, ErrTokenTimeout
	}

	n := rxBuf.Buffered()
	if n > 0 {
		buf := make([]byte, n)
		rxBuf.Read(buf[:n])
		return rx, buf[:n], nil
	} else {
		return rx, nil, nil
	}
}

func NewClient(serverAddr, host string) *Client {
	if host == "" {
		host = serverAddr
	}
	cl := &Client{
		TxMethod:     txMethod,
		RxMethod:     rxMethod,
		TxFlag:       txFlag,
		RxFlag:       rxFlag,
		TokenCookieA: tokenCookieA,
		TokenCookieB: tokenCookieB,
		TokenCookieC: tokenCookieC,
		UserAgent:    userAgent,
		Path:         path,
		Timeout:      timeout,
		Host:         host,
		ServerAddr:   serverAddr,
	}
	cl.Dialer = dialer(*cl)
	return cl
}

func (cl *Client) Dial() (net.Conn, error) {
	token, err := cl.getToken()
	if token == "" || err != nil {
		return nil, err
	}
	return cl.dial(token)
}

func (cl *Client) dial(token string) (net.Conn, error) {
	type ret struct {
		conn net.Conn
		buf  []byte
		err  error
	}
	txRetCh := make(chan ret, 1)
	rxRetCh := make(chan ret, 1)

	go func() {
		tx, _, err := cl.getTx(token)

		txRetCh <- ret{tx, nil, err}
	}()

	go func() {
		rx, rxBuf, err := cl.getRx(token)

		rxRetCh <- ret{rx, rxBuf, err}
	}()

	txRet := <-txRetCh
	tx, _, txErr := txRet.conn, txRet.buf, txRet.err

	rxRet := <-rxRetCh
	rx, rxBuf, rxErr := rxRet.conn, rxRet.buf, rxRet.err

	if txErr != nil {
		if rx != nil {
			rx.Close()
		}
		return nil, txErr
	}

	if rxErr != nil {
		if tx != nil {
			tx.Close()
		}
		return nil, rxErr
	}

	return mkConn(rx, tx, rxBuf), nil
}
