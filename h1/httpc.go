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
	Do(req *http.Request, timeout time.Duration) (*http.Response, error) // http.Client
	DialTimeout(host string, timeout time.Duration) (net.Conn, error)    // net.DialTimeout("tcp", Host, Timeout)
}

type dialNonTLS Client

func (dl dialNonTLS) GetProto() string {
	return "http://"
}
func (dl dialNonTLS) Do(req *http.Request, timeout time.Duration) (*http.Response, error) {
	client := &http.Client{
		Timeout: timeout,
	}
	return client.Do(req)
}
func (dl dialNonTLS) DialTimeout(host string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", host, timeout)
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
	Url          string
	Timeout      time.Duration
	Host         string

	Dialer NetDialer
}

func (cl *Client) getURL() string {
	url := cl.Host + cl.Url
	return cl.Dialer.GetProto() + url
}

func (cl *Client) getToken() (string, error) {
	req, err := http.NewRequest("GET", cl.getURL(), nil)
	if err != nil {

		return "", err
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

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "private, no-store, no-cache, max-age=0")
	req.Header.Set("User-Agent", cl.UserAgent)
	req.Header.Set(cl.TokenCookieB, token)
	req.Header.Set(cl.TokenCookieC, cl.RxFlag)
	req.Header.Set("Cookie", fmt.Sprintf("Tag=follow; %s=%s; %s=%s", cl.TokenCookieB, token, cl.TokenCookieC, cl.TxFlag))

	tx, err := cl.Dialer.DialTimeout(cl.Host, cl.Timeout)
	if err != nil {

		return nil, nil, err
	}

	req.Write(tx)

	txbuf := bufio.NewReaderSize(tx, 1024)

	res, err := http.ReadResponse(txbuf, req)
	if err != nil {

		tx.Close()
		return nil, nil, err
	}

	_, err = cl.checkToken(res)
	if err == nil {
		tx.Close()
		return nil, nil, ErrTokenTimeout
	}

	txbuf.Buffered()

	return tx, nil, nil
}

func (cl *Client) getRx(token string) (net.Conn, []byte, error) { //io.ReadCloser

	req, err := http.NewRequest(cl.RxMethod, cl.getURL(), nil)
	if err != nil {

		return nil, nil, err
	}

	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "private, no-store, no-cache, max-age=0")
	req.Header.Set("User-Agent", cl.UserAgent)
	req.Header.Set(cl.TokenCookieB, token)
	req.Header.Set(cl.TokenCookieC, cl.RxFlag)
	req.Header.Set("Cookie", fmt.Sprintf("Tag=follow; %s=%s; %s=%s", cl.TokenCookieB, token, cl.TokenCookieC, cl.RxFlag))

	rx, err := cl.Dialer.DialTimeout(cl.Host, cl.Timeout)
	if err != nil {

		return nil, nil, err
	}

	req.Write(rx)

	rxbuf := bufio.NewReaderSize(rx, 1024)

	res, err := http.ReadResponse(rxbuf, req)
	if err != nil {

		rx.Close()
		return nil, nil, err
	}

	_, err = cl.checkToken(res)
	if err == nil {
		rx.Close()
		return nil, nil, ErrTokenTimeout
	}

	n := rxbuf.Buffered()

	if n > 0 {
		buf := make([]byte, n)
		rxbuf.Read(buf[:n])
		return rx, buf[:n], nil
	} else {
		return rx, nil, nil
	}
}

func NewClient(target string) *Client {
	cl := &Client{
		TxMethod:     txMethod,
		RxMethod:     rxMethod,
		TxFlag:       txFlag,
		RxFlag:       rxFlag,
		TokenCookieA: tokenCookieA,
		TokenCookieB: tokenCookieB,
		TokenCookieC: tokenCookieC,
		UserAgent:    userAgent,
		Url:          targetUrl,
		Timeout:      timeout,
		Host:         target,
	}
	cl.Dialer = dialNonTLS(*cl)
	return cl
}

func Dial(target string) (net.Conn, error) {
	cl := NewClient(target)
	return cl.Dial()
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
		rx, rxbuf, err := cl.getRx(token)

		rxRetCh <- ret{rx, rxbuf, err}
	}()

	txRet := <-txRetCh
	tx, _, txErr := txRet.conn, txRet.buf, txRet.err

	rxRet := <-rxRetCh
	rx, rxbuf, rxErr := rxRet.conn, rxRet.buf, rxRet.err

	if txErr != nil {
		if rx != nil { // close other side, no half open
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

	return mkConn(rx, tx, rxbuf), nil
}
