package h1

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrServerClose = errors.New("server close")
)

type Server struct {
	mx      sync.Mutex
	die     chan struct{}
	dieLock sync.Mutex
	states  map[string]*state
	accepts chan net.Conn
	lis     net.Listener

	cleanerStarted uint32

	TxMethod     string
	RxMethod     string
	TxFlag       string
	RxFlag       string
	TokenCookieA string
	TokenCookieB string
	TokenCookieC string
	HeaderServer string
	HttpHandler  http.Handler
	TokenTTL     time.Duration
}

type state struct {
	IP    string
	mx    sync.Mutex
	connR net.Conn
	bufR  *bufio.ReadWriter
	connW net.Conn
	ttl   time.Time
}

func NewServer(lis net.Listener) *Server {
	srv := &Server{
		lis:          lis,
		states:       make(map[string]*state),
		accepts:      make(chan net.Conn, 128),
		TxMethod:     txMethod,
		RxMethod:     rxMethod,
		TxFlag:       txFlag,
		RxFlag:       rxFlag,
		TokenCookieA: tokenCookieA,
		TokenCookieB: tokenCookieB,
		TokenCookieC: tokenCookieC,
		HeaderServer: headerServer,
		HttpHandler:  http.FileServer(http.Dir("./www")),
		TokenTTL:     tokenTTL,
	}

	return srv
}

func NewHandle(handler http.Handler) *Server {
	srv := &Server{
		states:       make(map[string]*state),
		accepts:      make(chan net.Conn, 128),
		TxMethod:     txMethod,
		RxMethod:     rxMethod,
		TxFlag:       txFlag,
		RxFlag:       rxFlag,
		TokenCookieA: tokenCookieA,
		TokenCookieB: tokenCookieB,
		TokenCookieC: tokenCookieC,
		HeaderServer: headerServer,
		HttpHandler:  handler,
		TokenTTL:     tokenTTL,
	}

	srv.startTokenCleaner()

	return srv
}

// only start 1 goroutine
func (srv *Server) startTokenCleaner() {
	if atomic.CompareAndSwapUint32(&srv.cleanerStarted, 0, 1) {
		go srv.tokenCleaner()
	}
}

func (srv *Server) StartServer() {
	if srv.lis == nil {
		return
	}

	srv.startTokenCleaner()

	http.HandleFunc("/", srv.ServeHTTP)
	go http.Serve(srv.lis, nil)
}

func (srv *Server) Accept() (net.Conn, error) {
	select {
	case <-srv.die:
		return nil, ErrServerClose
	case conn := <-srv.accepts:
		return conn, nil
	}
}

func (srv *Server) Addr() net.Addr {
	if srv.lis == nil {
		return nil
	}
	return srv.lis.Addr()
}

func (srv *Server) Close() error {
	srv.dieLock.Lock()

	select {
	case <-srv.die:
		srv.dieLock.Unlock()
		return ErrServerClose
	default:
		close(srv.die)
		srv.dieLock.Unlock()
		if srv.lis != nil {
			return srv.lis.Close()
		}
		return nil
	}
}

// set cookie: TokenCookieA = XXXX
// try get cookie: TokenCookieB = XXXX
func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var cc *state
	var ok bool
	var err error
	var c, ct *http.Cookie

	c, err = r.Cookie(srv.TokenCookieB) // token
	if err != nil {

		goto FILE
	}

	ct, err = r.Cookie(srv.TokenCookieC) // flag
	if err != nil {

		goto FILE
	}

	cc, ok = srv.checkToken(c.Value)
	if ok {
		if r.Method == srv.RxMethod || r.Method == srv.TxMethod {

		} else {
			goto FILE
		}

		srv.handleNonWs(w, r, c.Value, ct.Value, cc)
		return
	}

FILE:
	srv.handleBase(w, r)
}

func (srv *Server) handleBase(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("Server", srv.HeaderServer)
	token := randStringBytes(16)
	expiration := time.Now().AddDate(0, 0, 3)
	cookie := http.Cookie{Name: srv.TokenCookieA, Value: token, Expires: expiration}
	http.SetCookie(w, &cookie)
	srv.regToken(token)

	srv.HttpHandler.ServeHTTP(w, r)
}

func (srv *Server) handleWs(w http.ResponseWriter, r *http.Request, token string, flag string, cc *state) {

	ip := r.Header.Get("Cf-Connecting-Ip")

	hj, ok := w.(http.Hijacker)
	if !ok {

		return
	}

	conn, bufRW, err := hj.Hijack()
	if err != nil {
		return
	}

	bufRW.Flush()

	conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + token + "\r\n\r\n"))

	cc.mx.Lock()
	defer cc.mx.Unlock()
	if r.Method == srv.RxMethod && flag == srv.RxFlag {

		srv.rmToken(token)
		srv.accepts <- mkConnAddr(conn, ip)
	}

}

func (srv *Server) handleNonWs(w http.ResponseWriter, r *http.Request, token string, flag string, cc *state) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		srv.handleBase(w, r)
		return
	}
	header := w.Header()
	header.Set("Cache-Control", "private, no-store, no-cache, max-age=0")
	header.Set("Content-Encoding", "gzip")
	flusher.Flush()

	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}

	conn, bufRW, err := hj.Hijack()
	if err != nil {
		return
	}

	bufRW.Flush()

	cc.mx.Lock()
	defer cc.mx.Unlock()
	if r.Method == srv.RxMethod && flag == srv.RxFlag {
		cc.connW = conn
	}
	if r.Method == srv.TxMethod && flag == srv.TxFlag {
		cc.connR = conn
		cc.bufR = bufRW
	}
	if cc.connR != nil && cc.connW != nil {
		srv.rmToken(token)

		n := cc.bufR.Reader.Buffered()
		buf := make([]byte, n)
		cc.bufR.Reader.Read(buf[:n])
		srv.accepts <- mkConn(cc.connR, cc.connW, buf[:n])
	}

}

func (srv *Server) regToken(token string) {
	srv.mx.Lock()
	defer srv.mx.Unlock()

	_, ok := srv.states[token]
	if ok {

	}
	srv.states[token] = &state{
		ttl: time.Now().Add(srv.TokenTTL),
	}
}
func (srv *Server) checkToken(token string) (*state, bool) {
	srv.mx.Lock()
	defer srv.mx.Unlock()

	c, ok := srv.states[token]
	if !ok {
		return nil, false
	}
	if time.Now().After(c.ttl) {
		delete(srv.states, token)
		return nil, false
	}
	return c, true
}
func (srv *Server) rmToken(token string) {
	srv.mx.Lock()
	defer srv.mx.Unlock()

	_, ok := srv.states[token]
	if !ok {
		return
	}

	delete(srv.states, token)

	return
}

func (srv *Server) tokenCleaner() {
	ticker := time.NewTicker(tokenClean)
	defer ticker.Stop()
	for {
		select {
		case <-srv.die:
			return
		case <-ticker.C:
		}

		list := make([]*state, 0)

		srv.mx.Lock()
		for idx, c := range srv.states {
			if time.Now().After(c.ttl) {
				delete(srv.states, idx)
				list = append(list, c)

			}
		}
		srv.mx.Unlock()

		// check and close half open connection
		for _, cc := range list {
			cc.mx.Lock()
			if cc.connR == nil && cc.connW != nil {
				cc.connW.Close()
				cc.connW = nil

			}
			if cc.connR != nil && cc.connW == nil {
				cc.connR.Close()
				cc.connR = nil

			}
			cc.mx.Unlock()
		}
	}
}
