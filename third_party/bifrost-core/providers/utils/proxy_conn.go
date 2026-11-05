package utils

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

// httpProxyDialer returns a connection before its TCP dial and CONNECT exchange.
// The transport can then close it when the request ends during either step.
func httpProxyDialer(rawURL string) fasthttp.DialFunc {
	// The proxy configuration also accepts an address without a URL scheme.
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	proxyURL, err := url.Parse(rawURL)
	if err != nil || proxyURL.Scheme != "http" || proxyURL.Path != "" {
		return dialErrorFunc("invalid HTTP proxy URL")
	}
	proxyAddr := proxyURL.Host
	if proxyAddr == "" {
		return dialErrorFunc("invalid HTTP proxy address")
	}
	if proxyURL.Port() == "" {
		proxyAddr = net.JoinHostPort(proxyURL.Hostname(), "80")
	}
	auth := ""
	if proxyURL.User != nil {
		// Match fasthttpproxy's Basic authentication encoding.
		auth = base64.StdEncoding.EncodeToString([]byte(proxyURL.User.String()))
	}
	return func(target string) (net.Conn, error) {
		if strings.ContainsAny(target, "\r\n") {
			return nil, errors.New("invalid proxy target address")
		}
		ctx, cancel := context.WithCancel(context.Background())
		return &httpProxyConn{proxyAddr: proxyAddr, target: target, auth: auth, ctx: ctx, cancel: cancel}, nil
	}
}

// httpProxyConn postpones network work until RoundTrip has installed its
// cancellation watcher and deadline. Close interrupts both DialContext and
// an unfinished CONNECT response.
type httpProxyConn struct {
	proxyAddr string
	target    string
	auth      string
	ctx       context.Context
	cancel    context.CancelFunc
	once      sync.Once
	initErr   error
	reader    *bufio.Reader

	mu            sync.Mutex
	conn          net.Conn
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time
}

func (c *httpProxyConn) initialize() error {
	c.once.Do(func() { c.initErr = c.connect() })
	return c.initErr
}

func (c *httpProxyConn) connect() error {
	c.mu.Lock()
	deadline := c.writeDeadline
	c.mu.Unlock()
	ctx := c.ctx
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	conn, err := (&net.Dialer{KeepAliveConfig: net.KeepAliveConfig{
		Enable: true, Idle: 10 * time.Second, Interval: 5 * time.Second, Count: 3,
	}}).DialContext(ctx, "tcp", c.proxyAddr)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return net.ErrClosed
	}
	c.conn = conn
	err = conn.SetReadDeadline(c.readDeadline)
	if err == nil {
		err = conn.SetWriteDeadline(c.writeDeadline)
	}
	c.mu.Unlock()
	if err != nil {
		_ = conn.Close()
		return err
	}
	request := "CONNECT " + c.target + " HTTP/1.1\r\nHost: " + c.target + "\r\n"
	if c.auth != "" {
		request += "Proxy-Authorization: Basic " + c.auth + "\r\n"
	}
	request += "\r\n"
	n, err := io.WriteString(conn, request)
	if err == nil && n != len(request) {
		err = io.ErrShortWrite
	}
	if err != nil {
		_ = conn.Close()
		return err
	}
	reader := bufio.NewReaderSize(conn, 1024)
	var response fasthttp.ResponseHeader
	if err := response.Read(reader); err != nil {
		_ = conn.Close()
		return err
	}
	if response.StatusCode() != fasthttp.StatusOK {
		_ = conn.Close()
		return fmt.Errorf("proxy CONNECT returned status %d", response.StatusCode())
	}
	c.reader = reader
	return nil
}

func (c *httpProxyConn) Read(p []byte) (int, error) {
	if err := c.initialize(); err != nil {
		return 0, err
	}
	return c.reader.Read(p)
}

func (c *httpProxyConn) Write(p []byte) (int, error) {
	if err := c.initialize(); err != nil {
		return 0, err
	}
	return c.conn.Write(p)
}

func (c *httpProxyConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *httpProxyConn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.LocalAddr()
	}
	return &net.TCPAddr{}
}

func (c *httpProxyConn) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.RemoteAddr()
	}
	return &net.TCPAddr{}
}

func (c *httpProxyConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.readDeadline, c.writeDeadline = t, t
	if c.conn != nil {
		return c.conn.SetDeadline(t)
	}
	return nil
}

func (c *httpProxyConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.readDeadline = t
	if c.conn != nil {
		return c.conn.SetReadDeadline(t)
	}
	return nil
}

func (c *httpProxyConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.writeDeadline = t
	if c.conn != nil {
		return c.conn.SetWriteDeadline(t)
	}
	return nil
}
