// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// actorHost is the authority inside the tunnel. The router routes on the
// ate-target-actor header, not on this name, and .invalid never resolves,
// so nothing can reach it by accident outside the tunnel.
const actorHost = "actor.invalid"

const (
	connectTimeout   = 45 * time.Second
	handshakeTimeout = 45 * time.Second
)

// Errors a TunnelError unwraps to.
var (
	ErrClusterFull = errors.New("the cluster is full")
	ErrNotAllowed  = errors.New("the cluster refused this connection (not allowed to reach this actor)")
	ErrNoActor     = errors.New("no such running actor")
	ErrCertRefused = errors.New("the router refused the client certificate")
	// ErrSessionRefused is what a SessionSource wraps when the person may
	// not reach the actor.
	ErrSessionRefused = errors.New("not allowed to reach this actor")
)

// TunnelError is a refusal by the router, or by the cluster inside the
// tunnel. Kind is one of ErrClusterFull, ErrNotAllowed, ErrNoActor,
// ErrCertRefused or nil (another status).
type TunnelError struct {
	Status     int
	RetryAfter time.Duration
	Target     Target
	Kind       error
}

func (e *TunnelError) Error() string {
	switch e.Kind {
	case ErrClusterFull:
		return fmt.Sprintf("the cluster is full (status %d)", e.Status)
	case ErrNotAllowed:
		return ErrNotAllowed.Error() + ": " + e.Target.String()
	case ErrNoActor:
		return ErrNoActor.Error() + ": " + e.Target.String()
	case ErrCertRefused:
		return ErrCertRefused.Error() + " (check the router certificate and key of this context, or sign in again)"
	}
	return fmt.Sprintf("the router answered %d %s", e.Status, http.StatusText(e.Status))
}

// Unwrap returns Kind.
func (e *TunnelError) Unwrap() error { return e.Kind }

// transient: another server error from the router, worth a retry.
func (e *TunnelError) transient() bool { return e.Kind == nil && e.Status >= 500 }

func statusError(status int, h http.Header, t Target) *TunnelError {
	e := &TunnelError{Status: status, Target: t}
	switch status {
	case http.StatusServiceUnavailable, http.StatusTooManyRequests:
		e.Kind = ErrClusterFull
		if h != nil {
			e.RetryAfter = parseRetryAfter(h.Get("Retry-After"), time.Now())
		}
	case http.StatusUnauthorized, http.StatusForbidden:
		e.Kind = ErrNotAllowed
	case http.StatusNotFound:
		e.Kind = ErrNoActor
	}
	return e
}

func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	if d < 0 {
		return 0
	}
	if d > time.Minute {
		d = time.Minute
	}
	return d
}

func retryAfterOf(err error) time.Duration {
	var te *TunnelError
	if errors.As(err, &te) {
		return te.RetryAfter
	}
	return 0
}

// dialError is a failure to reach the router. A fatal one is a setting to
// fix, not a network blip.
type dialError struct {
	what  string
	err   error
	fatal bool
}

func (e *dialError) Error() string {
	if e.err == nil {
		return e.what
	}
	return e.what + ": " + e.err.Error()
}
func (e *dialError) Unwrap() error { return e.err }

// fatalError is never retried.
type fatalError struct{ err error }

func (e *fatalError) Error() string { return e.err.Error() }
func (e *fatalError) Unwrap() error { return e.err }

var relayStatusRE = regexp.MustCompile(`\(status (\d{3})\)`)

// relayStatus reads the HTTP status of a refusal from the relay client's
// error ("relay refused the attachment (status N)").
func relayStatus(err error) int {
	if err == nil {
		return 0
	}
	m := relayStatusRE.FindStringSubmatch(err.Error())
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

func isBadHandshake(err error) bool { return errors.Is(err, websocket.ErrBadHandshake) }

type proxyFunc func(*http.Request) (*url.URL, error)

// Tunnel reaches one actor's relay through the router: every connection it
// dials is a new TLS connection to the router (TLS 1.3, mTLS when a client
// certificate is configured) with a CONNECT to the actor.
type Tunnel struct {
	target     Target
	routerURL  *url.URL
	routerHost string
	routerAddr string
	port       int
	tlsConf    *tls.Config
	dialRaw    func(ctx context.Context, network, addr string) (net.Conn, error)
	proxy      proxyFunc
	tr         *http.Transport
	client     *http.Client
	ws         *websocket.Dialer
}

// NewTunnel checks the router settings and the client certificate and
// returns a Tunnel. It dials nothing: the first request does.
func NewTunnel(ctx context.Context, r Router, g SessionGrant, t Target) (*Tunnel, error) {
	_ = ctx
	if t.Atespace == "" || t.Name == "" {
		return nil, errors.New("no actor named: an actor is atespace/name")
	}
	if strings.ContainsAny(t.String(), "\r\n\t ") {
		return nil, fmt.Errorf("actor name %q is not valid", t.String())
	}
	u, err := url.Parse(strings.TrimSpace(r.URL))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, errors.New("the router URL of this context must look like https://HOST:PORT")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	rp := r.RelayPort
	if rp == 0 {
		rp = 8080
	}
	if rp < 1 || rp > 65535 {
		return nil, fmt.Errorf("relay port %d is not a TCP port", rp)
	}
	conf := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: u.Hostname(), NextProtos: []string{"http/1.1"}}
	if r.CAFile != "" {
		pem, err := os.ReadFile(r.CAFile)
		if err != nil {
			return nil, fmt.Errorf("router CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("router CA file %s holds no certificate", r.CAFile)
		}
		conf.RootCAs = pool
	}
	switch {
	case len(g.ClientCertPEM) > 0 || len(g.ClientKeyPEM) > 0:
		if len(g.ClientCertPEM) == 0 || len(g.ClientKeyPEM) == 0 {
			return nil, errors.New("the session carries half a client certificate (certificate or key missing)")
		}
		c, err := tls.X509KeyPair(g.ClientCertPEM, g.ClientKeyPEM)
		if err != nil {
			return nil, errors.New("the session's client certificate is not usable (certificate and key do not parse or do not match)")
		}
		conf.Certificates = []tls.Certificate{c}
	case r.CertFile != "" || r.KeyFile != "":
		if r.CertFile == "" || r.KeyFile == "" {
			return nil, errors.New("the router client certificate needs both a certificate file and a key file")
		}
		c, err := tls.LoadX509KeyPair(r.CertFile, r.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("router client certificate %s and key %s are not usable: %s", r.CertFile, r.KeyFile, safeTLSLoadErr(err))
		}
		conf.Certificates = []tls.Certificate{c}
	}
	tu := &Tunnel{target: t, routerURL: u, routerHost: u.Hostname(), routerAddr: net.JoinHostPort(u.Hostname(), port), port: rp, tlsConf: conf}
	tu.dialRaw = r.dial
	if tu.dialRaw == nil {
		tu.dialRaw = (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	tu.proxy = r.proxy
	if tu.proxy == nil {
		tu.proxy = http.ProxyFromEnvironment
	}
	tu.tr = &http.Transport{
		DialContext:           tu.DialContext,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       60 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	tu.client = &http.Client{Transport: tu.tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	tu.ws = &websocket.Dialer{NetDialContext: tu.DialContext, HandshakeTimeout: handshakeTimeout, ReadBufferSize: 32 << 10, WriteBufferSize: 32 << 10}
	return tu, nil
}

// safeTLSLoadErr keeps the reason of a key pair load error, which names a
// file problem or a parse failure and never key material.
func safeTLSLoadErr(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// BaseURL is the relay's origin inside the tunnel.
func (tu *Tunnel) BaseURL() string { return "http://" + tu.actorAddr() }

// HTTPClient sends requests through the tunnel. It never follows redirects.
func (tu *Tunnel) HTTPClient() *http.Client { return tu.client }

// Dialer dials WebSocket through the tunnel.
func (tu *Tunnel) Dialer() *websocket.Dialer { return tu.ws }

// Close drops idle tunnel connections.
func (tu *Tunnel) Close() { tu.tr.CloseIdleConnections() }

func (tu *Tunnel) actorAddr() string { return net.JoinHostPort(actorHost, strconv.Itoa(tu.port)) }

// DialContext opens a new tunnel to the actor. addr must be the actor
// authority (BaseURL's host).
func (tu *Tunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if addr != tu.actorAddr() {
		return nil, fmt.Errorf("the tunnel reaches only the actor, not %s", addr)
	}
	return tu.dial(ctx)
}

// deadlineFor sets a deadline on c from ctx (or d) and makes ctx
// cancellation interrupt it. The returned func clears both.
func deadlineFor(ctx context.Context, c net.Conn, d time.Duration) func() bool {
	dl := time.Now().Add(d)
	if cd, ok := ctx.Deadline(); ok && cd.Before(dl) {
		dl = cd
	}
	_ = c.SetDeadline(dl)
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	return func() bool {
		ok := stop()
		_ = c.SetDeadline(time.Time{})
		return ok
	}
}

func (tu *Tunnel) dial(ctx context.Context) (net.Conn, error) {
	raw, err := tu.dialRouter(ctx)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, tu.tlsConf)
	release := deadlineFor(ctx, tc, connectTimeout)
	fail := func(err error) (net.Conn, error) {
		release()
		tc.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		return fail(tu.tlsError(err))
	}
	authority := tu.actorAddr()
	req := "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\nate-target-actor: " + tu.target.String() + "\r\n\r\n"
	if _, err := io.WriteString(tc, req); err != nil {
		return fail(tu.tlsError(err))
	}
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return fail(tu.tlsError(err))
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return fail(statusError(resp.StatusCode, resp.Header, tu.target))
	}
	if !release() && ctx.Err() != nil {
		tc.Close()
		return nil, ctx.Err()
	}
	if br.Buffered() > 0 {
		return &bufConn{Conn: tc, r: br}, nil
	}
	return tc, nil
}

// tlsError turns a TLS or CONNECT failure into what the person can act on.
// It never includes certificate or key material.
func (tu *Tunnel) tlsError(err error) error {
	if certRefused(err) {
		return &TunnelError{Target: tu.target, Kind: ErrCertRefused}
	}
	var ua x509.UnknownAuthorityError
	if errors.As(err, &ua) {
		return &dialError{what: "the router's certificate is not trusted here (set the router CA file of this context)", fatal: true}
	}
	var he x509.HostnameError
	if errors.As(err, &he) {
		return &dialError{what: "the router's certificate does not name " + tu.routerHost, fatal: true}
	}
	var ie x509.CertificateInvalidError
	if errors.As(err, &ie) {
		return &dialError{what: "the router's certificate is not valid", err: err, fatal: true}
	}
	return &dialError{what: "could not reach the router at " + tu.routerAddr, err: err}
}

// certRefused reports a TLS alert from the router about the client
// certificate: missing, untrusted, expired or revoked.
func certRefused(err error) bool {
	s := err.Error()
	if !strings.Contains(s, "remote error: tls:") {
		return false
	}
	for _, a := range []string{"bad certificate", "certificate required", "unknown certificate authority",
		"certificate revoked", "certificate expired", "unsupported certificate", "certificate unknown", "access denied"} {
		if strings.Contains(s, a) {
			return true
		}
	}
	return false
}

// dialRouter opens the TCP connection to the router, through an http://
// proxy when the environment names one (HTTPS_PROXY, NO_PROXY).
func (tu *Tunnel) dialRouter(ctx context.Context) (net.Conn, error) {
	pu, err := tu.proxy(&http.Request{URL: tu.routerURL})
	if err != nil {
		return nil, &dialError{what: "the proxy setting (HTTPS_PROXY) is not valid", fatal: true}
	}
	if pu == nil {
		c, err := tu.dialRaw(ctx, "tcp", tu.routerAddr)
		if err != nil {
			return nil, &dialError{what: "could not reach the router at " + tu.routerAddr, err: err}
		}
		return c, nil
	}
	if pu.Scheme != "http" {
		return nil, &dialError{what: "only an http:// proxy is supported for the router connection (HTTPS_PROXY)", fatal: true}
	}
	paddr := pu.Host
	if pu.Port() == "" {
		paddr = net.JoinHostPort(pu.Hostname(), "80")
	}
	c, err := tu.dialRaw(ctx, "tcp", paddr)
	if err != nil {
		return nil, &dialError{what: "could not reach the proxy " + pu.Hostname(), err: err}
	}
	release := deadlineFor(ctx, c, connectTimeout)
	req := "CONNECT " + tu.routerAddr + " HTTP/1.1\r\nHost: " + tu.routerAddr + "\r\n"
	if pu.User != nil {
		pw, _ := pu.User.Password()
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(pu.User.Username()+":"+pw)) + "\r\n"
	}
	req += "\r\n"
	fail := func(e *dialError) (net.Conn, error) {
		release()
		c.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, e
	}
	if _, err := io.WriteString(c, req); err != nil {
		return fail(&dialError{what: "could not reach the router through the proxy", err: err})
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return fail(&dialError{what: "could not reach the router through the proxy", err: err})
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusProxyAuthRequired:
		return fail(&dialError{what: "the proxy needs credentials (HTTPS_PROXY)", fatal: true})
	default:
		return fail(&dialError{what: fmt.Sprintf("the proxy refused the connection to the router (status %d)", resp.StatusCode)})
	}
	release()
	if br.Buffered() > 0 {
		return &bufConn{Conn: c, r: br}, nil
	}
	return c, nil
}

// bufConn is a connection whose first bytes were read into r.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }
