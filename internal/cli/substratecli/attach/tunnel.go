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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

const handshakeTimeout = 45 * time.Second

// Errors a RouteError unwraps to.
var (
	ErrNotSignedIn = errors.New("the cluster did not accept your sign-in")
	ErrNotAllowed  = errors.New("not allowed to attach to this agent")
	ErrNoActor     = errors.New("no such agent of yours")
	ErrClusterFull = errors.New("the cluster is full")
	ErrStarting    = errors.New("the agent is starting")
	ErrNotOffered  = errors.New("this cluster does not offer attach through the gateway yet")
)

// RouteError is an answer of the gateway's attach route that is not a
// success. Kind is one of the errors above, or nil for another status.
type RouteError struct {
	Status     int
	RetryAfter time.Duration
	Target     Target
	Kind       error
}

func (e *RouteError) Error() string {
	switch e.Kind {
	case ErrNotSignedIn:
		return "the cluster did not accept your sign-in (it may have expired); run: defenseclaw substrate login"
	case ErrNotAllowed:
		return "you are not allowed to attach to " + e.Target.String() + " (it belongs to someone else, or your administrator has not allowed it)"
	case ErrNoActor:
		return "no agent " + e.Target.String() + " of yours in this cluster; list yours with: defenseclaw substrate list"
	case ErrClusterFull:
		return fmt.Sprintf("the cluster is full (status %d)", e.Status)
	case ErrStarting:
		return fmt.Sprintf("the agent %s is starting (status %d)", e.Target.Name, e.Status)
	case ErrNotOffered:
		return ErrNotOffered.Error() + "; ask your administrator to upgrade DefenseClaw"
	}
	return fmt.Sprintf("the gateway answered %d %s", e.Status, http.StatusText(e.Status))
}

// Unwrap returns Kind.
func (e *RouteError) Unwrap() error { return e.Kind }

// final: a refusal that a retry cannot change.
func (e *RouteError) final() bool {
	return e.Kind == ErrNotSignedIn || e.Kind == ErrNotAllowed || e.Kind == ErrNoActor || e.Kind == ErrNotOffered
}

// waits: the cluster is full or the agent is starting; wait up to MaxWait.
func (e *RouteError) waits() bool { return e.Kind == ErrClusterFull || e.Kind == ErrStarting }

func routeError(status int, h http.Header, t Target) *RouteError {
	e := &RouteError{Status: status, Target: t}
	switch status {
	case http.StatusUnauthorized:
		e.Kind = ErrNotSignedIn
	case http.StatusForbidden:
		e.Kind = ErrNotAllowed
	case http.StatusNotFound:
		e.Kind = ErrNoActor
	case http.StatusNotImplemented:
		e.Kind = ErrNotOffered
	case http.StatusServiceUnavailable, http.StatusTooManyRequests:
		e.Kind = ErrClusterFull
	case http.StatusBadGateway, http.StatusGatewayTimeout:
		e.Kind = ErrStarting
	}
	if h != nil && e.waits() {
		e.RetryAfter = parseRetryAfter(h.Get("Retry-After"), time.Now())
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

// dialError is a failure to reach the admin listener. A fatal one is a
// setting to fix, not a network blip.
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

// bearerError is a failure of the BearerFunc. It carries the sign-in
// error (which names no token) so callers can match it with errors.Is.
type bearerError struct{ err error }

func (e *bearerError) Error() string {
	if e.transient() {
		return "could not refresh your sign-in (" + e.err.Error() + ")"
	}
	return e.err.Error()
}
func (e *bearerError) Unwrap() error { return e.err }

// transient: the issuer could not be reached; a later try may work.
func (e *bearerError) transient() bool {
	var ne net.Error
	return errors.As(e.err, &ne)
}

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

// Gateway is the admin listener of the cluster's DefenseClaw gateway, the
// only endpoint the launcher talks to.
type Gateway struct {
	// BaseURL is the admin origin, https://HOST:PORT (the context's
	// admin_url).
	BaseURL string
	// CAFile, when set, is the only CA trusted for the admin listener's
	// certificate; without it the system roots are used.
	CAFile string

	// dial and proxy replace the TCP dial and the proxy lookup (tests).
	dial  func(ctx context.Context, network, addr string) (net.Conn, error)
	proxy proxyFunc
}

// BearerFunc returns the person's current OIDC access token (or a CI
// workload token). It is called for every request and every WebSocket
// handshake, so it must cache and refresh by itself (auth.Source.Token
// does). Its errors must not contain the token.
type BearerFunc func(ctx context.Context) (string, error)

// AttachPrefix is the URL under which the gateway serves one actor's relay:
// every relay route (/dcrelay/1/ws, /poll, /task, /status, /exec, /files)
// is reachable with its own path appended. This is the one place that
// knows the route's shape.
func AttachPrefix(adminURL string, t Target) (string, error) {
	if err := t.validate(); err != nil {
		return "", err
	}
	u, err := url.Parse(strings.TrimSpace(adminURL))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("the admin URL of this context must look like https://HOST:PORT")
	}
	origin := u.Scheme + "://" + u.Host + strings.TrimRight(u.EscapedPath(), "/")
	return origin + "/api/v1/substrate/actors/" + url.PathEscape(t.Atespace) + "/" + url.PathEscape(t.Name) + "/attach", nil
}

// validate refuses names the route cannot carry as one path segment.
func (t Target) validate() error {
	if t.Atespace == "" || t.Name == "" {
		return errors.New("no actor named: an actor is atespace/name")
	}
	for _, s := range []string{t.Atespace, t.Name} {
		if s == "." || s == ".." || strings.ContainsAny(s, "/\\") || strings.IndexFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f }) >= 0 {
			return fmt.Errorf("actor name %q is not valid", t.String())
		}
	}
	return nil
}

// Tunnel reaches one actor's relay through the gateway's attach route. It is
// a plain HTTPS client of the admin listener (HTTPS_PROXY and NO_PROXY are
// honoured) that adds the person's bearer to every request.
type Tunnel struct {
	target   Target
	base     string
	host     string
	hostname string
	bearer   BearerFunc
	tr       *http.Transport
	client   *http.Client
	ws       *websocket.Dialer
	// retryAfter is the Retry-After of the last full or starting answer
	// (nanoseconds), taken by takeRetryAfter.
	retryAfter atomic.Int64
}

// NewTunnel checks the gateway settings and returns a Tunnel. It dials
// nothing: the first request does.
func NewTunnel(ctx context.Context, g Gateway, bearer BearerFunc, t Target) (*Tunnel, error) {
	_ = ctx
	if bearer == nil {
		return nil, errors.New("no sign-in configured for this cluster; run: defenseclaw substrate login")
	}
	base, err := AttachPrefix(g.BaseURL, t)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(base)
	conf := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname(), NextProtos: []string{"http/1.1"}}
	if g.CAFile != "" {
		pem, err := os.ReadFile(g.CAFile)
		if err != nil {
			return nil, fmt.Errorf("admin CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("admin CA file %s holds no certificate", g.CAFile)
		}
		conf.RootCAs = pool
	}
	dial := g.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	proxy := g.proxy
	if proxy == nil {
		proxy = http.ProxyFromEnvironment
	}
	tu := &Tunnel{target: t, base: base, host: u.Host, hostname: u.Hostname(), bearer: bearer}
	tu.tr = &http.Transport{
		Proxy:                 proxy,
		DialContext:           dial,
		TLSClientConfig:       conf.Clone(),
		TLSHandshakeTimeout:   15 * time.Second,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       60 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	tu.client = &http.Client{Transport: bearerTransport{tu}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	tu.ws = &websocket.Dialer{Proxy: proxy, NetDialContext: dial, TLSClientConfig: conf.Clone(),
		HandshakeTimeout: handshakeTimeout, ReadBufferSize: 32 << 10, WriteBufferSize: 32 << 10}
	return tu, nil
}

// BaseURL is the actor's attach prefix (see AttachPrefix).
func (tu *Tunnel) BaseURL() string { return tu.base }

// HTTPClient sends requests to the admin listener with the person's bearer
// on each (fetched again for every request). It never follows redirects
// and refuses any other host.
func (tu *Tunnel) HTTPClient() *http.Client { return tu.client }

// Dialer dials WebSocket to the admin listener. The bearer goes in the
// handshake headers (relay.AttachOptions.Token).
func (tu *Tunnel) Dialer() *websocket.Dialer { return tu.ws }

// Bearer returns the person's current bearer. It suits token callbacks
// such as the workspace client's.
func (tu *Tunnel) Bearer(ctx context.Context) (string, error) {
	tok, err := tu.bearer(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", &bearerError{err}
	}
	tok = strings.TrimSpace(tok)
	if tok == "" || strings.ContainsAny(tok, "\r\n") {
		return "", &bearerError{errors.New("the saved sign-in holds no usable token; run: defenseclaw substrate login")}
	}
	return tok, nil
}

// Close drops idle connections.
func (tu *Tunnel) Close() { tu.tr.CloseIdleConnections() }

func (tu *Tunnel) takeRetryAfter() time.Duration { return time.Duration(tu.retryAfter.Swap(0)) }

// netError turns a TLS or network failure into what the person can act on.
// It never includes certificate or key material.
func (tu *Tunnel) netError(err error) error {
	var be *bearerError
	if errors.As(err, &be) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var ua x509.UnknownAuthorityError
	if errors.As(err, &ua) {
		return &dialError{what: "the admin listener's certificate is not trusted here (set the admin CA file of this context)", fatal: true}
	}
	var he x509.HostnameError
	if errors.As(err, &he) {
		return &dialError{what: "the admin listener's certificate does not name " + tu.hostname, fatal: true}
	}
	var ie x509.CertificateInvalidError
	if errors.As(err, &ie) {
		return &dialError{what: "the admin listener's certificate is not valid", err: err, fatal: true}
	}
	var rh tls.RecordHeaderError
	if errors.As(err, &rh) {
		return &dialError{what: "the admin URL of this context does not answer with TLS (check the port)", fatal: true}
	}
	return &dialError{what: "could not reach the admin listener at " + tu.host, err: err}
}

// mapRelayPath turns the relay's own path under the attach prefix
// (<prefix>/dcrelay/1/status) into the path the gateway's attach route takes
// (<prefix>/status): the route adds /dcrelay/1 itself. The clients built on
// BaseURL keep writing the relay's paths.
func (tu *Tunnel) mapRelayPath(r *http.Request) {
	u, err := url.Parse(tu.base)
	if err != nil {
		return
	}
	base := u.EscapedPath()
	esc := r.URL.EscapedPath()
	if rest, ok := strings.CutPrefix(esc, base+"/dcrelay/1"); ok && (rest == "" || strings.HasPrefix(rest, "/")) {
		r.URL.RawPath = base + rest
		r.URL.Path, _ = url.PathUnescape(r.URL.RawPath)
	}
}

// bearerTransport adds the bearer to every request to the admin listener.
type bearerTransport struct{ tu *Tunnel }

func (b bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tu := b.tu
	if req.URL.Scheme != "https" || req.URL.Host != tu.host {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, fmt.Errorf("this connection reaches only the admin listener %s, not %s", tu.host, req.URL.Host)
	}
	tok, err := tu.Bearer(req.Context())
	if err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	r := req.Clone(req.Context())
	tu.mapRelayPath(r)
	r.Header.Set("Authorization", "Bearer "+tok)
	// The admin listener refuses a write without the client tag (its CSRF gate).
	api.SetClientHeaders(r.Header)
	resp, err := tu.tr.RoundTrip(r)
	if err != nil {
		return nil, tu.netError(err)
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
		tu.retryAfter.Store(int64(parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())))
	}
	return resp, nil
}
