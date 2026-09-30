// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package netguard

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"
)

// egressTunnelTimeout bounds the proxy dial, TLS handshake and CONNECT
// exchange when the caller's context has no earlier deadline (net/http uses
// the same one-minute cap for its own CONNECT).
const egressTunnelTimeout = time.Minute

// egressConnectResponseLimit bounds the proxy's CONNECT response header.
const egressConnectResponseLimit = 64 << 10

// EgressRoute is an enterprise proxy compiled for connection-level routing.
// It is the layer below an outbound client's destination check: the check
// resolves and validates the destination, then dials the address it selected
// through Dial, naming the checked host with WithDialTarget. A destination
// the proxy covers is reached through an HTTP CONNECT tunnel to that host
// name (so the proxy's own host rules still apply, and the proxy address
// itself is administrator configuration that no destination check
// inspects); a destination no_proxy excludes, and every loopback
// destination, is dialed directly at the address the check selected. A nil
// *EgressRoute dials every destination directly.
type EgressRoute struct {
	proxy     *url.URL
	proxyAddr string
	noProxy   string
	selector  func(*url.URL) (*url.URL, error)
	// proxyTLS is the client configuration for an https:// proxy; nil uses
	// the system roots (tests supply their own).
	proxyTLS *tls.Config
}

// Route compiles p for connection-level routing. It returns nil (no route)
// when no proxy is configured.
func (p EgressProxy) Route() (*EgressRoute, error) {
	if strings.TrimSpace(p.HTTPSProxy) == "" {
		return nil, nil
	}
	proxyURL, err := ParseEgressProxyURL(p.HTTPSProxy)
	if err != nil {
		return nil, err
	}
	proxyURL.Path = ""
	port := proxyURL.Port()
	if port == "" {
		port = "80"
		if proxyURL.Scheme == "https" {
			port = "443"
		}
	}
	noProxy := strings.TrimSpace(p.NoProxy)
	return &EgressRoute{
		proxy:     proxyURL,
		proxyAddr: net.JoinHostPort(proxyURL.Hostname(), port),
		noProxy:   noProxy,
		selector: (&httpproxy.Config{
			HTTPProxy:  proxyURL.String(),
			HTTPSProxy: proxyURL.String(),
			NoProxy:    noProxy,
		}).ProxyFunc(),
	}, nil
}

// URL returns a copy of the proxy URL, or nil for a nil route.
func (r *EgressRoute) URL() *url.URL {
	if r == nil {
		return nil
	}
	copied := *r.proxy
	return &copied
}

// ID identifies the route's proxy and exclusions (for client caches keyed
// by their connection settings); it is "" for a nil route.
func (r *EgressRoute) ID() string {
	if r == nil {
		return ""
	}
	return r.proxy.String() + "|" + r.noProxy
}

// Proxies reports whether a request to target goes through the proxy:
// false for a nil route, for loopback hosts and for no_proxy matches.
func (r *EgressRoute) Proxies(target *url.URL) (bool, error) {
	if r == nil || target == nil {
		return false, nil
	}
	proxyURL, err := r.selector(target)
	if err != nil {
		return false, err
	}
	return proxyURL != nil, nil
}

type dialTargetKey struct{}

// WithDialTarget records the destination host a client's destination check
// validated before it dials the address it selected for that host. An
// EgressRoute uses the name to apply no_proxy and as the CONNECT target, so
// the proxy connects to the checked name rather than to one resolved address.
func WithDialTarget(ctx context.Context, host string) context.Context {
	return context.WithValue(ctx, dialTargetKey{}, host)
}

// Dialer returns r as a dialer over direct, for clients that take a dialer
// (a nil route returns direct itself).
func (r *EgressRoute) Dialer(direct V8Dialer) V8Dialer {
	if r == nil && direct != nil {
		return direct
	}
	return egressRouteDialer{route: r, direct: direct}
}

type egressRouteDialer struct {
	route  *EgressRoute
	direct V8Dialer
}

func (d egressRouteDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.route.Dial(ctx, d.direct, network, address)
}

// Dial connects to address (host:port) through direct, or, when r proxies
// the destination, through a CONNECT tunnel that direct opens to the proxy.
// The destination is the host WithDialTarget recorded in ctx, or address's
// own host when ctx records none.
func (r *EgressRoute) Dial(ctx context.Context, direct V8Dialer, network, address string) (net.Conn, error) {
	if direct == nil {
		direct = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	}
	if r == nil {
		return direct.DialContext(ctx, network, address)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if target, ok := ctx.Value(dialTargetKey{}).(string); ok && target != "" {
		host = target
	}
	target := net.JoinHostPort(host, port)
	proxied, err := r.Proxies(&url.URL{Scheme: "https", Host: target})
	if err != nil {
		return nil, err
	}
	if !proxied {
		return direct.DialContext(ctx, network, address)
	}
	return r.tunnel(ctx, direct, target)
}

// tunnel opens an HTTP CONNECT tunnel to target through the proxy. Only
// client-first protocols (HTTP, TLS, h2c) run over it: like net/http, the
// buffered reader used for the CONNECT response is discarded.
func (r *EgressRoute) tunnel(ctx context.Context, direct V8Dialer, target string) (net.Conn, error) {
	if strings.ContainsAny(target, "\r\n\t ") {
		return nil, errors.New("netguard: egress proxy target is malformed")
	}
	ctx, cancel := context.WithTimeout(ctx, egressTunnelTimeout)
	defer cancel()
	conn, err := direct.DialContext(ctx, "tcp", r.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("netguard: connect to the egress proxy %s: %w", r.proxyAddr, err)
	}
	if conn == nil {
		return nil, fmt.Errorf("netguard: connect to the egress proxy %s: no connection", r.proxyAddr)
	}
	if r.proxy.Scheme == "https" {
		config := &tls.Config{MinVersion: tls.VersionTLS12}
		if r.proxyTLS != nil {
			config = r.proxyTLS.Clone()
		}
		config.ServerName = r.proxy.Hostname()
		tlsConn := tls.Client(conn, config)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("netguard: TLS to the egress proxy %s: %w", r.proxyAddr, err)
		}
		conn = tlsConn
	}
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	done := make(chan struct{})
	var (
		response *http.Response
		exchange error
	)
	go func() {
		defer close(done)
		if exchange = request.Write(conn); exchange != nil {
			return
		}
		reader := bufio.NewReader(&io.LimitedReader{R: conn, N: egressConnectResponseLimit})
		response, exchange = http.ReadResponse(reader, request)
	}()
	select {
	case <-ctx.Done():
		_ = conn.Close()
		<-done
		return nil, ctx.Err()
	case <-done:
	}
	if exchange != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("netguard: CONNECT through the egress proxy %s: %w", r.proxyAddr, exchange)
	}
	if response.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("netguard: the egress proxy %s refused CONNECT %s: %s", r.proxyAddr, target, response.Status)
	}
	return conn, nil
}
