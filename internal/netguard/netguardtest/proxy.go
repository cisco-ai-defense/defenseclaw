// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package netguardtest provides a recording HTTP CONNECT proxy for tests of
// outbound clients that route through an enterprise egress proxy.
package netguardtest

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
)

// RecordingProxy is a loopback HTTP CONNECT proxy. It records every CONNECT
// target and connects a target only to the address a route names for it,
// so a test can use unresolvable destination names that still reach a local
// server. A target without a route is refused with 403.
type RecordingProxy struct {
	// URL is the proxy URL (http://127.0.0.1:port, or https:// for a TLS
	// proxy).
	URL string

	listener net.Listener
	mu       sync.Mutex
	routes   map[string]string
	targets  []string
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
}

// NewRecordingProxy starts a plain-HTTP CONNECT proxy; routes maps a CONNECT
// target (host:port) to the address it reaches. It stops at test cleanup.
func NewRecordingProxy(t testing.TB, routes map[string]string) *RecordingProxy {
	t.Helper()
	return startRecordingProxy(t, routes, nil)
}

// NewTLSRecordingProxy starts the same proxy behind TLS with config's
// certificates (clients reach it with an https:// proxy URL).
func NewTLSRecordingProxy(t testing.TB, routes map[string]string, config *tls.Config) *RecordingProxy {
	t.Helper()
	return startRecordingProxy(t, routes, config)
}

func startRecordingProxy(t testing.TB, routes map[string]string, config *tls.Config) *RecordingProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("recording proxy listen: %v", err)
	}
	scheme := "http"
	if config != nil {
		listener = tls.NewListener(listener, config)
		scheme = "https"
	}
	proxy := &RecordingProxy{
		URL:      scheme + "://" + listener.Addr().String(),
		listener: listener,
		routes:   map[string]string{},
		conns:    map[net.Conn]struct{}{},
	}
	for target, address := range routes {
		proxy.routes[target] = address
	}
	proxy.wg.Add(1)
	go proxy.serve()
	t.Cleanup(proxy.close)
	return proxy
}

// Route adds or replaces the address a CONNECT target reaches.
func (p *RecordingProxy) Route(target, address string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.routes[target] = address
}

// Targets returns the CONNECT targets received so far, in order.
func (p *RecordingProxy) Targets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

func (p *RecordingProxy) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		if !p.track(conn) {
			_ = conn.Close()
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.untrack(conn)
			p.handle(conn)
		}()
	}
}

func (p *RecordingProxy) handle(client net.Conn) {
	reader := bufio.NewReader(client)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	if request.Method != http.MethodConnect {
		_, _ = io.WriteString(client, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	p.mu.Lock()
	p.targets = append(p.targets, request.Host)
	address, ok := p.routes[request.Host]
	p.mu.Unlock()
	if !ok {
		_, _ = io.WriteString(client, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		return
	}
	upstream, err := net.Dial("tcp", address)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if !p.track(upstream) {
		_ = upstream.Close()
		return
	}
	defer p.untrack(upstream)
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	copied := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, reader)
		copied <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		copied <- struct{}{}
	}()
	<-copied
}

func (p *RecordingProxy) track(conn net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conns == nil {
		return false
	}
	p.conns[conn] = struct{}{}
	return true
}

func (p *RecordingProxy) untrack(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conns != nil {
		delete(p.conns, conn)
	}
	_ = conn.Close()
}

func (p *RecordingProxy) close() {
	_ = p.listener.Close()
	p.mu.Lock()
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()
	for conn := range conns {
		_ = conn.Close()
	}
	p.wg.Wait()
}
