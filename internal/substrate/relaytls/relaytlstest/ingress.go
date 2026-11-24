// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Package relaytlstest models the Substrate worker ingress a gateway reaches
// an actor's relay through (GAP-1067). After the atenet router's CONNECT,
// the worker-side Envoy parses the tunnelled stream as HTTP/1.1: a request
// it can parse is proxied, a WebSocket upgrade is proxied and then carried
// as opaque bytes once the relay answers 101, and anything else (a raw TLS
// ClientHello) is answered by Envoy itself with 400. Tests put this model
// between the gateway's dial and the relay listener, so a design that needs
// a raw TCP tunnel fails in tests the way it fails on the cluster.
package relaytlstest

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Ingress is an HTTP-parsing ingress in front of one upstream address.
type Ingress struct {
	ln       net.Listener
	upstream string
	wg       sync.WaitGroup

	mu       sync.Mutex
	rejected int
}

// NewHTTPIngress listens on loopback and proxies to upstream as the worker
// Envoy does.
func NewHTTPIngress(upstream string) (*Ingress, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	in := &Ingress{ln: ln, upstream: upstream}
	in.wg.Add(1)
	go in.serve()
	return in, nil
}

// Addr is the address a test dialer connects to (the "tunnel").
func (in *Ingress) Addr() string { return in.ln.Addr().String() }

// Rejected counts streams the ingress answered itself with 400 because
// they were not HTTP.
func (in *Ingress) Rejected() int {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.rejected
}

// Close stops the listener.
func (in *Ingress) Close() error {
	err := in.ln.Close()
	in.wg.Wait()
	return err
}

func (in *Ingress) serve() {
	defer in.wg.Done()
	for {
		c, err := in.ln.Accept()
		if err != nil {
			return
		}
		go in.handle(c)
	}
}

// envoyBadRequest is what the worker Envoy answers to a stream it cannot
// parse as HTTP (the live GAP-1067 probe saw this answer to a ClientHello).
const envoyBadRequest = "HTTP/1.1 400 Bad Request\r\ncontent-length: 11\r\ncontent-type: text/plain\r\nserver: envoy\r\nconnection: close\r\n\r\nBad Request"

func (in *Ingress) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	var up net.Conn
	var upbr *bufio.Reader
	defer func() {
		if up != nil {
			_ = up.Close()
		}
	}()
	for {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		req, err := http.ReadRequest(br)
		_ = c.SetReadDeadline(time.Time{})
		if err != nil {
			if !errors.Is(err, io.EOF) {
				in.mu.Lock()
				in.rejected++
				in.mu.Unlock()
				_, _ = io.WriteString(c, envoyBadRequest)
			}
			return
		}
		upgrade := req.Header.Get("Upgrade")
		if upgrade != "" && !strings.EqualFold(upgrade, "websocket") {
			// Only the websocket upgrade type is configured.
			_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nserver: envoy\r\nconnection: close\r\n\r\n")
			return
		}
		if up == nil {
			if up, err = net.DialTimeout("tcp", in.upstream, 5*time.Second); err != nil {
				_, _ = io.WriteString(c, "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nserver: envoy\r\nconnection: close\r\n\r\n")
				return
			}
			upbr = bufio.NewReader(up)
		}
		if err := req.Write(up); err != nil {
			return
		}
		resp, err := http.ReadResponse(upbr, req)
		if err != nil {
			_, _ = io.WriteString(c, "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nserver: envoy\r\nconnection: close\r\n\r\n")
			return
		}
		if resp.StatusCode == http.StatusSwitchingProtocols && upgrade != "" {
			// After the upgrade the stream is opaque in both directions.
			head := fmt.Sprintf("HTTP/1.1 101 %s\r\n", http.StatusText(http.StatusSwitchingProtocols))
			if _, err := io.WriteString(c, head); err != nil {
				return
			}
			if err := resp.Header.Write(c); err != nil {
				return
			}
			if _, err := io.WriteString(c, "\r\n"); err != nil {
				return
			}
			splice(c, br, up, upbr)
			return
		}
		err = resp.Write(c)
		_ = resp.Body.Close()
		if err != nil || resp.Close || req.Close {
			return
		}
	}
}

// splice copies both ways until either side ends.
func splice(c net.Conn, cr io.Reader, up net.Conn, ur io.Reader) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, cr); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, ur); done <- struct{}{} }()
	<-done
	_ = c.Close()
	_ = up.Close()
	<-done
}
