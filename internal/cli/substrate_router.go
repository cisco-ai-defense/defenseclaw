// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/podcert"
)

// routerDialer reaches an actor's relay port through the atenet router's
// CONNECT-TLS listener, presenting the gateway's pod identity certificate
// (the router admits SPIFFE IDs on its ingressAllowedSPIFFEIDs list). The
// router's serving certificate is checked against routerCA for
// serverName.
type routerDialer struct {
	addr       string
	serverName string
	relayPort  int
	identity   *podcert.Files
	roots      func() (*x509.CertPool, error)
	dial       func(ctx context.Context, network, addr string) (net.Conn, error)
}

func newRouterDialer(addr, serverName, caFile string, relayPort int, identity *podcert.Files) (*routerDialer, error) {
	if addr == "" {
		return nil, errors.New("no router address")
	}
	if serverName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("router address %q: %w", addr, err)
		}
		serverName = host
	}
	if relayPort <= 0 {
		relayPort = 8080
	}
	d := &routerDialer{addr: addr, serverName: serverName, relayPort: relayPort, identity: identity,
		dial: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
	d.roots = func() (*x509.CertPool, error) {
		if caFile == "" {
			return x509.SystemCertPool()
		}
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("router CA %s holds no certificate", caFile)
		}
		return pool, nil
	}
	return d, nil
}

// DialRelay implements gateway.SubstrateRelayDialer.
func (d *routerDialer) DialRelay(ctx context.Context, atespace, name string) (net.Conn, error) {
	roots, err := d.roots()
	if err != nil {
		return nil, err
	}
	raw, err := d.dial(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: d.serverName, RootCAs: roots,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return d.identity.Certificate() },
	})
	deadline := time.Now().Add(30 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = tc.SetDeadline(deadline)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = tc.Close()
		return nil, fmt.Errorf("router TLS: %w", err)
	}
	authority := net.JoinHostPort("actor.invalid", strconv.Itoa(d.relayPort))
	req := "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\nate-target-actor: " + atespace + "/" + name + "\r\n\r\n"
	if _, err := tc.Write([]byte(req)); err != nil {
		_ = tc.Close()
		return nil, err
	}
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = tc.Close()
		return nil, fmt.Errorf("router CONNECT: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = tc.Close()
		return nil, fmt.Errorf("router CONNECT: HTTP %d", resp.StatusCode)
	}
	_ = tc.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: tc, r: br}, nil
	}
	return tc, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
