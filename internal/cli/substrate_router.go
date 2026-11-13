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
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
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
	identity   func() (*tls.Certificate, error)
	roots      func() (*x509.CertPool, error)
	dial       func(ctx context.Context, network, addr string) (net.Conn, error)
}

func newRouterDialer(addr, serverName, caFile string, relayPort int, identity func() (*tls.Certificate, error)) (*routerDialer, error) {
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

// errRouterRefusedIdentity: the router ended the TLS session with an alert,
// which is how its Envoy refuses a client certificate whose SPIFFE ID is not
// in ingressAllowedSPIFFEIDs (with TLS 1.3 the alert arrives on the first
// read, not in the handshake).
var errRouterRefusedIdentity = errors.New("the router refused the gateway's identity: its SPIFFE ID is not in Substrate's " +
	"ingressAllowedSPIFFEIDs (run `defenseclaw substrate setup`, then ate-setup; `defenseclaw substrate admin doctor` checks it)")

func routerTLSRefusal(err error) error {
	if err != nil && strings.Contains(err.Error(), "remote error: tls:") {
		return fmt.Errorf("%w (%v)", errRouterRefusedIdentity, err)
	}
	return err
}

// connect opens the CONNECT-TLS tunnel to target (atespace/name) and returns
// the CONNECT answer; on 200 the connection carries the relay stream.
func (d *routerDialer) connect(ctx context.Context, target string) (*tls.Conn, *bufio.Reader, *http.Response, error) {
	roots, err := d.roots()
	if err != nil {
		return nil, nil, nil, err
	}
	raw, err := d.dial(ctx, "tcp", d.addr)
	if err != nil {
		return nil, nil, nil, err
	}
	tc := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: d.serverName, RootCAs: roots,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return d.identity() },
	})
	deadline := time.Now().Add(30 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = tc.SetDeadline(deadline)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = tc.Close()
		return nil, nil, nil, fmt.Errorf("router TLS: %w", routerTLSRefusal(err))
	}
	authority := net.JoinHostPort("actor.invalid", strconv.Itoa(d.relayPort))
	req := "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\nate-target-actor: " + target + "\r\n\r\n"
	if _, err := tc.Write([]byte(req)); err != nil {
		_ = tc.Close()
		return nil, nil, nil, routerTLSRefusal(err)
	}
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = tc.Close()
		return nil, nil, nil, fmt.Errorf("router CONNECT: %w", routerTLSRefusal(err))
	}
	return tc, br, resp, nil
}

// DialRelay implements gateway.SubstrateRelayDialer.
func (d *routerDialer) DialRelay(ctx context.Context, atespace, name string) (net.Conn, error) {
	tc, br, resp, err := d.connect(ctx, atespace+"/"+name)
	if err != nil {
		return nil, err
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

// routerProbeTarget is an actor that never exists: the probe needs only the
// router's answer, which comes after it admitted the gateway's identity.
const routerProbeTarget = "defenseclaw-doctor/probe"

// substrateRouterCheck is the gateway's doctor row for attach (GAP-0157): the
// router address is set, the pod identity loads, and the router admits the
// gateway (ingressAllowedSPIFFEIDs). Without it run, connect, pull, logs and
// checkpoint answer attach_unavailable.
func substrateRouterCheck(ctx context.Context, d *routerDialer, buildErr error) gateway.SubstrateCheck {
	c := gateway.SubstrateCheck{ID: "substrate.attach_router", Status: "fail"}
	switch {
	case d == nil && buildErr == nil:
		c.Detail = "attach is off: the gateway runs without --router-address, so run, connect, pull, logs and checkpoint answer attach_unavailable"
		c.Fix = "set chart value substrate.router.enabled: true (the default; it needs podCertificates.enabled), or start the gateway with " +
			"--router-address=atenet-router.<Substrate namespace>.svc:8444 and --router-ca-file=<servicedns trust bundle>"
		return c
	case d == nil:
		c.Detail = "attach is off: " + buildErr.Error()
		c.Fix = "check the gateway's pod certificate mounts (podidentity credential bundle and trust bundle)"
		return c
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tc, _, resp, err := d.connect(pctx, routerProbeTarget)
	switch {
	case errors.Is(err, errRouterRefusedIdentity):
		c.Detail = "the router at " + d.addr + " refuses the gateway's identity" + routerIdentityName(d)
		c.Fix = "add the gateway's SPIFFE ID to Substrate's ingressAllowedSPIFFEIDs: `defenseclaw substrate setup` writes it into the " +
			"SubstrateInstall document, then run ate-setup deploy (a cluster-global setting)"
	case err != nil:
		c.Detail = "the router at " + d.addr + " cannot be reached: " + err.Error()
		c.Fix = "check substrate.router.address, the router CA (substrate.router.caFile) and the gateway's egress NetworkPolicy"
	default:
		_ = tc.Close()
		c.Status = "pass"
		c.Detail = fmt.Sprintf("the router at %s admits the gateway (probe answered HTTP %d)", d.addr, resp.StatusCode)
	}
	return c
}

// routerIdentityName names the SPIFFE ID the gateway presents, for the fix.
func routerIdentityName(d *routerDialer) string {
	cert, err := d.identity()
	if err != nil || len(cert.Certificate) == 0 {
		return ""
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return ""
	}
	for _, u := range leaf.URIs {
		if u.Scheme == "spiffe" {
			return " (" + u.String() + ")"
		}
	}
	return ""
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
