// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls/relaytlstest"
)

// tixRelayBehindIngress serves h as a TLS kit's relay does (relaytls.Split
// with kp) behind the HTTP-parsing worker ingress model, and returns the
// address attach dials (the router tunnel).
func tixRelayBehindIngress(t *testing.T, h http.Handler, kp *tls.Certificate) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	sp := relaytls.Split(ln.Addr(), &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*kp}}, nil)
	go func() { _ = http.Serve(sp.TLS(), h) }()
	go func() { _ = http.Serve(ln, sp.Handler(http.NotFoundHandler())) }()
	in, err := relaytlstest.NewHTTPIngress(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = in.Close()
		if n := in.Rejected(); n != 0 {
			t.Errorf("the ingress answered %d non-HTTP streams itself (raw TLS on the tunnel)", n)
		}
	})
	return in.Addr()
}

// gap1067Relay is a relay behind the HTTP-parsing worker ingress model:
// a TLS kit's listener (relaytls.Split with a certificate for uid) when
// serveTLS, else a plain-only one. TLS answers "tls", plain "plain".
func gap1067Relay(t *testing.T, ca *relaytls.CA, uid string, serveTLS bool) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			_, _ = io.WriteString(w, "tls")
			return
		}
		_, _ = io.WriteString(w, "plain")
	})
	if serveTLS {
		key, csr, err := relaytls.NewKeyAndCSR()
		if err != nil {
			t.Fatal(err)
		}
		p, err := ca.Sign(csr, uid, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		kp, err := relaytls.KeyPair(p, key)
		if err != nil {
			t.Fatal(err)
		}
		return tixRelayBehindIngress(t, mux, kp)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = http.Serve(ln, mux) }()
	in, err := relaytlstest.NewHTTPIngress(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close() })
	return in.Addr()
}

// gap1067Get sends one request on a dialed relay connection, as attach's
// reverse proxy does.
func gap1067Get(dial func(context.Context) (net.Conn, error)) (string, error) {
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext:       func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) },
		DisableKeepAlives: true,
	}}
	resp, err := c.Get("http://actor.invalid/readyz")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// TestGAP1067RelayTLSThroughHTTPIngress: on the supported Substrate the
// stream after the router CONNECT is parsed as HTTP by the worker Envoy. A
// TLS kit must still be attached with TLS end to end in every relay_tls
// mode, with the relay certificate pinned to the actor UID, and the ingress
// must never see a stream it cannot parse (at 003d353010 it answered the
// raw ClientHello with 400: "tls: first record does not look like a TLS
// handshake").
func TestGAP1067RelayTLSThroughHTTPIngress(t *testing.T) {
	const uid = "aaaa-0001"
	ca := tixRelayCA(t)
	addr := gap1067Relay(t, ca, uid, true) // its cleanup fails the test on any stream the ingress answered itself
	for _, mode := range []relaytls.Mode{relaytls.ModeAuto, relaytls.ModeRequired, relaytls.ModeOff} {
		st := &substrateState{cfg: SubstrateConfig{RelayTLS: mode, RelayCA: ca, Relays: tixDialer{addr}}}
		reg := registry.Registration{Atespace: "tix", Name: "a", UID: uid, RelayStreams: "tls"}
		dial, status, reason := (&APIServer{}).substrateRelayDial(t.Context(), st, reg)
		if status != http.StatusOK {
			t.Fatalf("%s: %d %s", mode, status, reason)
		}
		c, err := dial(t.Context())
		if err != nil {
			t.Fatalf("%s: dial through the HTTP ingress: %v", mode, err)
		}
		tc, ok := c.(*tls.Conn)
		if !ok {
			t.Fatalf("%s: the relay connection is not TLS", mode)
		}
		if cs := tc.ConnectionState(); len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0].DNSNames[0] != "uid."+uid+relaytls.SANSuffix {
			t.Fatalf("%s: relay certificate not pinned to the actor", mode)
		}
		_ = c.Close()
		body, err := gap1067Get(dial)
		if err != nil || body != "tls" {
			t.Fatalf("%s: request over the relay connection: %q %v", mode, body, err)
		}
	}
	// Another actor's relay behind the same ingress is still refused.
	st := &substrateState{cfg: SubstrateConfig{RelayTLS: relaytls.ModeRequired, RelayCA: ca, Relays: tixDialer{addr}}}
	dial, _, _ := (&APIServer{}).substrateRelayDial(t.Context(), st, registry.Registration{Atespace: "tix", Name: "b", UID: "bbbb-0002", RelayStreams: "tls"})
	if c, err := dial(t.Context()); err == nil {
		_ = c.Close()
		t.Fatal("another actor's relay certificate was accepted")
	}
}

// TestGAP1067NoPlainFallback: a TLS kit whose relay does not switch to TLS
// (a plain-only listener) is never attached in plain, in any mode.
func TestGAP1067NoPlainFallback(t *testing.T) {
	ca := tixRelayCA(t)
	addr := gap1067Relay(t, ca, "aaaa-0001", false)
	for _, mode := range []relaytls.Mode{relaytls.ModeAuto, relaytls.ModeRequired, relaytls.ModeOff} {
		st := &substrateState{cfg: SubstrateConfig{RelayTLS: mode, RelayCA: ca, Relays: tixDialer{addr}}}
		dial, status, reason := (&APIServer{}).substrateRelayDial(t.Context(), st, registry.Registration{Atespace: "tix", Name: "a", UID: "aaaa-0001", RelayStreams: "tls"})
		if status != http.StatusOK {
			t.Fatalf("%s: %d %s", mode, status, reason)
		}
		if c, err := dial(t.Context()); err == nil {
			_ = c.Close()
			t.Fatalf("%s: a TLS kit was attached without TLS", mode)
		}
		if body, err := gap1067Get(dial); err == nil {
			t.Fatalf("%s: a request reached a TLS kit's relay in plain: %q", mode, body)
		}
	}
}
