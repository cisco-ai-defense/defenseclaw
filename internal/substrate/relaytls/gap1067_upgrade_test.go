// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package relaytls

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls/relaytlstest"
)

// TestGAP1067UpgradeThroughHTTPIngress: behind the HTTP-parsing worker
// ingress, the upgrade carries TLS end to end (the relay CA and the actor
// UID still decide) and the plain probe still answers; the ingress never
// gets a stream it cannot parse.
func TestGAP1067UpgradeThroughHTTPIngress(t *testing.T) {
	ca := newCA(t)
	in, err := relaytlstest.NewHTTPIngress(serve(t, ca, uidA))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close() })
	confA, _ := ClientConfig(ca.Pool(), uidA)
	if body, err := get(t, in.Addr(), confA); err != nil || body != "tls" {
		t.Fatalf("upgrade through the ingress: %q %v", body, err)
	}
	confB, _ := ClientConfig(ca.Pool(), uidB)
	if _, err := get(t, in.Addr(), confB); err == nil {
		t.Fatal("another actor's relay was accepted through the ingress")
	}
	if body, err := get(t, in.Addr(), nil); err != nil || body != "plain" {
		t.Fatalf("plain probe through the ingress: %q %v", body, err)
	}
	if n := in.Rejected(); n != 0 {
		t.Fatalf("the ingress answered %d non-HTTP streams itself", n)
	}
}

// TestGAP1067RawClientHelloIsNotTLS: the raw first-byte route is gone (no
// ingress carries it); a raw ClientHello reaches the plain listener and
// fails, it never gets the relay's TLS handler.
func TestGAP1067RawClientHelloIsNotTLS(t *testing.T) {
	ca := newCA(t)
	addr := serve(t, ca, uidA)
	conf, _ := ClientConfig(ca.Pool(), uidA)
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, conf)
	if err == nil {
		_ = c.Close()
		t.Fatal("a raw TLS handshake was served")
	}
}

// TestGAP1067NoUpgradeRefused: a stream that does not switch (a relay that
// serves no TLS answers 426) or a 101 that is not the relay's answer is
// ErrNoUpgrade, never a plain connection.
func TestGAP1067NoUpgradeRefused(t *testing.T) {
	plainOnly := func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "relay_tls_required", http.StatusUpgradeRequired)
	}
	wrongAccept := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Protocol", UpgradeProtocol)
		w.Header().Set("Sec-WebSocket-Accept", "bm90LXRoZS1yZWxheQ==")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}
	ca := newCA(t)
	conf, _ := ClientConfig(ca.Pool(), uidA)
	for name, h := range map[string]http.HandlerFunc{"426": plainOnly, "wrong accept": wrongAccept} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() { _ = http.Serve(ln, h) }()
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, err = Upgrade(t.Context(), raw, conf)
		_ = raw.Close()
		if !errors.Is(err, ErrNoUpgrade) {
			t.Fatalf("%s: %v, want ErrNoUpgrade", name, err)
		}
	}
}

// TestGAP1067UpgradeOnAKeptAliveConnection: the worker Envoy pools its
// upstream HTTP/1.1 connections to the relay, so the upgrade can come as a
// later request on a connection that already carried a plain one (the
// first e1 run of the first-request design answered such a probe 426).
// Plain requests on the port are served unchanged.
func TestGAP1067UpgradeOnAKeptAliveConnection(t *testing.T) {
	ca := newCA(t)
	key, csr, err := NewKeyAndCSR()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := ca.Sign(csr, uidA, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kp, err := KeyPair(certPEM, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	sp := Split(ln.Addr(), &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*kp}}, nil)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(b)
		tag := "plain"
		if r.TLS != nil {
			tag = "tls"
		}
		_, _ = io.WriteString(w, tag+" "+hex.EncodeToString(sum[:]))
	})
	go func() { _ = http.Serve(sp.TLS(), h) }()
	go func() { _ = http.Serve(ln, sp.Handler(h)) }()
	body := bytes.Repeat([]byte("relay-body-"), 20000)
	want := sha256.Sum256(body)

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	req, _ := http.NewRequest(http.MethodPost, "http://actor.invalid/files", bytes.NewReader(body))
	if err := req.Write(raw); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(got) != "plain "+hex.EncodeToString(want[:]) {
		t.Fatalf("plain request: %q", got)
	}
	if br.Buffered() != 0 {
		t.Fatal("bytes after the plain answer")
	}
	conf, _ := ClientConfig(ca.Pool(), uidA)
	tc, err := Upgrade(t.Context(), raw, conf)
	if err != nil {
		t.Fatalf("upgrade on a kept-alive connection: %v", err)
	}
	req, _ = http.NewRequest(http.MethodGet, "http://actor.invalid/readyz", nil)
	if err := req.Write(tc); err != nil {
		t.Fatal(err)
	}
	resp, err = http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	empty := sha256.Sum256(nil)
	if string(got) != "tls "+hex.EncodeToString(empty[:]) {
		t.Fatalf("request over the upgraded TLS: %q", got)
	}
}
