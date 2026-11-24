// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
)

// tixRelayCerts is a leader record of live relay certificates (GAP-0861).
func tixRelayCerts(t *testing.T) registry.RelayCerts {
	t.Helper()
	s, err := registry.OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func tixRelayCA(t *testing.T) *relaytls.CA {
	t.Helper()
	c, k, err := relaytls.GenerateCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := relaytls.LoadCA(c, k)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

type tixAudit struct{ events []string }

func (a *tixAudit) fn(_ context.Context, _, _ string, d map[string]any) {
	a.events = append(a.events, d["event"].(string))
}

// TestRelayCertRouteSignsOwnUID: the certificate names the actor of the
// token, never what the CSR asks for; no CA is relay_ca_missing; GET is 405.
func TestRelayCertRouteSignsOwnUID(t *testing.T) {
	const uid = "3b6c2d1e-8f4a-4b9c-a1d2-5e6f7a8b9c0d"
	ca := tixRelayCA(t)
	au := &tixAudit{}
	st := &substrateState{cfg: SubstrateConfig{RelayCA: ca, RelayCerts: tixRelayCerts(t)}, audit: au.fn}
	a := &APIServer{}
	_, csr, err := relaytls.NewKeyAndCSR()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(relay.CertRequest{CSR: base64.StdEncoding.EncodeToString(csr)})
	ctx := withSubstrateActor(t.Context(), *f14Actor(t, "tix", uid))
	call := func(st *substrateState, method string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, substrateRelayCert, bytes.NewReader(body)).WithContext(ctx)
		a.serveSubstrateRelayCert(st, w, r)
		return w
	}
	w := call(st, http.MethodPost)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	var out relay.CertResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(out.Cert))
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if want := "uid." + uid + relaytls.SANSuffix; len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != want {
		t.Fatalf("names %v, want %s", leaf.DNSNames, want)
	}
	if strings.Join(au.events, ",") != "substrate.relay.cert" {
		t.Fatalf("audit %v", au.events)
	}
	if w := call(&substrateState{}, http.MethodPost); w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "relay_ca_missing") {
		t.Fatalf("no CA: %d %s", w.Code, w.Body)
	}
	if w := call(st, http.MethodGet); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", w.Code)
	}
	w = httptest.NewRecorder()
	a.serveSubstrateRelayCert(st, w, httptest.NewRequest(http.MethodPost, substrateRelayCert, bytes.NewReader(body)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no actor: %d", w.Code)
	}
}

// tixDialer serves the relay side of one attach on a loopback listener.
type tixDialer struct{ addr string }

func (d tixDialer) DialRelay(ctx context.Context, _, _ string) (net.Conn, error) {
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", d.addr)
}

func tixRelayServer(t *testing.T, ca *relaytls.CA, uid string) string {
	t.Helper()
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	// The relay's own listener: the upgrade, then TLS (GAP-1067).
	sp := relaytls.Split(ln.Addr(), &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*kp}}, nil)
	go func() { _ = http.Serve(ln, sp.Handler(http.NotFoundHandler())) }()
	go func() {
		for {
			c, err := sp.TLS().Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

// TestRelayTLSRequiredRefusesPlain: required refuses a template built
// before relay TLS before anything is dialed.
func TestRelayTLSRequiredRefusesPlain(t *testing.T) {
	st := &substrateState{cfg: SubstrateConfig{RelayTLS: relaytls.ModeRequired, RelayCA: tixRelayCA(t), Relays: tixDialer{"127.0.0.1:1"}}}
	_, status, reason := (&APIServer{}).substrateRelayDial(t.Context(), st, registry.Registration{Atespace: "tix", Name: "a", UID: "0001"})
	if status != http.StatusForbidden || reason != "relay_tls_required" {
		t.Fatalf("got %d %s", status, reason)
	}
}

// TestRelayTLSAutoFallsBackWithAudit: auto dials an old template plain with
// one audit row; off dials it plain with none.
func TestRelayTLSAutoFallsBackWithAudit(t *testing.T) {
	for _, tc := range []struct {
		mode relaytls.Mode
		rows int
	}{{"", 1}, {relaytls.ModeAuto, 1}, {relaytls.ModeOff, 0}} {
		au := &tixAudit{}
		st := &substrateState{cfg: SubstrateConfig{RelayTLS: tc.mode, Relays: tixDialer{"127.0.0.1:1"}}, audit: au.fn}
		dial, status, _ := (&APIServer{}).substrateRelayDial(t.Context(), st, registry.Registration{Atespace: "tix", Name: "a", UID: "0001"})
		if status != http.StatusOK || dial == nil || len(au.events) != tc.rows {
			t.Fatalf("mode %q: status %d rows %v", tc.mode, status, au.events)
		}
		if tc.rows == 1 && au.events[0] != "substrate.relay.plain" {
			t.Fatalf("row %v", au.events)
		}
	}
}

// TestRelayCertSANMismatchRefusedOnDial: a TLS template is dialed with TLS
// in every mode and the relay must present the target actor's UID; a
// relay with another actor's certificate fails, and no CA is
// relay_ca_missing.
func TestRelayCertSANMismatchRefusedOnDial(t *testing.T) {
	ca := tixRelayCA(t)
	addr := tixRelayServer(t, ca, "aaaa-0001")
	for _, mode := range []relaytls.Mode{relaytls.ModeAuto, relaytls.ModeRequired, relaytls.ModeOff} {
		st := &substrateState{cfg: SubstrateConfig{RelayTLS: mode, RelayCA: ca, Relays: tixDialer{addr}}}
		for uid, ok := range map[string]bool{"aaaa-0001": true, "bbbb-0002": false} {
			dial, status, reason := (&APIServer{}).substrateRelayDial(t.Context(), st, registry.Registration{Atespace: "tix", Name: "a", UID: uid, RelayStreams: "tls"})
			if status != http.StatusOK {
				t.Fatalf("%s %s: %d %s", mode, uid, status, reason)
			}
			c, err := dial(t.Context())
			if (err == nil) != ok {
				t.Fatalf("%s %s: dial err %v", mode, uid, err)
			}
			if c != nil {
				if _, isTLS := c.(*tls.Conn); !isTLS {
					t.Fatalf("%s: not TLS", mode)
				}
				_ = c.Close()
			}
		}
	}
	st := &substrateState{cfg: SubstrateConfig{Relays: tixDialer{addr}}}
	if _, status, reason := (&APIServer{}).substrateRelayDial(t.Context(), st, registry.Registration{UID: "aaaa-0001", RelayStreams: "tls"}); status != http.StatusServiceUnavailable || reason != "relay_ca_missing" {
		t.Fatalf("no CA: %d %s", status, reason)
	}
}
