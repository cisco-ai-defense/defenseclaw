// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
)

// tixGateway signs every CSR for the UID signFor returns, as the gateway
// does for the actor its JWT names.
func tixGateway(t *testing.T, signFor func() string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	c, k, err := relaytls.GenerateCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := relaytls.LoadCA(c, k)
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		var in CertRequest
		_ = json.NewDecoder(r.Body).Decode(&in)
		der, _ := base64.StdEncoding.DecodeString(in.CSR)
		p, err := ca.Sign(der, signFor(), time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(CertResponse{Cert: string(p)})
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

// TestRelayCertAfterForkNewUID: a resume or fork with a new UID gets a new
// certificate at the next handshake; the same UID reuses the held one.
func TestRelayCertAfterForkNewUID(t *testing.T) {
	var mu sync.Mutex
	uid := "aaaa-0001"
	cur := func() string { mu.Lock(); defer mu.Unlock(); return uid }
	srv, n := tixGateway(t, cur)
	cs := &CertSource{URL: srv.URL, Client: srv.Client(), Self: func() (Identity, error) {
		return Identity{Atespace: "s", Name: "a", UID: cur()}, nil
	}}
	for i := 0; i < 2; i++ {
		c, err := cs.Get(t.Context())
		if err != nil || c.Leaf.DNSNames[0] != "uid.aaaa-0001"+relaytls.SANSuffix {
			t.Fatalf("get: %v", err)
		}
	}
	if n.Load() != 1 {
		t.Fatalf("requests %d, want 1", n.Load())
	}
	mu.Lock()
	uid = "bbbb-0002"
	mu.Unlock()
	c, err := cs.Get(t.Context())
	if err != nil || c.Leaf.DNSNames[0] != "uid.bbbb-0002"+relaytls.SANSuffix || n.Load() != 2 {
		t.Fatalf("after fork: %v, requests %d", err, n.Load())
	}
}

// TestRelayCertRefusesOtherActorsCert: a certificate for another UID is
// never served, and a new actor without one fails the handshake.
func TestRelayCertRefusesOtherActorsCert(t *testing.T) {
	srv, _ := tixGateway(t, func() string { return "0ff0-0ff0" })
	cs := &CertSource{URL: srv.URL, Client: srv.Client(), Self: func() (Identity, error) {
		return Identity{Atespace: "s", Name: "a", UID: "aaaa-0001"}, nil
	}}
	if _, err := cs.Get(t.Context()); err == nil {
		t.Fatal("served another actor's certificate")
	}
}

// TestRelayPlainListenerOnlyReadyz: a TLS relay answers only the wake-up
// probe without TLS.
func TestRelayPlainListenerOnlyReadyz(t *testing.T) {
	h := plainOnlyHandler()
	for path, want := range map[string]int{"/readyz": 200, Path(RouteWS): http.StatusUpgradeRequired, Path(RouteStatus): http.StatusUpgradeRequired} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != want {
			t.Fatalf("%s: %d, want %d", path, w.Code, want)
		}
	}
}
