// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
)

// GAP-0929: when the gateway refuses the relay's certificate at a
// handshake (an emergency CA rotation dropped its CA, or recover cleared
// it), the relay asks again at once, not at half life; a renewal refused
// as renewal_ca_dropped is asked again without proof.
func TestGAP0929RelayRenewsWhenTheGatewayRefusesItsCert(t *testing.T) {
	c, k, err := relaytls.GenerateCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := relaytls.LoadCA(c, k)
	if err != nil {
		t.Fatal(err)
	}
	var reqs, proofless atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs.Add(1)
		var in CertRequest
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Proof != "" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"Forbidden","reason":"renewal_ca_dropped"}`))
			return
		}
		proofless.Add(1)
		der, _ := base64.StdEncoding.DecodeString(in.CSR)
		p, err := ca.Sign(der, "aaaa-0001", time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(CertResponse{Cert: string(p)})
	}))
	t.Cleanup(srv.Close)
	cs := &CertSource{URL: srv.URL, Client: srv.Client(), Self: func() (Identity, error) {
		return Identity{Atespace: "s", Name: "a", UID: "aaaa-0001"}, nil
	}}
	first, err := cs.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	failed := make(chan error, 4)
	sp := relaytls.Split(ln.Addr(), cs.ServerConfig(), func(err error) { cs.Rejected(err); failed <- err })
	go func() { _ = http.Serve(sp.TLS(), http.NotFoundHandler()) }()
	go func() { _ = http.Serve(ln, sp.Handler(http.NotFoundHandler())) }()
	refuse := func() {
		t.Helper()
		// A gateway that no longer trusts the CA (empty pool).
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		conn, err := relaytls.Upgrade(t.Context(), raw, &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "uid.aaaa-0001" + relaytls.SANSuffix, MinVersion: tls.VersionTLS13})
		if err == nil {
			_ = conn.Close()
			t.Fatal("the handshake passed")
		}
		select {
		case <-failed:
		case <-time.After(5 * time.Second):
			t.Fatal("the relay did not see the refused handshake")
		}
	}
	refuse()
	second, err := cs.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if second == first || reqs.Load() != 3 || proofless.Load() != 2 {
		t.Fatalf("after a refused handshake: new cert %v, requests %d (want 3), without proof %d (want 2)", second != first, reqs.Load(), proofless.Load())
	}
	// At most once a minute.
	refuse()
	if again, _ := cs.Get(t.Context()); again != second || reqs.Load() != 3 {
		t.Fatalf("a second refused handshake within a minute renewed again (requests %d)", reqs.Load())
	}
	// Other failures (a client that hangs up) do not renew.
	cs.Rejected(&net.OpError{Op: "read", Err: net.ErrClosed})
	if h := cs.cur.Load(); !h.renewAt.After(time.Now()) {
		t.Fatal("a failure that is not the gateway's refusal made the relay renew")
	}
}
