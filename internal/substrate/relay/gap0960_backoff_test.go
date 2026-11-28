// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
)

// GAP-0960: after a request that failed, the relay waits a minute before
// it asks again, however many handshakes come in meanwhile.
func TestGAP0960OneRequestPerMinuteAfterAFailure(t *testing.T) {
	c, k, err := relaytls.GenerateCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := relaytls.LoadCA(c, k)
	if err != nil {
		t.Fatal(err)
	}
	var reqs atomic.Int32
	var refuse atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs.Add(1)
		var in CertRequest
		_ = json.NewDecoder(r.Body).Decode(&in)
		if refuse.Load() {
			reason := "reissue_refused"
			if in.Proof != "" {
				reason = "renewal_not_live"
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"Forbidden","reason":"` + reason + `"}`))
			return
		}
		der, _ := base64.StdEncoding.DecodeString(in.CSR)
		p, err := ca.Sign(der, "aaaa-0001", time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(CertResponse{Cert: string(p)})
	}))
	t.Cleanup(srv.Close)
	now := time.Now()
	cs := &CertSource{URL: srv.URL, Client: srv.Client(), Now: func() time.Time { return now }, Self: func() (Identity, error) {
		return Identity{Atespace: "s", Name: "a", UID: "aaaa-0001"}, nil
	}}
	first, err := cs.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	refuse.Store(true)
	now = now.Add(13 * time.Hour) // past half life
	for i := 0; i < 5; i++ {
		if got, err := cs.Get(t.Context()); err != nil || got != first {
			t.Fatalf("handshake %d after a failed renewal: %v", i, err)
		}
	}
	if n := reqs.Load(); n != 3 { // the first, then one renewal (with proof, then without)
		t.Fatalf("requests after five handshakes: %d (want 3)", n)
	}
	now = now.Add(59 * time.Second)
	_, _ = cs.Get(t.Context())
	if n := reqs.Load(); n != 3 {
		t.Fatalf("asked again within a minute: %d requests", n)
	}
	now = now.Add(2 * time.Second)
	_, _ = cs.Get(t.Context())
	if n := reqs.Load(); n != 5 {
		t.Fatalf("did not ask again after a minute: %d requests (want 5)", n)
	}
	refuse.Store(false)
	now = now.Add(time.Minute)
	if got, err := cs.Get(t.Context()); err != nil || got == first {
		t.Fatalf("renewal after the gateway answers again: %v", err)
	}
	// A relay with no certificate waits too.
	refuse.Store(true)
	fresh := &CertSource{URL: srv.URL, Client: srv.Client(), Now: func() time.Time { return now }, Self: cs.Self}
	before := reqs.Load()
	for i := 0; i < 3; i++ {
		if _, err := fresh.Get(t.Context()); err == nil {
			t.Fatal("a refused relay got a certificate")
		}
	}
	if n := reqs.Load() - before; n != 1 {
		t.Fatalf("a relay with no certificate asked %d times in a minute (want 1)", n)
	}
}
