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

// GAP-1067 (live, e1): a template's relay warms its certificate in the
// golden snapshot, where it has no egress, so that request fails. An actor
// restored from the snapshot is a new actor (a new UID) seconds later on
// the relay's clock. Its first handshake must ask the gateway at once: the
// GAP-0960 wait after a failure is for the actor that failed, or every
// attach in the first minute of a restored actor fails with
// "tls: internal error" and run removes the agent as unreachable.
func TestGAP1067RestoredActorAsksAtOnce(t *testing.T) {
	c, k, err := relaytls.GenerateCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := relaytls.LoadCA(c, k)
	if err != nil {
		t.Fatal(err)
	}
	var uid atomic.Value
	uid.Store("aaaa-0001")
	var egress atomic.Bool
	var reqs atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs.Add(1)
		if !egress.Load() {
			http.Error(w, "no egress in the snapshot", http.StatusServiceUnavailable)
			return
		}
		var in CertRequest
		_ = json.NewDecoder(r.Body).Decode(&in)
		der, _ := base64.StdEncoding.DecodeString(in.CSR)
		p, err := ca.Sign(der, uid.Load().(string), time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(CertResponse{Cert: string(p)})
	}))
	t.Cleanup(srv.Close)
	now := time.Now()
	cs := &CertSource{URL: srv.URL, Client: srv.Client(), Now: func() time.Time { return now }, Self: func() (Identity, error) {
		return Identity{Atespace: "s", Name: "a", UID: uid.Load().(string)}, nil
	}}
	if err := cs.Warm(t.Context()); err == nil {
		t.Fatal("the snapshot's warm-up got a certificate without egress")
	}
	// Restored: a new actor, egress written, 5 s later on the relay's clock.
	uid.Store("bbbb-0002")
	egress.Store(true)
	now = now.Add(5 * time.Second)
	got, err := cs.Get(t.Context())
	if err != nil {
		t.Fatalf("first handshake of the restored actor: %v", err)
	}
	if want := "uid.bbbb-0002" + relaytls.SANSuffix; len(got.Leaf.DNSNames) != 1 || got.Leaf.DNSNames[0] != want {
		t.Fatalf("served %v, want %s", got.Leaf.DNSNames, want)
	}
	// The same actor failing still waits (GAP-0960 is kept).
	egress.Store(false)
	uid.Store("cccc-0003")
	now = now.Add(time.Second)
	_, _ = cs.Get(t.Context())
	n := reqs.Load()
	for i := 0; i < 5; i++ {
		_, _ = cs.Get(t.Context())
	}
	if reqs.Load() != n {
		t.Fatalf("a failing actor asked %d more times within a minute", reqs.Load()-n)
	}
}
