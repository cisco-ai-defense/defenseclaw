// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

const gap0861UID = "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a"

// GAP-0861: the leader keeps one live relay certificate per actor, over a
// restart; a claim without Replace does not take a live one; an expired one
// is not live and is dropped; Clear drops it.
func TestGAP0861RelayCertRecord(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now()
	c1 := RelayCert{Serial: "a1", NotAfter: now.Add(24 * time.Hour)}
	c2 := RelayCert{Serial: "b2", NotAfter: now.Add(24 * time.Hour)}
	claim := func(s RelayCerts, c RelayCert, replace bool, at time.Time) RelayCertClaimed {
		t.Helper()
		got, err := s.ClaimRelayCert(ctx, RelayCertClaim{Atespace: "eng-web", UID: gap0861UID, Cert: c, Replace: replace, Now: at})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := claim(s, c1, false, now); !got.Set || got.Prev.Serial != "" {
		t.Fatalf("first %+v", got)
	}
	if got := claim(s, c2, false, now); got.Set || got.Prev.Serial != "a1" {
		t.Fatalf("second without replace %+v", got)
	}
	// A registration written whole does not touch the record.
	if err := s.Put(ctx, reg("a1", gap0861UID, "alice")); err != nil {
		t.Fatal(err)
	}
	r, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := claim(r, c2, false, now); got.Set || got.Prev.Serial != "a1" {
		t.Fatalf("after a restart %+v", got)
	}
	if got := claim(r, c2, true, now); !got.Set || got.Prev.Serial != "a1" {
		t.Fatalf("replace %+v", got)
	}
	if got := claim(r, c1, false, now.Add(25*time.Hour)); !got.Set || got.Prev.Serial != "" {
		t.Fatalf("after expiry %+v", got)
	}
	if err := r.ClearRelayCert(ctx, "eng-web", gap0861UID); err != nil {
		t.Fatal(err)
	}
	if got := claim(r, c2, false, now); !got.Set {
		t.Fatalf("after clear %+v", got)
	}
	// Expired records of other actors are dropped from the folder.
	other := "5a0d4b2f-9e3c-4d88-af1b-7c6e2d3f4a5b"
	if _, err := r.ClaimRelayCert(ctx, RelayCertClaim{Atespace: "eng-web", UID: other, Cert: RelayCert{Serial: "c3", NotAfter: now.Add(time.Minute)}, Now: now}); err != nil {
		t.Fatal(err)
	}
	claim(r, c1, true, now.Add(time.Hour))
	if n, _ := os.ReadDir(filepath.Join(dir, relayCertDir)); len(n) != 1 {
		t.Fatalf("records %d, want 1", len(n))
	}
	if _, err := r.ClaimRelayCert(ctx, RelayCertClaim{Atespace: "eng-web", UID: "../x", Cert: c1}); err == nil {
		t.Fatal("bad UID claimed")
	}
	if _, err := r.ClaimRelayCert(ctx, RelayCertClaim{Atespace: "eng-web", UID: gap0861UID}); err == nil {
		t.Fatal("empty certificate claimed")
	}
}

// GAP-0861: the record over the leader transport, as gateway replicas use it.
func TestGAP0861RelayCertOverLeader(t *testing.T) {
	fs, err := OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, fs)
	hs := httptest.NewServer(srv)
	defer hs.Close()
	newRemote := func() *Remote {
		return &Remote{Client: &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: time.Second}}
	}
	a, b := newRemote(), newRemote()
	ctx := context.Background()
	c := RelayCert{Serial: "a1", NotAfter: time.Now().Add(time.Hour)}
	if got, err := a.ClaimRelayCert(ctx, RelayCertClaim{Atespace: "eng-web", UID: gap0861UID, Cert: c}); err != nil || !got.Set {
		t.Fatalf("A %+v %v", got, err)
	}
	if got, err := b.ClaimRelayCert(ctx, RelayCertClaim{Atespace: "eng-web", UID: gap0861UID, Cert: RelayCert{Serial: "b2", NotAfter: c.NotAfter}}); err != nil || got.Set || got.Prev.Serial != "a1" {
		t.Fatalf("B %+v %v", got, err)
	}
	if err := b.ClearRelayCert(ctx, "eng-web", gap0861UID); err != nil {
		t.Fatal(err)
	}
	if got, err := a.ClaimRelayCert(ctx, RelayCertClaim{Atespace: "eng-web", UID: gap0861UID, Cert: c}); err != nil || !got.Set {
		t.Fatalf("after clear %+v %v", got, err)
	}
	// GAP-0928: the live record and the renewal compare-and-swap over the leader.
	if live, ok, err := b.LiveRelayCert(ctx, "eng-web", gap0861UID); err != nil || !ok || live.Serial != c.Serial {
		t.Fatalf("live over the leader %+v %v %v", live, ok, err)
	}
	if got, err := b.ClaimRelayCert(ctx, RelayCertClaim{Atespace: "eng-web", UID: gap0861UID, Cert: RelayCert{Serial: "z9", NotAfter: c.NotAfter}, Expect: "not-live"}); err != nil || got.Set {
		t.Fatalf("renewal of a certificate that is not live over the leader %+v %v", got, err)
	}
	if _, err := a.ClaimRelayCert(ctx, RelayCertClaim{Atespace: "eng-web", UID: "../x", Cert: c}); err == nil {
		t.Fatal("bad UID over the leader")
	}
}
