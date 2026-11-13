// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package asks

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

func TestAsksOwnOnlyApproveAndPersist(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	s.Now = func() time.Time { return now }
	var approved []string
	s.OnApprove = func(_ context.Context, a Ask) error { approved = append(approved, a.Host); return nil }
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, s)
	hs := httptest.NewServer(srv)
	defer hs.Close()
	c := &Client{Leader: &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: time.Second}}
	ctx := context.Background()
	alice, bob := "https://idp#alice", "https://idp#bob"
	a, err := c.OpenAsk(ctx, Ask{Atespace: "eng-web", Actor: "alice-1", UID: "u1", OwnerID: alice, Host: "pypi.example.org"})
	if err != nil || a.ID == "" || a.State != StatePending {
		t.Fatalf("open %+v %v", a, err)
	}
	// The same question is asked once.
	if again, _ := c.OpenAsk(ctx, Ask{Atespace: "eng-web", Actor: "alice-1", UID: "u1", OwnerID: alice, Host: "pypi.example.org"}); again.ID != a.ID {
		t.Fatalf("duplicate ask %s vs %s", again.ID, a.ID)
	}
	if list, _ := c.List(ctx, ListRequest{OwnerID: bob, PendingOnly: true}); len(list) != 0 {
		t.Fatalf("bob sees %v", list)
	}
	if _, err := c.List(ctx, ListRequest{}); err == nil {
		t.Fatal("a list without an owner answered")
	}
	if _, err := c.Resolve(ctx, ResolveRequest{ID: a.ID, Decision: "approve", CallerID: bob}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob answered alice's ask: %v", err)
	}
	got, err := c.Resolve(ctx, ResolveRequest{ID: a.ID, Decision: "approve", CallerID: alice, Always: true})
	if err != nil || got.State != StateApproved || got.DecidedBy != alice || len(approved) != 1 {
		t.Fatalf("approve %+v %v %v", got, err, approved)
	}
	if _, err := c.Resolve(ctx, ResolveRequest{ID: a.ID, Decision: "deny", CallerID: alice}); !errors.Is(err, ErrDecided) {
		t.Fatalf("second answer %v", err)
	}
	// An administrator answers as themselves.
	b, _ := c.OpenAsk(ctx, Ask{Atespace: "eng-web", Actor: "bob-1", UID: "u2", OwnerID: bob, Tool: "mcp__docs__search"})
	if got, err := c.Resolve(ctx, ResolveRequest{ID: b.ID, Decision: "deny", CallerID: "https://idp#root", Admin: true}); err != nil || got.DecidedBy != "https://idp#root" {
		t.Fatalf("admin deny %+v %v", got, err)
	}
	// Decisions: own only, newest first.
	if _, err := c.Record(ctx, Decision{Atespace: "eng-web", Actor: "alice-1", UID: "u1", OwnerID: alice, Source: "hook", Verdict: "block"}); err != nil {
		t.Fatal(err)
	}
	ds, _ := c.Decisions(ctx, ListRequest{OwnerID: alice})
	if len(ds) != 2 || ds[0].Verdict != "block" || ds[1].Verdict != StateApproved {
		t.Fatalf("alice decisions %+v", ds)
	}
	// Expiry, the pending list and a restart.
	cAsk, _ := c.OpenAsk(ctx, Ask{Atespace: "eng-web", Actor: "alice-1", UID: "u1", OwnerID: alice, Host: "late.example.org"})
	if p := s.Pending(); len(p) != 1 || p[0] != "u1" {
		t.Fatalf("pending %v", p)
	}
	now = now.Add(DefaultAskExpiry + time.Second)
	if p := s.Pending(); len(p) != 0 {
		t.Fatalf("pending after expiry %v", p)
	}
	_ = s.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if a := s2.asks[cAsk.ID]; a == nil || a.State != StateExpired {
		t.Fatalf("reloaded ask %+v", a)
	}
	if len(s2.decisions) < 3 {
		t.Fatalf("reloaded decisions %d", len(s2.decisions))
	}
}

// E16: a crashed actor's open asks are closed; others stay.
func TestCloseActorEndsItsAsks(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	a1, _ := s.OpenAsk(ctx, Ask{Atespace: "eng-web", Actor: "a1", UID: "u1", OwnerID: "o", Host: "x.example.org"})
	_, _ = s.OpenAsk(ctx, Ask{Atespace: "eng-web", Actor: "a1", UID: "u1", OwnerID: "o", Tool: "mcp__t__x"})
	other, _ := s.OpenAsk(ctx, Ask{Atespace: "eng-web", Actor: "a2", UID: "u2", OwnerID: "o", Host: "y.example.org"})
	if n := s.CloseActor("u1", "the actor crashed"); n != 2 {
		t.Fatalf("closed %d, want 2", n)
	}
	if p := s.Pending(); len(p) != 1 || p[0] != "u2" {
		t.Fatalf("pending %v", p)
	}
	if _, err := s.Resolve(ctx, ResolveRequest{ID: a1.ID, Decision: "approve", CallerID: "o"}); !IsDecided(err) {
		t.Fatalf("approve a closed ask: %v", err)
	}
	if got, _ := s.List(ctx, ListRequest{OwnerID: "o"}); len(got) != 3 {
		t.Fatalf("list %d", len(got))
	}
	ds, _ := s.Decisions(ctx, ListRequest{OwnerID: "o"})
	if len(ds) != 2 || ds[0].Verdict != StateExpired || ds[0].Reason != "the actor crashed" {
		t.Fatalf("decisions %+v", ds)
	}
	_ = other
}
