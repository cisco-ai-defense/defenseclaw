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

// TestUseTakesAOnceApprovalOnceGAP0484: over the leader transport, Use
// answers a once approval for the first request only and ErrUsed after
// (also after a restart, and once OnceWindow has passed); an always
// approval answers every request; a pending or another actor's ask is
// never answered.
func TestUseTakesAOnceApprovalOnceGAP0484(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	s.Now = func() time.Time { return now }
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, s)
	hs := httptest.NewServer(srv)
	defer hs.Close()
	c := &Client{Leader: &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: time.Second}}
	ctx := context.Background()
	open := func(host string) Ask {
		t.Helper()
		a, err := c.OpenAsk(ctx, Ask{Atespace: "e", Actor: "a", UID: "u", OwnerID: "o", Host: host})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	once := open("once.example.com")
	if _, err := c.Use(ctx, UseRequest{ID: once.ID, UID: "u"}); !errors.Is(err, ErrUsed) {
		t.Fatalf("a pending ask let a request through: %v", err)
	}
	if _, err := c.Resolve(ctx, ResolveRequest{ID: once.ID, Decision: "approve", CallerID: "o"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Use(ctx, UseRequest{ID: once.ID, UID: "other"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another actor took the approval: %v", err)
	}
	got, err := c.Use(ctx, UseRequest{ID: once.ID, UID: "u"})
	if err != nil || got.State != StateApproved || !got.UsedAt.Equal(now) {
		t.Fatalf("the first request: %+v %v", got, err)
	}
	if _, err := c.Use(ctx, UseRequest{ID: once.ID, UID: "u"}); !errors.Is(err, ErrUsed) {
		t.Fatalf("the second request on a once approval: %v", err)
	}

	always := open("always.example.com")
	if _, err := c.Resolve(ctx, ResolveRequest{ID: always.ID, Decision: "approve", Always: true, CallerID: "o"}); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if got, err := c.Use(ctx, UseRequest{ID: always.ID, UID: "u"}); err != nil || !got.UsedAt.IsZero() {
			t.Fatalf("request %d on an always approval: %+v %v", i, got, err)
		}
	}

	late := open("late.example.com")
	if _, err := c.Resolve(ctx, ResolveRequest{ID: late.ID, Decision: "approve", CallerID: "o"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(OnceWindow + time.Second)
	if _, err := c.Use(ctx, UseRequest{ID: late.ID, UID: "u"}); !errors.Is(err, ErrUsed) {
		t.Fatalf("a once approval past its window: %v", err)
	}

	// A used once approval stays used after a restart.
	_ = s.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.Use(ctx, UseRequest{ID: once.ID, UID: "u"}); !IsUsed(err) {
		t.Fatalf("the used approval after a restart: %v", err)
	}
}
