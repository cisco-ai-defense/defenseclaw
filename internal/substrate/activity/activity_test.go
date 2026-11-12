// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

func TestReplicasLeaderAndController(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	store := &Store{Now: func() time.Time { return now }, Pending: func() []string { return []string{"u-ask"} }}
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, store)
	hs := httptest.NewServer(srv)
	defer hs.Close()
	client := func() *leader.Client { return &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: time.Second} }
	r1, r2 := &Recorder{Leader: client()}, &Recorder{Leader: client()}
	r1.ObserveActivity(KindHook, "eng-web", "u1", now.Add(-10*time.Minute))
	r2.ObserveActivity(KindModel, "eng-web", "u1", now.Add(-2*time.Minute))
	r2.ObserveActivity(KindRelay, "eng-web", "u2", now.Add(time.Hour)) // a future time is capped
	ctx := context.Background()
	if err := r1.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r2.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	src := &Source{Leader: client(), Now: func() time.Time { return now }}
	if got, ok := src.LastActivity("u1"); !ok || !got.Equal(now.Add(-2*time.Minute)) {
		t.Fatalf("u1 %v %v", got, ok)
	}
	if got, _ := src.LastActivity("u2"); !got.Equal(now) {
		t.Fatalf("future time not capped: %v", got)
	}
	if _, ok := src.LastActivity("u3"); ok {
		t.Fatal("unknown actor has activity")
	}
	if !src.PendingAsk("u-ask") || src.PendingAsk("u1") {
		t.Fatal("pending asks")
	}
	// A failed flush keeps the entries for the next one.
	down := &Recorder{Leader: &leader.Client{BaseURL: "http://127.0.0.1:1", HTTP: hs.Client(), Retry: 10 * time.Millisecond}}
	down.ObserveActivity(KindHook, "eng-web", "u9", now)
	if err := down.Flush(ctx); err == nil {
		t.Fatal("flush to a closed port succeeded")
	}
	down.mu.Lock()
	n := len(down.dirty)
	down.mu.Unlock()
	if n != 1 {
		t.Fatalf("entries after a failed flush: %d", n)
	}
}
