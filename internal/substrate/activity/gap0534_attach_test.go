// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// substrate-1 GAP-0534: a gateway's attachment report reaches the
// controller through the leader as an attachment, not as activity, so the
// opt-in idle_suspend_without_cpu can still ignore it.
func TestGAP0534AttachReportsReachTheControllerApart(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	store := &Store{Now: func() time.Time { return now }}
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, store)
	hs := httptest.NewServer(srv)
	defer hs.Close()
	client := &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: time.Second}
	rec := &Recorder{Leader: client}
	rec.ObserveActivity(KindHook, "eng-web", "u1", now.Add(-40*time.Minute))
	rec.ObserveActivity(KindAttach, "eng-web", "u1", now.Add(-time.Minute))
	if err := rec.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	src := &Source{Leader: client, Now: func() time.Time { return now }}
	var _ controller.AttachSource = src
	if got, ok := src.Attached("u1"); !ok || !got.Equal(now.Add(-time.Minute)) {
		t.Fatalf("attached %v %v", got, ok)
	}
	if got, _ := src.LastActivity("u1"); !got.Equal(now.Add(-40 * time.Minute)) {
		t.Fatalf("an attachment report counted as activity: %v", got)
	}
	if _, ok := src.Attached("u2"); ok {
		t.Fatal("an actor never attached is attached")
	}
}

// substrate-1 GAP-0538 (f): with the leader unreachable the controller
// kept reading its last snapshot, so an actor busy since then looked
// silent and was suspended. A snapshot older than two flushes and the TTL
// makes activity, task ends and attachments unknown (not idle).
func TestGAP0538StaleSnapshotIsUnknown(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	store := &Store{Now: clock}
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, store)
	hs := httptest.NewServer(srv)
	client := &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: 10 * time.Millisecond}
	rec := &Recorder{Leader: client}
	rec.ObserveActivity(KindHook, "eng-web", "u1", now.Add(-time.Hour))
	rec.ObserveActivity(KindTaskEnd, "eng-web", "u1", now.Add(-time.Hour))
	if err := rec.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	src := &Source{Leader: client, Now: clock}
	if _, ok := src.LastActivity("u1"); !ok {
		t.Fatal("fresh snapshot: activity unknown")
	}
	hs.Close() // the leader is gone
	now = now.Add(DefaultSnapshotTTL + DefaultFlushInterval)
	if _, ok := src.LastActivity("u1"); !ok {
		t.Fatal("a snapshot one flush past its TTL is still usable")
	}
	now = now.Add(2 * DefaultFlushInterval)
	if _, ok := src.LastActivity("u1"); ok {
		t.Fatal("a stale snapshot still reports activity")
	}
	if _, ok := src.TaskEnded("u1"); ok {
		t.Fatal("a stale snapshot still reports a task end")
	}
}
