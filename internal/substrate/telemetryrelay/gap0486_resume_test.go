// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetryrelay

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

func gap0486Leader(t *testing.T) (*Store, *leader.Client) {
	t.Helper()
	s := &Store{ResumeWarmup: -1} // a leader past its warm-up
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, s)
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	return s, &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: time.Millisecond}
}

func gap0486Suspend(s *Store, uid string, at time.Time) {
	s.Add(Record{Kind: KindLifecycle, Lifecycle: chainstate.LifecycleSuspended, At: at, UID: uid, Actor: "a"})
}

func gap0486Sync(t *testing.T, c *leader.Client, rs ...*Resumes) {
	t.Helper()
	for _, r := range rs {
		if err := r.Sync(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
}

// claimed is what a replica does on a hook call: note it and, when it may
// be the first after a resume, claim at the leader.
func gap0486Call(r *Resumes, c *leader.Client, uid string, start time.Time) bool {
	return r.Hook(uid, start) && r.Claim(context.Background(), c, uid, start)
}

// substrate-1 GAP-0486 (RV-T6A): the leader marks only the true first hook
// call after S, whichever replica serves it, and never a later one.
func TestGAP0486LeaderMarksOnlyTheFirstCall(t *testing.T) {
	s, c := gap0486Leader(t)
	var a, b Resumes
	gap0486Sync(t, c, &a, &b)
	S := time.Now()
	gap0486Suspend(s, "u1", S)
	gap0486Sync(t, c, &a, &b, &a, &b) // delivered, then acknowledged
	if gap0486Call(&a, c, "u1", S.Add(-time.Millisecond)) {
		t.Fatal("a call that started before S was marked")
	}
	if !gap0486Call(&b, c, "u1", S.Add(time.Second)) {
		t.Fatal("the first call after S, on the other replica, was not marked")
	}
	if gap0486Call(&a, c, "u1", S.Add(2*time.Second)) || gap0486Call(&b, c, "u1", S.Add(3*time.Second)) {
		t.Fatal("a later call was marked")
	}
}

// A call served after S by a replica that did not have S yet was the first
// one: no later call on any replica is marked, whether that call was
// reported first or a claim came before every replica acknowledged.
func TestGAP0486LeaderNeverMarksALaterCall(t *testing.T) {
	s, c := gap0486Leader(t)
	var a, b Resumes
	gap0486Sync(t, c, &a, &b)
	S := time.Now()
	gap0486Suspend(s, "u1", S)
	gap0486Sync(t, c, &a) // A has S; B does not yet
	if gap0486Call(&b, c, "u1", S.Add(time.Second)) {
		t.Fatal("B claimed without S")
	}
	gap0486Sync(t, c, &a)
	if gap0486Call(&a, c, "u1", S.Add(2*time.Second)) {
		t.Fatal("A's later call was marked before B acknowledged (B's first call was unreported)")
	}
	gap0486Sync(t, c, &a, &b, &a, &b)
	if gap0486Call(&a, c, "u1", S.Add(3*time.Second)) {
		t.Fatal("a call after a refused claim was marked")
	}

	// Reported before any claim: B served the first call before it had S.
	S2 := S.Add(10 * time.Second)
	gap0486Suspend(s, "u2", S2)
	gap0486Sync(t, c, &a)
	b.Hook("u2", S2.Add(time.Second))
	gap0486Sync(t, c, &b, &a, &b, &a)
	if gap0486Call(&a, c, "u2", S2.Add(2*time.Second)) {
		t.Fatal("a later call was marked after the first was reported")
	}

	// The record arrives after the first call was reported: no entry.
	S3 := S.Add(20 * time.Second)
	b.Hook("u3", S3.Add(time.Second))
	gap0486Sync(t, c, &b)
	gap0486Suspend(s, "u3", S3)
	gap0486Sync(t, c, &a, &b, &a, &b)
	if gap0486Call(&a, c, "u3", S3.Add(2*time.Second)) {
		t.Fatal("a call was marked after a record that came late")
	}
}

// A claim waits for every live replica's acknowledgement; a replica that
// stopped syncing for ResumeReplicaTTL no longer counts. A failed sync keeps
// its report; a suspend and resume in one pass, a deleted actor and an
// overflowing report mark nothing; the state is bounded.
func TestGAP0486LeaderEdges(t *testing.T) {
	s, c := gap0486Leader(t)
	clock := time.Now()
	s.resumes.now = func() time.Time { return clock }
	var a, gone Resumes
	gap0486Sync(t, c, &a, &gone)
	S := time.Now()
	gap0486Suspend(s, "u1", S)
	gap0486Sync(t, c, &a, &a)
	clock = clock.Add(ResumeReplicaTTL + time.Second)
	gap0486Sync(t, c, &a)
	if !gap0486Call(&a, c, "u1", S.Add(time.Second)) {
		t.Fatal("a replica gone past the TTL still held the claim back")
	}

	// A failed sync keeps its report for the next one.
	gap0486Suspend(s, "u2", S)
	gap0486Sync(t, c, &a, &a)
	bad := &leader.Client{BaseURL: "http://127.0.0.1:1", Retry: time.Millisecond}
	b2 := Resumes{}
	gap0486Sync(t, c, &b2)
	b2.Hook("u2", S.Add(time.Second)) // not a claim: b2 has S, but see below
	if err := b2.Sync(context.Background(), bad); err == nil {
		t.Fatal("a sync to no leader worked")
	}
	gap0486Sync(t, c, &b2, &a, &b2)
	if gap0486Call(&a, c, "u2", S.Add(2*time.Second)) {
		t.Fatal("the report of a failed sync was lost")
	}

	// One pass; deleted.
	gap0486Suspend(s, "u4", S)
	s.Add(Record{Kind: KindLifecycle, Lifecycle: chainstate.LifecycleResumed, At: S, UID: "u4", Actor: "a"})
	gap0486Suspend(s, "u5", S)
	s.Add(Record{Kind: KindLifecycle, Lifecycle: chainstate.LifecycleDeleted, At: S, UID: "u5", Actor: "a"})
	gap0486Sync(t, c, &a, &b2, &a, &b2)
	for _, uid := range []string{"u4", "u5"} {
		if gap0486Call(&a, c, uid, S.Add(time.Second)) {
			t.Fatalf("%s was marked", uid)
		}
	}
	// A replica that served more actors than it could keep.
	gap0486Suspend(s, "u6", S)
	var o Resumes
	for i := range MaxResumeActors + 1 {
		o.Hook(fmt.Sprintf("x%d", i), S.Add(-time.Second))
	}
	gap0486Sync(t, c, &o, &a, &b2, &o, &a, &b2)
	if gap0486Call(&a, c, "u6", S.Add(time.Second)) {
		t.Fatal("a mark after an overflowing report")
	}
	for i := range MaxResumeActors + 10 {
		gap0486Suspend(s, fmt.Sprintf("s%d", i), S.Add(time.Duration(i)))
	}
	s.resumes.mu.Lock()
	n := len(s.resumes.entries)
	s.resumes.mu.Unlock()
	if n > MaxResumeActors {
		t.Fatalf("the leader keeps %d suspended actors, bound %d", n, MaxResumeActors)
	}
}
