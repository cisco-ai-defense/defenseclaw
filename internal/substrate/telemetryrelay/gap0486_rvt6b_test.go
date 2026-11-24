// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetryrelay

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// substrate-1 GAP-0486 (RV-T6B): a leader that just started marks nothing
// for ResumeReplicaTTL, since a replica that has not synced with it yet may
// have served the first call. Before, a new leader (an empty replica set)
// let the first claim of the one replica it knew win.
func TestGAP0486NewLeaderWarmsUp(t *testing.T) {
	s := &Store{} // the default warm-up
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, s)
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	c := &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: time.Millisecond}
	clock := time.Now()
	s.resumes.now = func() time.Time { return clock }
	var a Resumes
	gap0486Sync(t, c, &a)
	S := time.Now()
	gap0486Suspend(s, "u1", S)
	gap0486Sync(t, c, &a, &a)
	if gap0486Call(&a, c, "u1", S.Add(time.Second)) {
		t.Fatal("a leader inside its warm-up marked a call: a replica it did not know yet may have served the first")
	}
	clock = clock.Add(ResumeReplicaTTL + time.Second)
	S2 := S.Add(time.Minute)
	gap0486Sync(t, c, &a)
	gap0486Suspend(s, "u2", S2)
	gap0486Sync(t, c, &a, &a)
	if !gap0486Call(&a, c, "u2", S2.Add(time.Second)) {
		t.Fatal("past its warm-up the leader did not mark the first call")
	}
}

// RV-T6B: a replica syncs once before it serves (Taker.Join), so a claim on
// another replica waits for its acknowledgement. Before, a new replica first
// synced one interval after it started: it served the first call after the
// resume unknown to the leader, and the other replica's claim for the second
// call won.
func TestGAP0486ReplicaJoinsBeforeServing(t *testing.T) {
	s, c := gap0486Leader(t)
	var a Resumes
	gap0486Sync(t, c, &a)
	S := time.Now()
	gap0486Suspend(s, "u1", S)
	gap0486Sync(t, c, &a, &a)
	r3 := &Taker{Leader: c}
	if err := r3.Join(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The first call, on the new replica: with S from its join it claims,
	// and the claim is refused until it acknowledged (a missed mark).
	gap0486Call(r3.Resumes(), c, "u1", S.Add(time.Second))
	if gap0486Call(&a, c, "u1", S.Add(2*time.Second)) {
		t.Fatal("the second call was marked: the leader did not know the replica that served the first")
	}
}

// RV-T6B P4: past MaxResumeActors the leader drops a batch of the oldest
// call starts at once (one sort per MaxResumeActors/8 new actors), not one
// per new actor after a scan of the whole map under the leader lock; the
// newest are kept.
func TestGAP0486HookSeenEvictsInBatches(t *testing.T) {
	batch := MaxResumeActors / 8
	var l resumeLeader
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range MaxResumeActors {
		l.noteHookLocked(fmt.Sprintf("u%d", i), int64(i+1))
	}
	l.noteHookLocked("new", int64(MaxResumeActors+1))
	if got, want := len(l.hookSeen), MaxResumeActors-batch+1; got != want {
		t.Fatalf("after one new actor past the bound the map holds %d, want %d (a batch of %d evicted)", got, want, batch)
	}
	for i := range batch {
		if _, ok := l.hookSeen[fmt.Sprintf("u%d", i)]; ok {
			t.Fatalf("u%d, among the oldest, was kept", i)
		}
	}
	for _, k := range []string{fmt.Sprintf("u%d", batch), fmt.Sprintf("u%d", MaxResumeActors-1), "new"} {
		if _, ok := l.hookSeen[k]; !ok {
			t.Fatalf("%s, among the newest, was evicted", k)
		}
	}
	for i := range batch - 1 {
		l.noteHookLocked(fmt.Sprintf("n%d", i), int64(MaxResumeActors+2+i))
	}
	if len(l.hookSeen) != MaxResumeActors {
		t.Fatalf("the next %d new actors fill the room the batch left: %d, want %d", batch-1, len(l.hookSeen), MaxResumeActors)
	}
}
