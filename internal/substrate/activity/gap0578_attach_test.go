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

// substrate-1:GAP-0578 (e): attachment reports reach the leader through each
// replica's flush. A replica that lost its way to the leader for longer than
// idle_suspend_after, while the controller still read a fresh leader
// snapshot, made an attached quiet actor look detached. Each flush now
// carries the replica's heartbeat (an entry, so the previous release's leader
// accepts it), and an attachment whose replica fell silent while it was
// being reported is unknown, reported as open; a replica that keeps beating
// without re-sending the report (the terminal closed) and a replica silent
// for over an hour (gone) leave the report at its own time.
func TestGAP0578SilentReplicaKeepsItsAttachmentOpen(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	store := &Store{Now: clock}
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, store)
	hs := httptest.NewServer(srv)
	defer hs.Close()
	client := &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: time.Second}
	send := func(replica string, entries ...Entry) {
		t.Helper()
		// The wire a replica's Recorder sends: its entries and its heartbeat.
		batch := Batch{Entries: append(entries, Entry{UID: "replica/" + replica,
			Last: map[string]time.Time{"heartbeat": now}})}
		if err := client.Call(context.Background(), leader.MethodActivityObserve, leader.NewRequestID(), batch, nil); err != nil {
			t.Fatal(err)
		}
	}
	attach := func(uid string) Entry {
		return Entry{Atespace: "eng-web", UID: uid, Last: map[string]time.Time{KindAttach: now, KindHook: now.Add(-time.Hour)}}
	}
	attachedAt := func(uid string) time.Time {
		t.Helper()
		src := &Source{Leader: client, Now: clock}
		at, ok := src.Attached(uid)
		if !ok {
			t.Fatalf("%s: attachment unknown to the source", uid)
		}
		return at
	}
	reported := now
	send("gw-a", attach("silent"))
	send("gw-b", attach("closed"))
	send("gw-c", attach("gone"))
	// gw-a falls silent; gw-b keeps beating but stops re-sending (the
	// terminal closed); gw-c falls silent too.
	for range 10 * 12 {
		now = now.Add(5 * time.Second)
		send("gw-b")
	}
	if got := attachedAt("silent"); !got.Equal(now) {
		t.Fatalf("an attachment whose replica fell silent 10 min ago reads %v, want open now (%v): a quiet attached actor looks detached",
			got, now)
	}
	if got := attachedAt("closed"); !got.Equal(reported) {
		t.Fatalf("an attachment no longer re-sent by a live replica reads %v, want its report time %v", got, reported)
	}
	// The same actor reported again through a live replica follows that one.
	now = now.Add(5 * time.Second)
	send("gw-b", attach("silent"))
	now = now.Add(5 * time.Minute)
	for range 3 {
		send("gw-b")
	}
	if got := attachedAt("silent"); !got.Equal(now.Add(-5 * time.Minute)) {
		t.Fatalf("an attachment last reported by a live replica reads %v, want its report time", got)
	}
	now = now.Add(time.Hour)
	send("gw-b")
	if got := attachedAt("gone"); !got.Equal(reported) {
		t.Fatalf("an attachment of a replica silent for over an hour reads %v, want its report time %v", got, reported)
	}
	// A batch of the previous release (no heartbeat) is not tracked.
	old := Batch{Entries: []Entry{attach("old-wire")}}
	if err := client.Call(context.Background(), leader.MethodActivityObserve, leader.NewRequestID(), old, nil); err != nil {
		t.Fatal(err)
	}
	reportedOld := now
	now = now.Add(10 * time.Minute)
	if got := attachedAt("old-wire"); !got.Equal(reportedOld) {
		t.Fatalf("an attachment without a heartbeat reads %v, want its report time", got)
	}
	if _, ok := store.last["replica/gw-b"]; ok {
		t.Fatal("a heartbeat entry was kept as an actor")
	}
}
