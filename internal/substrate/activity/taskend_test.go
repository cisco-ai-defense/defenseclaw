// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"testing"
	"time"
)

// GAP-0274: a task end is kept apart from activity.
func TestTaskEndIsNotActivity(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := &Store{Now: func() time.Time { return now }}
	_, _ = s.Observe(context.Background(), Batch{Entries: []Entry{
		{Atespace: "a", UID: "u1", Last: map[string]time.Time{KindHook: now.Add(-time.Hour), KindTaskEnd: now.Add(-time.Minute)}},
		{Atespace: "a", UID: "u2", Last: map[string]time.Time{KindModel: now.Add(-time.Second)}},
	}})
	snap, _ := s.Snapshot(context.Background(), SnapshotRequest{})
	if !snap.Last["u1"].Equal(now.Add(-time.Hour)) {
		t.Fatalf("the task end moved u1's last activity: %v", snap.Last["u1"])
	}
	if !snap.Ended["u1"].Equal(now.Add(-time.Minute)) {
		t.Fatalf("ended %v", snap.Ended)
	}
	if _, ok := snap.Ended["u2"]; ok {
		t.Fatal("u2 has no task end")
	}
	src := &Source{Now: func() time.Time { return now }, snap: snap, at: now, got: now}
	if got, ok := src.TaskEnded("u1"); !ok || !got.Equal(now.Add(-time.Minute)) {
		t.Fatalf("TaskEnded %v %v", got, ok)
	}
	if _, ok := src.TaskEnded("u2"); ok {
		t.Fatal("TaskEnded u2")
	}
}
