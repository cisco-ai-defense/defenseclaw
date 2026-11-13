// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"testing"
	"time"
)

// GAP-0234: the leader answers a name lookup on every egress chain check,
// so FileStore keeps each name's newest registration indexed. The index
// answers what a scan of List does: after a recreate, a late tombstone of
// the predecessor, a tie on CreatedAt, and a reload from disk.
func TestLookupNameIndexMatchesTheScan(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	u1, u2 := "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", "5f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4b"
	old := reg("w1", u1, "alice")
	old.CreatedAt = time.Unix(1000, 0)
	cur := reg("w1", u2, "alice")
	cur.CreatedAt = time.Unix(2000, 0)
	tieA, tieB := reg("t1", "6f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4c", "bob"), reg("t1", "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4d", "bob")
	tieA.CreatedAt, tieB.CreatedAt = time.Unix(3000, 0), time.Unix(3000, 0)
	// Put the newer first: an older registration written later is not the newest.
	for _, r := range []Registration{cur, old, tieB, tieA} {
		if err := s.Put(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	old.Deleted = true // the controller's tombstone lands after the recreate
	if err := s.Put(ctx, old); err != nil {
		t.Fatal(err)
	}
	check := func(what string, st Store) {
		t.Helper()
		for _, name := range []string{"w1", "t1", "nobody"} {
			got, err := LookupName(ctx, st, "eng-web", name)
			if err != nil {
				t.Fatal(err)
			}
			want, err := LookupName(ctx, listOnly{st}, "eng-web", name)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("%s %s: index %+v, scan %+v", what, name, got, want)
			}
		}
		if l, _ := LookupName(ctx, st, "eng-web", "w1"); !l.Found || l.Deleted || l.UID != u2 {
			t.Fatalf("%s: w1 %+v, want the live %s", what, l, u2)
		}
	}
	check("written", s)
	again, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	check("reloaded", again)
}

// listOnly hides FileStore's index: LookupName scans List.
type listOnly struct{ Store }

// GAP-0234: Current is true only for the name's newest, live incarnation.
func TestCurrent(t *testing.T) {
	s, err := OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	u1, u2 := "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", "5f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4b"
	old := reg("w1", u1, "alice")
	old.CreatedAt = time.Unix(1000, 0)
	if err := s.Put(ctx, old); err != nil {
		t.Fatal(err)
	}
	is := func(name, uid string, want bool) {
		t.Helper()
		if got, err := Current(ctx, s, "eng-web", name, uid); err != nil || got != want {
			t.Fatalf("Current(%s, %s) = %v %v, want %v", name, uid, got, err, want)
		}
	}
	is("w1", u1, true)
	is("w2", u1, false) // another name
	cur := reg("w1", u2, "alice")
	cur.CreatedAt = time.Unix(2000, 0)
	if err := s.Put(ctx, cur); err != nil {
		t.Fatal(err)
	}
	is("w1", u1, false) // replaced, not yet tombstoned
	is("w1", u2, true)
	cur.Deleted = true
	if err := s.Put(ctx, cur); err != nil {
		t.Fatal(err)
	}
	is("w1", u2, false) // deleted
	if _, err := Current(ctx, s, "eng-web", "", u2); err == nil {
		t.Fatal("Current without a name")
	}
}
