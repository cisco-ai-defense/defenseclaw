// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
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

// R8 (claude:c7409eb0/r8): the name index against the scan under concurrent
// writes and reads,
// with the same names in two atespaces, CreatedAt ties, out-of-order
// writes, late tombstones and a reload.
func TestNameIndexUnderConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	spaces := []string{"eng-web", "eng-ops"}
	names := []string{"a1", "a2", "a3"}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(int64(w)))
			for i := 0; i < 60; i++ {
				sp, nm := spaces[rnd.Intn(2)], names[rnd.Intn(3)]
				uid := fmt.Sprintf("%08x-0000-4000-8000-%012x", w, i)
				r := reg(nm, uid, "alice")
				r.Atespace = sp
				r.Key = ""
				r.CreatedAt = time.Unix(int64(1000+rnd.Intn(20)), 0) // many ties
				if err := s.Put(ctx, r); err != nil {
					t.Error(err)
					return
				}
				if rnd.Intn(3) == 0 {
					r.Deleted = true
					if err := s.Put(ctx, r); err != nil {
						t.Error(err)
						return
					}
				}
			}
		}(w)
	}
	var rw sync.WaitGroup
	for r := 0; r < 4; r++ {
		rw.Add(1)
		go func() {
			defer rw.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, sp := range spaces {
					for _, nm := range names {
						l, err := LookupName(ctx, s, sp, nm)
						if err != nil {
							t.Error(err)
							return
						}
						if _, err := Current(ctx, s, sp, nm, l.UID); err != nil {
							t.Error(err)
							return
						}
					}
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	rw.Wait()
	check := func(what string, st Store) {
		for _, sp := range spaces {
			for _, nm := range names {
				got, err := LookupName(ctx, st, sp, nm)
				if err != nil {
					t.Fatal(err)
				}
				want, err := LookupName(ctx, listOnly{st}, sp, nm)
				if err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Fatalf("%s %s/%s: index %+v, scan %+v", what, sp, nm, got, want)
				}
				// The other atespace's same name never answers.
				other := spaces[0]
				if sp == other {
					other = spaces[1]
				}
				if got.Found {
					if ok, _ := Current(ctx, st, other, nm, got.UID); ok {
						t.Fatalf("%s: %s/%s's UID is current under %s", what, sp, nm, other)
					}
				}
			}
		}
	}
	check("live", s)
	again, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	check("reloaded", again)
}
