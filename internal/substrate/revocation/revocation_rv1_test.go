// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package revocation

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Review RV-SECR1 fixes (lanes/tsecr/RV1.md), from the reviewer's probes.

// RV1-04: a stream opened after the pull that ended its sign-in is closed
// at once, not left open until the relay session expires.
func TestRV104StreamOpenedAfterTheEndCloses(t *testing.T) {
	st, err := OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	snap := NewSnapshot(time.Minute)
	streams := NewStreams(snap)
	ctx := context.Background()
	if _, err := st.Put(ctx, Entry{Person: alice, Token: "jti:x"}); err != nil {
		t.Fatal(err)
	}
	if err := snap.Pull(ctx, st); err != nil {
		t.Fatal(err)
	}
	sctx, release := streams.Open(ctx, Stream{Person: alice, TokenKey: "jti:x", IssuedAt: time.Now().Add(-time.Minute)})
	defer release()
	if sctx.Err() == nil || streams.Count() != 0 || streams.Closed() != 1 {
		t.Fatalf("stream of an ended token: err %v, open %d, closed %d", sctx.Err(), streams.Count(), streams.Closed())
	}
	live, done := streams.Open(ctx, Stream{Person: alice, TokenKey: "jti:y", IssuedAt: time.Now().Add(-time.Minute)})
	defer done()
	if live.Err() != nil || streams.Count() != 1 {
		t.Fatalf("a live sign-in's stream: %v, open %d", live.Err(), streams.Count())
	}
}

// RV1-05: past max_tokens_per_person a token end becomes a watermark; a
// lift of the person's end keeps it, so the ended tokens stay ended.
func TestRV105LiftKeepsOverflowEnds(t *testing.T) {
	st, _ := OpenFileStore(t.TempDir())
	st.MaxTokensPerPerson = 1
	ctx := context.Background()
	snap := NewSnapshot(time.Minute)
	iat := time.Now().Add(-time.Hour)
	_, _ = st.Put(ctx, Entry{Person: alice, Token: "jti:1"})
	over, _ := st.Put(ctx, Entry{Person: alice, Token: "jti:2"})
	if !over.Overflow || over.Token != "" {
		t.Fatalf("the token past the cap: %+v", over)
	}
	_, _ = st.Put(ctx, Entry{Person: alice, NotBefore: Watermark(time.Now()), By: "admin"})
	_ = snap.Pull(ctx, st)
	if n := len(snap.Active()); n != 2 {
		t.Fatalf("active: %d, want the admin end and the overflow end", n)
	}
	_, _ = st.Put(ctx, Entry{Person: alice, Lift: true})
	_ = snap.Pull(ctx, st)
	if err := snap.Check(alice, "jti:2", iat); !errors.Is(err, ErrEnded) {
		t.Fatalf("lift brought ended token jti:2 back: %v", err)
	}
	if a := snap.Active(); len(a) != 1 || !a[0].Overflow {
		t.Fatalf("after the lift: %+v, want only the overflow end", a)
	}
	// A replica that rebuilds from a full pull keeps it too.
	fresh := NewSnapshot(time.Minute)
	_ = fresh.Pull(ctx, st)
	if err := fresh.Check(alice, "jti:2", iat); !errors.Is(err, ErrEnded) {
		t.Fatalf("full pull after the lift: %v", err)
	}
	// A caller can't mark its own entry as overflow.
	if e, _ := st.Put(ctx, Entry{Person: "i#b", NotBefore: Watermark(time.Now()), Overflow: true}); e.Overflow {
		t.Fatal("a put set Overflow")
	}
}

// RV1-07: a reset of the leader's list (new generation) is reported, and
// the replica keeps what it knew until it lapses.
func TestRV107ResetKeepsEndsAndIsReported(t *testing.T) {
	ctx := context.Background()
	a, _ := OpenFileStore(t.TempDir())
	b, _ := OpenFileStore(t.TempDir())
	now := time.Now()
	snap := NewSnapshot(0)
	snap.SetClock(func() time.Time { return now })
	var kept []int
	snap.OnReset(func(n int) { kept = append(kept, n) })
	_, _ = a.Put(ctx, Entry{Person: alice, Token: "jti:1"})
	_, _ = a.Put(ctx, Entry{Person: "i#bob", NotBefore: Watermark(time.Now())})
	_ = snap.Pull(ctx, a)
	if len(kept) != 0 {
		t.Fatalf("first pull reported a reset: %v", kept)
	}
	_ = snap.Pull(ctx, b)
	if len(kept) != 1 || kept[0] != 2 {
		t.Fatalf("reset reports %v, want [2]", kept)
	}
	old := now.Add(-time.Hour)
	if err := snap.Check(alice, "jti:1", old); !errors.Is(err, ErrEnded) {
		t.Fatalf("reset forgot ended token jti:1: %v", err)
	}
	if err := snap.Check("i#bob", "", old); !errors.Is(err, ErrEnded) {
		t.Fatalf("reset forgot bob's end: %v", err)
	}
	if n := len(snap.Active()); n != 1 {
		t.Fatalf("active after the reset: %d, want bob's carried end", n)
	}
	// A lift in the new list removes a carried end.
	_, _ = b.Put(ctx, Entry{Person: "i#bob", Lift: true})
	_ = snap.Pull(ctx, b)
	if err := snap.Check("i#bob", "", old); err != nil {
		t.Fatalf("lift after the reset: %v", err)
	}
	// Carried entries lapse like any other.
	now = now.Add(Life + time.Minute)
	_ = snap.Pull(ctx, b)
	if err := snap.Check(alice, "jti:1", old); err != nil {
		t.Fatalf("carried entry did not lapse: %v", err)
	}
}
