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
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

const alice = "https://sso.example.test#alice"

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newStore(t *testing.T, dir string, c *clock) *FileStore {
	t.Helper()
	s, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.SetClock(c.now)
	return s
}

func synced(t *testing.T, src Source, c *clock) *Snapshot {
	t.Helper()
	snap := NewSnapshot(time.Minute)
	snap.SetClock(c.now)
	pull(t, snap, src)
	return snap
}

func pull(t *testing.T, snap *Snapshot, src Source) {
	t.Helper()
	gen, seq := snap.Cursor()
	d, err := src.Since(context.Background(), gen, seq)
	if err != nil {
		t.Fatal(err)
	}
	snap.Apply(d)
}

func TestTokenKeyHidesTheToken(t *testing.T) {
	k := identity.TokenKey("iss", "jti-1", "raw.token.value")
	if k == identity.TokenKey("other", "jti-1", "raw.token.value") || len(k) != 36 {
		t.Fatalf("key %q must depend on the issuer and be a fixed-size hash", k)
	}
	if identity.TokenKey("iss", "", "raw.token.value") == identity.TokenKey("iss", "", "raw.token.other") {
		t.Fatal("a token without jti is keyed by a hash of the whole token")
	}
}

func TestRevokedTokenAndWatermark(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	s := newStore(t, t.TempDir(), c)
	key := identity.TokenKey("iss", "j1", "")
	if _, err := s.Put(context.Background(), Entry{Person: alice, Token: key}); err != nil {
		t.Fatal(err)
	}
	snap := synced(t, s, c)
	iat := c.t.Add(-time.Minute)
	if err := snap.Check(alice, key, iat); !errors.Is(err, ErrEnded) {
		t.Fatalf("revoked token: %v", err)
	}
	if err := snap.Check(alice, identity.TokenKey("iss", "j2", ""), iat); err != nil {
		t.Fatalf("another token of the same person: %v", err)
	}
	// logout --all: every token issued before now.
	c.t = c.t.Add(10 * time.Second)
	if _, err := s.Put(context.Background(), Entry{Person: alice, NotBefore: c.t}); err != nil {
		t.Fatal(err)
	}
	pull(t, snap, s)
	if err := snap.Check(alice, identity.TokenKey("iss", "j2", ""), iat); !errors.Is(err, ErrEnded) {
		t.Fatalf("token from before the watermark: %v", err)
	}
	if err := snap.Check(alice, identity.TokenKey("iss", "j3", ""), c.t); err != nil {
		t.Fatalf("a sign-in made after the watermark must work: %v", err)
	}
	if err := snap.Check("https://sso.example.test#bob", "", iat); err != nil {
		t.Fatalf("another person: %v", err)
	}
	if got := snap.Active(); len(got) != 1 || got[0].Person != alice {
		t.Fatalf("Active = %+v", got)
	}
	// An admin lifts it early.
	if _, err := s.Put(context.Background(), Entry{Person: alice, Lift: true}); err != nil {
		t.Fatal(err)
	}
	pull(t, snap, s)
	if err := snap.Check(alice, identity.TokenKey("iss", "j2", ""), iat); err != nil || len(snap.Active()) != 0 {
		t.Fatalf("after a lift: %v, active %+v", err, snap.Active())
	}
}

func TestRevocationSurvivesLeaderRestart(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	dir := t.TempDir()
	s := newStore(t, dir, c)
	key := identity.TokenKey("iss", "j1", "")
	_, _ = s.Put(context.Background(), Entry{Person: alice, Token: key})
	s2 := newStore(t, dir, c) // a new leader opens the same volume
	if err := synced(t, s2, c).Check(alice, key, c.t); !errors.Is(err, ErrEnded) {
		t.Fatalf("after a restart: %v", err)
	}
	// A list that does not parse is refused, never silently emptied.
	if err := os.WriteFile(filepath.Join(dir, "revocations.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(dir); err == nil {
		t.Fatal("a corrupt list must stop the leader")
	}
}

func TestRevocationPurgeAtExpiry(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	s := newStore(t, t.TempDir(), c)
	key := identity.TokenKey("iss", "j1", "")
	_, _ = s.Put(context.Background(), Entry{Person: alice, Token: key})
	c.t = c.t.Add(Life + time.Second)
	d, _ := s.Since(context.Background(), "", 0)
	if len(d.Entries) != 0 {
		t.Fatalf("entries past their life are purged: %+v", d.Entries)
	}
}

func TestRevocationBoundedPerPerson(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	s := newStore(t, t.TempDir(), c)
	s.MaxTokensPerPerson = 3
	var last Entry
	for i := 0; i < 4; i++ {
		var err error
		last, err = s.Put(context.Background(), Entry{Person: alice, Token: identity.TokenKey("iss", string(rune('a'+i)), "")})
		if err != nil {
			t.Fatal(err)
		}
	}
	if last.Token != "" || last.NotBefore.IsZero() {
		t.Fatalf("the entry past the cap must become a watermark: %+v", last)
	}
	snap := synced(t, s, c)
	if err := snap.Check(alice, identity.TokenKey("iss", "z", ""), c.t.Add(-time.Second)); !errors.Is(err, ErrEnded) {
		t.Fatalf("past the cap every earlier token is refused: %v", err)
	}
}

func TestReplicaRefusesBeforeFirstSync(t *testing.T) {
	snap := NewSnapshot(time.Minute)
	if err := snap.Check(alice, "", time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("not loaded: %v", err)
	}
	var off *Snapshot
	if err := off.Check(alice, "", time.Now()); err != nil {
		t.Fatalf("revocation off accepts: %v", err)
	}
}

func TestReplicaRefusesWhenRevocationStale(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	s := newStore(t, t.TempDir(), c)
	snap := synced(t, s, c)
	c.t = c.t.Add(59 * time.Second)
	if err := snap.Check(alice, "", c.t); err != nil {
		t.Fatalf("within max_stale: %v", err)
	}
	c.t = c.t.Add(2 * time.Second)
	if err := snap.Check(alice, "", c.t); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("past max_stale: %v", err)
	}
}

func TestRevocationGenerationChangeFullPull(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	s := newStore(t, t.TempDir(), c)
	key := identity.TokenKey("iss", "j1", "")
	_, _ = s.Put(context.Background(), Entry{Person: alice, Token: key})
	snap := synced(t, s, c)
	// The leader's volume was replaced: a new, empty list. The replica
	// follows the new list and keeps the ends it knew until they lapse
	// (RV1-07, TestRV107ResetKeepsEndsAndIsReported).
	s2 := newStore(t, t.TempDir(), c)
	pull(t, snap, s2)
	if err := snap.Check(alice, key, c.t); !errors.Is(err, ErrEnded) {
		t.Fatalf("a new generation dropped an end the replica knew: %v", err)
	}
	if gen, _ := snap.Cursor(); gen != s2.doc.Generation {
		t.Fatalf("cursor generation %q, want %q", gen, s2.doc.Generation)
	}
}

func TestStreamsCloseOnRevoke(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	s := newStore(t, t.TempDir(), c)
	snap := synced(t, s, c)
	streams := NewStreams(snap)
	iat := c.t.Add(-time.Minute)
	key := identity.TokenKey("iss", "j1", "")
	actx, release := streams.Open(context.Background(), Stream{Person: alice, TokenKey: key, IssuedAt: iat})
	defer release()
	bctx, releaseB := streams.Open(context.Background(), Stream{Person: "https://sso.example.test#bob", IssuedAt: iat})
	defer releaseB()
	// A stale list closes nothing.
	c.t = c.t.Add(2 * time.Minute)
	if n := streams.CloseEnded(); n != 0 || actx.Err() != nil {
		t.Fatalf("stale list closed %d streams", n)
	}
	_, _ = s.Put(context.Background(), Entry{Person: alice, NotBefore: c.t})
	pull(t, snap, s) // OnChange closes the ended streams
	select {
	case <-actx.Done():
	case <-time.After(time.Second):
		t.Fatal("alice's stream was not closed")
	}
	if bctx.Err() != nil || streams.Count() != 1 {
		t.Fatalf("bob's stream must stay open (count %d)", streams.Count())
	}
	var off *Streams
	ctx, rel := off.Open(context.Background(), Stream{})
	rel()
	if ctx.Err() != nil {
		t.Fatal("a nil registry must not cancel")
	}
}

func TestLeaderRPCRoundTrip(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	s := newStore(t, t.TempDir(), c)
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, s)
	hs := httptest.NewServer(srv)
	defer hs.Close()
	cl := &Client{Leader: &leader.Client{BaseURL: hs.URL, HTTP: hs.Client()}}
	key := identity.TokenKey("iss", "j1", "")
	e, err := cl.Put(context.Background(), Entry{Person: alice, Token: key})
	if err != nil || e.Seq != 1 {
		t.Fatalf("Put = %+v, %v", e, err)
	}
	if _, err := cl.Put(context.Background(), Entry{}); err == nil {
		t.Fatal("an empty entry must be refused")
	}
	if err := synced(t, cl, c).Check(alice, key, c.t); !errors.Is(err, ErrEnded) {
		t.Fatalf("over RPC: %v", err)
	}
}
