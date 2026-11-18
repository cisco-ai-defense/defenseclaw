// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"testing"
	"time"
)

// TestSubstrateGAP0565RepeatedActorTokenIsNotVerifiedAgain: substrate-1
// GAP-0565. An actor sends the same token on every request; a flood of them
// was verified in full (JWS parse, claims, ECDSA) before the rate-limit
// bucket refused it, and slowed the other actors of the replica. A token
// already verified costs a digest and two map reads.
func TestSubstrateGAP0565RepeatedActorTokenIsNotVerifiedAgain(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tok := f.token(t)
	if _, err := f.v.Verify(ctx, tok); err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(200, func() {
		if _, err := f.v.Verify(ctx, tok); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 4 {
		t.Fatalf("verifying a token again took %.0f allocations, want the cached checks (at most 4)", allocs)
	}
}

// A cached token is still held to its times, its actor's live state and the
// key set: expired, not live, or signed with a key removed from the pool, it
// is refused as before.
func TestSubstrateGAP0565CachedTokenKeepsEveryCheck(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	short := f.token(t, func(c map[string]any) { c["exp"] = f.now.Unix() + 60 })
	long := f.token(t)
	for _, tok := range []string{short, long} {
		if _, err := f.v.Verify(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	f.now = f.now.Add(3 * time.Minute) // past exp + DefaultSkew; the key set is still fresh
	_, err := f.v.Verify(ctx, short)
	wantReason(t, err, ReasonExpired)
	if _, err := f.v.Verify(ctx, long); err != nil {
		t.Fatalf("the other token: %v", err)
	}

	f.actors["team-a/agent-1"] = LiveActor{UID: "uid-1", State: "SUSPENDED"}
	f.now = f.now.Add(DefaultLiveTTL + time.Second)
	if _, err := f.v.Verify(ctx, long); err == nil {
		t.Fatal("a cached token of an actor that is not live verified")
	}
	f.actors["team-a/agent-1"] = LiveActor{UID: "uid-1", State: ActorRunning}
	f.now = f.now.Add(DefaultLiveTTL + time.Second)
	if _, err := f.v.Verify(ctx, long); err != nil {
		t.Fatalf("running again: %v", err)
	}

	// A key removed from the pool stops verifying the cached token once the
	// key set is past MaxAge, as an uncached one does. (The pool keeps
	// another key: a key set with none is a failed fetch, which keeps the
	// last good keys for DefaultKeyStaleLimit.)
	f.idp.addKey(t, "k2", "ES256")
	f.idp.mu.Lock()
	delete(f.idp.keys, "k1")
	f.idp.mu.Unlock()
	f.now = f.now.Add(DefaultKeyMaxAge + time.Second)
	_, err = f.v.Verify(ctx, long)
	wantReason(t, err, ReasonUnknownKey)
}
