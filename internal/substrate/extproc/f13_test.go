// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"context"
	"slices"
	"sync"
	"testing"
)

// fakeLeader answers chain checks as the leader does after GAP-0234: only
// for the name's live incarnation (live), stale for any other UID, and a
// deny for a UID whose window holds a secret read.
type fakeLeader struct {
	mu        sync.Mutex
	live      string
	secretFor map[string]bool
	seen      []string
}

func (l *fakeLeader) CheckEgress(_ context.Context, s ChainStep) (ChainVerdict, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen = append(l.seen, s.Actor.UID)
	switch {
	case s.Actor.UID != l.live:
		return ChainVerdict{Stale: true, Deny: true, Rule: "actor_not_current"}, nil
	case l.secretFor[s.Actor.UID]:
		return ChainVerdict{Deny: true, Rule: "secret-read-then-egress"}, nil
	}
	return ChainVerdict{}, nil
}

func (l *fakeLeader) set(live string) { l.mu.Lock(); l.live = live; l.mu.Unlock() }

func (l *fakeLeader) uids() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.seen)
}

// recreate stands for the person deleting a1 and creating it again: the
// registrations now name uid-2 (and profile), the callout's cache still
// holds uid-1.
func (h *harness) recreate(l *fakeLeader, uid, profile string) {
	h.uids.mu.Lock()
	h.uids.uid, h.uids.profile = uid, profile
	h.uids.mu.Unlock()
	l.set(uid)
}

// GAP-0234 (R7's TestR7RecreatedActorIsCheckedUnderItsOwnUID, failed at
// 18ad6a2dc2 with checks [uid-1 uid-1]): a same-name actor deleted and
// created again inside uid.cache_ttl. The leader answers the cached
// predecessor UID stale; the callout resolves the name again and checks the
// request under the new incarnation, whose window holds a secret read: the
// egress is refused, in every mode.
func TestRecreatedActorIsCheckedUnderItsOwnUID(t *testing.T) {
	for _, managed := range []bool{true, false} {
		l := &fakeLeader{live: "uid-1", secretFor: map[string]bool{"uid-2": true}}
		h := newHarness(t, func(c *Config, o *Options) { c.Managed = managed; o.ChainChecker = l })
		ctx := context.Background()
		if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); !v.Allow {
			t.Fatalf("managed=%v first incarnation: %+v", managed, v)
		}
		h.recreate(l, "uid-2", "")
		v := h.eng.DecideHeaders(ctx, req("eng-web", "POST", "example.com", "/"))
		if got := l.uids(); !slices.Equal(got, []string{"uid-1", "uid-1", "uid-2"}) {
			t.Fatalf("managed=%v chain checks went to UIDs %v; the recreated actor must be checked under uid-2", managed, got)
		}
		if v.Allow || v.Category != CategoryChainEgress {
			t.Fatalf("managed=%v egress after the new incarnation's secret read: %+v, want a chain refusal", managed, v)
		}
		// The cache now holds uid-2: the next request asks once.
		h.eng.DecideHeaders(ctx, req("eng-web", "POST", "example.com", "/"))
		if got := l.uids(); len(got) != 4 || got[3] != "uid-2" {
			t.Fatalf("managed=%v after the refresh: %v", managed, got)
		}
	}
}

// GAP-0234 class: the request is decided under the new incarnation's
// registration from the start, so its profile, not the predecessor's,
// applies (here it blocks the host).
func TestRecreatedActorGetsItsOwnProfile(t *testing.T) {
	l := &fakeLeader{live: "uid-1"}
	h := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = l })
	ctx := context.Background()
	if v := h.eng.DecideHeaders(ctx, req("ops", "GET", "blocked.example.net", "/")); !v.Allow || v.Profile != "base" {
		t.Fatalf("first incarnation (base): %+v", v)
	}
	h.recreate(l, "uid-2", "eng")
	if v := h.eng.DecideHeaders(ctx, req("ops", "GET", "blocked.example.net", "/")); v.Allow || v.Profile != "eng" {
		t.Fatalf("recreated under eng: %+v, want eng's block list", v)
	}
}

// GAP-0234 class: an actor deleted and not created again. The leader
// answers its cached UID stale; resolved again, the actor is not live.
func TestDeletedActorIsRefusedBeforeTheCacheAgesOut(t *testing.T) {
	l := &fakeLeader{live: "uid-1"}
	h := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = l })
	ctx := context.Background()
	h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/"))
	h.uids.mu.Lock()
	h.uids.live = false
	h.uids.mu.Unlock()
	l.set("")
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "POST", "example.com", "/")); v.Allow || v.Category != CategoryActorNotLive {
		t.Fatalf("deleted actor: %+v, want actor_not_live", v)
	}
}

// A UID the leader answers stale again after a fresh resolve is refused,
// retryable, in every mode: a new actor's UID comes from its registration
// and is never stale, so the refusal loses nothing (R8).
func TestStaleTwiceIsRefused(t *testing.T) {
	always := checkerFunc(func(context.Context, ChainStep) (ChainVerdict, error) {
		return ChainVerdict{Stale: true, Deny: true}, nil
	})
	ctx := context.Background()
	for _, mode := range []string{"managed", "unattended", "attended oss"} {
		h := newHarness(t, func(c *Config, o *Options) { c.Managed = mode == "managed"; o.ChainChecker = always })
		h.uids.unattended = mode == "unattended"
		v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/"))
		if v.Allow || v.Category != CategoryChainUnchecked || v.Rule != uncheckedStale || !v.Retryable {
			t.Fatalf("%s: %+v", mode, v)
		}
		if h.uids.calls != 2 {
			t.Fatalf("%s: %d resolves, want 2 (one after the stale answer)", mode, h.uids.calls)
		}
	}
}

// GAP-0237 (R8's TestR8RecreatedActorIsNotRefusedUnderThePredecessorsProfile,
// failed at f8a9610180 with Profile eng, operator_block): the predecessor's
// profile (eng) blocks the host, the recreated incarnation's (base) allows
// it. The refusal came from a cached entry no chain answer confirmed, so the
// name is resolved again and the request decided under base.
func TestRecreatedActorIsNotRefusedUnderThePredecessorsProfile(t *testing.T) {
	l := &fakeLeader{live: "uid-1"}
	h := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = l })
	h.uids.mu.Lock()
	h.uids.profile = "eng"
	h.uids.mu.Unlock()
	ctx := context.Background()
	if v := h.eng.DecideHeaders(ctx, req("ops", "GET", "example.com", "/")); !v.Allow || v.Profile != "eng" {
		t.Fatalf("first incarnation (eng): %+v", v)
	}
	h.recreate(l, "uid-2", "")
	v := h.eng.DecideHeaders(ctx, req("ops", "GET", "blocked.example.net", "/"))
	if v.Profile != "base" || !v.Allow {
		t.Fatalf("recreated under base: %+v (leader saw %v), want base's decision (allow), not eng's block", v, l.uids())
	}
}

// GAP-0237: a refusal on a cached entry whose registration did not change
// stands after one fresh lookup, and is not decided again; a refusal on a
// fresh lookup costs none.
func TestACachedRefusalIsConfirmedOnce(t *testing.T) {
	l := &fakeLeader{live: "uid-1"}
	h := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = l })
	h.uids.profile = "eng"
	ctx := context.Background()
	if v := h.eng.DecideHeaders(ctx, req("ops", "GET", "blocked.example.net", "/")); v.Allow || v.Profile != "eng" || h.uids.calls != 1 {
		t.Fatalf("fresh lookup, refused: %+v after %d resolves", v, h.uids.calls)
	}
	if v := h.eng.DecideHeaders(ctx, req("ops", "GET", "blocked.example.net", "/")); v.Allow || v.Profile != "eng" || h.uids.calls != 2 {
		t.Fatalf("cached, refused: %+v after %d resolves, want 2", v, h.uids.calls)
	}
	// An allowed request is confirmed by its chain check: no lookup.
	h.eng.DecideHeaders(ctx, req("ops", "GET", "example.com", "/"))
	if h.uids.calls != 2 || len(l.uids()) != 1 {
		t.Fatalf("allowed: %d resolves, chain checks %v", h.uids.calls, l.uids())
	}
}

// GAP-0237 class: a deleted actor's not-live entry is cached; the name is
// created again. The refusal from the cached entry is checked, and the new
// incarnation is decided under its own registration.
func TestRecreatedAfterACachedDeleteIsDecidedAgain(t *testing.T) {
	l := &fakeLeader{live: ""}
	h := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = l })
	h.uids.live = false
	ctx := context.Background()
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); v.Allow || v.Category != CategoryActorNotLive {
		t.Fatalf("deleted: %+v", v)
	}
	h.uids.mu.Lock()
	h.uids.live = true
	h.uids.mu.Unlock()
	h.recreate(l, "uid-2", "")
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); !v.Allow {
		t.Fatalf("recreated: %+v (chain checks %v)", v, l.uids())
	}
}
