// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// slowUIDs is a leader registration lookup that takes delay after its
// first answer (the cache fill), and counts the lookups.
type slowUIDs struct {
	mu      sync.Mutex
	rec     ActorRecord
	live    bool
	delay   time.Duration
	calls   atomic.Int64
	started atomic.Int64
}

func (f *slowUIDs) ResolveActor(ctx context.Context, _, _ string) (ActorRecord, bool, error) {
	n := f.calls.Add(1)
	f.mu.Lock()
	rec, live, d := f.rec, f.live, f.delay
	f.mu.Unlock()
	if n > 1 && d > 0 {
		f.started.Add(1)
		time.Sleep(d) // a slow leader that does not watch the deadline
	}
	return rec, live, nil
}

func (f *slowUIDs) set(rec ActorRecord, live bool, delay time.Duration) {
	f.mu.Lock()
	f.rec, f.live, f.delay = rec, live, delay
	f.mu.Unlock()
}

// flood sends n requests at once and returns their verdicts.
func flood(eng *Engine, n int, mk func() *Request) []Verdict {
	out := make([]Verdict, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range out {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out[i] = eng.DecideHeaders(context.Background(), mk())
		}()
	}
	close(start)
	wg.Wait()
	return out
}

// GAP-0243: 200 concurrent refusals on a cached entry make at most one
// leader lookup for the name (one at f8a9610180, 200 at efb88d1354), and
// every one is still refused.
func TestARefusalFloodLooksUpOnce(t *testing.T) {
	u := &slowUIDs{rec: ActorRecord{UID: "uid-1", Profile: "eng"}, live: true}
	l := &fakeLeader{live: "uid-1"}
	h := newHarness(t, func(_ *Config, o *Options) { o.UIDs = u; o.ChainChecker = l })
	h.eng.DecideHeaders(context.Background(), req("ops", "GET", "example.com", "/")) // fills the cache
	u.set(ActorRecord{UID: "uid-1", Profile: "eng"}, true, 5*time.Millisecond)
	for i, v := range flood(h.eng, 200, func() *Request { return req("ops", "GET", "blocked.example.net", "/") }) {
		if v.Allow || v.Profile != "eng" {
			t.Fatalf("request %d: %+v, want eng's refusal", i, v)
		}
	}
	if n := u.calls.Load() - 1; n > 1 {
		t.Fatalf("200 refusals made %d leader lookups, want at most 1", n)
	}
}

// GAP-0243: with a slow leader a cached refusal still answers within the
// refresh budget (the chain check budget, 20 ms), and stays a refusal.
func TestASlowLeaderDoesNotDelayACachedRefusal(t *testing.T) {
	u := &slowUIDs{rec: ActorRecord{UID: "uid-1", Profile: "eng"}, live: true}
	h := newHarness(t, func(_ *Config, o *Options) { o.UIDs = u; o.ChainChecker = &fakeLeader{live: "uid-1"} })
	h.eng.DecideHeaders(context.Background(), req("ops", "GET", "example.com", "/"))
	u.set(ActorRecord{UID: "uid-1", Profile: "eng"}, true, 500*time.Millisecond)
	start := time.Now()
	v := h.eng.DecideHeaders(context.Background(), req("ops", "GET", "blocked.example.net", "/"))
	if took := time.Since(start); took > 200*time.Millisecond {
		t.Fatalf("a cached refusal waited %v for a slow leader, want about the 20 ms budget", took)
	}
	if v.Allow || v.Profile != "eng" {
		t.Fatalf("cached refusal after a refresh timeout: %+v, want eng's refusal", v)
	}
}

// GAP-0243: a deleted UID, a slow leader (its chain check misses the budget
// and its lookup is slower still), an attended OSS install (where an
// unchecked step alerts), and a flood. No request is allowed, and the name
// is looked up once.
func TestADeletedUIDUnderASlowLeaderIsNeverAllowed(t *testing.T) {
	u := &slowUIDs{rec: ActorRecord{UID: "uid-1"}, live: true}
	slowChain := checkerFunc(func(ctx context.Context, _ ChainStep) (ChainVerdict, error) {
		<-ctx.Done() // past the check budget
		return ChainVerdict{}, ctx.Err()
	})
	h := newHarness(t, func(_ *Config, o *Options) { o.UIDs = u; o.ChainChecker = slowChain })
	h.eng.DecideHeaders(context.Background(), req("ops", "GET", "example.com", "/")) // caches uid-1
	u.set(ActorRecord{}, false, 300*time.Millisecond)                                // deleted; the leader is slow
	for i, v := range flood(h.eng, 100, func() *Request { return req("ops", "POST", "example.com", "/") }) {
		if v.Allow {
			t.Fatalf("request %d of a deleted actor under a slow leader allowed: %+v", i, v)
		}
		if v.Rule != uncheckedUnconfirmed || !v.Retryable {
			t.Fatalf("request %d: %+v, want refused, retryable, %s", i, v, uncheckedUnconfirmed)
		}
	}
	if n := u.calls.Load() - 1; n > 1 {
		t.Fatalf("the flood made %d leader lookups, want at most 1", n)
	}
	// Once the lookup lands, the actor is refused as deleted.
	time.Sleep(400 * time.Millisecond)
	if v := h.eng.DecideHeaders(context.Background(), req("ops", "POST", "example.com", "/")); v.Allow {
		t.Fatalf("after the lookup: %+v", v)
	}
}

// GAP-0243: a name is refreshed once per uid.cache_ttl/4. A refresh that
// confirmed the cached registration serves the next refusals without a
// lookup; past the interval the name is looked up again.
func TestRefreshIsRateLimitedPerName(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 11, 13, 19, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	u := &slowUIDs{rec: ActorRecord{UID: "uid-1", Profile: "eng"}, live: true}
	h := newHarness(t, func(_ *Config, o *Options) { o.UIDs = u; o.ChainChecker = &fakeLeader{live: "uid-1"}; o.Now = clock })
	ctx := context.Background()
	h.eng.DecideHeaders(ctx, req("ops", "GET", "example.com", "/")) // lookup 1
	blocked := func() Verdict { return h.eng.DecideHeaders(ctx, req("ops", "GET", "blocked.example.net", "/")) }
	if v := blocked(); v.Allow || u.calls.Load() != 2 {
		t.Fatalf("first cached refusal: %+v after %d lookups, want 2", v, u.calls.Load())
	}
	for range 5 {
		if v := blocked(); v.Allow || u.calls.Load() != 2 {
			t.Fatalf("refusal within the interval: %+v after %d lookups, want 2", v, u.calls.Load())
		}
	}
	mu.Lock()
	now = now.Add(16 * time.Second) // past 60 s / 4, still within the cache TTL
	mu.Unlock()
	if v := blocked(); v.Allow || u.calls.Load() != 3 {
		t.Fatalf("refusal past the interval: %+v after %d lookups, want 3", v, u.calls.Load())
	}
}
