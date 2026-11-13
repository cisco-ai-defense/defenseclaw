// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"context"
	"errors"
	"runtime"
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

// GAP-0243: a refresh that confirmed the cached registration keeps the
// next policy-stage refusals for refusalReuse (1 s) without a lookup; past
// it the name is looked up again.
func TestARefusalReusesAConfirmationBriefly(t *testing.T) {
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
			t.Fatalf("refusal within refusalReuse: %+v after %d lookups, want 2", v, u.calls.Load())
		}
	}
	mu.Lock()
	now = now.Add(refusalReuse + time.Millisecond)
	mu.Unlock()
	if v := blocked(); v.Allow || u.calls.Load() != 3 {
		t.Fatalf("refusal past refusalReuse: %+v after %d lookups, want 3", v, u.calls.Load())
	}
}

// toggledChain answers clear, or waits out its budget (a slow leader).
func toggledChain(slow *atomic.Bool) checkerFunc {
	return checkerFunc(func(ctx context.Context, _ ChainStep) (ChainVerdict, error) {
		if slow.Load() {
			<-ctx.Done()
			return ChainVerdict{}, ctx.Err()
		}
		return ChainVerdict{}, nil
	})
}

// GAP-0234 (R8's TestR8cDeletedWithinRefreshWindowSlowLeader, allowed with
// an alert at 1d31b29b02): a name a refresh confirmed just now is deleted;
// the leader is then too slow for the chain check, on an attended OSS
// install. The unchecked step does not stand on the earlier refresh: it is
// refused.
func TestADeletedUIDJustAfterARefreshIsNotAllowed(t *testing.T) {
	var slow atomic.Bool
	h := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = toggledChain(&slow) })
	h.uids.profile = "eng" // eng blocks blocked.example.net
	ctx := context.Background()
	h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/"))
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "blocked.example.net", "/")); v.Allow {
		t.Fatal("blocked host allowed")
	}
	h.uids.mu.Lock()
	h.uids.live = false
	h.uids.mu.Unlock()
	slow.Store(true)
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "POST", "example.com", "/")); v.Allow {
		t.Fatalf("deleted UID just after a refresh, slow leader, attended OSS: %+v, want a refusal", v)
	}
}

// GAP-0243 (R8's TestR8cRecreatedAfterConfirmedDeleteNotStuck, refused
// actor_not_live at 1d31b29b02): a cached delete looks the name up at once,
// so a name created again right after a confirmed delete is allowed.
func TestARecreatedNameIsSeenRightAfterAConfirmedDelete(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	h.uids.live = false
	h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/"))
	h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/"))
	h.uids.mu.Lock()
	h.uids.live, h.uids.uid = true, "uid-2"
	h.uids.mu.Unlock()
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); !v.Allow {
		t.Fatalf("recreated right after a confirmed delete: %+v, want allow", v)
	}
}

// GAP-0237 (R8's TestR8cRecreatedProfileInsideRefreshWindow, bounded form;
// refused under eng for 15 s at 1d31b29b02). A refresh confirmed the
// predecessor (eng blocks the host); the name is created again under base
// (allows it). Inside refusalReuse (1 s) the request may be refused under
// eng, never allowed. Past it, the request is decided under base, and its
// audit row names base and the new UID. The clock is injected.
func TestRecreatedProfileInsideRefreshWindow(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 11, 13, 19, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	l := &fakeLeader{live: "uid-1"}
	h := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = l; o.Now = clock })
	h.uids.profile = "eng"
	ctx := context.Background()
	decide := func(host string) Verdict {
		r := req("ops", "GET", host, "/")
		v := h.eng.DecideHeaders(ctx, r)
		h.eng.Finish(r, v)
		return v
	}
	decide("example.com")
	if v := decide("blocked.example.net"); v.Allow || v.Profile != "eng" { // a refresh confirms uid-1
		t.Fatalf("predecessor: %+v, want eng's refusal", v)
	}
	h.recreate(l, "uid-2", "")
	for _, d := range []time.Duration{0, refusalReuse / 2, refusalReuse - time.Millisecond} {
		mu.Lock()
		now = time.Date(2026, 11, 13, 19, 0, 0, 0, time.UTC).Add(d)
		mu.Unlock()
		if v := decide("blocked.example.net"); v.Allow {
			t.Fatalf("inside refusalReuse (+%v): %+v, never allowed", d, v)
		}
	}
	advance(2 * time.Millisecond) // past refusalReuse
	v := decide("blocked.example.net")
	if !v.Allow || v.Profile != "base" {
		t.Fatalf("past refusalReuse: %+v, want base's allow", v)
	}
	h.events.mu.Lock()
	last := h.events.events[len(h.events.events)-1]
	h.events.mu.Unlock()
	if last.Profile != "base" || last.ActorUID != "uid-2" {
		t.Fatalf("audit row %+v, want profile base and uid-2", last)
	}
}

// GAP-0237: inside refusalReuse, a request the predecessor's profile allows
// is not decided on the old registration: its chain check answers the old
// UID stale, and the request is decided under the new incarnation.
func TestRecreatedActorsAllowIsNeverDecidedOnThePredecessor(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 11, 13, 19, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	l := &fakeLeader{live: "uid-1", secretFor: map[string]bool{"uid-2": true}}
	h := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = l; o.Now = clock })
	h.uids.profile = "eng"
	ctx := context.Background()
	h.eng.DecideHeaders(ctx, req("ops", "GET", "example.com", "/"))
	h.eng.DecideHeaders(ctx, req("ops", "GET", "blocked.example.net", "/")) // a refresh confirms uid-1
	h.recreate(l, "uid-2", "")
	if v := h.eng.DecideHeaders(ctx, req("ops", "POST", "example.com", "/")); v.Allow || v.Category != CategoryChainEgress {
		t.Fatalf("inside refusalReuse, allowed host: %+v, want uid-2's chain refusal", v)
	}
}

// GAP-0243 (R8's TestR8cFloodBoundedNoLeak): 2,000 concurrent refusals
// while a lookup takes 1.5 s make one lookup, each returns within its
// budget, and no goroutine is left once the flight ends.
func TestARefusalFloodOf2000IsBounded(t *testing.T) {
	u := &slowUIDs{rec: ActorRecord{UID: "uid-1", Profile: "eng"}, live: true}
	h := newHarness(t, func(_ *Config, o *Options) { o.UIDs = u; o.ChainChecker = &fakeLeader{live: "uid-1"} })
	h.eng.DecideHeaders(context.Background(), req("ops", "GET", "example.com", "/"))
	u.set(ActorRecord{UID: "uid-1", Profile: "eng"}, true, 1500*time.Millisecond)
	runtime.GC()
	before := runtime.NumGoroutine()
	start := time.Now()
	vs := flood(h.eng, 2000, func() *Request { return req("ops", "GET", "blocked.example.net", "/") })
	took := time.Since(start) // the slowest request, at most
	for i, v := range vs {
		if v.Allow {
			t.Fatalf("request %d allowed", i)
		}
	}
	lookups := u.calls.Load() - 1
	time.Sleep(2 * time.Second)
	runtime.GC()
	after := runtime.NumGoroutine()
	t.Logf("2000 concurrent refusals: %d lookups, all answered in %v, goroutines %d -> %d", lookups, took, before, after)
	if lookups > 1 || after > before+5 || took > 500*time.Millisecond {
		t.Fatalf("flood not bounded: %d lookups, all answered in %v, goroutines %d -> %d", lookups, took, before, after)
	}
}

// GAP-0245: an unreachable leader has one rule. Its chain check and its
// lookups get no answer (a transport error), on a fresh cache entry: from
// the first request, chain.failure_mode decides, as after the entry ages
// out (attended OSS: allowed with an alert; managed or unattended:
// refused). A leader that answers, but slowly, is not unreachable: the
// deleted-UID guarantee holds (TestADeletedUIDUnderASlowLeaderIsNeverAllowed).
func TestAnUnreachableLeaderIsDecidedByTheFailureMode(t *testing.T) {
	down := errors.New("leader unreachable")
	for _, tc := range []struct {
		name                string
		managed, unattended bool
		mode                string
		allow               bool
	}{
		{"oss attended auto", false, false, "", true},
		{"oss attended open", false, false, FailureOpen, true},
		{"oss unattended auto", false, true, "", false},
		{"managed auto", true, false, "", false},
		{"oss attended closed", false, false, FailureClosed, false},
	} {
		var out atomic.Bool
		ck := checkerFunc(func(context.Context, ChainStep) (ChainVerdict, error) {
			if out.Load() {
				return ChainVerdict{}, down
			}
			return ChainVerdict{}, nil
		})
		h := newHarness(t, func(c *Config, o *Options) {
			o.ChainChecker = ck
			c.Managed = tc.managed
			if tc.mode != "" {
				c.Chain.FailureMode = tc.mode
			}
		})
		h.uids.unattended = tc.unattended
		ctx := context.Background()
		h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/"))
		out.Store(true)
		h.uids.mu.Lock()
		h.uids.err = down
		h.uids.mu.Unlock()
		for i := range 3 {
			v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/"))
			if v.Allow != tc.allow || v.Rule == uncheckedUnconfirmed {
				t.Fatalf("%s, request %d of the outage: %+v, want allow=%v by chain.failure_mode", tc.name, i, v, tc.allow)
			}
			if v.Allow && !v.Alert {
				t.Fatalf("%s: allowed without an alert: %+v", tc.name, v)
			}
		}
	}
}
