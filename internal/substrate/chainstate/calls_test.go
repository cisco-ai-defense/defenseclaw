// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// The leader's call memory (calls.go; substrate-1 GAP-0348, GAP-0345,
// GAP-0350, review rk347 P3-1/P3-2).

func hex64(prefix string, i int) string {
	s := fmt.Sprintf("%s%x", prefix, i)
	return s + strings.Repeat("0", 64-len(s))
}

func secretReadProposal(t *testing.T) guardrail.ToolChainProjection {
	t.Helper()
	bit, ok := guardrail.ToolChainStepMask(guardrail.ToolChainSecretReadThenEgress, 1)
	index, indexed := guardrail.ToolChainIndexByID(guardrail.ToolChainSecretReadThenEgress)
	other, otherOK := guardrail.ToolChainStepMask(guardrail.ToolChainDownloadThenExecuteSameArtifact, 1)
	if !ok || !indexed || !otherOK {
		t.Fatal("chain catalog")
	}
	p := guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete, DetectionStepMask: bit | other, EnforcementStepMask: bit | other}
	p.EnforcementJoinDigests[index], p.EnforcementOutputJoinDigests[index] = hex64("a", 1), hex64("b", 1)
	return p
}

// The kept step is exactly what ToolChainProjectionStep keeps, and a
// proposal without the secret read keeps nothing.
func TestCallStartKeepsTheSecretReadStepOnly(t *testing.T) {
	p := secretReadProposal(t)
	want, _ := guardrail.ToolChainProjectionStep(p, guardrail.ToolChainSecretReadThenEgress, 1)
	c := newCallStart(p, hex64("r", 1))
	if c == nil || c.projection() != want || c.ruleset != hex64("r", 1) {
		t.Fatalf("start %+v: projection differs from ToolChainProjectionStep", c)
	}
	if newCallStart(guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete}, "r") != nil {
		t.Fatal("a proposal with no secret read kept a start")
	}
}

func TestFurtherResultVerdict(t *testing.T) {
	start := &callStart{ruleset: "r1"}
	type in struct {
		c                            scopeCall
		remembered, mayRead, showsRd bool
		ruleset                      string
	}
	cleared := scopeCall{known: true, resolved: true, cleared: true, start: start}
	read := scopeCall{known: true, resolved: true, start: start}
	for _, tc := range []struct {
		name string
		in   in
		want furtherVerdict
	}{
		{"never seen (another call id, session or actor; evicted; past the window; leader restart)", in{scopeCall{}, false, true, true, "r1"}, furtherMissing},
		{"prepared, not resolved (its proposal was discarded)", in{scopeCall{known: true, start: start}, true, true, true, "r1"}, furtherMissing},
		{"resolved, content proves nothing read", in{read, true, false, false, "r1"}, furtherReplay},
		{"resolved, may have read: chains", in{read, true, true, true, "r1"}, furtherChain},
		{"resolved, proposal read no credentials file", in{scopeCall{known: true, resolved: true}, true, true, true, "r1"}, furtherReplay},
		{"resolved, proposal unknown (prepared before this leader)", in{scopeCall{resolved: true}, true, true, true, "r1"}, furtherMissing},
		{"resolved, ruleset changed", in{read, true, true, true, "r2"}, furtherMissing},
		{"GAP-0352: cleared, then a result with no output", in{cleared, true, true, false, "r1"}, furtherReplay},
		{"GAP-0352: cleared, then the same failure", in{cleared, true, false, false, "r1"}, furtherReplay},
		{"GAP-0352: cleared, then a result that printed: chains", in{cleared, true, true, true, "r1"}, furtherChain},
		{"cleared, printed, ruleset changed", in{cleared, true, true, true, "r2"}, furtherMissing},
	} {
		if got := furtherResultVerdict(tc.in.c, tc.in.remembered, tc.in.mayRead, tc.in.showsRd, tc.in.ruleset); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func resolvedCall(c *scopeCall) { *c = scopeCall{known: true, resolved: true} }

// A call past the chain window is forgotten, and dropped from memory on the
// next update, not only at a cap (rk347 TestRK347ExpiredKeptBelowCap).
func TestCallTableForgetsPastTheWindow(t *testing.T) {
	tb := newCallTable()
	t0 := time.Unix(1_800_000_000, 0)
	for i := 0; i < 1000; i++ {
		tb.update(callKey{"a/1", hex64("s", 1), hex64("i", i)}, ScopeSession, t0, resolvedCall)
	}
	later := t0.Add(guardrail.ToolChainMaxHorizon + time.Second)
	if _, ok := tb.lookup(callKey{"a/1", hex64("s", 1), hex64("i", 0)}, ScopeSession, later); ok {
		t.Fatal("a call past the window is still remembered")
	}
	tb.update(callKey{"a/1", hex64("s", 1), hex64("i", 5000)}, ScopeSession, later, resolvedCall)
	if n := tb.len(); n != 1 {
		t.Fatalf("%d calls kept after the window, want 1", n)
	}
}

// One actor at 100 calls/s for an hour stays at its bound; its oldest call
// is gone (so its further result is marked, never replayed); another
// actor's calls stay.
func TestCallTableBoundsOneBusyActor(t *testing.T) {
	tb := newCallTable()
	t0 := time.Unix(1_800_000_000, 0)
	other := callKey{"a/other", hex64("s", 9), hex64("i", 9)}
	tb.update(other, ScopeSession, t0, resolvedCall)
	for i := 0; i < 100*3600; i++ {
		now := t0.Add(time.Duration(i) * 10 * time.Millisecond)
		k := callKey{"a/busy", hex64("s", 1), hex64("i", i)}
		tb.update(k, ScopeSession, now, resolvedCall)
		tb.update(k, ScopeActor, now, resolvedCall)
		if i == 100*3600-1000 {
			tb.update(other, ScopeSession, now, resolvedCall)
		}
	}
	end := t0.Add(time.Hour)
	if got := len(tb.byKey); got > callsPerActorMax+1 || tb.all.Len() != got {
		t.Fatalf("%d calls kept, want at most %d", got, callsPerActorMax+1)
	}
	c, ok := tb.lookup(callKey{"a/busy", hex64("s", 1), hex64("i", 0)}, ScopeSession, end)
	if furtherResultVerdict(c, ok, true, true, "") != furtherMissing || furtherResultVerdict(c, ok, false, false, "") != furtherMissing {
		t.Fatal("an evicted call is replayed")
	}
	if _, ok := tb.lookup(other, ScopeSession, end); !ok {
		t.Fatal("a busy actor evicted another actor's call")
	}
	// A call's two scopes leave together (rk347 P3-1).
	for _, n := range tb.byKey {
		if n.key.actor == "a/busy" && n.scopes[0].resolved != n.scopes[1].resolved {
			t.Fatalf("call %s kept one scope", n.key.invocation[:8])
		}
	}
}

// Many actors stay under the leader's bound, oldest calls first.
func TestCallTableBoundsTheLeader(t *testing.T) {
	tb := newCallTable()
	tb.max = 10_000
	t0 := time.Unix(1_800_000_000, 0)
	for a := 0; a < 100; a++ {
		for i := 0; i < 500; i++ {
			tb.update(callKey{fmt.Sprintf("a/%d", a), hex64("s", a), hex64("i", i)}, ScopeSession, t0.Add(time.Duration(a*500+i)*time.Millisecond), resolvedCall)
			if n := tb.all.Len(); n > tb.max {
				t.Fatalf("%d calls, over the leader bound %d", n, tb.max)
			}
		}
	}
	now := t0.Add(time.Minute)
	if _, ok := tb.lookup(callKey{"a/0", hex64("s", 0), hex64("i", 0)}, ScopeSession, now); ok {
		t.Fatal("the leader's oldest call is still remembered over the bound")
	}
	if _, ok := tb.lookup(callKey{"a/99", hex64("s", 99), hex64("i", 499)}, ScopeSession, now); !ok {
		t.Fatal("the newest call was evicted")
	}
}

// A remembered call costs well under 1 KiB, its secret-read step included,
// so callsLeaderMax calls stay far below the 2 GiB leader limit (GAP-0350:
// the first version kept a whole projection, about 8 KiB a scope).
func TestCallTableBytesPerCall(t *testing.T) {
	const n = 20_000
	p := secretReadProposal(t)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	tb := newCallTable()
	t0 := time.Unix(1_800_000_000, 0)
	for i := 0; i < n; i++ {
		start := newCallStart(p, hex64("r", 1))
		k := callKey{fmt.Sprintf("dc-eng/%08x-8d5c-4056-a730-5ca741ca31b0", i%64), hex64("s", i), hex64("i", i)}
		tb.update(k, ScopeSession, t0, func(c *scopeCall) { *c = scopeCall{known: true, resolved: true, start: start} })
		tb.update(k, ScopeActor, t0, func(c *scopeCall) { *c = scopeCall{known: true, resolved: true, start: start} })
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	per := float64(after.HeapAlloc-before.HeapAlloc) / n
	runtime.KeepAlive(tb)
	t.Logf("%.0f bytes per remembered call (both scopes, with its secret-read step); leader bound %d calls = %.0f MiB",
		per, callsLeaderMax, per*callsLeaderMax/(1<<20))
	if per > 1024 {
		t.Fatalf("%.0f bytes per call, want under 1024", per)
	}
	if per*callsLeaderMax > 160<<20 {
		t.Fatalf("leader bound %.0f MiB, want under 160 MiB", per*callsLeaderMax/(1<<20))
	}
}

// A reused call id forgets the scope; a purged actor forgets every call.
func TestCallTableForgetAndPurge(t *testing.T) {
	tb := newCallTable()
	t0 := time.Unix(1_800_000_000, 0)
	k := callKey{"a/1", hex64("s", 1), hex64("i", 1)}
	tb.update(k, ScopeSession, t0, resolvedCall)
	tb.update(k, ScopeActor, t0, resolvedCall)
	tb.forget(k, ScopeSession)
	if _, ok := tb.lookup(k, ScopeSession, t0); ok {
		t.Fatal("a forgotten scope is remembered")
	}
	if _, ok := tb.lookup(k, ScopeActor, t0); !ok {
		t.Fatal("forget dropped the other scope")
	}
	tb.update(callKey{"a/1", hex64("s", 1), hex64("i", 2)}, ScopeSession, t0, resolvedCall)
	tb.update(callKey{"a/2", hex64("s", 1), hex64("i", 2)}, ScopeSession, t0, resolvedCall)
	tb.dropActor("a/1")
	if n := tb.len(); n != 1 || len(tb.byActor) != 1 {
		t.Fatalf("%d calls, %d actors after the purge, want 1 and 1", n, len(tb.byActor))
	}
}
