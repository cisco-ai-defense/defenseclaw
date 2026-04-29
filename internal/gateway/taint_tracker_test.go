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

package gateway

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func newTestTracker() *TaintTracker {
	return NewTaintTracker(TaintConfig{
		FlagDecayEvents:      10,
		FileTaintDecayEvents: 30,
		SensitiveFiles: []string{
			"~/.aws/credentials",
			"~/.aws/config",
			"~/.ssh/id_*",
			"**/.env",
			"**/.env.*",
			"/etc/shadow",
			"/etc/passwd",
		},
		NetworkExclusions: []string{
			"127.0.0.0/8",
			"10.0.0.0/8",
			"::1",
			"localhost",
		},
		SessionIdleTTL: 1 * time.Hour,
	}, 100)
}

// taintSourceFinding builds a finding tagged as a taint source.
func taintSourceFinding(id string, conf float64) RuleFinding {
	return RuleFinding{
		RuleID:     id,
		Title:      id,
		Severity:   "HIGH",
		Confidence: conf,
		Tags:       []string{taintSourceTag, "credential"},
	}
}

// taintConsumerFinding builds a finding tagged as a taint consumer.
func taintConsumerFinding(id string, conf float64) RuleFinding {
	return RuleFinding{
		RuleID:     id,
		Title:      id,
		Severity:   "MEDIUM",
		Confidence: conf,
		Tags:       []string{taintConsumerTag, "exfiltration"},
	}
}

// ---------------------------------------------------------------------------
// Observe / Record / IsTainted basics
// ---------------------------------------------------------------------------

func TestTaintTracker_RecordSetsFlag(t *testing.T) {
	tt := newTestTracker()
	tt.Observe("s1")
	tt.Record("s1", []RuleFinding{taintSourceFinding("CHAIN-CRED-READ", 0.9)})
	if !tt.IsTainted("s1") {
		t.Errorf("session should be tainted after recording a source finding")
	}
}

func TestTaintTracker_NonSourceFindingIsIgnored(t *testing.T) {
	tt := newTestTracker()
	tt.Observe("s1")
	// Tag missing "taint-source" — should NOT taint the session.
	tt.Record("s1", []RuleFinding{{
		RuleID:   "RANDOM",
		Tags:     []string{"some-other-tag"},
		Severity: "HIGH",
	}})
	if tt.IsTainted("s1") {
		t.Errorf("non-source finding should not taint the session")
	}
}

func TestTaintTracker_FlagSlidingWindowDecay(t *testing.T) {
	tt := newTestTracker() // FlagDecayEvents = 10
	tt.Observe("s1")
	tt.Record("s1", []RuleFinding{taintSourceFinding("CHAIN-CRED-READ", 0.9)})

	// Advance 10 more events — flag should still be live (set at 1, now at 11; 11-1=10).
	for i := 0; i < 10; i++ {
		tt.Observe("s1")
	}
	if !tt.IsTainted("s1") {
		t.Errorf("flag should be live at exactly the decay boundary")
	}
	// One more event — flag should now have decayed.
	tt.Observe("s1")
	if tt.IsTainted("s1") {
		t.Errorf("flag should have decayed after FlagDecayEvents+1")
	}
}

func TestTaintTracker_FlagRefreshSlides(t *testing.T) {
	tt := newTestTracker()
	tt.Observe("s1")
	tt.Record("s1", []RuleFinding{taintSourceFinding("CHAIN-CRED-READ", 0.9)})

	// Advance 9 events.
	for i := 0; i < 9; i++ {
		tt.Observe("s1")
	}
	// Re-record — should refresh to current event counter.
	tt.Record("s1", []RuleFinding{taintSourceFinding("CHAIN-CRED-READ", 0.9)})

	// Advance 10 more events — still live because re-recording refreshed.
	for i := 0; i < 10; i++ {
		tt.Observe("s1")
	}
	if !tt.IsTainted("s1") {
		t.Errorf("flag should still be live after refresh + 10 events")
	}
}

// ---------------------------------------------------------------------------
// File taint propagation
// ---------------------------------------------------------------------------

func TestTaintTracker_BaselineSensitiveFileTaint(t *testing.T) {
	tt := newTestTracker()
	tt.Observe("s1")
	// `cat ~/.aws/credentials > /tmp/x` ⇒ /tmp/x becomes tainted.
	tt.RecordShellOps("s1", ShellOps{
		Reads:        []string{"~/.aws/credentials"},
		Writes:       []string{"/tmp/x"},
		WriteSources: map[string][]string{"/tmp/x": {"~/.aws/credentials"}},
	})
	meta, ok := tt.IsFileTainted("s1", "/tmp/x")
	if !ok {
		t.Fatalf("/tmp/x should be tainted via baseline-sensitive source")
	}
	if meta.OriginPath != "~/.aws/credentials" {
		t.Errorf("OriginPath = %q, want ~/.aws/credentials", meta.OriginPath)
	}
}

func TestTaintTracker_FileTaintPropagation(t *testing.T) {
	tt := newTestTracker()
	tt.Observe("s1")
	// Step 1: cat creds > a.
	tt.RecordShellOps("s1", ShellOps{
		WriteSources: map[string][]string{"/tmp/a": {"~/.aws/credentials"}},
	})
	tt.Observe("s1")
	// Step 2: cp a b — should propagate.
	tt.RecordShellOps("s1", ShellOps{
		WriteSources: map[string][]string{"/tmp/b": {"/tmp/a"}},
	})
	meta, ok := tt.IsFileTainted("s1", "/tmp/b")
	if !ok {
		t.Fatalf("/tmp/b should inherit taint from /tmp/a")
	}
	if meta.OriginPath != "~/.aws/credentials" {
		t.Errorf("OriginPath should track ultimate source; got %q", meta.OriginPath)
	}
	if meta.PropagatedFrom != "/tmp/a" {
		t.Errorf("PropagatedFrom = %q, want /tmp/a", meta.PropagatedFrom)
	}
}

func TestTaintTracker_NonSensitiveSourceDoesNotPropagate(t *testing.T) {
	tt := newTestTracker()
	tt.Observe("s1")
	tt.RecordShellOps("s1", ShellOps{
		WriteSources: map[string][]string{"/tmp/x": {"/tmp/random.txt"}},
	})
	if _, ok := tt.IsFileTainted("s1", "/tmp/x"); ok {
		t.Errorf("/tmp/x should NOT be tainted from a non-sensitive source")
	}
}

func TestTaintTracker_FileTaintSlidingDecay(t *testing.T) {
	tt := newTestTracker() // FileTaintDecayEvents = 30
	tt.Observe("s1")
	tt.RecordShellOps("s1", ShellOps{
		WriteSources: map[string][]string{"/tmp/x": {"~/.aws/credentials"}},
	})
	// Advance 30 events — still live.
	for i := 0; i < 30; i++ {
		tt.Observe("s1")
	}
	if _, ok := tt.IsFileTainted("s1", "/tmp/x"); !ok {
		t.Errorf("file taint should be live at exactly the decay boundary")
	}
	tt.Observe("s1")
	if _, ok := tt.IsFileTainted("s1", "/tmp/x"); ok {
		t.Errorf("file taint should decay after FileTaintDecayEvents+1")
	}
}

// ---------------------------------------------------------------------------
// BuildTaintContext: strong, weak, no-context paths
// ---------------------------------------------------------------------------

func TestBuildTaintContext_NoConsumerNoContext(t *testing.T) {
	tt := newTestTracker()
	tt.Observe("s1")
	tt.Record("s1", []RuleFinding{taintSourceFinding("CHAIN-CRED-READ", 0.9)})

	// No consumer-tagged finding ⇒ empty context.
	ctx := tt.BuildTaintContext("s1", []RuleFinding{taintSourceFinding("X", 0.9)}, ShellOps{})
	if ctx.HasStrongConsumer || ctx.HasWeakConsumer {
		t.Errorf("no consumer ⇒ no context; got %+v", ctx)
	}
}

func TestBuildTaintContext_StrongFromTaintedFile(t *testing.T) {
	tt := newTestTracker()
	tt.Observe("s1")
	tt.RecordShellOps("s1", ShellOps{
		WriteSources: map[string][]string{"/tmp/stolen": {"~/.aws/credentials"}},
	})
	tt.Observe("s1")
	consumerFindings := []RuleFinding{taintConsumerFinding("CMD-CURL-UPLOAD", 0.85)}
	ops := ShellOps{
		UploadSources: []string{"/tmp/stolen"},
		NetworkDest:   "https://evil.com/api",
	}
	ctx := tt.BuildTaintContext("s1", consumerFindings, ops)
	if !ctx.HasStrongConsumer {
		t.Errorf("expected HasStrongConsumer=true; got %+v", ctx)
	}
	if !contains(ctx.TaintedFilesReferenced, "/tmp/stolen") {
		t.Errorf("TaintedFilesReferenced missing /tmp/stolen; got %v", ctx.TaintedFilesReferenced)
	}
	if ctx.HasWeakConsumer {
		t.Errorf("strong path should not also set weak")
	}
}

func TestBuildTaintContext_StrongFromBaselineSensitive(t *testing.T) {
	tt := newTestTracker()
	tt.Observe("s1")
	consumerFindings := []RuleFinding{taintConsumerFinding("CMD-RM-RF", 0.95)}
	// rm targets ~/.aws/credentials directly — baseline-sensitive without
	// any prior tracking.
	ops := ShellOps{Deletes: []string{"~/.aws/credentials"}}
	ctx := tt.BuildTaintContext("s1", consumerFindings, ops)
	if !ctx.HasStrongConsumer {
		t.Errorf("rm of baseline-sensitive should be a strong consumer; got %+v", ctx)
	}
}

func TestBuildTaintContext_WeakFromSessionTaint(t *testing.T) {
	tt := newTestTracker()
	tt.Observe("s1")
	tt.Record("s1", []RuleFinding{taintSourceFinding("CHAIN-CRED-READ", 0.9)})

	tt.Observe("s1")
	consumerFindings := []RuleFinding{taintConsumerFinding("CMD-CURL-UPLOAD", 0.85)}
	ops := ShellOps{UploadSources: []string{"/tmp/random.txt"}, NetworkDest: "https://example.com"}
	ctx := tt.BuildTaintContext("s1", consumerFindings, ops)
	if ctx.HasStrongConsumer {
		t.Errorf("non-tainted file ⇒ no strong; got %+v", ctx)
	}
	if !ctx.HasWeakConsumer {
		t.Errorf("session is tainted ⇒ should be weak; got %+v", ctx)
	}
	if !ctx.HasTaintSourceInSession {
		t.Errorf("session source should be live")
	}
}

func TestBuildTaintContext_NoSessionTaint_NoEscalation(t *testing.T) {
	tt := newTestTracker()
	tt.Observe("s1")
	// No Record — session has no taint flag.
	consumerFindings := []RuleFinding{taintConsumerFinding("CMD-CURL-UPLOAD", 0.85)}
	ops := ShellOps{UploadSources: []string{"/tmp/random.txt"}, NetworkDest: "https://example.com"}
	ctx := tt.BuildTaintContext("s1", consumerFindings, ops)
	if ctx.HasStrongConsumer || ctx.HasWeakConsumer {
		t.Errorf("clean session ⇒ no escalation; got %+v", ctx)
	}
}

func TestBuildTaintContext_NetworkDestExcluded(t *testing.T) {
	tt := newTestTracker()
	tt.Observe("s1")
	tt.Record("s1", []RuleFinding{taintSourceFinding("CHAIN-CRED-READ", 0.9)})

	tt.Observe("s1")
	cases := []struct {
		name string
		dest string
	}{
		{"loopback_url", "http://127.0.0.1:8080/api"},
		{"localhost_hostname", "https://localhost/api"},
		{"private_cidr", "http://10.5.5.5/x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ops := ShellOps{
				UploadSources: []string{"/tmp/random.txt"},
				NetworkDest:   c.dest,
			}
			ctx := tt.BuildTaintContext("s1", []RuleFinding{taintConsumerFinding("CMD-CURL-UPLOAD", 0.85)}, ops)
			if !ctx.NetworkDestExcluded {
				t.Errorf("expected NetworkDestExcluded=true for %q; got %+v", c.dest, ctx)
			}
		})
	}
}

func TestBuildTaintContext_PublicNetworkNotExcluded(t *testing.T) {
	tt := newTestTracker()
	tt.Observe("s1")
	tt.Record("s1", []RuleFinding{taintSourceFinding("CHAIN-CRED-READ", 0.9)})

	tt.Observe("s1")
	ctx := tt.BuildTaintContext("s1", []RuleFinding{taintConsumerFinding("CMD-CURL-UPLOAD", 0.85)},
		ShellOps{NetworkDest: "https://public.example.com/api"})
	if ctx.NetworkDestExcluded {
		t.Errorf("public destination should not be excluded; got %+v", ctx)
	}
}

func TestBuildTaintContext_MaxConsumerConfidence(t *testing.T) {
	tt := newTestTracker()
	tt.Observe("s1")
	findings := []RuleFinding{
		taintConsumerFinding("low", 0.50),
		taintConsumerFinding("high", 0.92),
		taintConsumerFinding("mid", 0.75),
	}
	ctx := tt.BuildTaintContext("s1", findings, ShellOps{})
	if ctx.MaxConsumerConfidence != 0.92 {
		t.Errorf("MaxConsumerConfidence = %v, want 0.92", ctx.MaxConsumerConfidence)
	}
}

func TestBuildTaintContext_EventsSinceSource(t *testing.T) {
	tt := newTestTracker()
	tt.Observe("s1") // event=1
	tt.Record("s1", []RuleFinding{taintSourceFinding("CHAIN-CRED-READ", 0.9)})
	tt.Observe("s1") // event=2
	tt.Observe("s1") // event=3
	tt.Observe("s1") // event=4

	ctx := tt.BuildTaintContext("s1",
		[]RuleFinding{taintConsumerFinding("CMD-CURL-UPLOAD", 0.85)},
		ShellOps{NetworkDest: "https://evil.com"})
	if ctx.EventsSinceSource != 3 {
		t.Errorf("EventsSinceSource = %d, want 3 (set@1, now@4)", ctx.EventsSinceSource)
	}
}

// ---------------------------------------------------------------------------
// Eviction
// ---------------------------------------------------------------------------

func TestTaintTracker_LRUPrune(t *testing.T) {
	tt := NewTaintTracker(TaintConfig{
		FlagDecayEvents:      10,
		FileTaintDecayEvents: 30,
		SessionIdleTTL:       1 * time.Hour,
	}, 4)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tick := 0
	tt.SetNowFunc(func() time.Time {
		t := base.Add(time.Duration(tick) * time.Second)
		tick++
		return t
	})

	// Fill past capacity. Each Observe advances the clock so LastSeen is
	// strictly increasing, giving a deterministic prune order.
	for i := 0; i < 6; i++ {
		tt.Observe(fmt.Sprintf("s%d", i))
	}
	if got := tt.SessionCount(); got > 4 {
		t.Errorf("SessionCount = %d, want <= 4 after LRU prune", got)
	}
}

func TestTaintTracker_IdleEviction(t *testing.T) {
	tt := NewTaintTracker(TaintConfig{
		FlagDecayEvents:      10,
		FileTaintDecayEvents: 30,
		SessionIdleTTL:       100 * time.Millisecond,
	}, 200)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	current := base
	tt.SetNowFunc(func() time.Time { return current })

	// Session created at t=0.
	tt.Observe("idle1")
	if tt.SessionCount() != 1 {
		t.Fatalf("expected 1 session, got %d", tt.SessionCount())
	}

	// Skip clock past TTL.
	current = base.Add(1 * time.Hour)

	// Trigger sweep by writing to a different session enough times.
	for i := 0; i < taintStaleSweepFrequency+1; i++ {
		tt.Observe(fmt.Sprintf("active-%d", i))
	}
	if _, ok := tt.sessions["idle1"]; ok {
		t.Errorf("idle1 should have been evicted by SessionIdleTTL sweep")
	}
}

func TestTaintTracker_IdleEvictionDoesNotAffectLiveDecisions(t *testing.T) {
	// Even with aggressive idle TTL, a session that's actively writing
	// should keep its taint state intact — TTL is wall-clock memory
	// hygiene, not a decay mechanism.
	tt := NewTaintTracker(TaintConfig{
		FlagDecayEvents:      10,
		FileTaintDecayEvents: 30,
		SessionIdleTTL:       1 * time.Nanosecond, // absurdly short
		SensitiveFiles:       []string{"~/.aws/credentials"},
	}, 200)
	tt.Observe("s1")
	tt.RecordShellOps("s1", ShellOps{
		WriteSources: map[string][]string{"/tmp/x": {"~/.aws/credentials"}},
	})
	tt.Observe("s1")
	// File taint should still be live (event-count, not wall-clock).
	if _, ok := tt.IsFileTainted("s1", "/tmp/x"); !ok {
		t.Errorf("file taint should be event-count gated, not wall-clock")
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestTaintTracker_ConcurrentObserveRecord(t *testing.T) {
	// Run with -race to exercise the sync.RWMutex coverage.
	tt := newTestTracker()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sid := fmt.Sprintf("s%d", i%5)
			for j := 0; j < 100; j++ {
				tt.Observe(sid)
				tt.Record(sid, []RuleFinding{taintSourceFinding("R", 0.8)})
				tt.RecordShellOps(sid, ShellOps{
					WriteSources: map[string][]string{
						fmt.Sprintf("/tmp/%d-%d", i, j): {"~/.aws/credentials"},
					},
				})
				_ = tt.IsTainted(sid)
				_ = tt.BuildTaintContext(sid,
					[]RuleFinding{taintConsumerFinding("CMD-CURL-UPLOAD", 0.9)},
					ShellOps{UploadSources: []string{fmt.Sprintf("/tmp/%d-%d", i, j)}})
			}
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Glob and CIDR matchers
// ---------------------------------------------------------------------------

func TestGlobMatcher_BasicPatterns(t *testing.T) {
	m := newGlobMatcher([]string{
		"~/.aws/credentials",
		"~/.ssh/id_*",
		"**/.env",
		"**/.env.*",
		"/etc/shadow",
	})
	cases := []struct {
		path string
		want bool
	}{
		{"~/.aws/credentials", true},
		{"~/.aws/config", false},
		{"~/.ssh/id_rsa", true},
		{"~/.ssh/id_ed25519", true},
		{"~/.ssh/known_hosts", false},
		{".env", true},
		{"/proj/.env", true},
		{"/proj/.env.production", true},
		{"/proj/env.production", false},
		{"/etc/shadow", true},
		{"/etc/passwd", false},
	}
	for _, c := range cases {
		got := m.Match(c.path)
		if got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestCIDRHostMatcher(t *testing.T) {
	m := newCIDRHostMatcher([]string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"::1",
		"localhost",
	})
	cases := []struct {
		input string
		want  bool
	}{
		{"http://127.0.0.1/api", true},
		{"https://10.5.5.5/api", true},
		{"http://localhost:8080", true},
		{"http://Localhost:8080", true},
		{"https://[::1]/", true},
		{"https://example.com", false},
		{"http://8.8.8.8/", false},
	}
	for _, c := range cases {
		if got := m.IsExcluded(c.input); got != c.want {
			t.Errorf("IsExcluded(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestNilMatchersAreSafe(t *testing.T) {
	var gm *globMatcher
	if gm.Match("/anything") {
		t.Errorf("nil glob matcher should not match")
	}
	var cm *cidrHostMatcher
	if cm.IsExcluded("https://example.com") {
		t.Errorf("nil CIDR matcher should not match")
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestTaintTracker_EmptySessionID(t *testing.T) {
	tt := newTestTracker()
	tt.Observe("")
	tt.Record("", []RuleFinding{taintSourceFinding("X", 0.9)})
	tt.RecordShellOps("", ShellOps{Reads: []string{"x"}})
	if tt.IsTainted("") {
		t.Errorf("empty session should not be tainted")
	}
}

func TestTaintTracker_UnknownSessionInBuildCtx(t *testing.T) {
	tt := newTestTracker()
	ctx := tt.BuildTaintContext("never-seen", []RuleFinding{taintConsumerFinding("X", 0.9)}, ShellOps{})
	if ctx.HasStrongConsumer || ctx.HasWeakConsumer {
		t.Errorf("unknown session ⇒ no escalation; got %+v", ctx)
	}
}
