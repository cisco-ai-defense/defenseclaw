// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"testing"
	"time"
)

// TestGroupSignalsForRollup_DedupesByLowercaseEcosystemName confirms the
// two-axis emitter sees the same dedupe key the API rollup uses, so an
// "OpenAI" and "openai" install share one OTel emission instead of
// double-counting from a casing diff.
func TestGroupSignalsForRollup_DedupesByLowercaseEcosystemName(t *testing.T) {
	t.Parallel()
	signals := []AISignal{
		newComponentSignal("a", "PyPI", "OpenAI", "1.40.0", "ws-1", AIStateNew, ""),
		newComponentSignal("b", "pypi", "openai", "1.40.0", "ws-1", AIStateSeen, ""),
		newComponentSignal("c", "pypi", "openai", "1.41.0", "ws-2", AIStateSeen, ""),
		newComponentSignal("d", "npm", "openai", "1.0.0", "ws-1", AIStateSeen, ""),
		// Catch-all signal without component should be ignored.
		{Fingerprint: "no-component", State: AIStateNew},
	}
	got := groupSignalsForRollup(signals)
	if len(got) != 2 {
		t.Fatalf("groupSignalsForRollup returned %d groups; want 2", len(got))
	}
	byKey := map[string]componentSignalGroup{}
	for _, g := range got {
		byKey[g.Ecosystem+"/"+g.Name] = g
	}
	pypi := mustGroup(t, byKey, "PyPI/OpenAI")
	if len(pypi.Signals) != 3 {
		t.Fatalf("pypi group signals = %d; want 3", len(pypi.Signals))
	}
	if pypi.WorkspaceCount != 2 {
		t.Fatalf("pypi workspace count = %d; want 2", pypi.WorkspaceCount)
	}
	if !pypi.HasLifecycleChange {
		t.Fatalf("pypi group should be flagged as lifecycle (has 1 New signal)")
	}
	npm := mustGroup(t, byKey, "npm/openai")
	if npm.HasLifecycleChange {
		t.Fatalf("npm group should NOT be lifecycle (only Seen)")
	}
}

// TestGroupSignalsForRollup_FrameworkFirstNonEmpty pins the first-non-empty
// rule for the Framework label so a noisy detector that emits the package
// name without a framework can't blank out a richer signal in the same
// group.
func TestGroupSignalsForRollup_FrameworkFirstNonEmpty(t *testing.T) {
	t.Parallel()
	first := newComponentSignal("a", "pypi", "openai", "1.0.0", "ws-1", AIStateSeen, "")
	second := newComponentSignal("b", "pypi", "openai", "1.0.0", "ws-1", AIStateSeen, "OpenAI Python SDK")
	got := groupSignalsForRollup([]AISignal{first, second})
	if len(got) != 1 || got[0].Framework != "OpenAI Python SDK" {
		t.Fatalf("framework = %q; want OpenAI Python SDK", got[0].Framework)
	}
}

func TestGroupSignalsForRollup_SkipsGoneSignals(t *testing.T) {
	t.Parallel()
	gone := newComponentSignal("gone", "pypi", "openai", "1.0.0", "ws-old", AIStateGone, "OpenAI Python SDK")
	if got := groupSignalsForRollup([]AISignal{gone}); len(got) != 0 {
		t.Fatalf("gone-only rollup len=%d want 0: %+v", len(got), got)
	}
	active := newComponentSignal("active", "pypi", "openai", "1.0.0", "ws-new", AIStateSeen, "OpenAI Python SDK")
	got := groupSignalsForRollup([]AISignal{gone, active})
	if len(got) != 1 {
		t.Fatalf("mixed rollup len=%d want 1: %+v", len(got), got)
	}
	if len(got[0].Signals) != 1 || got[0].Signals[0].State == AIStateGone {
		t.Fatalf("gone signal contributed to active confidence rollup: %+v", got[0].Signals)
	}
	if got[0].WorkspaceCount != 1 {
		t.Fatalf("workspace count = %d, want only active workspace", got[0].WorkspaceCount)
	}
}

// TestGroupSignalsForRollup_NULByteInEcosystemDoesNotCollide pins the
// F3 invariant: the dedupe key MUST be a struct, not a delimited
// string. Two distinct components whose lowercased keys would
// collide under a NUL-delimited string MUST be tracked separately.
func TestGroupSignalsForRollup_NULByteInEcosystemDoesNotCollide(t *testing.T) {
	t.Parallel()
	a := newComponentSignal("a", "pypi", "foo\x00bar", "1.0.0", "ws-1", AIStateNew, "")
	b := newComponentSignal("b", "pypi\x00foo", "bar", "1.0.0", "ws-1", AIStateNew, "")
	got := groupSignalsForRollup([]AISignal{a, b})
	if len(got) != 2 {
		t.Fatalf("expected two distinct groups; got %d (likely string-key collision regression)", len(got))
	}
}

// TestComponentRollupSnapshot_ScoreForUnknownGroup confirms the
// helper returns ok=false when called with a group not in the
// snapshot (defensive — current callers don't hit this branch
// but a future caller could).
func TestComponentRollupSnapshot_ScoreForUnknownGroup(t *testing.T) {
	t.Parallel()
	snap := componentRollupSnapshot{Scores: map[componentKey]*ConfidenceResult{}}
	if _, ok := snap.ScoreFor(componentSignalGroup{Ecosystem: "ghost", Name: "missing"}); ok {
		t.Fatal("ScoreFor returned ok=true for an unknown group")
	}
	// Nil Scores branch (the "default-config skipped snapshot" case):
	empty := componentRollupSnapshot{}
	if _, ok := empty.ScoreFor(componentSignalGroup{Ecosystem: "any", Name: "any"}); ok {
		t.Fatal("ScoreFor returned ok=true on empty snapshot")
	}
	if got := empty.LookupSignal(AISignal{Component: &AIComponent{Ecosystem: "p", Name: "n"}}); got != nil {
		t.Fatalf("LookupSignal on empty snapshot should be nil; got %+v", got)
	}
}

// ---------- helpers --------------------------------------------------------

func newComponentSignal(id, ecosystem, name, version, workspace, state, framework string) AISignal {
	now := time.Now().UTC()
	return AISignal{
		Fingerprint:   id,
		SignalID:      id,
		Detector:      "package_manifest",
		Category:      SignalAICLI,
		State:         state,
		WorkspaceHash: workspace,
		Component: &AIComponent{
			Ecosystem: ecosystem,
			Name:      name,
			Version:   version,
			Framework: framework,
		},
		LastSeen: now,
	}
}

func mustGroup(t *testing.T, by map[string]componentSignalGroup, key string) componentSignalGroup {
	t.Helper()
	g, ok := by[key]
	if !ok {
		t.Fatalf("group %q not found; have %+v", key, by)
	}
	return g
}
