// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// The GAP-1324 cap of a read-only statement reaches the hook call
// (CallState.GlobCut), from this process's own walk and from the managed hook
// client's GlobCapFactPrefix answer for a pattern this process cannot see; a
// write into the capped pattern is the rel/1.0.10 protected target with no
// cut (rel-1-0-10:GAP-2300). Decode keeps that answer and refuses a capped
// value under GlobFactPrefix (no client sends one).
func TestGAP1324GlobWalkCapReachesTheCall(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	gap1324Tree(t, filepath.Join(project, "at"), 63)
	gap1324Tree(t, filepath.Join(project, "past"), 64)
	cut := func(read func()) bounded.CapSet {
		end := HookCall()
		defer end()
		read()
		return HookCallState().GlobCut()
	}
	for _, row := range []struct {
		command, decision string
		cut               bool
	}{
		{"cp a.txt at/b*/c*", "", false},
		{"cp a.txt past/b*/c*", "protected-target", false},
		{"ls past/b*/c*; cp a.txt b.txt", "", true},
	} {
		var decision string
		got := cut(func() { decision = ActionCommandDecision(row.command, project, home) })
		if decision != row.decision || got.Any() != row.cut || row.cut && !got.Has(bounded.Paths) {
			t.Errorf("%q: decision %q call cut %q, want %q cut=%v (paths)", row.command, decision, got.Reason(), row.decision, row.cut)
		}
	}
	// Behind ProtectHome: the home is not there for this process, the
	// client's answer decides.
	hidden := filepath.Join(t.TempDir(), "gone", "home")
	pattern := filepath.Join(hidden, "proj", "w", "b*", "c*")
	write, read := "cp a.txt "+pattern, "ls "+pattern+"; cp a.txt b.txt"
	for _, row := range []struct {
		command  string
		facts    map[string]string
		decision string
		cut      bool
	}{
		{write, map[string]string{GlobCapFactPrefix + pattern: "1"}, "protected-target", false},
		{read, map[string]string{GlobCapFactPrefix + pattern: "1"}, "", true},
		{write, map[string]string{GlobFactPrefix + pattern: "0"}, "", false},
		{write, map[string]string{GlobFactPrefix + pattern: "1"}, "protected-target", false},
		// A match that reaches a protected file wins over a cap.
		{write, map[string]string{GlobFactPrefix + pattern: "1", GlobCapFactPrefix + pattern: "1"}, "protected-target", false},
		{read, map[string]string{GlobFactPrefix + pattern: "1", GlobCapFactPrefix + pattern: "1"}, "protected-target", false},
	} {
		facts := row.facts
		var decision string
		got := cut(func() {
			decision = ActionCommandDecisionWithDialectAndGlobFacts(row.command, filepath.Join(hidden, "proj"), hidden, "", facts)
		})
		if decision != row.decision || got.Any() != row.cut {
			t.Errorf("%q, client answer %q: decision %q cut %q, want %q cut=%v", row.command, row.facts, decision, got.Reason(), row.decision, row.cut)
		}
	}
	for _, row := range []struct {
		facts map[string]string
		ok    bool
	}{
		{map[string]string{GlobCapFactPrefix + pattern: "1"}, true},
		{map[string]string{GlobCapFactPrefix + pattern: "0"}, false},
		{map[string]string{GlobCapFactPrefix + "w/b*": "1"}, false},
		{map[string]string{GlobFactPrefix + pattern: GlobFactCapped}, false},
	} {
		encoded, err := json.Marshal(row.facts)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := Decode(base64.RawURLEncoding.EncodeToString(encoded)); ok != row.ok {
			t.Errorf("Decode(%q) ok=%v, want %v", row.facts, ok, row.ok)
		}
	}
}
