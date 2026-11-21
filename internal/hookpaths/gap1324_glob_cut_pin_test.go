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

// The GAP-1324 cap reaches the hook call (CallState.GlobCut), from this
// process's own walk and from the managed hook client's GlobFactCapped answer
// for a pattern this process cannot see; Decode keeps that answer.
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
		command string
		cut     bool
	}{
		{"cp a.txt at/b*/c*", false},
		{"cp a.txt past/b*/c*", true},
	} {
		got := cut(func() { ActionCommandDecision(row.command, project, home) })
		if got.Any() != row.cut || row.cut && !got.Has(bounded.Paths) {
			t.Errorf("%q: call cut %q, want cut=%v (paths)", row.command, got.Reason(), row.cut)
		}
	}
	// Behind ProtectHome: the home is not there for this process, the
	// client's answer decides.
	hidden := filepath.Join(t.TempDir(), "gone", "home")
	pattern := filepath.Join(hidden, "proj", "w", "b*", "c*")
	for _, row := range []struct {
		answer, decision string
		cut              bool
	}{
		{GlobFactCapped, "", true},
		{"0", "", false},
		{"1", "protected-target", false},
	} {
		facts := map[string]string{GlobFactPrefix + pattern: row.answer}
		var decision string
		got := cut(func() {
			decision = ActionCommandDecisionWithDialectAndGlobFacts("cp a.txt "+pattern, filepath.Join(hidden, "proj"), hidden, "", facts)
		})
		if decision != row.decision || got.Any() != row.cut {
			t.Errorf("client answer %q: decision %q cut %q, want %q cut=%v", row.answer, decision, got.Reason(), row.decision, row.cut)
		}
	}
	encoded, err := json.Marshal(map[string]string{GlobFactPrefix + pattern: GlobFactCapped})
	if err != nil {
		t.Fatal(err)
	}
	if targets, ok := Decode(base64.RawURLEncoding.EncodeToString(encoded)); !ok || targets[GlobFactPrefix+pattern] != GlobFactCapped {
		t.Errorf("Decode refused the capped answer: %v %q", ok, targets)
	}
}
