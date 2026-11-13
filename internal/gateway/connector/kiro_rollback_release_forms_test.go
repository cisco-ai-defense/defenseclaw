// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A rollback from 1.0.9 to 1.0.5 rewrote the per-user Windows Kiro hooks
// into the form 1.0.8 renders, which 1.0.0 to 1.0.7 do not own. 1.0.5 could
// not remove them, and they outlived the Kiro connector on an install that
// later guarded only OpenClaw (rel-1-0-10:GAP-0275). The rollback converter
// writes, for each target release, the exact command that release renders
// (testdata: every release tag rendered), and for an unknown target the form
// every release from 1.0.0 owns; the restore of an aborted rollback brings
// either form back to the form of this release.
func TestKiroRollbackWritesTheFormTheTargetReleaseOwns(t *testing.T) {
	pinWindowsSystemDirectoryForTest(t)
	raw, err := os.ReadFile(filepath.Join("testdata", "kiro_windows_release_hook_forms.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Launcher string                       `json:"launcher"`
		Releases map[string]map[string]string `json:"releases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	current := map[string]string{
		"v2": windowsKiroHookCommandForBinary(fixture.Launcher, "", false),
		"v3": windowsKiroHookCommandForBinary(fixture.Launcher, KiroHookSurfaceV3, false),
	}
	file := func(v2, v3 string) []byte {
		data, err := json.MarshalIndent(map[string]any{
			"hooks":   []any{map[string]any{"name": "defenseclaw-pre-tool", "action": map[string]any{"type": "command", "command": v3}}},
			"agent":   map[string]any{"preToolUse": []any{map[string]any{"command": v2}}},
			"foreign": "echo operator",
		}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	original := file(current["v2"], current["v3"])
	targets := map[string]map[string]string{"": fixture.Releases["1.0.0"]}
	for version, forms := range fixture.Releases {
		targets[version] = forms
	}
	for target, want := range targets {
		converted, changed := convertKiroHookFileForms(original, kiroWindowsHookFormPairs([]string{fixture.Launcher}, target, true), true)
		if changed != 2 {
			t.Fatalf("rollback to %q converted %d commands, want 2", target, changed)
		}
		if expected := file(want["v2"], want["v3"]); string(converted) != string(expected) {
			t.Fatalf("rollback to %q wrote a form that release does not render", target)
		}
		restored, back := convertKiroHookFileForms(converted, kiroWindowsHookFormPairs([]string{fixture.Launcher}, "", false), false)
		if back != 2 || string(restored) != string(original) {
			t.Fatalf("restore after a rollback to %q changed %d commands; bytes equal = %v", target, back, string(restored) == string(original))
		}
	}
	// 1.0.9 and later own the 1.0.8 form, so a rollback there keeps it.
	if pairs := kiroWindowsHookFormPairs([]string{fixture.Launcher}, "1.0.9", true); len(pairs) != 2 ||
		pairs[0][1] != preStartAnswerWindowsKiroHookCommand(fixture.Launcher, "") || !strings.Contains(pairs[0][1], "-EncodedCommand") {
		t.Fatalf("pairs for 1.0.9 = %d", len(pairs))
	}
}
