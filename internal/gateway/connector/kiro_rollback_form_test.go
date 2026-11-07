// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Before a rollback, the per-user Kiro commands this release writes become
// the form releases before 1.0.9 own, and only exact whole commands change;
// the restore of an aborted rollback gives back the same bytes
// (rel-1-0-6 GAP-0676, the GAP-1284 rule).
func TestKiroRollbackConvertsTheAnsweringBridgeToTheEarlierFormAndBack(t *testing.T) {
	pinWindowsSystemDirectoryForTest(t)
	const launcher = `C:\Users\dcw std1\.local\bin\defenseclaw-hook.exe`
	pairs := kiroWindowsHookFormPairs([]string{launcher, launcher, ""})
	if len(pairs) != 2 {
		t.Fatalf("pairs = %d, want one per surface", len(pairs))
	}
	v2 := windowsKiroHookCommandForBinary(launcher, "", false)
	v3 := windowsKiroHookCommandForBinary(launcher, KiroHookSurfaceV3, false)
	managed := windowsKiroHookCommandForBinary(launcher, KiroHookSurfaceV3, true)
	file := map[string]any{
		"hooks": map[string]any{
			"preToolUse": []any{
				map[string]any{"command": v2},
				map[string]any{"command": "echo operator"},
				map[string]any{"command": v3 + " --extra"},
			},
		},
		"v3":      []any{map[string]any{"type": "command", "command": v3}},
		"managed": managed,
	}
	original, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	converted, changed := convertKiroHookFileForms(original, pairs, true)
	if changed != 2 {
		t.Fatalf("converted %d commands, want 2", changed)
	}
	for _, want := range []string{preStartAnswerWindowsKiroHookCommand(launcher, ""), preStartAnswerWindowsKiroHookCommand(launcher, KiroHookSurfaceV3)} {
		if !bytes.Contains(converted, kiroJSONString(want, true)) {
			t.Fatalf("the earlier form %q is missing:\n%s", want[:80], converted)
		}
	}
	for _, kept := range []string{"echo operator", v3 + " --extra", managed} {
		if !bytes.Contains(converted, kiroJSONString(kept, true)) {
			t.Fatalf("%q was rewritten", kept[:min(len(kept), 80)])
		}
	}
	if again, n := convertKiroHookFileForms(converted, pairs, true); n != 0 || !bytes.Equal(again, converted) {
		t.Fatalf("a second conversion changed %d commands", n)
	}
	restored, back := convertKiroHookFileForms(converted, pairs, false)
	if back != 2 || !bytes.Equal(restored, original) {
		t.Fatalf("restore changed %d commands; bytes equal = %v", back, bytes.Equal(restored, original))
	}
	if strings.Contains(string(kiroJSONString(v2, true)), "\n") {
		t.Fatal("the JSON form of the command holds a raw line break")
	}
}
