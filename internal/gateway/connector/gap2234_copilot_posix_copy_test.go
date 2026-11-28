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

// GAP-2234: the doctor reports a Copilot bound-event entry that runs a copy
// of copilot-hook.sh named by a POSIX path in another folder, on every OS.
// On Windows, Setup's repair read that word with filepath.IsAbs (false for
// /dir/x there), so it kept the entry and refused the event; on Linux and
// macOS it removes it. Setup now reads the word as the doctor does.
func TestGAP2234CopilotSetupRemovesAPOSIXPathCopyOnEveryOS(t *testing.T) {
	const copy = "'/nonexistent-lane/copilot-hook.sh' --event 'preToolUse'"
	root := t.TempDir()
	hookScript := filepath.Join(root, ".defenseclaw", "hooks", copilotHookScriptName)
	if !copilotBoundEventOwnsCommand("bash", copy, hookScript) {
		t.Fatalf("Setup does not claim the POSIX-path copy %s", copy)
	}
	for _, command := range []string{
		"'/nonexistent-lane/other-hook.sh' --event 'preToolUse'",
		"'nonexistent-lane/copilot-hook.sh' --event 'preToolUse'",
		"'/nonexistent-lane/../copilot-hook.sh' --event 'preToolUse'",
		"'//host/share/copilot-hook.sh' --event 'preToolUse'",
		"'/nonexistent-lane/copilot-hook.sh' --event 'preToolUse' --debug",
	} {
		if copilotBoundEventOwnsCommand("bash", command, hookScript) {
			t.Errorf("Setup claims %s", command)
		}
	}

	path := filepath.Join(root, "agent", "defenseclaw.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(map[string]interface{}{
		"version": 1,
		"hooks": map[string]interface{}{
			"preToolUse": []interface{}{map[string]interface{}{"type": "command", "bash": copy}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := patchCopilotHooks(path, hookScript); err != nil {
		t.Fatalf("Setup refused the event: %v", err)
	}
	after, err := readJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range hookCommandStrings(after) {
		if strings.Contains(command, "/nonexistent-lane/") {
			t.Fatalf("Setup kept the copy the doctor reports: %s", command)
		}
	}
}
