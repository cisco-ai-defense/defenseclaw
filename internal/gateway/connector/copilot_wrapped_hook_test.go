// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCopilotRepairsWrappedManagedCopiesAndRefusesUnprovenPreToolHooks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix script registrations")
	}
	dir := t.TempDir()
	current := filepath.Join(dir, "hooks", "copilot-hook.sh")
	retired := filepath.Join(dir, "retired hook.sh")
	body, err := os.ReadFile(filepath.Join("testdata", "released-hooks", "1.0.3", "copilot-hook.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(retired, body, 0o600); err != nil {
		t.Fatal(err)
	}
	entry := map[string]interface{}{"type": "command", "bash": "bash " + shellWord(retired) + " --event preToolUse", "timeoutSec": 30}
	path := filepath.Join(dir, "defenseclaw.json")
	if err := writeJSONObject(path, map[string]interface{}{"version": 1, "hooks": map[string]interface{}{"preToolUse": []interface{}{entry}}}); err != nil {
		t.Fatal(err)
	}
	conn := NewCopilotConnector()
	opts := SetupOpts{DataDir: dir, HookFailMode: "closed"}
	if err := patchCopilotHooksForOS(path, current, conn.copilotHookEvents(opts), runtime.GOOS); err != nil {
		t.Fatal(err)
	}
	document, err := readJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	if !conn.renderedHookEntriesPresent(opts, document) {
		t.Error("repair did not converge")
	}
	hooks := document["hooks"].(map[string]interface{})
	entries := hooks["preToolUse"].([]interface{})
	if len(entries) != 1 {
		t.Errorf("retained wrapped managed copy: %v", entries)
	}
	// An opaque command cannot be proved to use the closed runtime. Keep the
	// operator's registration, but refuse to certify the closed posture.
	hooks["preToolUse"] = append(entries, map[string]interface{}{"type": "command", "bash": "operator-hook"})
	if conn.renderedHookEntriesPresent(opts, document) {
		t.Error("unproven pre-tool registration passed closed verification")
	}
}
