// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Review P2 of rel-1-0-10 GAP-1092/GAP-1174: a Windows Kiro command runs the
// account's launcher and is the same for every DefenseClaw data folder of the
// account. A data folder that never set Kiro up (a second DEFENSECLAW_HOME,
// `connector prune-orphans --data-dir`) took the live hooks of the install
// that guards Kiro for its own, and its boot reclaim or prune removed them.
// The Windows commands are owned only with proof in this data folder: its
// live hook script or a Kiro backup record (a teardown's tombstone is none).
// A POSIX command names the data folder itself and needs no more (GAP-1092).
// The rule is checked here with the Windows spelling on every host.
func TestKiroWindowsHookCommandsAreOwnedOnlyWithProofInThisDataFolder(t *testing.T) {
	home := t.TempDir()
	KiroHomeOverride = home
	t.Cleanup(func() { KiroHomeOverride = "" })
	hooksFile := filepath.Join(home, "hooks", kiroManagedHooksName)
	agentFile := filepath.Join(home, "agents", kiroManagedAgentName+".json")
	writeEntries := func(command string) {
		t.Helper()
		v3 := map[string]interface{}{"version": "v1", "hooks": []interface{}{map[string]interface{}{
			"name": "defenseclaw-pre-tool", "trigger": "preToolUse", "matcher": "*",
			"action": map[string]interface{}{"type": "command", "command": command},
		}}}
		agent := map[string]interface{}{"name": kiroManagedAgentName, "hooks": map[string]interface{}{
			"preToolUse": []interface{}{map[string]interface{}{"command": command, "matcher": "*"}},
		}}
		for path, cfg := range map[string]map[string]interface{}{hooksFile: v3, agentFile: agent} {
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := writeJSONObject(path, cfg); err != nil {
				t.Fatal(err)
			}
		}
	}
	newDataDir := func(script string) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), ".defenseclaw")
		if err := os.MkdirAll(filepath.Join(dir, "hooks"), 0o700); err != nil {
			t.Fatal(err)
		}
		if script != "" {
			if err := os.WriteFile(filepath.Join(dir, "hooks", kiroHookScriptName), []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	conn := NewKiroConnector()
	found := func(goos, dataDir string) []string {
		t.Helper()
		got, err := conn.orphanedHookFilesFor(goos, SetupOpts{DataDir: dataDir})
		if err != nil {
			t.Fatalf("orphanedHookFilesFor(%s): %v", goos, err)
		}
		return got
	}

	windows := kiroWindowsOwnedHookCommandsFor(false)
	if len(windows) == 0 {
		t.Fatal("no Windows Kiro command to write")
	}
	writeEntries(windows[0])
	other := newDataDir("")
	if got := found("windows", other); len(got) != 0 {
		t.Fatalf("a data folder that never set Kiro up owns the account's Windows Kiro hooks: %v", got)
	}
	if got := found("windows", newDataDir(disabledHookTombstone("Kiro"))); len(got) != 0 {
		t.Fatalf("a data folder with only the teardown tombstone owns the account's Windows Kiro hooks: %v", got)
	}
	scripted := newDataDir("#!/bin/sh\nexit 0\n")
	if got := found("windows", scripted); !slices.Contains(got, hooksFile) || !slices.Contains(got, agentFile) {
		t.Fatalf("the data folder with its live hook script does not own its Windows Kiro hooks: %v", got)
	}
	recorded := newDataDir("")
	if err := captureManagedFileBackup(recorded, "kiro", kiroBackupLogicalName(hooksFile), hooksFile); err != nil {
		t.Fatal(err)
	}
	if got := found("windows", recorded); !slices.Contains(got, hooksFile) {
		t.Fatalf("the data folder with a Kiro backup record does not own its Windows Kiro hooks: %v", got)
	}
	if got := conn.installHookCommandsFor("windows", SetupOpts{DataDir: scripted, ManagedEnterprise: true}); len(got) != 0 {
		t.Fatalf("a managed install owns Windows commands %v", got)
	}

	// POSIX: the command names the data folder, so no script is needed (a
	// rollback's data swap drops it, GAP-1092), and another folder owns none.
	posix := newDataDir("")
	writeEntries(kiroHookInvocationCommandFor("linux", filepath.Join(posix, "hooks", kiroHookScriptName), KiroHookSurfaceV3, false))
	if got := found("linux", posix); !slices.Contains(got, hooksFile) || !slices.Contains(got, agentFile) {
		t.Fatalf("the POSIX data folder does not own the hooks that name it: %v", got)
	}
	if got := found("linux", other); len(got) != 0 {
		t.Fatalf("another POSIX data folder owns hooks that name %s: %v", posix, got)
	}
}
