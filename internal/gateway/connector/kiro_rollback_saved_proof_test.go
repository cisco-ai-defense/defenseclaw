// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// rel-1-0-10 GAP-1221: a rollback from 1.0.10 to 1.0.5 converted the
// per-user Windows Kiro hooks into the form 1.0.5 owns, then swapped in the
// 1.0.5 data folder, which never set Kiro up. The prune the installer runs
// after the swap with this release's gateway (`connector prune-orphans
// --rollback-backups-dir <the saved newer data>`) owned the Windows commands
// only with proof in the restored folder, so it left them, 1.0.5 neither
// removed nor guarded them, and Kiro failed closed without its token. The
// saved folder of the install the rollback left is that proof now; a saved
// folder that never set Kiro up, or whose teardown finished, is none. The
// rule is checked with the Windows spelling on every host.
func TestKiroRollbackPruneOwnsTheConvertedWindowsHooksThroughTheSavedNewerInstall(t *testing.T) {
	home := t.TempDir()
	KiroHomeOverride = home
	t.Cleanup(func() { KiroHomeOverride = "" })
	pairs := kiroWindowsHookFormPairs(nativeHookBinaryOwnershipCandidates(), "1.0.5", true)
	if len(pairs) == 0 {
		t.Fatal("no Windows Kiro command converts for a rollback to 1.0.5")
	}
	converted := pairs[0][1]
	if !slices.Contains(kiroWindowsOwnedHookCommandsFor(false), converted) {
		t.Fatalf("this release does not own the 1.0.5 form it converts to: %q", converted)
	}
	hooksFile := filepath.Join(home, "hooks", kiroManagedHooksName)
	agentFile := filepath.Join(home, "agents", kiroManagedAgentName+".json")
	v3 := map[string]interface{}{"version": "v1", "hooks": []interface{}{map[string]interface{}{
		"name": "defenseclaw-pre-tool", "trigger": "preToolUse", "matcher": "*",
		"action": map[string]interface{}{"type": "command", "command": converted},
	}}}
	agent := map[string]interface{}{"name": kiroManagedAgentName, "hooks": map[string]interface{}{
		"preToolUse": []interface{}{map[string]interface{}{"command": converted, "matcher": "*"}},
	}}
	for path, cfg := range map[string]map[string]interface{}{hooksFile: v3, agentFile: agent} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := writeJSONObject(path, cfg); err != nil {
			t.Fatal(err)
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
	found := func(opts SetupOpts) []string {
		t.Helper()
		got, err := conn.orphanedHookFilesFor("windows", opts)
		if err != nil {
			t.Fatalf("orphanedHookFilesFor: %v", err)
		}
		return got
	}

	restored := newDataDir("")
	if got := found(SetupOpts{DataDir: restored}); len(got) != 0 {
		t.Fatalf("the restored data folder alone owns the account's Windows Kiro hooks: %v", got)
	}
	saved := newDataDir("#!/bin/sh\nexit 0\n")
	got := found(SetupOpts{DataDir: restored, RollbackSavedDataDir: saved})
	if !slices.Contains(got, hooksFile) || !slices.Contains(got, agentFile) {
		t.Fatalf("the prune after the rollback does not own the hooks the newer install left: %v", got)
	}
	if got := found(SetupOpts{DataDir: restored, RollbackSavedDataDir: newDataDir("")}); len(got) != 0 {
		t.Fatalf("a saved folder that never set Kiro up owns the account's Windows Kiro hooks: %v", got)
	}
	if got := found(SetupOpts{DataDir: restored, RollbackSavedDataDir: newDataDir(disabledHookTombstone("Kiro"))}); len(got) != 0 {
		t.Fatalf("a saved folder whose teardown finished owns the account's Windows Kiro hooks: %v", got)
	}
	if got := conn.installHookCommandsFor("windows", SetupOpts{DataDir: restored, RollbackSavedDataDir: saved, ManagedEnterprise: true}); len(got) != 0 {
		t.Fatalf("a managed install owns Windows commands through the saved folder: %v", got)
	}
}
