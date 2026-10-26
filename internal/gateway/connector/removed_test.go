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

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// removedTestHook is the head of an OpenHands hook script a 1.0.3 setup
// wrote: DefenseClaw's marker and the OpenHands name.
const removedTestHook = "#!/usr/bin/env bash\n# defenseclaw-managed-hook v6\n# OpenHands hook (openhands)\nexit 0\n"

// removedTestTombstone is the head of the stub an older teardown left.
const removedTestTombstone = "#!/bin/sh -p\n# defenseclaw-managed-hook v0 (disabled tombstone)\n# OpenHands support was removed.\nexit 0\n"

func removedTestHome(t *testing.T) (home, dataDir string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("OMNIGENT_CONFIG", "")
	t.Setenv("OMNIGENT_CONFIG_HOME", "")
	dataDir = filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	return home, dataDir
}

func removedTestWrite(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func removedTestHooksJSON(t *testing.T, commands ...string) string {
	t.Helper()
	var hooks []any
	for _, command := range commands {
		hooks = append(hooks, map[string]any{"type": "command", "command": command})
	}
	body, err := json.MarshalIndent(map[string]any{
		"PreToolUse": []any{map[string]any{"matcher": "*", "hooks": hooks}},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func removedTestCommands(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string][]struct {
		Hooks []struct {
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("%s: %v\n%s", path, err, data)
	}
	var out []string
	for _, group := range doc["PreToolUse"] {
		for _, hook := range group.Hooks {
			out = append(out, hook.Command)
		}
	}
	return out
}

func removedTestTeardown(t *testing.T, name string, opts SetupOpts) {
	t.Helper()
	conn, ok := RetiredConnector(name)
	if !ok {
		t.Fatalf("RetiredConnector(%q) = false", name)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v (a removed connector's cleanup must never fail)", err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v (a removed connector's leftovers never fail a verify)", err)
	}
}

func removedTestGone(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			t.Errorf("%s is still there", path)
		}
	}
}

// The removal rule: an upgraded host loses exactly what DefenseClaw wrote
// for OpenHands (its hooks.json entries, script, tokens, runtime record and
// receipts), keeps the operator's own hooks, and nothing blocks.
func TestRemovedOpenHandsTeardownRemovesOnlyWhatDefenseClawWrote(t *testing.T) {
	home, dataDir := removedTestHome(t)
	script := filepath.Join(dataDir, "hooks", removedOpenHandsHookScript)
	removedTestWrite(t, script, removedTestHook, 0o700)
	config := filepath.Join(home, ".openhands", "hooks.json")
	removedTestWrite(t, config, removedTestHooksJSON(t, script, "/usr/local/bin/my-own-hook --check"), 0o640)
	tokenPath, err := HookAPITokenFilePath(dataDir, removedOpenHandsID)
	if err != nil {
		t.Fatal(err)
	}
	removedTestWrite(t, tokenPath, "token\n", 0o600)
	record := filepath.Join(dataDir, "hooks", hookConfigSidecarName+"."+removedOpenHandsID)
	removedTestWrite(t, record, "DEFENSECLAW_FAIL_MODE=open\n", 0o600)
	receipts := filepath.Join(dataDir, "connector_backups", removedOpenHandsID)
	removedTestWrite(t, filepath.Join(receipts, "config.json"), "{}", 0o600)
	// GAP-0955 class: a lock entry an older release left for OpenHands is a
	// peer every later setup checks; the teardown clears it and only it.
	for _, entry := range []HookContractLockEntry{
		{Connector: removedOpenHandsID, HookScriptDigests: map[string]string{removedOpenHandsHookScript: "sha256:00"}},
		{Connector: "codex", ContractID: "codex-test"},
	} {
		if err := SaveHookContractLockEntry(dataDir, entry); err != nil {
			t.Fatal(err)
		}
	}

	opts := SetupOpts{DataDir: dataDir}
	removedTestTeardown(t, removedOpenHandsID, opts)

	if entry := LoadHookContractLockEntry(dataDir, removedOpenHandsID); entry.Connector != "" {
		t.Fatalf("the OpenHands lock entry is still there: %+v", entry)
	}
	if entry := LoadHookContractLockEntry(dataDir, "codex"); entry.ContractID != "codex-test" {
		t.Fatalf("the codex lock entry changed: %+v", entry)
	}

	if got := removedTestCommands(t, config); len(got) != 1 || got[0] != "/usr/local/bin/my-own-hook --check" {
		t.Fatalf("hooks.json commands after teardown = %q, want only the operator's hook", got)
	}
	if info, err := os.Stat(config); err != nil || info.Mode().Perm() != 0o640 && runtime.GOOS != "windows" {
		t.Fatalf("hooks.json mode changed: %v %v", info, err)
	}
	removedTestGone(t, script, tokenPath, record, receipts)
	if left, _ := RemovedConnectorLeftovers(removedOpenHandsID, opts); len(left) != 0 {
		t.Fatalf("leftovers after a clean removal = %+v, want none", left)
	}
}

// GAP-0558/GAP-1322 class: a hooks.json that runs a hard link of the old hook
// outside DefenseClaw's hooks folder. The registration runs DefenseClaw's
// hook, so it is DefenseClaw's and goes; the teardown never fails on it.
func TestRemovedOpenHandsTeardownRemovesARegistrationOfAHardLinkElsewhere(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenHands hook scripts are POSIX")
	}
	home, dataDir := removedTestHome(t)
	script := filepath.Join(dataDir, "hooks", removedOpenHandsHookScript)
	removedTestWrite(t, script, removedTestHook, 0o700)
	outside := filepath.Join(home, "bin", "oh-guard.sh")
	if err := os.MkdirAll(filepath.Dir(outside), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(script, outside); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(home, ".openhands", "hooks.json")
	removedTestWrite(t, config, removedTestHooksJSON(t, "bash "+outside, "echo mine"), 0o600)

	removedTestTeardown(t, removedOpenHandsID, SetupOpts{DataDir: dataDir})

	if got := removedTestCommands(t, config); len(got) != 1 || got[0] != "echo mine" {
		t.Fatalf("hooks.json commands = %q, want only the operator's hook", got)
	}
	removedTestGone(t, script)
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("the operator's own file name was removed: %v", err)
	}
}

// GAP-0446 class: an operator-edited hooks.json that still runs the exit-0
// tombstone an older teardown left keeps its own entries; the tombstone's
// entry and file go.
func TestRemovedOpenHandsTeardownRemovesAnOldTombstoneFromAnEditedConfig(t *testing.T) {
	home, dataDir := removedTestHome(t)
	script := filepath.Join(dataDir, "hooks", removedOpenHandsHookScript)
	removedTestWrite(t, script, removedTestTombstone, 0o700)
	config := filepath.Join(home, ".openhands", "hooks.json")
	body, err := json.Marshal(map[string]any{
		"PreToolUse": []any{
			map[string]any{"matcher": "*", "hooks": []any{map[string]any{"type": "command", "command": script}}},
			map[string]any{"matcher": "terminal", "hooks": []any{map[string]any{"type": "command", "command": "/opt/audit/hook"}}},
		},
		"note": "mine",
	})
	if err != nil {
		t.Fatal(err)
	}
	removedTestWrite(t, config, string(body), 0o600)

	removedTestTeardown(t, removedOpenHandsID, SetupOpts{DataDir: dataDir})

	data, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), removedOpenHandsHookScript) || !strings.Contains(string(data), "/opt/audit/hook") ||
		!strings.Contains(string(data), `"note": "mine"`) {
		t.Fatalf("hooks.json after teardown:\n%s", data)
	}
	removedTestGone(t, script)
}

// OmniGent: DefenseClaw's policy module entry, its policy, its import-path
// line and its module go; the operator's modules, policies and import paths
// stay.
func TestRemovedOmnigentTeardownRemovesOnlyWhatDefenseClawWrote(t *testing.T) {
	home, dataDir := removedTestHome(t)
	module := filepath.Join(dataDir, "hooks", removedOmnigentModuleName+".py")
	removedTestWrite(t, module, "# defenseclaw-managed-policy v3\nPOLICY_REGISTRY = []\n", 0o600)
	config := filepath.Join(home, ".omnigent", "config.yaml")
	removedTestWrite(t, config, "policy_modules:\n  - my_policies\n  - "+removedOmnigentModuleName+"\npolicies:\n"+
		"  "+removedOmnigentPolicyKey+":\n    handler: "+removedOmnigentModuleName+".defenseclaw_policy\n"+
		"  mine:\n    handler: my_policies.check\nmodel: x\n", 0o600)
	pth := filepath.Join(home, "site-packages", "defenseclaw_omnigent.pth")
	removedTestWrite(t, pth, filepath.Join(dataDir, "hooks")+"\n/opt/other\n", 0o600)
	record, err := json.Marshal(map[string]any{"version": managedBackupVersion, "connector": removedOmnigentID, "logical_name": "pth", "path": pth})
	if err != nil {
		t.Fatal(err)
	}
	removedTestWrite(t, managedFileBackupPath(dataDir, removedOmnigentID, "pth"), string(record), 0o600)

	opts := SetupOpts{DataDir: dataDir}
	removedTestTeardown(t, removedOmnigentID, opts)

	data, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, removedOmnigentModuleName) || !strings.Contains(text, "my_policies") ||
		!strings.Contains(text, "my_policies.check") || !strings.Contains(text, "model: x") {
		t.Fatalf("config.yaml after teardown:\n%s", text)
	}
	if got, err := os.ReadFile(pth); err != nil || strings.TrimSpace(string(got)) != "/opt/other" {
		t.Fatalf("import-path file after teardown = %q, %v; want only the operator's line", got, err)
	}
	removedTestGone(t, module, filepath.Join(dataDir, "connector_backups", removedOmnigentID))
	if left, _ := RemovedConnectorLeftovers(removedOmnigentID, opts); len(left) != 0 {
		t.Fatalf("leftovers after a clean removal = %+v, want none", left)
	}
}

// A config DefenseClaw cannot parse is never rewritten and never fails the
// teardown; it is listed under the one notice line, as information.
func TestRemovedConnectorLeftoverIsInformationUnderTheNotice(t *testing.T) {
	home, dataDir := removedTestHome(t)
	script := filepath.Join(dataDir, "hooks", removedOpenHandsHookScript)
	config := filepath.Join(home, ".openhands", "hooks.json")
	broken := `{"PreToolUse": [ "` + script + `" ` // not JSON
	removedTestWrite(t, config, broken, 0o600)

	opts := SetupOpts{DataDir: dataDir}
	removedTestTeardown(t, removedOpenHandsID, opts)

	if got, _ := os.ReadFile(config); string(got) != broken {
		t.Fatalf("an unparseable hooks.json was rewritten:\n%s", got)
	}
	left, ok := RemovedConnectorLeftovers(removedOpenHandsID, opts)
	if !ok || len(left) != 1 || left[0].Path != config {
		t.Fatalf("leftovers = %+v, %v; want the one unparseable config", left, ok)
	}
	text := FormatRemovedLeftovers(removedOpenHandsID, left)
	if first := strings.SplitN(text, "\n", 2)[0]; first != RemovedConnectorNotice {
		t.Fatalf("first line = %q, want %q", first, RemovedConnectorNotice)
	}
	if RemovedConnectorNotice != "OpenHands/OmniGent support was removed in 1.0.5; DefenseClaw no longer guards it." {
		t.Fatalf("notice changed: %q", RemovedConnectorNotice)
	}
}

// GAP-1842 class: a hook is DefenseClaw's by identity (its path, its marker
// or the launcher flag), never by its name. An operator's own hook whose
// name is or holds openhands-hook.sh stays on every teardown, also on a host
// DefenseClaw never set up for OpenHands, and is never listed as a leftover.
func TestRemovedOpenHandsTeardownKeepsTheOperatorsHookOfTheSameName(t *testing.T) {
	t.Run("never set up", func(t *testing.T) {
		home, dataDir := removedTestHome(t)
		config := filepath.Join(home, ".openhands", "hooks.json")
		body := removedTestHooksJSON(t, filepath.Join(home, "bin", "my-"+removedOpenHandsHookScript))
		removedTestWrite(t, config, body, 0o600)

		opts := SetupOpts{DataDir: dataDir}
		removedTestTeardown(t, removedOpenHandsID, opts)

		if got, err := os.ReadFile(config); err != nil || string(got) != body {
			t.Fatalf("the operator's hooks.json changed: %v\n%s", err, got)
		}
		if left, _ := RemovedConnectorLeftovers(removedOpenHandsID, opts); len(left) != 0 {
			t.Fatalf("leftovers = %+v, want none", left)
		}
	})
	t.Run("next to DefenseClaw's", func(t *testing.T) {
		home, dataDir := removedTestHome(t)
		script := filepath.Join(dataDir, "hooks", removedOpenHandsHookScript)
		removedTestWrite(t, script, removedTestHook, 0o700)
		own := filepath.Join(home, "scripts", removedOpenHandsHookScript)
		removedTestWrite(t, own, "#!/bin/sh\n# my OpenHands hook\nexit 0\n", 0o700)
		mine := []string{
			filepath.Join(home, "bin", "my-"+removedOpenHandsHookScript),
			own,
			"bash ~/scripts/" + removedOpenHandsHookScript + " --pre",
			script + ".bak",
		}
		config := filepath.Join(home, ".openhands", "hooks.json")
		ours := []string{script, `"` + script + `"`, "~/.defenseclaw/hooks/" + removedOpenHandsHookScript}
		removedTestWrite(t, config, removedTestHooksJSON(t, append(ours, mine...)...), 0o600)

		opts := SetupOpts{DataDir: dataDir}
		removedTestTeardown(t, removedOpenHandsID, opts)

		if got := removedTestCommands(t, config); strings.Join(got, "\n") != strings.Join(mine, "\n") {
			t.Fatalf("hooks.json commands = %q, want only the operator's %q", got, mine)
		}
		removedTestGone(t, script)
		if _, err := os.Stat(own); err != nil {
			t.Fatalf("the operator's own hook script was removed: %v", err)
		}
		if left, _ := RemovedConnectorLeftovers(removedOpenHandsID, opts); len(left) != 0 {
			t.Fatalf("leftovers = %+v, want none", left)
		}
	})
	t.Run("data dir with a space", func(t *testing.T) {
		home, _ := removedTestHome(t)
		dataDir := filepath.Join(home, "My Data")
		script := filepath.Join(dataDir, "hooks", removedOpenHandsHookScript)
		config := filepath.Join(home, ".openhands", "hooks.json")
		removedTestWrite(t, config, removedTestHooksJSON(t, script, "echo mine"), 0o600)

		removedTestTeardown(t, removedOpenHandsID, SetupOpts{DataDir: dataDir})

		if got := removedTestCommands(t, config); len(got) != 1 || got[0] != "echo mine" {
			t.Fatalf("hooks.json commands = %q, want only the operator's hook", got)
		}
	})
}
