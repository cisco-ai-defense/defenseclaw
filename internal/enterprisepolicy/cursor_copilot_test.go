// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const adminCursorHooks = `{
  "version": 1,
  "company": {"owner": "platform"},
  "hooks": {
    "beforeShellExecution": [
      {"command": "/usr/local/bin/company-shell-policy"}
    ],
    "afterFileEdit": [
      {"command": "/usr/local/bin/company-format"}
    ]
  }
}
`

func TestCursorMergePreservesForeignEntriesInOrder(t *testing.T) {
	opts := testOptions(t)
	path, _ := CursorEnterpriseHooksPath(opts)
	writeFile(t, path, adminCursorHooks)
	state, err := cursorTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	if !state.Covered || state.ForeignEntries != 2 {
		t.Fatalf("state: %+v", state)
	}
	merged := readFile(t, path)
	if strings.Index(merged, `"company"`) > strings.Index(merged, `"hooks"`) {
		t.Fatalf("top-level key order must be preserved:\n%s", merged)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(merged), &doc); err != nil {
		t.Fatal(err)
	}
	shell := doc["hooks"].(map[string]any)["beforeShellExecution"].([]any)
	if len(shell) != 2 || shell[0].(map[string]any)["command"] != "/usr/local/bin/company-shell-policy" {
		t.Fatalf("administrator entry must stay first: %v", shell)
	}
	if again, err := (cursorTarget{}).Reconcile(opts); err != nil || again.Changed {
		t.Fatalf("second reconcile must be a no-op: %v %+v", err, again)
	}
	if _, err := (cursorTarget{}).RemoveOwned(opts); err != nil {
		t.Fatal(err)
	}
	if readFile(t, path) != adminCursorHooks {
		t.Fatalf("remove must restore the administrator file byte for byte:\n%s", readFile(t, path))
	}
}

func TestCursorRepairsDriftedOwnedEntry(t *testing.T) {
	opts := testOptions(t)
	path, _ := CursorEnterpriseHooksPath(opts)
	if _, err := (cursorTarget{}).Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	drifted := strings.Replace(readFile(t, path), `"failClosed": true`, `"failClosed": false`, 1)
	writeFile(t, path, drifted)
	state, err := cursorTarget{}.Verify(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !hasConflict(state, "not failClosed") {
		t.Fatalf("verify must catch a weakened DefenseClaw entry: %+v", state.Conflicts)
	}
	state, err = cursorTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	if strings.Contains(readFile(t, path), `"failClosed": false`) {
		t.Fatal("reconcile must restore failClosed")
	}
}

func TestCopilotDropInAndAdminPolicyCoexist(t *testing.T) {
	opts := testOptions(t)
	dir, _ := CopilotPolicyDir(opts)
	admin := filepath.Join(dir, "10-company.json")
	writeFile(t, admin, `{"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": "/usr/local/bin/company-audit", "timeoutSec": 5}]}}`)
	// The administrator's VS Code policy value is kept; DefenseClaw adds
	// only the policy that is absent, and removes only that one.
	vscodePolicy := filepath.Join(opts.Root, "etc/vscode/policy.json")
	writeFile(t, vscodePolicy, `{"ChatHooks": false, "UpdateMode": "manual"}`)
	state, err := copilotTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	if !state.Covered || state.ForeignEntries != 1 {
		t.Fatalf("state: %+v", state)
	}
	drop := readFile(t, filepath.Join(dir, DefenseClawDropInName))
	if !strings.Contains(drop, `hook --connector copilot --enterprise-managed --event 'preToolUse'`) {
		t.Fatalf("copilot drop-in: %s", drop)
	}
	if got := readFile(t, vscodePolicy); !strings.Contains(got, `"ChatEditorPreferCopilotHarness": true`) || !strings.Contains(got, `"ChatHooks": false`) {
		t.Fatalf("vscode policy: %s", got)
	}
	if _, err := (copilotTarget{}).RemoveOwned(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, DefenseClawDropInName)); !os.IsNotExist(err) {
		t.Fatal("drop-in must be removed")
	}
	if _, err := os.Stat(admin); err != nil {
		t.Fatal("administrator policy file must survive")
	}
	if got := readFile(t, vscodePolicy); strings.Contains(got, "ChatEditorPreferCopilotHarness") || !strings.Contains(got, `"ChatHooks": false`) || !strings.Contains(got, "UpdateMode") {
		t.Fatalf("vscode policy after removal: %s", got)
	}
}

func TestCopilotWindowsRendering(t *testing.T) {
	opts := Options{GOOS: "windows", HookBinary: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`, WindowsProgramFiles: `C:\Program Files`, WindowsProgramData: `C:\ProgramData`}
	data, err := renderCopilotDropIn(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"powershell"`) || !strings.Contains(string(data), `-Wait -PassThru`) || strings.Contains(string(data), `"bash"`) {
		t.Fatalf("windows copilot drop-in: %s", data)
	}
	if path, _ := copilotDropInPath(opts); path != `C:\ProgramData\GitHub\Copilot\policy.d\90-defenseclaw.json` {
		t.Fatalf("path = %q", path)
	}
}

func TestCopilotUntrustedDropInIsAConflict(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix ownership rule")
	}
	opts := testOptions(t)
	opts.SkipTrustChecks = false
	previous := trustedOwner
	uid := uint32(os.Getuid())
	trustedOwner = func(owner uint32) bool { return owner == uid }
	t.Cleanup(func() { trustedOwner = previous })
	if err := os.Chmod(opts.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	state, err := copilotTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	path, _ := copilotDropInPath(opts)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("drop-in must be written 0644: %v %v", info, err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	state, err = copilotTarget{}.Verify(opts)
	if err != nil {
		t.Fatal(err)
	}
	if state.Covered || !hasConflict(state, "Copilot silently ignores") {
		t.Fatalf("a world-writable drop-in is ignored by Copilot and must not count: %+v", state)
	}
	// Reconcile replaces DefenseClaw's own drop-in when it is untrusted
	// instead of failing every pass.
	state, err = copilotTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatalf("reconcile must repair an untrusted DefenseClaw drop-in: %v", err)
	}
	mustNoConflicts(t, state)
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 || !state.Covered {
		t.Fatalf("repaired drop-in: %v %v %+v", info, err, state)
	}
}
