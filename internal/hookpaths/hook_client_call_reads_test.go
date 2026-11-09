// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"testing"
)

// The hook client reads the folders of the working directory and the home
// for each instruction name and each protected key file; on Windows each read
// is walked for a link into a share, and the client of an ordinary command
// made about 400 walk reads (the table test of the archive programs makes
// 260,000 such calls and took 11 minutes of the Windows hookpaths package).
// Each folder is now proved once for a client call (rel-1-0-9:GAP-0963).
func TestHookClientCallReadsEachFolderOnce(t *testing.T) {
	resetPlainFolders(t)
	restore := OverrideNetworkSharesForTest(func(string) string { return "" }, func(string) {})
	defer restore()
	cwd, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	reads := countWalkReads(t)
	payload, err := json.Marshal(map[string]any{"session_id": "s", "hook_event_name": "PreToolUse", "cwd": cwd,
		"tool_name": "Bash", "tool_input": map[string]any{"command": "unzip -d out a.zip"}})
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() string{
		"Resolve":                  func() string { return Resolve(payload) },
		"ResolveConnector (codex)": func() string { return ResolveConnector("codex", "", "PreToolUse", payload) },
	} {
		call()
		*reads = 0
		if call() == "" {
			t.Errorf("%s: no evidence for an ordinary command", name)
		}
		if *reads > 200 {
			t.Errorf("%s: an ordinary command made %d walk reads, want at most 200 (before: 403)", name, *reads)
		}
	}
}
