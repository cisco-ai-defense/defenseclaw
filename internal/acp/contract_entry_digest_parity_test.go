// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"os"
	"path/filepath"
	"testing"
)

// TestClientEntrySHA256MatchesTheCLIVerify pins GAP-0912: `defenseclaw acp
// verify` (cmd_acp._guard_entry_sha256) must compute the same entry pin as
// the guard. cli/tests/test_acp_verify_guard_parity_r105.py asserts the same
// digest for the same settings text: <, >, &, U+2028 escaped, sorted keys,
// the Zed-owned default_mode left out.
func TestClientEntrySHA256MatchesTheCLIVerify(t *testing.T) {
	const settings = `{"agent_servers":{"DefenseClaw · Kiro":{"command":"/opt/dc/defenseclaw-acp","args":["--client","zed","--","/opt/a&b<c>","acp"],"env":{"K":"v\u2028w","N":"ü"},"type":"custom","default_mode":"acceptEdits"}}}`
	const want = "25bb929d7ff7b94cf02c9b800bd98b742c93fe53afcdc458d4223b8da191ad7e"
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ClientEntrySHA256(path, "zed", "kiro", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("ClientEntrySHA256 = %s, want %s (the CLI verify digest)", got, want)
	}
}

// TestClientEntrySHA256PinsTheEntriesThatStartTheLock pins GAP-0504: the
// guard pins every entry that starts it with its contract lock (an adopted or
// numbered one too), not only the reserved name. The CLI computes the same
// digests (cli/tests/test_acp_verify_guard_parity_r105.py
// test_guard_entries_digest_matches_go).
func TestClientEntrySHA256PinsTheEntriesThatStartTheLock(t *testing.T) {
	const settings = `{"agent_servers":{"DefenseClaw · Kiro":{"command":"/opt/dc/defenseclaw-acp","args":["--client","zed","--contract-lock","/l/zed-kiro.contract-lock.json","--","/opt/a&b<c>","acp"],"type":"custom","default_mode":"ask"},"My Kiro":{"command":"/opt/dc/defenseclaw-acp","args":["--client","zed","--contract-lock","/l/zed-kiro.contract-lock.json","--","/opt/a&b<c>","acp"],"env":{"N":"ü"}},"Other":{"command":"/opt/dc/defenseclaw-acp","args":["--contract-lock","/l/zed-opencode.contract-lock.json","--","/o"]}}}`
	const lock = "/l/zed-kiro.contract-lock.json"
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ClientEntrySHA256(path, "zed", "kiro", lock)
	if err != nil {
		t.Fatal(err)
	}
	if want := "0e5ca901649cabbb9d3bd4ace7f7c4a84431c625fa6e59b69325c0cdf712ed34"; got != want {
		t.Fatalf("two entries start the lock: digest = %s, want %s", got, want)
	}
	const alone = `{"agent_servers":{"My Kiro":{"command":"/opt/dc/defenseclaw-acp","args":["--client","zed","--contract-lock","/l/zed-kiro.contract-lock.json","--","/opt/a&b<c>","acp"],"env":{"N":"ü"}},"Other":{"command":"/opt/dc/defenseclaw-acp","args":["--contract-lock","/l/zed-opencode.contract-lock.json","--","/o"]}}}`
	if err := os.WriteFile(path, []byte(alone), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = ClientEntrySHA256(path, "zed", "kiro", lock)
	if err != nil {
		t.Fatal(err)
	}
	if want := "a6dac44c3a23621edd8fd9d27e60f9b86c5e92d18cf621e15df07c7189025d59"; got != want {
		t.Fatalf("only the adopted entry starts the lock: digest = %s, want %s", got, want)
	}
}

// TestPinnedEntriesLabelNamesTheEntriesTheLockPins pins GAP-0043: the
// changed-entry refusal names the entries that start the guard with the lock
// (an adopted entry has its own name), and the reserved name only when no
// entry starts the lock.
func TestPinnedEntriesLabelNamesTheEntriesTheLockPins(t *testing.T) {
	const lock = "/l/zed-opencode.contract-lock.json"
	const guarded = `{"command":"/opt/dc/defenseclaw-acp","args":["--client","zed","--contract-lock","/l/zed-opencode.contract-lock.json","--","/o","acp"]}`
	path := filepath.Join(t.TempDir(), "settings.json")
	for _, tc := range []struct{ settings, want string }{
		{`{"agent_servers":{"My OpenCode":` + guarded + `}}`, `My OpenCode entry`},
		{`{"agent_servers":{"My OpenCode":` + guarded + `,"My OpenCode stale":` + guarded + `}}`, `My OpenCode, My OpenCode stale entries`},
		{`{"agent_servers":{"DefenseClaw · Opencode":{"command":"/o","args":["acp"]}}}`, `DefenseClaw · Opencode entry`},
		{`{"agent_servers":{}}`, `DefenseClaw · Opencode entry`},
	} {
		if err := os.WriteFile(path, []byte(tc.settings), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, _ := pinnedEntriesLabel(path, "zed", "opencode", lock); got != tc.want {
			t.Fatalf("pinnedEntriesLabel(%s) = %q, want %q", tc.settings, got, tc.want)
		}
	}
}
