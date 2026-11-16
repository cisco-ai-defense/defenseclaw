// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import "testing"

// The digest enterprise setup records for its entry is the one the per-user
// CLI computes (cmd_acp._entry_digest), or verify reads DefenseClaw's own
// entry as foreign (GAP-2111). The want value is Python's:
// json.dumps(entry without default_mode, sort_keys=True,
// separators=(",", ":"), ensure_ascii=False), SHA-256.
func TestRecordedEntrySHA256MatchesThePerUserCLIRecord(t *testing.T) {
	entry := map[string]any{
		"type":    "custom",
		"command": "/opt/a&b/<guard>",
		"args":    []any{"--agent", "kiro", "\u00e9\u2028", "tab\tnl\n\x01", "q\"b\\\\"},
		"env":     map[string]any{},
		// Zed keeps the mode picked in its agent panel here; it is not pinned.
		"default_mode": "ask",
		"z":            true,
		"n":            nil,
	}
	got, err := RecordedEntrySHA256("zed", entry)
	if err != nil {
		t.Fatal(err)
	}
	if want := "60f7a975eeca4ad56f4692a2fa0bace21b096a97c0a40d3020bf0cf122038631"; got != want {
		t.Fatalf("RecordedEntrySHA256 = %s, want the per-user CLI digest %s", got, want)
	}
	if _, err := RecordedEntrySHA256("zed", map[string]any{"timeout": 1.5}); err == nil {
		t.Fatal("a value kind the CLI record never holds was digested")
	}
}
