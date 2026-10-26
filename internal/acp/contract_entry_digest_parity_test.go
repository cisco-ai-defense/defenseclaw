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
	got, err := ClientEntrySHA256(path, "zed", "kiro")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("ClientEntrySHA256 = %s, want %s (the CLI verify digest)", got, want)
	}
}
