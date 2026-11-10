// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// GAP-1034: the caller's own status says blocked, with the administrator's
// wording, for each machine-hook connector its own hook refuses as enrollment
// pending, and changes nothing else.
func TestOverlayOwnStatusPendingBlocksOnlyThePendingRows(t *testing.T) {
	const body = `{"own":true,"account":{"sid":"S-1-5-21-1-2-3-1001"},"claude_code":{"protected":true},
	"cowork":{"protected":true,"state":"protected","reason_code":"cowork_hooks","reason":"Cowork runs the Claude Code hooks your organization manages"},
	"connectors":{
	 "claudecode":{"protected":true,"state":"protected"},
	 "codex":{"protected":false,"state":"not confirmed","reason_code":"windows_unchecked","reason":"x","next_step":"y"},
	 "cursor":{"protected":false,"state":"not protected","reason_code":"scan_unprotected","reason":"scan said so","next_step":"z"},
	 "copilot":{"protected":false,"state":"not confirmed","reason_code":"windows_unchecked","reason":"x","next_step":"y"},
	 "hermes":{"protected":false,"state":"not managed (removed from roster)"}}}`
	type view struct {
		ClaudeCode struct {
			Protected bool `json:"protected"`
		} `json:"claude_code"`
		Cowork     ownStatusRow            `json:"cowork"`
		Connectors map[string]ownStatusRow `json:"connectors"`
	}
	read := func(raw []byte) view {
		var out view
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		return out
	}
	asked := map[string]bool{}
	got := read(overlayOwnStatusPending([]byte(body), func(connector string) bool {
		asked[connector] = true
		return true
	}))
	for _, name := range []string{"claudecode", "codex"} {
		row := got.Connectors[name]
		if row.Protected || row.State != "blocked" || row.ReasonCode != "pending_sign_in" || row.Reason != ownStatusBlockedReason ||
			!strings.Contains(row.NextStep, "connected session") {
			t.Fatalf("%s = %+v, want the blocked row", name, row)
		}
	}
	if got.ClaudeCode.Protected || got.Cowork.State != "blocked" || got.Cowork.Protected ||
		!strings.Contains(got.Cowork.Reason, "blocked until this account signs in or reconnects") {
		t.Fatalf("Claude Code and Cowork follow the blocked row: %+v %+v", got.ClaudeCode, got.Cowork)
	}
	// An unprotected scan row, other connectors and a removed one keep their state, and are not asked about.
	if got.Connectors["cursor"].State != "not protected" || got.Connectors["copilot"].State != "not confirmed" ||
		got.Connectors["hermes"].State != "not managed (removed from roster)" {
		t.Fatalf("other rows changed: %+v", got.Connectors)
	}
	if asked["cursor"] || asked["copilot"] || asked["hermes"] || !asked["claudecode"] || !asked["codex"] {
		t.Fatalf("asked about %v", asked)
	}
	// A hook that lets the account through changes nothing.
	if out := overlayOwnStatusPending([]byte(body), func(string) bool { return false }); string(out) != body {
		t.Fatalf("a hook that is not pending changed the body: %s", out)
	}
	// Only Codex pending: Claude Code and Cowork stay protected.
	only := read(overlayOwnStatusPending([]byte(body), func(connector string) bool { return connector == "codex" }))
	if only.Connectors["codex"].State != "blocked" || only.Connectors["claudecode"].State != "protected" || !only.ClaudeCode.Protected || only.Cowork.State != "protected" {
		t.Fatalf("only codex pending: %+v", only)
	}
	// An answer that does not decode, or lists no connector, is returned as it was.
	for _, raw := range []string{"not json", `{"own":true}`} {
		if out := overlayOwnStatusPending([]byte(raw), func(string) bool { return true }); string(out) != raw {
			t.Fatalf("%q changed: %s", raw, out)
		}
	}
}
