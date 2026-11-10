// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1034: the Windows own-status answer says blocked for each connector the
// standalone hook refuses as enrollment pending, with the wording of the
// administrator's status; a connector the check does not name, another
// account, and every account while the check says no keep their rows; the
// caller is only ever asked about its own SID.
func TestOwnStatusForWindowsAccountSaysBlockedForAPendingAccount(t *testing.T) {
	completeOwnStatusScan(t, nil)
	previousName, previousPending := ownStatusWindowsAccount, ownWindowsRuntimePending
	ownStatusWindowsAccount = func(string) (string, string) { return `WIN11\alice`, "" }
	t.Cleanup(func() { ownStatusWindowsAccount, ownWindowsRuntimePending = previousName, previousPending })
	const alice, bob = "S-1-5-21-1004336348-1177238915-682003330-1001", "S-1-5-21-1004336348-1177238915-682003330-1002"
	enabled := true
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex": {Enabled: &enabled}, "cursor": {Enabled: &enabled}, "opencode": {Enabled: &enabled},
	}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	asked := map[string]bool{}
	pending := map[string]bool{"claudecode": true, "codex": true, "cursor": true, "opencode": false}
	ownWindowsRuntimePending = func(connector, sid string) bool {
		asked[sid] = true
		return sid == alice && pending[connector]
	}
	type rows struct {
		Cowork     map[string]any            `json:"cowork"`
		ClaudeCode struct{ Protected bool } `json:"claude_code"`
		Connectors map[string]struct {
			Protected  bool   `json:"protected"`
			State      string `json:"state"`
			ReasonCode string `json:"reason_code"`
			Reason     string `json:"reason"`
			NextStep   string `json:"next_step"`
		} `json:"connectors"`
	}
	read := func(sid string) rows {
		var out rows
		if err := json.Unmarshal(api.ownStatusForWindowsAccount(context.Background(), sid), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	const wording = "blocked until this account signs in or reconnects (DefenseClaw refuses every tool call of the agent)"
	mine := read(alice)
	for _, name := range []string{"claudecode", "codex", "cursor"} {
		row := mine.Connectors[name]
		if row.Protected || row.State != "blocked" || row.ReasonCode != "pending_sign_in" || row.Reason != wording ||
			!strings.Contains(row.NextStep, "connected session") {
			t.Fatalf("%s row = %+v; want the blocked row", name, row)
		}
	}
	if row := mine.Connectors["opencode"]; row.State != "not confirmed" {
		t.Fatalf("a connector the check does not block changed: %+v", row)
	}
	if mine.ClaudeCode.Protected || mine.Cowork["state"] != "blocked" || mine.Cowork["protected"] != false ||
		!strings.Contains(mine.Cowork["reason"].(string), "blocked until this account signs in or reconnects") {
		t.Fatalf("Claude Code and Cowork follow the blocked row: %+v %+v", mine.ClaudeCode, mine.Cowork)
	}
	// Another account whose hook is not pending is protected, as before.
	other := read(bob)
	if row := other.Connectors["claudecode"]; !row.Protected || row.State != "protected" || !other.ClaudeCode.Protected || other.Cowork["state"] != "protected" {
		t.Fatalf("an account that is not pending: %+v", other)
	}
	if row := other.Connectors["codex"]; row.State != "not confirmed" {
		t.Fatalf("codex of an account that is not pending: %+v", row)
	}
	// Nothing but the caller's own SID is ever asked about.
	if len(asked) != 2 || !asked[alice] || !asked[bob] {
		t.Fatalf("pending check asked about %v", asked)
	}
	// Where the check cannot say (the default), the answer is what it was.
	ownWindowsRuntimePending = func(string, string) bool { return false }
	if row := read(alice).Connectors["claudecode"]; !row.Protected || row.State != "protected" {
		t.Fatalf("default check changed the Claude Code row: %+v", row)
	}
}
