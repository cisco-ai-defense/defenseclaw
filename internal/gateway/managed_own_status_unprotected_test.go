// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// rel-1-0-6 GAP-0789: a managed user whose only OpenCode is a machine-wide
// V1, which cannot run the DefenseClaw plugin, was told "OpenCode protected"
// while the administrator's status listed the user as opencode_v1_unprotected.
// The caller's own status now reads the same unprotected-agents entries, for
// every connector, so it never says protected where the administrator says
// the agent is not.
func ownStatusUnprotectedFixture(t *testing.T, agents []enterprisehooks.UnprotectedAgent, readErr error) *APIServer {
	t.Helper()
	previousGuardian, previousAgents := ownStatusGuardianAuthorization, ownStatusUnprotectedAgents
	ownStatusGuardianAuthorization = func(string) (*managedGuardianAuthorization, string) { return nil, "unavailable" }
	ownStatusUnprotectedAgents = func(string) ([]enterprisehooks.UnprotectedAgent, error) { return agents, readErr }
	t.Cleanup(func() { ownStatusGuardianAuthorization, ownStatusUnprotectedAgents = previousGuardian, previousAgents })
	enabled := true
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {Enabled: &enabled}, "codex": {Enabled: &enabled}, "opencode": {Enabled: &enabled},
	}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	api.managedPolicyView.Store(&managedPolicyView{connectors: map[string]managedPolicyViewConnector{
		"claudecode": {}, "codex": {}, "opencode": {},
	}})
	return api
}

func ownStatusConnectorRow(t *testing.T, api *APIServer, uid, name, connector string) map[string]any {
	t.Helper()
	roster, ok := api.ownStatusAnswer(context.Background(), "uid", uid, name)["connectors"].(map[string]any)
	if !ok {
		t.Fatal("own status has no connector roster")
	}
	row, ok := roster[connector].(map[string]any)
	if !ok {
		t.Fatalf("own status has no %s row: %#v", connector, roster)
	}
	return row
}

func unprotectedAgentFor(user string, uid int, connector, code, reason string) enterprisehooks.UnprotectedAgent {
	return enterprisehooks.UnprotectedAgent{User: user, UID: &uid, Connector: connector, Code: code, Reason: reason,
		Version: "1.18.34", InstallPath: "/opt/dc-agents/lib/node_modules/opencode-ai"}
}

func TestOwnStatusMachineWideOpenCodeV1IsNotProtected(t *testing.T) {
	v1 := unprotectedAgentFor("alice", 5001, "opencode", enterprisehooks.UnprotectedCodeOpenCodeV1,
		"it is OpenCode V1 (opencode-ai), which cannot run the DefenseClaw OpenCode V2 plugin, so its tool calls run unchecked: OpenCode is NOT protected until OpenCode V2 (@opencode/cli 2.x) is installed. Fix: npm install -g @opencode/cli@2")
	api := ownStatusUnprotectedFixture(t, []enterprisehooks.UnprotectedAgent{v1}, nil)

	row := ownStatusConnectorRow(t, api, "5001", "alice", "opencode")
	state, _ := row["state"].(string)
	if row["protected"] != false || !strings.HasPrefix(state, "not protected: ") ||
		!strings.Contains(state, "OpenCode V2") || !strings.Contains(state, "@opencode/cli") {
		t.Fatalf("V1-only user's OpenCode row = %#v, want not protected with the administrator's reason and remedy", row)
	}
	// The class: the same user's other connectors stay as the policy view
	// says, and another account sharing the machine-wide copy is judged by its
	// own entry only.
	for _, connector := range []string{"claudecode", "codex"} {
		if row := ownStatusConnectorRow(t, api, "5001", "alice", connector); row["protected"] != true {
			t.Fatalf("alice's %s row = %#v, want protected", connector, row)
		}
	}
	if row := ownStatusConnectorRow(t, api, "5002", "bob", "opencode"); row["protected"] != true || row["state"] != "protected" {
		t.Fatalf("bob has no unprotected entry; his OpenCode row = %#v, want protected", row)
	}
}

// Benign twin: a user on OpenCode V2 has no unprotected entry and stays
// protected; the record listing only a V1 for someone else changes nothing.
func TestOwnStatusOpenCodeV2UserStaysProtected(t *testing.T) {
	other := unprotectedAgentFor("bob", 5002, "opencode", enterprisehooks.UnprotectedCodeOpenCodeV1, "V1")
	for name, agents := range map[string][]enterprisehooks.UnprotectedAgent{"no record": nil, "another user's V1 entry": {other}} {
		api := ownStatusUnprotectedFixture(t, agents, nil)
		if row := ownStatusConnectorRow(t, api, "5001", "alice", "opencode"); row["protected"] != true || row["state"] != "protected" {
			t.Fatalf("%s: V2 user's OpenCode row = %#v, want protected", name, row)
		}
	}
}

// A user with both a V2 and a machine-wide V1 is judged as the administrator
// judges: the runnable V1 copy is unprotected, so the row is not protected.
func TestOwnStatusV1BesideV2IsNotProtected(t *testing.T) {
	v1 := unprotectedAgentFor("alice", 5001, "opencode", enterprisehooks.UnprotectedCodeOpenCodeV1, "V1 copy runs unchecked")
	api := ownStatusUnprotectedFixture(t, []enterprisehooks.UnprotectedAgent{v1}, nil)
	if row := ownStatusConnectorRow(t, api, "5001", "alice", "opencode"); row["protected"] != false {
		t.Fatalf("OpenCode row = %#v, want not protected while a V1 copy is runnable", row)
	}
}

// The same rule for every connector, not only OpenCode, and for an entry
// matched by account name when the record carries no uid.
func TestOwnStatusEveryUnprotectedConnectorIsNotProtected(t *testing.T) {
	codex := unprotectedAgentFor("alice", 5001, "codex", enterprisehooks.UnprotectedCodeHookContractUnverified, "not verified against a known hook contract")
	named := enterprisehooks.UnprotectedAgent{User: "carol", Connector: "claudecode", Code: enterprisehooks.UnprotectedCodeAgentUnprotected, Reason: "cannot enroll"}
	api := ownStatusUnprotectedFixture(t, []enterprisehooks.UnprotectedAgent{codex, named}, nil)
	if row := ownStatusConnectorRow(t, api, "5001", "alice", "codex"); row["protected"] != false ||
		!strings.Contains(row["state"].(string), "hook contract") {
		t.Fatalf("alice's Codex row = %#v, want not protected with the reason", row)
	}
	if row := ownStatusConnectorRow(t, api, "5003", "carol", "claudecode"); row["protected"] != false {
		t.Fatalf("carol's Claude Code row = %#v, want not protected", row)
	}
	answer := api.ownStatusAnswer(context.Background(), "uid", "5003", "carol")
	if answer["claude_code"].(map[string]any)["protected"] != false {
		t.Fatalf("carol's claude_code = %#v, want not protected, as the roster says", answer["claude_code"])
	}
}

// An account whose home is untrusted has an account-level entry that covers
// every connector row.
func TestOwnStatusAccountLevelEntryCoversEveryConnector(t *testing.T) {
	uid := 5001
	account := enterprisehooks.UnprotectedAgent{User: "alice", UID: &uid, Code: enterprisehooks.UnprotectedCodeHomeUntrusted, Reason: "home is not trusted"}
	api := ownStatusUnprotectedFixture(t, []enterprisehooks.UnprotectedAgent{account}, nil)
	for _, connector := range []string{"claudecode", "codex", "opencode"} {
		if row := ownStatusConnectorRow(t, api, "5001", "alice", connector); row["protected"] != false {
			t.Fatalf("%s row = %#v, want not protected", connector, row)
		}
	}
}

// A record that cannot be read confirms nothing.
func TestOwnStatusUnreadableUnprotectedRecordIsNotConfirmed(t *testing.T) {
	api := ownStatusUnprotectedFixture(t, nil, errors.New("record is not trusted"))
	row := ownStatusConnectorRow(t, api, "5001", "alice", "opencode")
	if row["protected"] != false || row["state"] != "not confirmed" {
		t.Fatalf("OpenCode row = %#v, want not confirmed", row)
	}
}

func TestReadManagedUnprotectedAgentsMissingRecordIsNone(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR", t.TempDir())
	agents, err := readManagedUnprotectedAgents("/nonexistent")
	if err != nil || len(agents) != 0 {
		t.Fatalf("missing record = %v, %v; want none", agents, err)
	}
}
