// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// rel-1-0-6 GAP-0789: a managed user whose only OpenCode is a machine-wide
// V1, which cannot run the DefenseClaw plugin, was told "OpenCode protected"
// while the administrator status listed the user as opencode_v1_unprotected.
// The caller own status now reads the same completed scan, for every
// connector, so it never says protected where the administrator says the
// agent is not, and never from a scan it does not know.

// completeOwnStatusScan makes the enumerator scan the own status reads a
// completed scan that found agents (none for nil).
func completeOwnStatusScan(t *testing.T, agents []enterprisehooks.UnprotectedAgent) {
	t.Helper()
	failOwnStatusScan(t, agents, nil)
}

// failOwnStatusScan makes the scan read return agents and readErr.
func failOwnStatusScan(t *testing.T, agents []enterprisehooks.UnprotectedAgent, readErr error) {
	t.Helper()
	previous := ownStatusUnprotectedAgents
	ownStatusUnprotectedAgents = func(string, string, bool) ([]enterprisehooks.UnprotectedAgent, error) {
		return agents, readErr
	}
	t.Cleanup(func() { ownStatusUnprotectedAgents = previous })
}

func ownStatusUnprotectedFixture(t *testing.T, agents []enterprisehooks.UnprotectedAgent, readErr error) *APIServer {
	t.Helper()
	previousGuardian := ownStatusGuardianAuthorization
	ownStatusGuardianAuthorization = func(string) (*managedGuardianAuthorization, string) { return nil, "unavailable" }
	t.Cleanup(func() { ownStatusGuardianAuthorization = previousGuardian })
	failOwnStatusScan(t, agents, readErr)
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
	roster, ok := api.ownStatusAnswer(context.Background(), "uid", uid, name, "")["connectors"].(map[string]any)
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
	state := ownRowText(row)
	if row["protected"] != false || !strings.HasPrefix(state, "not protected: ") ||
		!strings.Contains(state, "OpenCode V2") || !strings.Contains(state, "@opencode/cli") {
		t.Fatalf("V1-only user OpenCode row = %#v, want not protected with the administrator reason and remedy", row)
	}
	// The class: the same user other connectors stay as the policy view
	// says, and another account sharing the machine-wide copy is judged by its
	// own entry only.
	for _, connector := range []string{"claudecode", "codex"} {
		if row := ownStatusConnectorRow(t, api, "5001", "alice", connector); row["protected"] != true {
			t.Fatalf("alice %s row = %#v, want protected", connector, row)
		}
	}
	if row := ownStatusConnectorRow(t, api, "5002", "bob", "opencode"); row["protected"] != true || ownRowText(row) != "protected" {
		t.Fatalf("bob has no unprotected entry; his OpenCode row = %#v, want protected", row)
	}
}

// Benign twin: a user on OpenCode V2 has no unprotected entry and stays
// protected; the record listing only a V1 for someone else changes nothing.
func TestOwnStatusOpenCodeV2UserStaysProtected(t *testing.T) {
	other := unprotectedAgentFor("bob", 5002, "opencode", enterprisehooks.UnprotectedCodeOpenCodeV1, "V1")
	for name, agents := range map[string][]enterprisehooks.UnprotectedAgent{"empty completed scan": nil, "another user V1 entry": {other}} {
		api := ownStatusUnprotectedFixture(t, agents, nil)
		if row := ownStatusConnectorRow(t, api, "5001", "alice", "opencode"); row["protected"] != true || ownRowText(row) != "protected" {
			t.Fatalf("%s: V2 user OpenCode row = %#v, want protected", name, row)
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
		!strings.Contains(ownRowText(row), "hook contract") {
		t.Fatalf("alice Codex row = %#v, want not protected with the reason", row)
	}
	if row := ownStatusConnectorRow(t, api, "5003", "carol", "claudecode"); row["protected"] != false {
		t.Fatalf("carol Claude Code row = %#v, want not protected", row)
	}
	// A Unix name is exact: another case is another account.
	if row := ownStatusConnectorRow(t, api, "5004", "Carol", "claudecode"); row["protected"] != true {
		t.Fatalf("Carol (another account) Claude Code row = %#v, want protected", row)
	}
	answer := api.ownStatusAnswer(context.Background(), "uid", "5003", "carol", "")
	if answer["claude_code"].(map[string]any)["protected"] != false {
		t.Fatalf("carol claude_code = %#v, want not protected, as the roster says", answer["claude_code"])
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

// A scan that is unknown confirms nothing.
func TestOwnStatusUnknownScanIsNotConfirmed(t *testing.T) {
	api := ownStatusUnprotectedFixture(t, nil, errors.New("record is not trusted"))
	row := ownStatusConnectorRow(t, api, "5001", "alice", "opencode")
	if row["protected"] != false || ownRowText(row) != "not confirmed: "+ownCauseScanUnknown.text() {
		t.Fatalf("OpenCode row = %#v, want not confirmed", row)
	}
	if answer := api.ownStatusAnswer(context.Background(), "uid", "5001", "alice", ""); answer["claude_code"].(map[string]any)["protected"] != false {
		t.Fatalf("claude_code = %#v, want not protected while the scan is unknown", answer["claude_code"])
	}
}

// One connector with several unprotected installs names each distinct reason,
// so a Kiro CLI and a Kiro IDE with different remedies both show theirs.
func TestOwnStatusSeveralInstallsOfOneConnectorShowEachReason(t *testing.T) {
	cli := unprotectedAgentFor("alice", 5001, "codex", enterprisehooks.UnprotectedCodeHookContractUnverified, "the CLI copy needs an upgrade")
	ide := unprotectedAgentFor("alice", 5001, "codex", enterprisehooks.UnprotectedCodeAgentUnprotected, "the IDE copy needs a setting")
	twin := unprotectedAgentFor("alice", 5001, "codex", enterprisehooks.UnprotectedCodeAgentUnprotected, "the CLI copy needs an upgrade")
	api := ownStatusUnprotectedFixture(t, []enterprisehooks.UnprotectedAgent{cli, ide, twin}, nil)
	state := ownRowText(ownStatusConnectorRow(t, api, "5001", "alice", "codex"))
	if !strings.Contains(state, "CLI copy needs an upgrade") || !strings.Contains(state, "IDE copy needs a setting") ||
		strings.Count(state, "CLI copy needs an upgrade") != 1 {
		t.Fatalf("Codex state = %q, want each distinct reason once", state)
	}
}

// GAP-0789 on Windows: the standard account own status is the same class.
// Claude Code was protected from configuration alone while the administrator
// status listed the account Claude Code (a private unsupported copy) as
// unprotected.
func windowsOwnStatusRow(t *testing.T, api *APIServer, sid, connector string) (map[string]any, map[string]any) {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(api.ownStatusForWindowsAccount(context.Background(), sid), &out); err != nil {
		t.Fatal(err)
	}
	row, _ := out["connectors"].(map[string]any)[connector].(map[string]any)
	if row == nil {
		t.Fatalf("no %s row in %#v", connector, out)
	}
	return row, out
}

func windowsOwnStatusAPI(t *testing.T, agents []enterprisehooks.UnprotectedAgent, readErr error) *APIServer {
	t.Helper()
	previous := ownStatusWindowsAccount
	ownStatusWindowsAccount = func(sid string) (string, string) {
		if sid == windowsAliceSID {
			return `WIN11\alice`, ""
		}
		return `WIN11\bob`, ""
	}
	t.Cleanup(func() { ownStatusWindowsAccount = previous })
	failOwnStatusScan(t, agents, readErr)
	enabled := true
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {Enabled: &enabled}}
	return NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
}

const (
	windowsAliceSID = "S-1-5-21-1004336348-1177238915-682003330-1001"
	windowsBobSID   = "S-1-5-21-1004336348-1177238915-682003330-1002"
)

func TestOwnStatusWindowsPrivateClaudeCopyIsNotProtected(t *testing.T) {
	private := enterprisehooks.UnprotectedAgent{User: "alice", SID: windowsAliceSID, Connector: "claudecode", Version: "2.0.77",
		InstallPath: `C:\Users\alice\old-a\node_modules\@anthropic-ai\claude-code`,
		Code:        enterprisehooks.UnprotectedCodeHookContractUnverified, Reason: "unsupported version"}
	// The entry may carry the SID in another case, or no SID and only the
	// account name (with or without its domain).
	byName := private
	byName.SID, byName.User = "", "alice"
	byDomainName := private
	byDomainName.SID, byDomainName.User = "", `WIN11\alice`
	for name, entry := range map[string]enterprisehooks.UnprotectedAgent{
		"sid": private, "sid in another case": func() enterprisehooks.UnprotectedAgent {
			e := private
			e.SID = strings.ToLower(e.SID)
			return e
		}(), "bare account name": byName, "domain account name": byDomainName,
	} {
		api := windowsOwnStatusAPI(t, []enterprisehooks.UnprotectedAgent{entry}, nil)
		row, out := windowsOwnStatusRow(t, api, windowsAliceSID, "claudecode")
		if row["protected"] != false || !strings.Contains(ownRowText(row), "unsupported version") {
			t.Fatalf("%s: Claude Code row = %#v, want not protected with the administrator reason", name, row)
		}
		if out["claude_code"].(map[string]any)["protected"] != false || out["cowork"].(map[string]any)["protected"] != false {
			t.Fatalf("%s: claude_code/cowork = %#v / %#v, want not protected", name, out["claude_code"], out["cowork"])
		}
		// Another account sharing the computer is judged by its own entries.
		if row, _ := windowsOwnStatusRow(t, api, windowsBobSID, "claudecode"); row["protected"] != true {
			t.Fatalf("%s: bob Claude Code row = %#v, want protected", name, row)
		}
	}
}

// Benign twin: an account with no unprotected entry of its own stays protected
// for Claude Code, and a Codex entry changes only the Codex row.
func TestOwnStatusWindowsAccountWithoutAnEntryStaysProtected(t *testing.T) {
	codex := enterprisehooks.UnprotectedAgent{User: "alice", SID: windowsAliceSID, Connector: "codex",
		Code: enterprisehooks.UnprotectedCodeHookContractUnverified, Reason: "codex copy not verified"}
	for name, agents := range map[string][]enterprisehooks.UnprotectedAgent{"empty completed scan": nil, "a codex entry": {codex}} {
		api := windowsOwnStatusAPI(t, agents, nil)
		row, out := windowsOwnStatusRow(t, api, windowsAliceSID, "claudecode")
		if row["protected"] != true || ownRowText(row) != "protected" || out["cowork"].(map[string]any)["protected"] != true {
			t.Fatalf("%s: Claude Code row = %#v, cowork = %#v, want protected", name, row, out["cowork"])
		}
	}
	api := windowsOwnStatusAPI(t, []enterprisehooks.UnprotectedAgent{codex}, nil)
	if row, _ := windowsOwnStatusRow(t, api, windowsAliceSID, "codex"); row["protected"] != false ||
		!strings.Contains(ownRowText(row), "codex copy not verified") {
		t.Fatalf("Codex row = %#v, want not protected with the reason", row)
	}
}

func TestOwnStatusWindowsAccountLevelEntryAndUnknownScan(t *testing.T) {
	account := enterprisehooks.UnprotectedAgent{User: "alice", SID: windowsAliceSID, Code: enterprisehooks.UnprotectedCodeHomeUntrusted, Reason: "home is not trusted"}
	api := windowsOwnStatusAPI(t, []enterprisehooks.UnprotectedAgent{account}, nil)
	for _, connector := range []string{"claudecode", "codex"} {
		if row, _ := windowsOwnStatusRow(t, api, windowsAliceSID, connector); row["protected"] != false {
			t.Fatalf("%s row = %#v, want not protected", connector, row)
		}
	}
	// A missing, old or unmatched scan confirms nothing: not even Claude Code.
	api = windowsOwnStatusAPI(t, nil, errors.New("the unprotected agents record is missing"))
	row, out := windowsOwnStatusRow(t, api, windowsAliceSID, "claudecode")
	if row["protected"] != false || ownRowText(row) != "not confirmed: "+ownCauseScanUnknown.text() ||
		out["claude_code"].(map[string]any)["protected"] != false || out["cowork"].(map[string]any)["protected"] != false {
		t.Fatalf("unknown scan: Claude Code row = %#v, answer = %#v, want not confirmed", row, out)
	}
}

// The enumerator can name an entry by account only (its SID lookup failed),
// and the gateway can fail to name the caller account too. Such an entry may
// be the caller, so a row it can affect is not confirmed (review 2 M2); a row
// it cannot affect, and an account whose name is known, are judged as before.
func TestOwnStatusNameOnlyEntryOfAnUnnamedWindowsCallerIsNotProtected(t *testing.T) {
	nameOnly := func(user, connector string) enterprisehooks.UnprotectedAgent {
		return enterprisehooks.UnprotectedAgent{User: user, Connector: connector,
			Code: enterprisehooks.UnprotectedCodeAgentUnprotected, Reason: "running copy has no resolved SID"}
	}
	unnamed := func(t *testing.T, agents []enterprisehooks.UnprotectedAgent) *APIServer {
		t.Helper()
		api := windowsOwnStatusAPI(t, agents, nil)
		ownStatusWindowsAccount = func(string) (string, string) { return "", "" }
		return api
	}
	// A name-only Claude Code entry, and one for an account that could not be
	// identified at all: the Claude Code row and Cowork are not protected.
	for name, entry := range map[string]enterprisehooks.UnprotectedAgent{
		"name only":          nameOnly("alice", "claudecode"),
		"unidentified owner": nameOnly(enterprisehooks.UnprotectedUnknownAccount, "claudecode"),
	} {
		row, out := windowsOwnStatusRow(t, unnamed(t, []enterprisehooks.UnprotectedAgent{entry}), windowsAliceSID, "claudecode")
		if row["protected"] != false || !strings.HasPrefix(ownRowText(row), "not confirmed") ||
			out["claude_code"].(map[string]any)["protected"] != false || out["cowork"].(map[string]any)["protected"] != false {
			t.Fatalf("%s: Claude Code row = %#v, answer = %#v, want not confirmed", name, row, out)
		}
	}
	// An account-level name-only entry affects every connector.
	account := nameOnly("alice", "")
	account.Code = enterprisehooks.UnprotectedCodeHomeUntrusted
	if row, _ := windowsOwnStatusRow(t, unnamed(t, []enterprisehooks.UnprotectedAgent{account}), windowsAliceSID, "codex"); row["protected"] != false {
		t.Fatalf("account-level name-only entry: Codex row = %#v, want not protected", row)
	}
	// Benign twins: a name-only entry for another connector leaves Claude Code
	// protected; the caller account name known, the entry of another account
	// is not the caller, and the entry of the caller still is.
	if row, _ := windowsOwnStatusRow(t, unnamed(t, []enterprisehooks.UnprotectedAgent{nameOnly("alice", "codex")}), windowsAliceSID, "claudecode"); row["protected"] != true {
		t.Fatalf("name-only Codex entry: Claude Code row = %#v, want protected", row)
	}
	api := windowsOwnStatusAPI(t, []enterprisehooks.UnprotectedAgent{nameOnly("bob", "claudecode")}, nil)
	if row, _ := windowsOwnStatusRow(t, api, windowsAliceSID, "claudecode"); row["protected"] != true {
		t.Fatalf("another account name-only entry: Claude Code row = %#v, want protected", row)
	}
	if row, _ := windowsOwnStatusRow(t, api, windowsBobSID, "claudecode"); row["protected"] != false {
		t.Fatalf("own name-only entry: Claude Code row = %#v, want not protected", row)
	}
}

// The same rule on Unix: a name-only entry and a caller whose name the
// kernel peer lookup did not give.
func TestOwnStatusNameOnlyEntryOfAnUnnamedUnixCallerIsNotProtected(t *testing.T) {
	entry := enterprisehooks.UnprotectedAgent{User: "alice", Connector: "opencode",
		Code: enterprisehooks.UnprotectedCodeOpenCodeV1, Reason: "V1 copy"}
	api := ownStatusUnprotectedFixture(t, []enterprisehooks.UnprotectedAgent{entry}, nil)
	if row := ownStatusConnectorRow(t, api, "5001", "", "opencode"); row["protected"] != false {
		t.Fatalf("unnamed caller OpenCode row = %#v, want not protected", row)
	}
	// Benign twins: the other connectors of that caller, and the named caller.
	if row := ownStatusConnectorRow(t, api, "5001", "", "codex"); row["protected"] != true {
		t.Fatalf("unnamed caller Codex row = %#v, want protected", row)
	}
	if row := ownStatusConnectorRow(t, api, "5002", "bob", "opencode"); row["protected"] != true {
		t.Fatalf("another named caller OpenCode row = %#v, want protected", row)
	}
}
