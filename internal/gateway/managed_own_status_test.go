// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// cowork-1-0-8 GAP-0053: a standard user of a managed computer reads their
// own Claude Code and Cowork protection state on the hook socket. The answer
// is the kernel-verified caller's: another account's last Cowork event, the
// administrator's profiles and paths are never in it.
func TestOwnStatusAnswersOnlyTheCaller(t *testing.T) {
	completeOwnStatusScan(t, nil)
	previous := ownStatusCoworkEvents
	t.Cleanup(func() { ownStatusCoworkEvents = previous })
	mine := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	var readPath string
	ownStatusCoworkEvents = func(_ context.Context, path string) ([]enterprisestatus.CoworkAccountEvent, bool, error) {
		readPath = path
		return []enterprisestatus.CoworkAccountEvent{
			{UserID: "5002", UserName: "bob", At: mine.Add(time.Hour)},
			{UserID: "5001", UserName: "alice", At: mine},
			{UserName: "carol", At: mine.Add(2 * time.Hour)},
		}, false, nil
	}
	status := func(api *APIServer, peer *managedHookPeer) (int, string, map[string]any) {
		req := httptest.NewRequest(http.MethodGet, managed.OwnStatusPath, nil)
		if peer != nil {
			req = req.WithContext(withManagedHookPeer(req.Context(), *peer))
		}
		rec := httptest.NewRecorder()
		api.handleOwnStatus(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, rec.Body.String(), out
	}
	cfg := &config.Config{AuditDB: "/var/lib/defenseclaw/audit.db"}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"secret-admin-profile": {Mode: "observe"}}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	api.managedPolicyView.Store(&managedPolicyView{connectors: map[string]managedPolicyViewConnector{"claudecode": {}}})
	alice := &managedHookPeer{UID: 5001, Name: "alice"}
	code, body, out := status(api, alice)
	cowork, _ := out["cowork"].(map[string]any)
	claude, _ := out["claude_code"].(map[string]any)
	if code != http.StatusOK || out["own"] != true || out["managed_by"] != "your organization" ||
		cowork["protected"] != true || claude["protected"] != true || cowork["last_event_at"] != mine.Format(time.RFC3339) {
		t.Fatalf("own status = %d %s; want alice's protected state and her own last Cowork event", code, body)
	}
	if readPath != cfg.AuditDB {
		t.Fatalf("read the audit store at %q, want %q", readPath, cfg.AuditDB)
	}
	for _, leak := range []string{"bob", "5002", "carol", "secret-admin-profile", "audit.db", "profiles", "enrolled"} {
		if strings.Contains(body, leak) {
			t.Fatalf("own status names %q: %s", leak, body)
		}
	}
	// An account with no Cowork event of its own gets none, not another
	// account's; a row without a user id counts only for its own name.
	if _, body, out := status(api, &managedHookPeer{UID: 5003, Name: "carol"}); !strings.Contains(body, mine.Add(2*time.Hour).Format(time.RFC3339)) {
		t.Fatalf("carol's own name-only row is missing: %s", body)
	} else if out["cowork"].(map[string]any)["protected"] != true {
		t.Fatalf("carol = %s", body)
	}
	if _, body, _ := status(api, &managedHookPeer{UID: 5004, Name: "dave"}); strings.Contains(body, "last_event_at") {
		t.Fatalf("dave sees someone else's Cowork event: %s", body)
	}
	if code, _, _ := status(api, nil); code != http.StatusForbidden {
		t.Fatalf("own status without a verified peer = %d; want 403", code)
	}

	off := &config.Config{}
	off.Guardrail.Mode = "action"
	off.Guardrail.Connector = "codex"
	_, body, out = status(NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, off), alice)
	if out["cowork"].(map[string]any)["protected"] != false || out["claude_code"].(map[string]any)["protected"] != false {
		t.Fatalf("own status without the Claude Code connector = %s; want not protected", body)
	}
}

func TestManagedOwnStatusReportsConfiguredConnectorProof(t *testing.T) {
	completeOwnStatusScan(t, nil)
	previousGuardian := ownStatusGuardianAuthorization
	ownStatusGuardianAuthorization = func(string) (*managedGuardianAuthorization, string) { return nil, "unavailable" }
	t.Cleanup(func() { ownStatusGuardianAuthorization = previousGuardian })
	enabled := true
	disabled := false
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {Enabled: &enabled},
		"codex":      {Enabled: &enabled},
		"opencode":   {Enabled: &enabled},
		"hermes":     {Enabled: &enabled},
		"copilot":    {Enabled: &disabled},
	}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	api.managedPolicyView.Store(&managedPolicyView{connectors: map[string]managedPolicyViewConnector{
		"claudecode": {}, "codex": {}, "opencode": {},
	}})
	read := func(uid, name string) map[string]any {
		t.Helper()
		return api.ownStatusAnswer(context.Background(), "uid", uid, name, "")
	}
	connectors, ok := read("5001", "alice")["connectors"].(map[string]any)
	if !ok || len(connectors) != 4 {
		t.Fatalf("own connector roster = %#v, want four enabled connectors", connectors)
	}
	for _, name := range []string{"claudecode", "codex", "opencode"} {
		row, ok := connectors[name].(map[string]any)
		if !ok || row["protected"] != true {
			t.Fatalf("%s = %#v, want protected", name, connectors[name])
		}
	}
	if _, listed := connectors["copilot"]; listed {
		t.Fatal("disabled connector was listed as enrolled")
	}
	if row, ok := connectors["hermes"].(map[string]any); !ok || row["protected"] != false || ownRowText(row) != "not confirmed: "+ownCauseNoGuardianRecord.text() {
		t.Fatalf("per-user connector without guardian proof = %#v", connectors["hermes"])
	}
	api.managedPolicyView.Store(&managedPolicyView{
		connectors: map[string]managedPolicyViewConnector{"claudecode": {}, "codex": {}, "opencode": {}},
		admitted:   map[string]bool{"claudecode": true, "opencode": true},
	})
	connectors = read("5001", "alice")["connectors"].(map[string]any)
	if connectors["codex"].(map[string]any)["protected"] != false {
		t.Fatalf("unadmitted connector was reported protected: %#v", connectors)
	}

	// A changed shared source or a caller-specific preference is never
	// reported protected. Another account's preference does not affect mine.
	api.managedPolicyView.Store(&managedPolicyView{connectors: map[string]managedPolicyViewConnector{
		"claudecode": {},
		"codex":      {shared: true},
		"opencode":   {accounts: map[string]bool{"bob": true}},
	}})
	connectors = read("5001", "alice")["connectors"].(map[string]any)
	if connectors["codex"].(map[string]any)["protected"] != false ||
		connectors["opencode"].(map[string]any)["protected"] != true {
		t.Fatalf("alice's connector proof = %#v", connectors)
	}
	connectors = read("5002", "bob")["connectors"].(map[string]any)
	if connectors["opencode"].(map[string]any)["protected"] != false {
		t.Fatalf("bob's connector proof = %#v", connectors)
	}

	// Per-user connectors use the guardian's current account target. Strict
	// machine policy also requires the same caller's enrollment; a different
	// account's target cannot make this caller appear protected. The target
	// carries a SID because the guardian ledger keys Windows rows by SID
	// (managedGuardianTargetKey) and rejects a row without one; the caller is
	// still matched by UID and user name.
	ownStatusGuardianAuthorization = func(string) (*managedGuardianAuthorization, string) {
		return &managedGuardianAuthorization{
			TargetCount: 1, SuccessCount: 1,
			ProtectedTargets: []managedGuardianAuthorizationTarget{{User: "alice", UID: 5001, SID: "S-1-5-21-1-2-3-5001", Connector: "hermes", OK: true}},
		}, ""
	}
	cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledDeny
	connectors = read("5001", "alice")["connectors"].(map[string]any)
	if connectors["hermes"].(map[string]any)["protected"] != true ||
		connectors["claudecode"].(map[string]any)["protected"] != true {
		t.Fatalf("alice's enrolled connector proof = %#v", connectors)
	}
	connectors = read("5002", "bob")["connectors"].(map[string]any)
	if connectors["hermes"].(map[string]any)["protected"] != false ||
		connectors["claudecode"].(map[string]any)["protected"] != false {
		t.Fatalf("bob's unenrolled connector proof = %#v", connectors)
	}
	cfg.Enterprise.Enrollment.ExemptUsers = []string{"bob"}
	connectors = read("5002", "bob")["connectors"].(map[string]any)
	if connectors["claudecode"].(map[string]any)["protected"] != true {
		t.Fatalf("enrollment exemption still inspects Bob's machine-policy hooks: %#v", connectors)
	}
}

func TestManagedOwnStatusIncludesStandaloneConnectorSources(t *testing.T) {
	completeOwnStatusScan(t, nil)
	previousGuardian := ownStatusGuardianAuthorization
	ownStatusGuardianAuthorization = func(string) (*managedGuardianAuthorization, string) { return nil, "unavailable" }
	t.Cleanup(func() { ownStatusGuardianAuthorization = previousGuardian })

	for _, tc := range []struct {
		name string
		cfg  *config.Config
		want []string
	}{
		{
			name: "singular beside plural",
			cfg: &config.Config{Guardrail: config.GuardrailConfig{
				Mode: "action", Connector: "claudecode",
				Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {}},
			}},
			want: []string{"claudecode", "codex"},
		},
		{
			name: "machine policy only",
			cfg: &config.Config{Enterprise: config.EnterpriseConfig{
				MachinePolicy: config.EnterpriseMachinePolicyConfig{
					Connectors: map[string]config.EnterpriseConnectorPolicy{"codex": {}},
				},
			}},
			want: []string{"codex"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, tc.cfg)
			api.managedPolicyView.Store(&managedPolicyView{connectors: map[string]managedPolicyViewConnector{
				"claudecode": {}, "codex": {},
			}})
			answer := api.ownStatusAnswer(context.Background(), "uid", "5001", "alice", "")
			roster, ok := answer["connectors"].(map[string]any)
			if !ok || len(roster) != len(tc.want) {
				t.Fatalf("roster = %#v, want %v", answer["connectors"], tc.want)
			}
			for _, name := range tc.want {
				row, ok := roster[name].(map[string]any)
				if !ok || row["protected"] != true {
					t.Fatalf("%s = %#v, want confirmed protection", name, roster[name])
				}
			}
		})
	}
}

// cowork-1-0-8 GAP-0060: on a managed Windows computer the gateway answers a
// standard account's own status for the SID its own-status pipe read from
// the client token, with the same rule as the hook socket: that account's
// own state and last Cowork event only. A SID that is not a user account's
// gets no answer.
func TestOwnStatusForWindowsAccountAnswersOnlyThatAccount(t *testing.T) {
	completeOwnStatusScan(t, nil)
	previousEvents, previousName := ownStatusCoworkEvents, ownStatusWindowsAccount
	t.Cleanup(func() { ownStatusCoworkEvents, ownStatusWindowsAccount = previousEvents, previousName })
	const alice, bob = "S-1-5-21-1004336348-1177238915-682003330-1001", "S-1-5-21-1004336348-1177238915-682003330-1002"
	mine := time.Date(2026, 11, 4, 13, 0, 0, 0, time.UTC)
	ownStatusCoworkEvents = func(context.Context, string) ([]enterprisestatus.CoworkAccountEvent, bool, error) {
		return []enterprisestatus.CoworkAccountEvent{
			{UserID: bob, UserName: `WIN11\bob`, At: mine.Add(time.Hour)},
			// The row's SID in another case is still alice's.
			{UserID: strings.ToLower(alice), UserName: `WIN11\alice`, At: mine},
		}, false, nil
	}
	ownStatusWindowsAccount = func(sid string) (string, string) {
		if sid == alice {
			return `WIN11\alice`, ""
		}
		return "", ""
	}
	cfg := &config.Config{AuditDB: `C:\ProgramData\Cisco\DefenseClaw\audit.db`}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"secret-admin-profile": {Mode: "observe"}}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)

	body := api.ownStatusForWindowsAccount(context.Background(), alice)
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("answer %q: %v", body, err)
	}
	account, _ := out["account"].(map[string]any)
	cowork, _ := out["cowork"].(map[string]any)
	if out["own"] != true || account["sid"] != alice || account["name"] != `WIN11\alice` || account["uid"] != nil ||
		cowork["protected"] != true || cowork["last_event_at"] != mine.Format(time.RFC3339) {
		t.Fatalf("own status for alice = %s", body)
	}
	for _, leak := range []string{"bob", "1002", "secret-admin-profile", "audit.db", "ProgramData", "profiles"} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("own status names %q: %s", leak, body)
		}
	}
	// An account with no Cowork event of its own sees none of bob's.
	const carol = "S-1-12-1-3541625939-1147367106-2371843228-3893412310"
	if body := api.ownStatusForWindowsAccount(context.Background(), carol); !strings.Contains(string(body), carol) || strings.Contains(string(body), "last_event_at") {
		t.Fatalf("own status for carol = %s", body)
	}
	// SYSTEM, a service SID or a well-known group is not an account the
	// answer is for.
	for _, sid := range []string{"S-1-5-18", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", "S-1-1-0", ""} {
		if body := api.ownStatusForWindowsAccount(context.Background(), sid); body != nil {
			t.Fatalf("own status for %q = %s; want no answer", sid, body)
		}
	}
}

// GAP-0635: the Windows own-status pipe carries the same configured roster
// as the Unix answer while retaining its existing Claude Code and Cowork
// status. A connector without per-user proof stays unconfirmed.
func TestOwnStatusForWindowsAccountListsConfiguredConnectors(t *testing.T) {
	completeOwnStatusScan(t, nil)
	previousName := ownStatusWindowsAccount
	ownStatusWindowsAccount = func(string) (string, string) { return `WIN11\alice`, "" }
	t.Cleanup(func() { ownStatusWindowsAccount = previousName })
	enabled, disabled := true, false
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex": {Enabled: &enabled}, "opencode": {Enabled: &enabled},
		"copilot": {Enabled: &disabled},
	}
	cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{
		"hermes": {},
	}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	const alice = "S-1-5-21-1004336348-1177238915-682003330-1001"
	var out struct {
		ClaudeCode struct {
			Protected bool `json:"protected"`
		} `json:"claude_code"`
		Cowork struct {
			Protected bool `json:"protected"`
		} `json:"cowork"`
		Connectors map[string]struct {
			Protected bool   `json:"protected"`
			State     string `json:"state"`
			Reason    string `json:"reason"`
			NextStep  string `json:"next_step"`
		} `json:"connectors"`
	}
	if err := json.Unmarshal(api.ownStatusForWindowsAccount(context.Background(), alice), &out); err != nil {
		t.Fatal(err)
	}
	if !out.ClaudeCode.Protected || !out.Cowork.Protected {
		t.Fatalf("existing Claude Code and Cowork state changed: %+v", out)
	}
	if len(out.Connectors) != 4 {
		t.Fatalf("Windows connector roster = %+v; want four configured entries", out.Connectors)
	}
	if row := out.Connectors["claudecode"]; !row.Protected || row.State != "protected" {
		t.Fatalf("Claude Code row = %+v; want existing protected state", row)
	}
	for _, name := range []string{"codex", "opencode", "hermes"} {
		if row := out.Connectors[name]; row.Protected || row.State != "not confirmed" || row.Reason != ownCauseWindowsUnchecked.reason || row.NextStep != ownCauseWindowsUnchecked.next {
			t.Fatalf("%s row = %+v; want unconfirmed", name, row)
		}
	}
	if _, listed := out.Connectors["copilot"]; listed {
		t.Fatal("disabled connector was listed")
	}
}
