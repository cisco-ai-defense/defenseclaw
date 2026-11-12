// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// A row the launcher prints as not protected or not confirmed names the cause
// and the next step: a reason sentence, and either "ask IT" or the command to
// run again.
var ownReasonedRow = regexp.MustCompile(`^not (protected|confirmed): \S.{30,}`)

// text is the sentence the launcher prints after the state.
func (c ownCause) text() string {
	if c.next == "" {
		return c.reason
	}
	return strings.TrimRight(c.reason, ". ") + ". " + c.next
}

// ownRowText is the sentence the launcher prints for a row: the state, then
// the reason and the next step when the row has them.
func ownRowText(row map[string]any) string {
	state, _ := row["state"].(string)
	reason, _ := row["reason"].(string)
	next, _ := row["next_step"].(string)
	if reason == "" {
		return state
	}
	return state + ": " + strings.TrimRight(reason, ". ") + ". " + next
}

// requireOwnRowJSONContract holds a connector row to the contract scripts and
// MDM tools read: through a JSON round trip the state is exactly one of
// protected, not protected or not confirmed, matches the protected flag, and
// the reason code, reason and next step are separate fields present exactly
// when the row is not protected.
func requireOwnRowJSONContract(t *testing.T, label, connector string, row map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Protected  bool   `json:"protected"`
		State      string `json:"state"`
		ReasonCode string `json:"reason_code"`
		Reason     string `json:"reason"`
		NextStep   string `json:"next_step"`
	}
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatal(err)
	}
	if out.State != "protected" && out.State != "not protected" && out.State != "not confirmed" {
		t.Fatalf("%s: %s state = %q, want protected, not protected or not confirmed: %s", label, connector, out.State, encoded)
	}
	if out.Protected != (out.State == "protected") {
		t.Fatalf("%s: %s protected=%v with state %q: %s", label, connector, out.Protected, out.State, encoded)
	}
	hasText := out.ReasonCode != "" && out.Reason != "" && out.NextStep != ""
	if out.Protected && (out.ReasonCode != "" || out.Reason != "" || out.NextStep != "") || !out.Protected && !hasText {
		t.Fatalf("%s: %s reason fields do not match its state: %s", label, connector, encoded)
	}
}

func requireOwnRowSaysWhy(t *testing.T, label, connector string, row map[string]any) {
	t.Helper()
	requireOwnRowJSONContract(t, label, connector, row)
	if row["protected"] == true {
		return
	}
	text := ownRowText(row)
	lower := strings.ToLower(text)
	hasNextStep := strings.Contains(lower, "ask it") || strings.Contains(lower, "defenseclaw status again")
	if !ownReasonedRow.MatchString(text) || !hasNextStep {
		t.Fatalf("%s: %s row %#v says no reason and next step", label, connector, row)
	}
}

type ownReasonsScenario struct {
	name      string
	guardian  *managedGuardianAuthorization
	view      *managedPolicyView
	scan      []enterprisehooks.UnprotectedAgent
	scanErr   error
	configure func(*config.Config)
	uid, user string
	want      map[string]string // connector -> exact state; a connector not named only has to say why
}

func ownReasonsAPI(t *testing.T, sc ownReasonsScenario) *APIServer {
	t.Helper()
	failOwnStatusScan(t, sc.scan, sc.scanErr)
	previous := ownStatusGuardianAuthorization
	ownStatusGuardianAuthorization = func(string) (*managedGuardianAuthorization, string) {
		if sc.guardian == nil {
			return nil, "unavailable"
		}
		return sc.guardian, ""
	}
	t.Cleanup(func() { ownStatusGuardianAuthorization = previous })
	enabled := true
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {Enabled: &enabled}, "hermes": {Enabled: &enabled}, "opencode": {Enabled: &enabled},
	}
	if sc.configure != nil {
		sc.configure(cfg)
	}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	if sc.view != nil {
		api.managedPolicyView.Store(sc.view)
	}
	return api
}

func guardianFor(user string, uid int, connectors ...string) *managedGuardianAuthorization {
	targets := make([]managedGuardianAuthorizationTarget, 0, len(connectors))
	for _, connector := range connectors {
		targets = append(targets, managedGuardianAuthorizationTarget{User: user, UID: uid, SID: "S-1-5-21-1-2-3-5001", Connector: connector, OK: true})
	}
	return &managedGuardianAuthorization{TargetCount: len(targets), SuccessCount: len(targets), ProtectedTargets: targets}
}

// A connector on the account roster that is not protected says why and what to
// do, for every cause the gateway decides on: an agent with nothing set up for
// the account (the reported Hermes row), an unreadable enrollment record, an
// unknown or unmatched scan, a scan entry with no recorded reason, the root
// account, vendor sources that cannot be proven, and strict enrollment.
func TestOwnStatusEveryNotProtectedConnectorRowSaysWhyAndWhatToDo(t *testing.T) {
	proven := &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"claudecode": {}, "opencode": {}, "hermes": {}}}
	// Hermes is a per-user connector: the vendor view proves no policy source for it.
	vendorOnly := &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"claudecode": {}, "opencode": {}}}
	unmatched := enterprisehooks.UnprotectedAgent{User: enterprisehooks.UnprotectedUnknownAccount, Connector: "hermes",
		Code: enterprisehooks.UnprotectedCodeAgentUnprotected, Reason: "running copy has no resolved account"}
	noReason := unprotectedAgentFor("alice", 5001, "opencode", "", "")
	codeOnly := unprotectedAgentFor("alice", 5001, "opencode", enterprisehooks.UnprotectedCodeAgentUnprotected, "")
	// A recorded reason that is only punctuation or space says nothing.
	dotOnly := unprotectedAgentFor("alice", 5001, "opencode", enterprisehooks.UnprotectedCodeAgentUnprotected, ".")
	dotsAndSpace := unprotectedAgentFor("alice", 5001, "opencode", enterprisehooks.UnprotectedCodeAgentUnprotected, " .\t. \n")
	// A reason with a trailing period still shows its words.
	periodEnded := unprotectedAgentFor("alice", 5001, "opencode", enterprisehooks.UnprotectedCodeAgentUnprotected, "the plugin folder is not writable by the agent.")
	// A recorded reason is shown as written: one that starts with a hidden
	// path keeps its leading period.
	hiddenPath := unprotectedAgentFor("alice", 5001, "opencode", enterprisehooks.UnprotectedCodeAgentUnprotected, ".claude/settings.json is not writable by the agent")
	// The enumerator records this reason with no action when version discovery fails.
	scanIncomplete := unprotectedAgentFor("alice", 5001, "opencode", enterprisehooks.UnprotectedCodeInstallScanIncomplete,
		"the account's agent versions and private installs could not be inspected this cycle")
	strictDeny := func(cfg *config.Config) { cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledDeny }
	rootDeny := func(cfg *config.Config) { cfg.Enterprise.Enrollment.Root = config.EnterpriseRootDeny }
	scenarios := []ownReasonsScenario{
		{name: "hermes has nothing set up for the account", uid: "5001", user: "alice", view: vendorOnly,
			guardian: guardianFor("bob", 5002, "hermes"),
			want:     map[string]string{"hermes": "not protected: " + ownCauseNoSetup.text(), "opencode": "protected"}},
		{name: "no enrollment record", uid: "5001", user: "alice", guardian: nil,
			want: map[string]string{"hermes": "not confirmed: " + ownCauseNoGuardianRecord.text()}},
		{name: "no enrollment record under strict enrollment", uid: "5001", user: "alice", view: proven, configure: strictDeny,
			want: map[string]string{"hermes": "not confirmed: " + ownCauseNoGuardianRecord.text(), "opencode": "not confirmed: " + ownCauseNoGuardianRecord.text()}},
		{name: "scan unknown", uid: "5001", user: "alice", view: proven, scanErr: errors.New("record is not trusted"),
			want: map[string]string{"hermes": "not confirmed: " + ownCauseScanUnknown.text(), "opencode": "not confirmed: " + ownCauseScanUnknown.text()}},
		{name: "scan entry that cannot be matched", uid: "5001", user: "alice", view: proven, scan: []enterprisehooks.UnprotectedAgent{unmatched},
			want: map[string]string{"hermes": "not confirmed: " + ownCauseScanUnmatched.text()}},
		{name: "scan entry with no recorded reason", uid: "5001", user: "alice", view: proven, scan: []enterprisehooks.UnprotectedAgent{noReason},
			want: map[string]string{"opencode": "not protected: " + ownCauseNoUnprotectedReason.text()}},
		{name: "scan entry with a code and no recorded reason", uid: "5001", user: "alice", view: proven, scan: []enterprisehooks.UnprotectedAgent{codeOnly},
			want: map[string]string{"opencode": "not protected: " + ownCauseNoUnprotectedReason.text()}},
		{name: "scan entry whose reason is only a period", uid: "5001", user: "alice", view: proven, scan: []enterprisehooks.UnprotectedAgent{dotOnly},
			want: map[string]string{"opencode": "not protected: " + ownCauseNoUnprotectedReason.text()}},
		{name: "scan entry whose reason is only periods and space", uid: "5001", user: "alice", view: proven, scan: []enterprisehooks.UnprotectedAgent{dotsAndSpace},
			want: map[string]string{"opencode": "not protected: " + ownCauseNoUnprotectedReason.text()}},
		{name: "scan entry whose reason ends with a period", uid: "5001", user: "alice", view: proven, scan: []enterprisehooks.UnprotectedAgent{periodEnded},
			want: map[string]string{"opencode": "not protected: the plugin folder is not writable by the agent. " + ownScanNextStep}},
		{name: "scan entry whose reason starts with a hidden path", uid: "5001", user: "alice", view: proven, scan: []enterprisehooks.UnprotectedAgent{hiddenPath},
			want: map[string]string{"opencode": "not protected: .claude/settings.json is not writable by the agent. " + ownScanNextStep}},
		{name: "scan entry whose reason names no action", uid: "5001", user: "alice", view: proven, scan: []enterprisehooks.UnprotectedAgent{scanIncomplete},
			want: map[string]string{"opencode": "not protected: " + scanIncomplete.Reason + ". " + ownScanNextStep}},
		{name: "root denied", uid: "0", user: "root", view: proven, configure: rootDeny,
			want: map[string]string{"opencode": "not protected: " + ownCauseRootDenied.text(), "hermes": "not protected: " + ownCauseRootDenied.text()}},
		{name: "shared vendor source unproven", uid: "5001", user: "alice", guardian: guardianFor("alice", 5001, "hermes"),
			view: &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"opencode": {shared: true}}},
			want: map[string]string{"opencode": "not protected: " + ownCauseUnprovenSource.text(), "hermes": "protected"}},
		{name: "managed preferences unreadable", uid: "5001", user: "alice",
			view: &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"opencode": {allAccounts: true}}},
			want: map[string]string{"opencode": "not protected: " + ownCauseUnprovenSource.text()}},
		{name: "own managed preference unproven", uid: "5001", user: "alice",
			view: &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"opencode": {accounts: map[string]bool{"alice": true}}}},
			want: map[string]string{"opencode": "not protected: " + ownCauseUnprovenSource.text()}},
		{name: "strict enrollment, account not enrolled", uid: "5001", user: "alice", view: proven, configure: strictDeny,
			guardian: guardianFor("bob", 5002, "hermes"),
			want:     map[string]string{"opencode": "not protected: " + ownCauseNotEnrolled.text()}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			api := ownReasonsAPI(t, sc)
			roster, ok := api.ownStatusAnswer(context.Background(), "uid", sc.uid, sc.user, "")["connectors"].(map[string]any)
			if !ok || len(roster) == 0 {
				t.Fatalf("no roster: %#v", roster)
			}
			for connector, value := range roster {
				row := value.(map[string]any)
				requireOwnRowSaysWhy(t, sc.name, connector, row)
				if want, named := sc.want[connector]; named && ownRowText(row) != want {
					t.Fatalf("%s row = %#v, want state %q", connector, row, want)
				}
			}
			for connector := range sc.want {
				if _, listed := roster[connector]; !listed {
					t.Fatalf("no %s row in %#v", connector, roster)
				}
			}
		})
	}
}

// Benign twin: an account that is set up and enrolled keeps the plain
// "protected" row and the scan keeps its own recorded reason and fix, followed by the one next step.
func TestOwnStatusProtectedRowsAndRecordedReasonsAreUnchanged(t *testing.T) {
	proven := &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"claudecode": {}, "opencode": {}}}
	api := ownReasonsAPI(t, ownReasonsScenario{view: proven, guardian: guardianFor("alice", 5001, "hermes")})
	for connector, want := range map[string]string{"claudecode": "protected", "opencode": "protected", "hermes": "protected"} {
		row := ownStatusConnectorRow(t, api, "5001", "alice", connector)
		if row["protected"] != true || ownRowText(row) != want {
			t.Fatalf("%s row = %#v, want %q", connector, row, want)
		}
		requireOwnRowJSONContract(t, "protected twin", connector, row)
	}
	v1 := unprotectedAgentFor("alice", 5001, "opencode", enterprisehooks.UnprotectedCodeOpenCodeV1, "it is OpenCode V1. Fix: npm install -g @opencode/cli@2")
	api = ownReasonsAPI(t, ownReasonsScenario{view: proven, guardian: guardianFor("alice", 5001, "hermes"), scan: []enterprisehooks.UnprotectedAgent{v1}})
	if row := ownStatusConnectorRow(t, api, "5001", "alice", "opencode"); ownRowText(row) != "not protected: it is OpenCode V1. Fix: npm install -g @opencode/cli@2. "+ownScanNextStep {
		t.Fatalf("recorded reason changed: %#v", row)
	}
}

// Windows rows other than Claude Code, and a Windows account whose scan is
// unknown, say why too.
func TestOwnStatusWindowsNotConfirmedRowsSayWhyAndWhatToDo(t *testing.T) {
	for name, scanErr := range map[string]error{"scan known": nil, "scan unknown": errors.New("the unprotected agents record is missing")} {
		t.Run(name, func(t *testing.T) {
			api := windowsOwnStatusAPI(t, nil, scanErr)
			var out map[string]any
			if err := json.Unmarshal(api.ownStatusForWindowsAccount(context.Background(), windowsAliceSID), &out); err != nil {
				t.Fatal(err)
			}
			roster, _ := out["connectors"].(map[string]any)
			if len(roster) == 0 {
				t.Fatalf("no roster in %#v", out)
			}
			for connector, value := range roster {
				requireOwnRowSaysWhy(t, name, connector, value.(map[string]any))
			}
		})
	}
}

// The reason field of a scan row is the recorded text byte for byte: nothing
// at its start is removed, and the closing period stays (the launcher joins
// the next step after it).
func TestOwnUnprotectedStateKeepsRecordedReasonText(t *testing.T) {
	for _, reason := range []string{".claude/settings.json is not writable", "..hidden dir is not writable.", "  indented reason"} {
		agent := unprotectedAgentFor("alice", 5001, "opencode", enterprisehooks.UnprotectedCodeAgentUnprotected, reason)
		row := ownUnprotectedState([]enterprisehooks.UnprotectedAgent{agent})
		if got, _ := row["reason"].(string); got != reason {
			t.Errorf("reason %q was shown as %q", reason, got)
		}
	}
}
