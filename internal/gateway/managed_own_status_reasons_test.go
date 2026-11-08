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

func requireOwnRowSaysWhy(t *testing.T, label, connector string, row map[string]any) {
	t.Helper()
	if row["protected"] == true {
		return
	}
	state, _ := row["state"].(string)
	lower := strings.ToLower(state)
	hasNextStep := strings.Contains(lower, "ask it") || strings.Contains(lower, "defenseclaw status") || strings.Contains(lower, "install")
	if !ownReasonedRow.MatchString(state) || !hasNextStep {
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
	strictDeny := func(cfg *config.Config) { cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledDeny }
	rootDeny := func(cfg *config.Config) { cfg.Enterprise.Enrollment.Root = config.EnterpriseRootDeny }
	scenarios := []ownReasonsScenario{
		{name: "hermes has nothing set up for the account", uid: "5001", user: "alice", view: vendorOnly,
			guardian: guardianFor("bob", 5002, "hermes"),
			want:     map[string]string{"hermes": "not protected: " + ownCauseNoSetup, "opencode": "protected"}},
		{name: "no enrollment record", uid: "5001", user: "alice", guardian: nil,
			want: map[string]string{"hermes": "not confirmed: " + ownCauseNoGuardianRecord}},
		{name: "no enrollment record under strict enrollment", uid: "5001", user: "alice", view: proven, configure: strictDeny,
			want: map[string]string{"hermes": "not confirmed: " + ownCauseNoGuardianRecord, "opencode": "not confirmed: " + ownCauseNoGuardianRecord}},
		{name: "scan unknown", uid: "5001", user: "alice", view: proven, scanErr: errors.New("record is not trusted"),
			want: map[string]string{"hermes": "not confirmed: " + ownCauseScanUnknown, "opencode": "not confirmed: " + ownCauseScanUnknown}},
		{name: "scan entry that cannot be matched", uid: "5001", user: "alice", view: proven, scan: []enterprisehooks.UnprotectedAgent{unmatched},
			want: map[string]string{"hermes": "not confirmed: " + ownCauseScanUnmatched}},
		{name: "scan entry with no recorded reason", uid: "5001", user: "alice", view: proven, scan: []enterprisehooks.UnprotectedAgent{noReason},
			want: map[string]string{"opencode": "not protected: " + ownCauseNoUnprotectedReason}},
		{name: "root denied", uid: "0", user: "root", view: proven, configure: rootDeny,
			want: map[string]string{"opencode": "not protected: " + ownCauseRootDenied, "hermes": "not protected: " + ownCauseRootDenied}},
		{name: "shared vendor source unproven", uid: "5001", user: "alice", guardian: guardianFor("alice", 5001, "hermes"),
			view: &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"opencode": {shared: true}}},
			want: map[string]string{"opencode": "not protected: " + ownCauseUnprovenSource, "hermes": "protected"}},
		{name: "managed preferences unreadable", uid: "5001", user: "alice",
			view: &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"opencode": {allAccounts: true}}},
			want: map[string]string{"opencode": "not protected: " + ownCauseUnprovenSource}},
		{name: "own managed preference unproven", uid: "5001", user: "alice",
			view: &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"opencode": {accounts: map[string]bool{"alice": true}}}},
			want: map[string]string{"opencode": "not protected: " + ownCauseUnprovenSource}},
		{name: "strict enrollment, account not enrolled", uid: "5001", user: "alice", view: proven, configure: strictDeny,
			guardian: guardianFor("bob", 5002, "hermes"),
			want:     map[string]string{"opencode": "not protected: " + ownCauseNotEnrolled}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			api := ownReasonsAPI(t, sc)
			roster, ok := api.ownStatusAnswer(context.Background(), "uid", sc.uid, sc.user)["connectors"].(map[string]any)
			if !ok || len(roster) == 0 {
				t.Fatalf("no roster: %#v", roster)
			}
			for connector, value := range roster {
				row := value.(map[string]any)
				requireOwnRowSaysWhy(t, sc.name, connector, row)
				if want, named := sc.want[connector]; named && row["state"] != want {
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
// "protected" row and the scan keeps its own recorded reason and fix.
func TestOwnStatusProtectedRowsAndRecordedReasonsAreUnchanged(t *testing.T) {
	proven := &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"claudecode": {}, "opencode": {}}}
	api := ownReasonsAPI(t, ownReasonsScenario{view: proven, guardian: guardianFor("alice", 5001, "hermes")})
	for connector, want := range map[string]string{"claudecode": "protected", "opencode": "protected", "hermes": "protected"} {
		if row := ownStatusConnectorRow(t, api, "5001", "alice", connector); row["protected"] != true || row["state"] != want {
			t.Fatalf("%s row = %#v, want %q", connector, row, want)
		}
	}
	v1 := unprotectedAgentFor("alice", 5001, "opencode", enterprisehooks.UnprotectedCodeOpenCodeV1, "it is OpenCode V1. Fix: npm install -g @opencode/cli@2")
	api = ownReasonsAPI(t, ownReasonsScenario{view: proven, guardian: guardianFor("alice", 5001, "hermes"), scan: []enterprisehooks.UnprotectedAgent{v1}})
	if row := ownStatusConnectorRow(t, api, "5001", "alice", "opencode"); row["state"] != "not protected: it is OpenCode V1. Fix: npm install -g @opencode/cli@2" {
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
