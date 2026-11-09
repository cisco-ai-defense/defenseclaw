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
)

// An excluded account is out of enrollment, but a machine policy runs the hook
// for every local account, so its own status must say what the hook really does
// with the calls: inspects them (unenrolled_users: inspect), refuses them
// (deny), or nothing runs. The state stays excluded; only the reason moves.

const (
	inspectedReason  = "excluded from enrollment; the machine policy still inspects your calls (unenrolled_users: inspect)"
	exemptReason     = "the machine policy still inspects your calls (enterprise.enrollment.exempt_users names your account)"
	ledgerReason     = "the guardian still lists an enrollment for your account, so the gateway inspects your calls"
	refusedReason    = "the gateway refuses the calls its hook sends for your account (unenrolled_users: deny)"
	unverifiedReason = "DefenseClaw cannot verify the vendor policy that runs the hook for your account"
	admittedReason   = "the gateway admits the calls of your account, but DefenseClaw cannot verify that a hook still sends them"
	nothingReason    = "excluded from enrollment; nothing inspects your calls"
)

func ownExcludedRowsOf(t *testing.T, api *APIServer, idKey, id, name string) (map[string]map[string]any, map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(api.ownStatusAnswer(context.Background(), idKey, id, name, ""))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Connectors map[string]map[string]any `json:"connectors"`
		Cowork     map[string]any            `json:"cowork"`
	}
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatal(err)
	}
	return out.Connectors, out.Cowork
}

func requireExcludedReason(t *testing.T, label string, row map[string]any, wantCode, wantText string) {
	t.Helper()
	reason, _ := row["reason"].(string)
	if row["state"] != "excluded" || row["protected"] != false || row["reason_code"] != wantCode || !strings.Contains(reason, wantText) {
		t.Fatalf("%s row = %#v, want state excluded, not protected, code %s, reason containing %q", label, row, wantCode, wantText)
	}
	if !strings.Contains(reason, "enterprise.enrollment.exclude_users") {
		t.Fatalf("%s reason %q does not name enterprise.enrollment.exclude_users", label, reason)
	}
}

func carolTarget(connector string, ok bool) managedHookLedgerTarget {
	uid := 5003
	return managedHookLedgerTarget{User: "carol", UID: &uid, Connector: connector, OK: ok}
}

func TestOwnStatusExcludedReasonFollowsTheMachinePolicyHook(t *testing.T) {
	proven := func() *managedPolicyView {
		return &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"claudecode": {}, "copilot": {}, "opencode": {}}}
	}
	provenWith := func(state map[string]managedPolicyViewConnector) func() *managedPolicyView {
		return func() *managedPolicyView {
			view := proven()
			for name, connectorState := range state {
				view.connectors[name] = connectorState
			}
			return view
		}
	}
	deny := func(cfg *config.Config) { cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledDeny }
	exempt := func(cfg *config.Config) { cfg.Enterprise.Enrollment.ExemptUsers = []string{"carol"} }
	both := func(configure ...func(*config.Config)) func(*config.Config) {
		return func(cfg *config.Config) {
			for _, apply := range configure {
				apply(cfg)
			}
		}
	}
	all := func(code, text string) map[string][2]string {
		return map[string][2]string{"claudecode": {code, text}, "copilot": {code, text}, "opencode": {code, text}}
	}
	for _, tc := range []struct {
		name      string
		configure func(*config.Config)
		machine   []string                  // connectors the authorizer admitted; nil = all three
		noMachine bool                      // the authorizer admitted none
		view      func() *managedPolicyView // nil = every connector proven
		noView    bool                      // no policy view published
		ledger    []managedHookLedgerTarget
		ledgerErr bool
		want      map[string][2]string // connector -> code, reason text
		cowork    [2]string
	}{
		{name: "inspect by default", want: all("excluded_users_inspected", inspectedReason),
			cowork: [2]string{"excluded_users_inspected", inspectedReason}},
		{name: "inspect written out", configure: func(cfg *config.Config) {
			cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledInspect
		}, want: all("excluded_users_inspected", inspectedReason), cowork: [2]string{"excluded_users_inspected", inspectedReason}},
		{name: "deny refuses", configure: deny, want: all("excluded_users_refused", refusedReason),
			cowork: [2]string{"excluded_users_refused", refusedReason}},
		{name: "deny with exempt_users still inspects", configure: both(deny, exempt), want: all("excluded_users_inspected", exemptReason),
			cowork: [2]string{"excluded_users_inspected", exemptReason}},
		{name: "deny with a ledger target the account still holds", configure: deny, ledger: []managedHookLedgerTarget{carolTarget("claudecode", true)},
			want: all("excluded_users_inspected", ledgerReason), cowork: [2]string{"excluded_users_inspected", ledgerReason}},
		{name: "deny with a ledger target for another connector", configure: deny, ledger: []managedHookLedgerTarget{carolTarget("copilot", true)},
			want: all("excluded_users_inspected", ledgerReason), cowork: [2]string{"excluded_users_inspected", ledgerReason}},
		{name: "deny with a ledger target that is not ok", configure: deny, ledger: []managedHookLedgerTarget{carolTarget("claudecode", false)},
			want: all("excluded_users_refused", refusedReason), cowork: [2]string{"excluded_users_refused", refusedReason}},
		{name: "deny with another account on the ledger", configure: deny,
			ledger: []managedHookLedgerTarget{{User: "dave", Connector: "claudecode", OK: true}},
			want:   all("excluded_users_refused", refusedReason), cowork: [2]string{"excluded_users_refused", refusedReason}},
		{name: "deny with the ledger unreadable claims nothing", configure: deny, ledgerErr: true,
			want: all("excluded_users", "excluded from enrollment"), cowork: [2]string{"excluded_users", "excluded from enrollment"}},
		{name: "connector the authorizer did not admit", machine: []string{"claudecode"},
			want:   map[string][2]string{"claudecode": {"excluded_users_inspected", inspectedReason}, "copilot": {"excluded_users", nothingReason}, "opencode": {"excluded_users", nothingReason}},
			cowork: [2]string{"excluded_users_inspected", inspectedReason}},
		{name: "admitted connector missing from the view is unverified", view: func() *managedPolicyView {
			return &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"claudecode": {}}}
		}, want: map[string][2]string{"claudecode": {"excluded_users_inspected", inspectedReason}, "copilot": {"excluded_users_unverified", unverifiedReason}, "opencode": {"excluded_users_unverified", unverifiedReason}},
			cowork: [2]string{"excluded_users_inspected", inspectedReason}},
		{name: "no policy view while the authorizer keeps its admission", noView: true,
			want: all("excluded_users_unverified", unverifiedReason), cowork: [2]string{"excluded_users_unverified", unverifiedReason}},
		{name: "no policy view under deny still refuses", noView: true, configure: deny,
			want: all("excluded_users_refused", refusedReason), cowork: [2]string{"excluded_users_refused", refusedReason}},
		{name: "unpinned shared vendor source claims no inspection", view: provenWith(map[string]managedPolicyViewConnector{"claudecode": {shared: true}}),
			want:   map[string][2]string{"claudecode": {"excluded_users_unverified", unverifiedReason}, "copilot": {"excluded_users_inspected", inspectedReason}, "opencode": {"excluded_users_inspected", inspectedReason}},
			cowork: [2]string{"excluded_users_unverified", unverifiedReason}},
		{name: "unreadable preference folder claims no inspection", view: provenWith(map[string]managedPolicyViewConnector{"opencode": {allAccounts: true}}),
			want:   map[string][2]string{"claudecode": {"excluded_users_inspected", inspectedReason}, "opencode": {"excluded_users_unverified", unverifiedReason}},
			cowork: [2]string{"excluded_users_inspected", inspectedReason}},
		{name: "own preference unproven for this account", view: provenWith(map[string]managedPolicyViewConnector{"claudecode": {accounts: map[string]bool{"carol": true}}}),
			want:   map[string][2]string{"claudecode": {"excluded_users_unverified", unverifiedReason}, "copilot": {"excluded_users_inspected", inspectedReason}},
			cowork: [2]string{"excluded_users_unverified", unverifiedReason}},
		{name: "another account preference unproven leaves this one inspected", view: provenWith(map[string]managedPolicyViewConnector{"claudecode": {accounts: map[string]bool{"dave": true}}}),
			want: all("excluded_users_inspected", inspectedReason), cowork: [2]string{"excluded_users_inspected", inspectedReason}},
		{name: "deny with an unpinned source still refuses", configure: deny, view: provenWith(map[string]managedPolicyViewConnector{"claudecode": {shared: true}}),
			want: all("excluded_users_refused", refusedReason), cowork: [2]string{"excluded_users_refused", refusedReason}},
		{name: "no machine policy", noMachine: true, noView: true, want: all("excluded_users", nothingReason),
			cowork: [2]string{"excluded_users", nothingReason}},
		{name: "no machine policy under deny", noMachine: true, noView: true, configure: deny, want: all("excluded_users", nothingReason),
			cowork: [2]string{"excluded_users", nothingReason}},
		{name: "no machine policy, an old ledger target alone proves no hook", noMachine: true, noView: true,
			ledger: []managedHookLedgerTarget{carolTarget("claudecode", true)},
			want:   map[string][2]string{"claudecode": {"excluded_users_unverified", admittedReason}, "copilot": {"excluded_users", nothingReason}, "opencode": {"excluded_users", nothingReason}},
			cowork: [2]string{"excluded_users_unverified", admittedReason}},
		{name: "no machine policy, an old ledger target and a pinned vendor hook", noMachine: true,
			ledger: []managedHookLedgerTarget{carolTarget("claudecode", true)},
			want:   map[string][2]string{"claudecode": {"excluded_users_inspected", ledgerReason}, "copilot": {"excluded_users", nothingReason}},
			cowork: [2]string{"excluded_users_inspected", ledgerReason}},
		{name: "no machine policy, an old ledger target and an unpinned vendor source", noMachine: true,
			view:   provenWith(map[string]managedPolicyViewConnector{"claudecode": {shared: true}}),
			ledger: []managedHookLedgerTarget{carolTarget("claudecode", true)},
			want:   map[string][2]string{"claudecode": {"excluded_users_unverified", unverifiedReason}},
			cowork: [2]string{"excluded_users_unverified", unverifiedReason}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var configure []func(*config.Config)
			if tc.configure != nil {
				configure = append(configure, tc.configure)
			}
			api := ownStatusExcludedFixture(t, []string{"carol"}, nil, configure...)
			machine := tc.machine
			if machine == nil && !tc.noMachine {
				machine = []string{"claudecode", "copilot", "opencode"}
			}
			ledger, ledgerErr := managedHookLedger{Targets: tc.ledger}, error(nil)
			if tc.ledgerErr {
				ledgerErr = errors.New("ledger unreadable")
			}
			api.managedHookAuthz.Store(newManagedHookAuthorizer(api.runtimeConfigSnapshot().Enterprise.Enrollment, machine,
				func() (managedHookLedger, error) { return ledger, ledgerErr }))
			switch {
			case tc.noView:
				api.managedPolicyView.Store(nil)
			case tc.view != nil:
				api.managedPolicyView.Store(tc.view())
			}
			rows, cowork := ownExcludedRowsOf(t, api, "uid", "5003", "carol")
			if len(rows) != 3 {
				t.Fatalf("roster = %v, want the 3 configured connectors", rows)
			}
			for connector, want := range tc.want {
				requireExcludedReason(t, connector, rows[connector], want[0], want[1])
			}
			requireExcludedReason(t, "cowork", cowork, tc.cowork[0], tc.cowork[1])
		})
	}
}

// The status says inspected exactly when the hook authorizer lets the excluded
// account through, and refused exactly when it refuses it as excluded.
func TestOwnStatusExcludedReasonAgreesWithTheHookAuthorizer(t *testing.T) {
	peer := managedHookPeer{UID: 5003, Name: "carol"}
	for _, unenrolled := range []string{"", config.EnterpriseUnenrolledInspect, config.EnterpriseUnenrolledDeny} {
		for _, exempt := range []bool{false, true} {
			for _, listed := range []bool{false, true} {
				name := "unenrolled=" + unenrolled
				if exempt {
					name += ",exempt"
				}
				if listed {
					name += ",ledger"
				}
				t.Run(name, func(t *testing.T) {
					api := ownStatusExcludedFixture(t, []string{"carol"}, nil, func(cfg *config.Config) {
						cfg.Enterprise.Enrollment.UnenrolledUsers = unenrolled
						if exempt {
							cfg.Enterprise.Enrollment.ExemptUsers = []string{"carol"}
						}
					})
					ledger := managedHookLedger{}
					if listed {
						ledger.Targets = []managedHookLedgerTarget{carolTarget("copilot", true)}
					}
					authorizer := newManagedHookAuthorizer(api.runtimeConfigSnapshot().Enterprise.Enrollment, []string{"claudecode", "copilot", "opencode"},
						func() (managedHookLedger, error) { return ledger, nil })
					api.managedHookAuthz.Store(authorizer)
					decision := authorizer.decide(peer, "claudecode", "")
					rows, _ := ownExcludedRowsOf(t, api, "uid", "5003", "carol")
					want := "excluded_users_inspected"
					if !decision.Allow {
						want = "excluded_users_refused"
						if !decision.Excluded {
							t.Fatalf("authorizer decision = %+v, want an excluded refusal", decision)
						}
					}
					if got := rows["claudecode"]["reason_code"]; got != want {
						t.Fatalf("claudecode row = %#v, want code %s for decision %+v", rows["claudecode"], want, decision)
					}
				})
			}
		}
	}
}

// The Windows pipe has no policy view, so an excluded Windows account is told
// it is excluded and nothing more: no claim that the calls are inspected, none
// that nothing inspects them.
func TestOwnStatusWindowsExcludedReasonClaimsNothingAboutInspection(t *testing.T) {
	const alice = "S-1-5-21-1004336348-1177238915-682003330-1001"
	api := ownStatusExcludedFixture(t, []string{"alice"}, nil)
	rows, cowork := ownExcludedRowsOf(t, api, "sid", alice, `WIN11\alice`)
	for name, row := range rows {
		requireExcludedReason(t, name, row, "excluded_users", "excluded from enrollment")
		if reason, _ := row["reason"].(string); strings.Contains(reason, "inspect") || strings.Contains(reason, "refuses") {
			t.Fatalf("%s reason %q claims something about inspection", name, reason)
		}
	}
	requireExcludedReason(t, "cowork", cowork, "excluded_users", "excluded from enrollment")
}

// exempt_users admits the account whatever the machine admission is, so with
// a pinned vendor hook and no machine admission the call still arrives and is
// served; without the pinned source nothing proves a hook sends it, and
// nothing proves none does.
func TestOwnStatusExcludedExemptCallerWithoutMachineAdmission(t *testing.T) {
	for _, tc := range []struct {
		name     string
		view     *managedPolicyView
		wantCode string
		wantText string
	}{
		{name: "pinned vendor hook", view: &managedPolicyView{
			connectors: map[string]managedPolicyViewConnector{"claudecode": {}}, admitted: map[string]bool{}},
			wantCode: "excluded_users_inspected", wantText: exemptReason},
		{name: "unpinned vendor source", view: &managedPolicyView{
			connectors: map[string]managedPolicyViewConnector{"claudecode": {shared: true}}},
			wantCode: "excluded_users_unverified", wantText: unverifiedReason},
		{name: "no policy view", wantCode: "excluded_users_unverified", wantText: admittedReason},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := ownStatusExcludedFixture(t, []string{"carol"}, nil, func(cfg *config.Config) {
				cfg.Enterprise.Enrollment.ExemptUsers = []string{"carol"}
			})
			api.managedPolicyView.Store(tc.view)
			authorizer := newManagedHookAuthorizer(api.runtimeConfigSnapshot().Enterprise.Enrollment, nil,
				func() (managedHookLedger, error) { return managedHookLedger{}, nil })
			api.managedHookAuthz.Store(authorizer)
			if decision := authorizer.decide(managedHookPeer{UID: 5003, Name: "carol"}, "claudecode", ""); !decision.Allow || !decision.Exempt {
				t.Fatalf("authorizer decision = %+v, want an exempt allow", decision)
			}
			rows, _ := ownExcludedRowsOf(t, api, "uid", "5003", "carol")
			requireExcludedReason(t, "claudecode", rows["claudecode"], tc.wantCode, tc.wantText)
		})
	}
}
