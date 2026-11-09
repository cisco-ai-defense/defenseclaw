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
// for every local account. Its own status claims only what it can prove: the
// machine policy still inspects the calls when a pinned machine-policy hook is
// proven for the account (whatever verdict the hook authorizer returns,
// refusing included), DefenseClaw does not inspect them when no machine-policy
// hook covers the account, and otherwise the row sends the reader to the
// administrator status. The state stays excluded; only the reason moves.

const (
	inspectedReason = "excluded from enrollment; the machine policy still inspects your calls"
	nothingReason   = "excluded from enrollment; DefenseClaw does not inspect your calls"
	unknownReason   = "excluded from enrollment; run defenseclaw-managed status as an administrator to see what still inspects calls"

	inspectedCode = "excluded_users_inspected"
	nothingCode   = "excluded_users"
	unknownCode   = "excluded_users_unverified"
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
	one := func(connector, code, text string) map[string][2]string {
		return map[string][2]string{connector: {code, text}}
	}
	for _, tc := range []struct {
		name       string
		configure  func(*config.Config)
		machine    []string                  // connectors the authorizer admitted; nil = all three
		noMachine  bool                      // the authorizer admitted none
		view       func() *managedPolicyView // nil = every connector proven
		noView     bool                      // no policy view published
		vendorHook bool                      // the vendor files hold a machine-policy hook
		ledger     []managedHookLedgerTarget
		ledgerErr  bool
		want       map[string][2]string // connector -> code, reason text
		cowork     [2]string
	}{
		{name: "inspect by default", want: all(inspectedCode, inspectedReason), cowork: [2]string{inspectedCode, inspectedReason}},
		{name: "inspect written out", configure: func(cfg *config.Config) {
			cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledInspect
		}, want: all(inspectedCode, inspectedReason), cowork: [2]string{inspectedCode, inspectedReason}},
		{name: "a refusing pinned hook is still the machine policy", configure: deny, want: all(inspectedCode, inspectedReason),
			cowork: [2]string{inspectedCode, inspectedReason}},
		{name: "deny with exempt_users", configure: both(deny, exempt), want: all(inspectedCode, inspectedReason),
			cowork: [2]string{inspectedCode, inspectedReason}},
		{name: "deny with a ledger target the account still holds", configure: deny, ledger: []managedHookLedgerTarget{carolTarget("claudecode", true)},
			want: all(inspectedCode, inspectedReason), cowork: [2]string{inspectedCode, inspectedReason}},
		{name: "deny with a ledger target for another connector", configure: deny, ledger: []managedHookLedgerTarget{carolTarget("copilot", true)},
			want: all(inspectedCode, inspectedReason), cowork: [2]string{inspectedCode, inspectedReason}},
		{name: "deny with a ledger target that is not ok", configure: deny, ledger: []managedHookLedgerTarget{carolTarget("claudecode", false)},
			want: all(inspectedCode, inspectedReason), cowork: [2]string{inspectedCode, inspectedReason}},
		{name: "deny with another account on the ledger", configure: deny,
			ledger: []managedHookLedgerTarget{{User: "dave", Connector: "claudecode", OK: true}},
			want:   all(inspectedCode, inspectedReason), cowork: [2]string{inspectedCode, inspectedReason}},
		{name: "deny with the ledger unreadable and a pinned hook", configure: deny, ledgerErr: true,
			want: all(inspectedCode, inspectedReason), cowork: [2]string{inspectedCode, inspectedReason}},
		{name: "ledger unreadable and no policy view claims nothing", noView: true, noMachine: true, ledgerErr: true,
			want: all(unknownCode, unknownReason), cowork: [2]string{unknownCode, unknownReason}},
		{name: "connector the authorizer did not admit, hook pinned", machine: []string{"claudecode"},
			want: all(inspectedCode, inspectedReason), cowork: [2]string{inspectedCode, inspectedReason}},
		{name: "connector the authorizer did not admit, no view", machine: []string{"claudecode"}, noView: true,
			want:   map[string][2]string{"claudecode": {unknownCode, unknownReason}, "copilot": {nothingCode, nothingReason}, "opencode": {nothingCode, nothingReason}},
			cowork: [2]string{unknownCode, unknownReason}},
		{name: "admitted connector missing from the view is unknown", view: func() *managedPolicyView {
			return &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"claudecode": {}}}
		}, want: map[string][2]string{"claudecode": {inspectedCode, inspectedReason}, "copilot": {unknownCode, unknownReason}, "opencode": {unknownCode, unknownReason}},
			cowork: [2]string{inspectedCode, inspectedReason}},
		{name: "no policy view while the authorizer keeps its admission", noView: true,
			want: all(unknownCode, unknownReason), cowork: [2]string{unknownCode, unknownReason}},
		{name: "no policy view under deny", noView: true, configure: deny,
			want: all(unknownCode, unknownReason), cowork: [2]string{unknownCode, unknownReason}},
		{name: "unpinned shared vendor source claims no inspection", view: provenWith(map[string]managedPolicyViewConnector{"claudecode": {shared: true}}),
			want:   map[string][2]string{"claudecode": {unknownCode, unknownReason}, "copilot": {inspectedCode, inspectedReason}, "opencode": {inspectedCode, inspectedReason}},
			cowork: [2]string{unknownCode, unknownReason}},
		{name: "unreadable preference folder claims no inspection", view: provenWith(map[string]managedPolicyViewConnector{"opencode": {allAccounts: true}}),
			want:   map[string][2]string{"claudecode": {inspectedCode, inspectedReason}, "opencode": {unknownCode, unknownReason}},
			cowork: [2]string{inspectedCode, inspectedReason}},
		{name: "own preference unproven for this account", view: provenWith(map[string]managedPolicyViewConnector{"claudecode": {accounts: map[string]bool{"carol": true}}}),
			want:   map[string][2]string{"claudecode": {unknownCode, unknownReason}, "copilot": {inspectedCode, inspectedReason}},
			cowork: [2]string{unknownCode, unknownReason}},
		{name: "another account preference unproven leaves this one inspected", view: provenWith(map[string]managedPolicyViewConnector{"claudecode": {accounts: map[string]bool{"dave": true}}}),
			want: all(inspectedCode, inspectedReason), cowork: [2]string{inspectedCode, inspectedReason}},
		{name: "deny with an unpinned source", configure: deny, view: provenWith(map[string]managedPolicyViewConnector{"claudecode": {shared: true}}),
			want: one("claudecode", unknownCode, unknownReason), cowork: [2]string{unknownCode, unknownReason}},
		{name: "no machine admission, hook pinned, nothing exempts the account", noMachine: true,
			want: all(inspectedCode, inspectedReason), cowork: [2]string{inspectedCode, inspectedReason}},
		{name: "no machine admission, hook pinned, deny and nothing exempts the account", noMachine: true, configure: deny,
			want: all(inspectedCode, inspectedReason), cowork: [2]string{inspectedCode, inspectedReason}},
		{name: "no machine policy", noMachine: true, noView: true, want: all(nothingCode, nothingReason),
			cowork: [2]string{nothingCode, nothingReason}},
		{name: "no machine policy, descriptor lost, vendor hook still installed", noMachine: true, noView: true, vendorHook: true,
			want: all(unknownCode, unknownReason), cowork: [2]string{unknownCode, unknownReason}},
		{name: "no machine policy, descriptor lost, vendor hook still installed, deny", noMachine: true, noView: true, vendorHook: true, configure: deny,
			want: all(unknownCode, unknownReason), cowork: [2]string{unknownCode, unknownReason}},
		{name: "no machine policy under deny", noMachine: true, noView: true, configure: deny, want: all(nothingCode, nothingReason),
			cowork: [2]string{nothingCode, nothingReason}},
		{name: "no machine policy, an old ledger target alone proves no hook", noMachine: true, noView: true,
			ledger: []managedHookLedgerTarget{carolTarget("claudecode", true)},
			want:   map[string][2]string{"claudecode": {unknownCode, unknownReason}, "copilot": {nothingCode, nothingReason}, "opencode": {nothingCode, nothingReason}},
			cowork: [2]string{unknownCode, unknownReason}},
		{name: "no machine policy, an old ledger target and a pinned vendor hook", noMachine: true,
			ledger: []managedHookLedgerTarget{carolTarget("claudecode", true)},
			want:   all(inspectedCode, inspectedReason), cowork: [2]string{inspectedCode, inspectedReason}},
		{name: "no machine policy, an old ledger target and an unpinned vendor source", noMachine: true,
			view:   provenWith(map[string]managedPolicyViewConnector{"claudecode": {shared: true}}),
			ledger: []managedHookLedgerTarget{carolTarget("claudecode", true)},
			want:   one("claudecode", unknownCode, unknownReason),
			cowork: [2]string{unknownCode, unknownReason}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var configure []func(*config.Config)
			if tc.configure != nil {
				configure = append(configure, tc.configure)
			}
			api := ownStatusExcludedFixture(t, []string{"carol"}, nil, configure...)
			savedAbsent := machineHookAbsent
			machineHookAbsent = func(string, *config.Config, string) bool { return !tc.vendorHook }
			t.Cleanup(func() { machineHookAbsent = savedAbsent })
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

// A pinned machine-policy hook is the machine policy whatever the hook
// authorizer answers for the excluded account: the status says inspected when
// the authorizer lets the call through and when it refuses it as excluded.
func TestOwnStatusExcludedReasonDoesNotDependOnTheAuthorizerVerdict(t *testing.T) {
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
					if !decision.Allow && !decision.Excluded {
						t.Fatalf("authorizer decision = %+v, want an allow or an excluded refusal", decision)
					}
					rows, _ := ownExcludedRowsOf(t, api, "uid", "5003", "carol")
					requireExcludedReason(t, "claudecode", rows["claudecode"], inspectedCode, inspectedReason)
				})
			}
		}
	}
}

// The status never matches the per-account proof by a name it does not have:
// a uid that exclude_users names, with the account name lookup failed, gets no
// claim either way, whatever the proof of an account of any name says.
func TestOwnStatusExcludedAccountNameUnresolvedClaimsNothing(t *testing.T) {
	proofOf := func(carolUnproven bool) *managedPolicyView {
		return &managedPolicyView{connectors: map[string]managedPolicyViewConnector{
			"claudecode": {accounts: map[string]bool{"carol": carolUnproven}},
			"copilot":    {},
			"opencode":   {},
		}}
	}
	for _, tc := range []struct {
		name          string
		carolUnproven bool
		account       string
		wantCode      string
		wantText      string
	}{
		{"name known, own preference unproven", true, "carol", unknownCode, unknownReason},
		{"name known, own preference pinned", false, "carol", inspectedCode, inspectedReason},
		{"name lookup failed, another account preference unproven", true, "", unknownCode, unknownReason},
		{"name lookup failed, every preference pinned", false, "", unknownCode, unknownReason},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := ownStatusExcludedFixture(t, []string{"5003"}, nil)
			api.managedPolicyView.Store(proofOf(tc.carolUnproven))
			rows, cowork := ownExcludedRowsOf(t, api, "uid", "5003", tc.account)
			requireExcludedReason(t, "claudecode", rows["claudecode"], tc.wantCode, tc.wantText)
			requireExcludedReason(t, "cowork", cowork, tc.wantCode, tc.wantText)
			// copilot is pinned for every account, but is judged by the name too.
			copilotCode, copilotText := inspectedCode, inspectedReason
			if tc.account == "" {
				copilotCode, copilotText = unknownCode, unknownReason
			}
			requireExcludedReason(t, "copilot", rows["copilot"], copilotCode, copilotText)
		})
	}
}

// The Windows pipe has no policy view and no authorizer, so an excluded Windows
// account is told it is excluded and where to look, and nothing about whether
// its calls are inspected.
func TestOwnStatusWindowsExcludedReasonClaimsNothingAboutInspection(t *testing.T) {
	const alice = "S-1-5-21-1004336348-1177238915-682003330-1001"
	api := ownStatusExcludedFixture(t, []string{"alice"}, nil)
	rows, cowork := ownExcludedRowsOf(t, api, "sid", alice, `WIN11\alice`)
	check := func(name string, row map[string]any) {
		requireExcludedReason(t, name, row, unknownCode, unknownReason)
		if reason, _ := row["reason"].(string); strings.Contains(reason, "still inspects your calls") || strings.Contains(reason, "does not inspect your calls") {
			t.Fatalf("%s reason %q claims something about inspection", name, reason)
		}
	}
	for name, row := range rows {
		check(name, row)
	}
	check("cowork", cowork)
}

// exempt_users admits the account whatever the machine admission is. With a
// pinned vendor hook and no machine admission the machine policy handles the
// call; without the pinned source nothing proves a hook sends it, and nothing
// proves none does.
func TestOwnStatusExcludedExemptCallerWithoutMachineAdmission(t *testing.T) {
	for _, tc := range []struct {
		name     string
		view     *managedPolicyView
		wantCode string
		wantText string
	}{
		{name: "pinned vendor hook", view: &managedPolicyView{
			connectors: map[string]managedPolicyViewConnector{"claudecode": {}}, admitted: map[string]bool{}},
			wantCode: inspectedCode, wantText: inspectedReason},
		{name: "unpinned vendor source", view: &managedPolicyView{
			connectors: map[string]managedPolicyViewConnector{"claudecode": {shared: true}}},
			wantCode: unknownCode, wantText: unknownReason},
		{name: "no policy view", wantCode: unknownCode, wantText: unknownReason},
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
