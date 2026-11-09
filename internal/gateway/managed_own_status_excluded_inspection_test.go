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

// An excluded account is out of enrollment, but a machine policy runs the hook
// for every local account, so its own status must say what the hook really does
// with the calls: inspects them (unenrolled_users: inspect), refuses them
// (deny), or nothing runs. The state stays excluded; only the reason moves.

const (
	inspectedReason = "excluded from enrollment; the machine policy still inspects your calls (unenrolled_users: inspect)"
	nothingReason   = "excluded from enrollment; nothing inspects your calls"
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

func TestOwnStatusExcludedReasonFollowsTheMachinePolicyHook(t *testing.T) {
	policyFor := func(admitted ...string) *managedPolicyView {
		view := &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"claudecode": {}, "copilot": {}, "opencode": {}}}
		if admitted != nil {
			view.admitted = map[string]bool{}
			for _, name := range admitted {
				view.admitted[name] = true
			}
		}
		return view
	}
	deny := func(cfg *config.Config) { cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledDeny }
	for _, tc := range []struct {
		name      string
		configure func(*config.Config)
		view      *managedPolicyView
		want      map[string][2]string // connector -> code, reason text
		cowork    [2]string
	}{
		{"inspect by default", nil, policyFor(), map[string][2]string{
			"claudecode": {"excluded_users_inspected", inspectedReason}, "copilot": {"excluded_users_inspected", inspectedReason}, "opencode": {"excluded_users_inspected", inspectedReason},
		}, [2]string{"excluded_users_inspected", inspectedReason}},
		{"inspect written out", func(cfg *config.Config) {
			cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledInspect
		},
			policyFor("claudecode", "copilot", "opencode"), map[string][2]string{
				"claudecode": {"excluded_users_inspected", inspectedReason}, "copilot": {"excluded_users_inspected", inspectedReason},
			}, [2]string{"excluded_users_inspected", inspectedReason}},
		{"deny refuses", deny, policyFor(), map[string][2]string{
			"claudecode": {"excluded_users_refused", "(unenrolled_users: deny)"}, "opencode": {"excluded_users_refused", "refuses your calls"},
		}, [2]string{"excluded_users_refused", "refuses your calls"}},
		{"deny with exempt_users still inspects", func(cfg *config.Config) {
			deny(cfg)
			cfg.Enterprise.Enrollment.ExemptUsers = []string{"carol"}
		}, policyFor(), map[string][2]string{
			"claudecode": {"excluded_users_inspected", inspectedReason},
		}, [2]string{"excluded_users_inspected", inspectedReason}},
		{"connector outside the policy view", nil, &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"claudecode": {}}},
			map[string][2]string{"claudecode": {"excluded_users_inspected", inspectedReason}, "copilot": {"excluded_users", nothingReason}, "opencode": {"excluded_users", nothingReason}},
			[2]string{"excluded_users_inspected", inspectedReason}},
		{"connector the authorizer did not admit", nil, policyFor("claudecode"),
			map[string][2]string{"claudecode": {"excluded_users_inspected", inspectedReason}, "copilot": {"excluded_users", nothingReason}},
			[2]string{"excluded_users_inspected", inspectedReason}},
		{"no machine policy", nil, nil, map[string][2]string{
			"claudecode": {"excluded_users", nothingReason}, "copilot": {"excluded_users", nothingReason}, "opencode": {"excluded_users", nothingReason},
		}, [2]string{"excluded_users", nothingReason}},
		{"no machine policy under deny", deny, nil, map[string][2]string{
			"claudecode": {"excluded_users", nothingReason},
		}, [2]string{"excluded_users", nothingReason}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var configure []func(*config.Config)
			if tc.configure != nil {
				configure = append(configure, tc.configure)
			}
			api := ownStatusExcludedFixture(t, []string{"carol"}, nil, configure...)
			api.managedPolicyView.Store(tc.view)
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
	for _, tc := range []struct {
		name       string
		unenrolled string
		wantCode   string
		wantAllow  bool
	}{
		{"inspect", config.EnterpriseUnenrolledInspect, "excluded_users_inspected", true},
		{"default", "", "excluded_users_inspected", true},
		{"deny", config.EnterpriseUnenrolledDeny, "excluded_users_refused", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := ownStatusExcludedFixture(t, []string{"carol"}, nil, func(cfg *config.Config) {
				cfg.Enterprise.Enrollment.UnenrolledUsers = tc.unenrolled
			})
			authorizer := newManagedHookAuthorizer(api.runtimeConfigSnapshot().Enterprise.Enrollment, []string{"claudecode"},
				func() (managedHookLedger, error) { return managedHookLedger{}, nil })
			decision := authorizer.decide(peer, "claudecode", "")
			if decision.Allow != tc.wantAllow || (!tc.wantAllow && !decision.Excluded) {
				t.Fatalf("authorizer decision = %+v, want allow %v", decision, tc.wantAllow)
			}
			rows, _ := ownExcludedRowsOf(t, api, "uid", "5003", "carol")
			if got := rows["claudecode"]["reason_code"]; got != tc.wantCode {
				t.Fatalf("claudecode row = %#v, want code %s", rows["claudecode"], tc.wantCode)
			}
		})
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
