// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"testing"
)

// A recovered config generation record does not replace ensure's plan. Every
// plan the planner selects for an installed deployment is kept: a newer
// Setup over 1.0.2 upgrades (a forced repair put the newer binaries in place
// and recorded 1.0.2), drift is reapplied and a pending transaction is
// recovered. Only a compliant deployment becomes the repair that restarts
// the gateway on the recovered record, and a refusal stays a refusal.
func TestWindowsEnterpriseGenerationRecoveryKeepsThePlannedAction(t *testing.T) {
	refused := errors.New("downgrade_refused: installed version 1.0.5 is newer than 1.0.4")
	for _, tc := range []struct {
		name    string
		planned windowsEnterpriseEnsurePlan
		err     error
		want    windowsEnterpriseEnsurePlan
	}{
		{"1.0.2 to 1.0.4 upgrade", windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "older_version:1.0.2"}, nil,
			windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "older_version:1.0.2"}},
		{"0.8.10 to 1.0.4 upgrade", windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "older_version:0.8.10"}, nil,
			windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "older_version:0.8.10"}},
		{"binary drift", windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:gateway"}, nil,
			windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:gateway"}},
		{"manifest drift", windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:manifest"}, nil,
			windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:manifest"}},
		{"bundle drift", windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:bundle"}, nil,
			windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:bundle"}},
		{"pending transaction", windowsEnterpriseEnsurePlan{Action: "repair", Reason: "transaction_pending"}, nil,
			windowsEnterpriseEnsurePlan{Action: "repair", Reason: "transaction_pending"}},
		{"compliant", windowsEnterpriseEnsurePlan{Reason: "compliant"}, nil,
			windowsEnterpriseEnsurePlan{Action: "repair", Reason: "verify_failed", Detail: windowsEnterpriseGenerationRecoveryDetail}},
		{"refusal", windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "ignored"}, refused, windowsEnterpriseEnsurePlan{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			got, err := planWindowsEnterpriseEnsureAfterGenerationRecovery(func() (windowsEnterpriseEnsurePlan, error) {
				calls++
				return tc.planned, tc.err
			})
			if calls != 1 {
				t.Fatalf("planner ran %d times, want once", calls)
			}
			if !errors.Is(err, tc.err) || got != tc.want {
				t.Fatalf("plan = %+v, %v; want %+v, %v", got, err, tc.want, tc.err)
			}
		})
	}
}
