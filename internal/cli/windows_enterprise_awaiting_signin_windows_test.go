// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0644: a target an earlier release protected that waits for its
// signed-out account's next sign-in counts as pending in the enrollment
// summary and in the account's detail, not as failed or enrolled.
func TestWindowsStandaloneEnrollmentCountsSignInWaitsAsPending(t *testing.T) {
	previousCfg := cfg
	t.Cleanup(func() { cfg = previousCfg })
	cfg = nil
	dir := t.TempDir()
	manifest := filepath.Join(dir, "targets.yaml")
	if err := os.WriteFile(manifest, []byte("version: 1\ntargets:\n"+
		"  - {sid: S-1-12-1-1-2-3-1001, connector: codex, enabled: true, deferred: true}\n"+
		"  - {sid: S-1-12-1-1-2-3-1002, connector: codex, enabled: true, deferred: true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waiting := enterpriseHookAwaitingSignInPrefix + ": DefenseClaw 1.0.2-rc.3 protected it; its exact active Windows session is unavailable"
	body, err := json.Marshal(enterpriseHookGuardianState{
		Version: 1, TargetCount: 2, SuccessCount: 1, FailureCount: 1,
		Results: []enterpriseHookReconcileRow{
			{SID: "S-1-12-1-1-2-3-1001", Connector: "codex", OK: true},
			{SID: "S-1-12-1-1-2-3-1002", Connector: "codex", Error: waiting},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hookGuardianStateFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	enrollment, err := readWindowsEnterpriseStandaloneEnrollmentAt(manifest, dir)
	if err != nil || enrollment.Targets != 2 || enrollment.Pending != 1 {
		t.Fatalf("enrollment = %+v, %v; want 2 targets, 1 pending", enrollment, err)
	}
	if len(enrollment.Accounts) != 2 || enrollment.Accounts[1].Connectors["codex"] != "pending" ||
		!strings.HasPrefix(enrollment.Accounts[1].Reason, "pending:") ||
		strings.Contains(enrollment.Accounts[1].Reason, "failed:") {
		t.Fatalf("enrollment accounts = %+v, want the waiting account pending without a failure", enrollment.Accounts)
	}
}
