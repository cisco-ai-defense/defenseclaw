// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-2463: after a managed Windows upgrade, a disconnected account whose
// Hermes still runs the hooks the earlier release registered (that matrix
// lacks only the fail_closed setting this release adds) is reported as
// enrolled with an older hook matrix, upgrade pending at its next connect,
// not as pending and "not guarded". Any other earlier-release drift keeps
// the pending sign-in wait.
func TestEnterpriseHookEarlierHookMatrixIsReportedEnrolledNotPending(t *testing.T) {
	stubSecureClientSignInReconcile(t)
	previousEarlier := enterpriseHookReconcileTargetEarlierMatrix
	t.Cleanup(func() { enterpriseHookReconcileTargetEarlierMatrix = previousEarlier })
	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{}, errors.New("enterprise hooks: connector hermes hook verification failed: canonical hook matrix is absent: owned hook command not present")
	}
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return false, nil }
	enterpriseHookReconcileSecureClient = func() bool { return false }
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "1.0.2", true, nil }
	installs := 0
	enterpriseHookReconcileInstaller = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		installs++
		return enterprisehooks.InstallResult{}, nil
	}
	earlier := true
	enterpriseHookReconcileTargetEarlierMatrix = func(enterprisehooks.InstallOptions) (bool, error) { return earlier, nil }
	opts := enterprisehooks.InstallOptions{ConnectorName: "hermes"}
	target := enterprisehooks.ManifestTarget{Connector: "hermes", SID: "S-1-5-21-1-2-3-1017", UserHome: `C:\Users\dcw-std1`, Deferred: true}

	_, repaired, err := enterpriseHookVerifyOrRepairTarget(context.Background(), target, opts, true)
	if !errors.Is(err, errEnterpriseHookAwaitingSignIn) || repaired || installs != 0 {
		t.Fatalf("earlier matrix: err=%v repaired=%t installs=%d, want the sign-in wait without an install", err, repaired, installs)
	}
	row := enterpriseHookReconcileRow{SID: target.SID, UserHome: target.UserHome, Connector: "hermes", Error: err.Error()}
	if !enterpriseHookEarlierMatrixRow(row) || !enterpriseHookSessionUnavailable(row.Error) {
		t.Fatalf("earlier matrix row not recognized (or lost the session-unavailable words): %q", row.Error)
	}
	codex := enterpriseHookReconcileRow{SID: target.SID, UserHome: target.UserHome, Connector: "codex", OK: true}
	accounts := windowsEnterpriseEnrollmentAccounts([]enterpriseHookReconcileRow{row, codex})
	if len(accounts) != 1 || accounts[0].Connectors["hermes"] != "enrolled" || accounts[0].Connectors["codex"] != "enrolled" {
		t.Fatalf("enrollment = %+v, want hermes and codex enrolled", accounts)
	}
	if strings.Contains(accounts[0].Reason, windowsEnterpriseEnrollmentPending) ||
		!strings.Contains(accounts[0].Reason, "hermes: "+enterpriseHookEarlierMatrixState) {
		t.Fatalf("reason = %q, want the older hook matrix state and not the pending wait", accounts[0].Reason)
	}
	var result enterprisestatus.Result
	applyWindowsEnterpriseGuardianTargetGaps(&result, enterpriseHookGuardianState{Results: []enterpriseHookReconcileRow{row, codex}}, nil)
	if len(result.Warnings) != 1 || result.Warnings[0].Code != windowsEnterpriseGuardianRepairPendingCode ||
		!strings.Contains(result.Warnings[0].Message, "it is guarded, but a hook spawn error or timeout does not block") ||
		strings.Contains(result.Warnings[0].Message, "may not be inspected") {
		t.Fatalf("warnings = %+v, want one guarded-but-not-fail-closed guardian_repair_pending warning", result.Warnings)
	}

	// Any other drift of an earlier release's target still waits as pending.
	earlier = false
	_, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), target, opts, true)
	if !errors.Is(err, errEnterpriseHookAwaitingSignIn) {
		t.Fatalf("other drift: err=%v, want the sign-in wait", err)
	}
	row.Error = err.Error()
	if enterpriseHookEarlierMatrixRow(row) {
		t.Fatalf("other drift reported as the earlier matrix: %q", row.Error)
	}
	accounts = windowsEnterpriseEnrollmentAccounts([]enterpriseHookReconcileRow{row, codex})
	if accounts[0].Connectors["hermes"] != "pending" || !strings.Contains(accounts[0].Reason, windowsEnterpriseEnrollmentPending) {
		t.Fatalf("other drift enrollment = %+v, want hermes pending", accounts)
	}
}
