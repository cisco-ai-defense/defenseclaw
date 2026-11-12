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

func stubEarlierReleaseClosedMachineRegistration(t *testing.T) {
	t.Helper()
	previous := enterpriseHookReconcileClosedMachineRegistration
	t.Cleanup(func() { enterpriseHookReconcileClosedMachineRegistration = previous })
	enterpriseHookReconcileClosedMachineRegistration = func(opts enterprisehooks.InstallOptions) (bool, error) {
		return opts.ConnectorName == "claudecode" || opts.ConnectorName == "codex", nil
	}
}

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

	// A lock without a proved registered closed hook cannot wait as pending.
	earlier = false
	_, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), target, opts, true)
	if err == nil || errors.Is(err, errEnterpriseHookAwaitingSignIn) {
		t.Fatalf("other drift: err=%v, want the signed-out refusal", err)
	}
}

// GAP-0513: Setup restores the exact owner-rewritten ACL of an older
// account's hook lock before the guardian checks it. Model a signed-out
// account: before that restore the release cannot be read, so the failure
// must stay a failure; afterwards the guardian can carry its older hooks
// forward and name the pending sign-in repair without installing as SYSTEM.
func TestSignedOutOwnerRewrittenAccountUpgradeNeedsReadableOlderLock(t *testing.T) {
	stubSecureClientSignInReconcile(t)
	previousEarlier := enterpriseHookReconcileTargetEarlierMatrix
	previousClosed := enterpriseHookReconcileClosedMachineRegistration
	previousRemoved := enterpriseHookRemovedAccountRow
	t.Cleanup(func() {
		enterpriseHookReconcileTargetEarlierMatrix = previousEarlier
		enterpriseHookReconcileClosedMachineRegistration = previousClosed
		enterpriseHookRemovedAccountRow = previousRemoved
	})
	// The account exists and is only signed out. The test says so itself:
	// the real check reads the package cfg, and on a standalone deployment
	// this fixture account, which has no profile on the computer, reads as
	// removed and its row is skipped. A test that left the computer's own
	// standalone config in cfg made this one fail on a managed host only
	// (GAP-0093).
	enterpriseHookRemovedAccountRow = func(enterpriseHookReconcileRow) bool { return false }
	enterpriseHookReconcileSecureClient = func() bool { return false }
	ownerRightsRestored := false
	signedIn := false
	installs := 0
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return signedIn, nil }
	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{}, errors.New("protected hook lock belongs to an earlier release")
	}
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) {
		if !ownerRightsRestored {
			return "", false, errors.New("owner-rewritten hook lock is unreadable")
		}
		return "1.0.6", true, nil
	}
	enterpriseHookReconcileTargetEarlierMatrix = func(enterprisehooks.InstallOptions) (bool, error) { return false, nil }
	registered, closed := true, true
	enterpriseHookReconcileClosedMachineRegistration = func(enterprisehooks.InstallOptions) (bool, error) {
		return registered && closed, nil
	}
	enterpriseHookReconcileInstaller = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		installs++
		return enterprisehooks.InstallResult{}, nil
	}
	target := enterprisehooks.ManifestTarget{
		User: "EXAMPLE\\signedout", UserHome: `C:\Users\signedout`, SID: "S-1-5-21-1-2-3-1120",
		Connector: "codex", Deferred: true,
	}
	opts := enterprisehooks.InstallOptions{ConnectorName: target.Connector}
	_, repaired, err := enterpriseHookVerifyOrRepairTarget(context.Background(), target, opts, true)
	if err == nil || errors.Is(err, errEnterpriseHookAwaitingSignIn) || repaired || installs != 0 {
		t.Fatalf("unreadable older lock: err=%v repaired=%t installs=%d, want a refusal", err, repaired, installs)
	}
	ownerRightsRestored = true
	_, repaired, err = enterpriseHookVerifyOrRepairTarget(context.Background(), target, opts, true)
	if !errors.Is(err, errEnterpriseHookAwaitingSignIn) || repaired || installs != 0 {
		t.Fatalf("restored lock, signed out: err=%v repaired=%t installs=%d, want pending repair", err, repaired, installs)
	}
	pendingErr := err
	registered = false
	_, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), target, opts, true)
	if err == nil || errors.Is(err, errEnterpriseHookAwaitingSignIn) {
		t.Fatalf("missing machine registration: err=%v, want refusal", err)
	}
	registered, closed = true, false
	_, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), target, opts, true)
	if err == nil || errors.Is(err, errEnterpriseHookAwaitingSignIn) {
		t.Fatalf("open machine runtime: err=%v, want refusal", err)
	}
	closed = true
	row := enterpriseHookReconcileRow{User: target.User, UserHome: target.UserHome, SID: target.SID, Connector: target.Connector, Error: pendingErr.Error()}
	accounts := windowsEnterpriseEnrollmentAccounts([]enterpriseHookReconcileRow{row})
	if len(accounts) != 1 || accounts[0].Account != target.User || accounts[0].Connectors["codex"] != "pending" ||
		!strings.Contains(accounts[0].Reason, windowsEnterpriseEnrollmentPending) {
		t.Fatalf("signed-out account status = %+v, want the account and pending repair", accounts)
	}
	for _, action := range []string{"status", "verify"} {
		status := &enterprisestatus.Result{Action: action, SecurityComplete: true}
		applyWindowsEnterpriseGuardianTargetGaps(status, enterpriseHookGuardianState{Results: []enterpriseHookReconcileRow{row}}, nil)
		if status.SecurityComplete || len(status.Warnings) != 1 ||
			status.Warnings[0].Code != windowsEnterpriseGuardianRepairPendingCode ||
			!strings.Contains(status.Warnings[0].Message, "codex for "+target.User) ||
			!strings.Contains(status.Warnings[0].Message, "until the account signs in") {
			t.Fatalf("%s = %+v, want incomplete coverage and the named pending repair", action, status)
		}
	}
	signedIn = true
	_, repaired, err = enterpriseHookVerifyOrRepairTarget(context.Background(), target, opts, true)
	if err != nil || !repaired || installs != 1 {
		t.Fatalf("next sign-in: err=%v repaired=%t installs=%d, want one in-session repair", err, repaired, installs)
	}
}
