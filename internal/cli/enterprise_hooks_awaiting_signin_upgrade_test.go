// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0980: an in-place Setup over a published 1.0.5 install rolled back
// with 1603 while an enrolled account was signed out: the Copilot target of
// that account failed this release's verification (its VS Code Local hooks
// are not current), no machine registration is provably closed for Copilot,
// and a runtime was still selected for it, so it was a failure and the
// guardian published no required coverage. An earlier release's lock makes
// the drift the upgrade's own: on the standalone profile every deferred
// connector of an account without an active session (signed out,
// disconnected) waits for the sign-in, whatever the connector, and status,
// verify and the coverage gate count it pending, never protected. An account
// with an active session whose repair fails still fails the run.
func TestEnterpriseHookVerifyOrRepairTargetWaitsForSignInAfterAnUpgradeForEveryConnector(t *testing.T) {
	stubSecureClientSignInReconcile(t)
	previousCfg := cfg
	t.Cleanup(func() { cfg = previousCfg })
	cfg = &config.Config{
		DeploymentMode: string(managed.DeploymentModeManagedEnterprise),
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	verifyErr := errors.New("enterprise hooks: copilot VS Code Local hooks: DefenseClaw's VS Code Local hooks are not current")
	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{}, verifyErr
	}
	signedOut := true
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return !signedOut, nil }
	// A runtime is still selected for the account: the pending proof of
	// GAP-0909 does not hold, so the wait cannot come from that branch.
	enterpriseHookReconcileDeferredSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) {
		return false, errors.New("deferred target already has a selected runtime without protected Guardian authorization")
	}
	// No machine registration is proven closed here (that proof is for
	// Claude Code and Codex), and the machine policy of a Copilot, OpenCode
	// or Cursor hook is in force unless a row says otherwise.
	previousClosed := enterpriseHookReconcileClosedMachineRegistration
	previousRegistration := enterpriseHookReconcileMachineHookRegistration
	t.Cleanup(func() {
		enterpriseHookReconcileClosedMachineRegistration = previousClosed
		enterpriseHookReconcileMachineHookRegistration = previousRegistration
	})
	enterpriseHookReconcileClosedMachineRegistration = func(enterprisehooks.InstallOptions) (bool, error) { return false, nil }
	registered, registrationErr := true, error(nil)
	enterpriseHookReconcileMachineHookRegistration = func(enterprisehooks.InstallOptions) (bool, error) {
		return registered, registrationErr
	}
	enterpriseHookReconcileSecureClient = func() bool { return false }
	released, releaseErr, other := "1.0.5", error(nil), true
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) {
		return released, other && releaseErr == nil, releaseErr
	}
	installs := 0
	var installErr error
	enterpriseHookReconcileInstaller = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		installs++
		if installErr != nil {
			return enterprisehooks.InstallResult{}, installErr
		}
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName}, nil
	}
	signedOutRepair := "enterprise hooks: protected target requires repair but its exact active Windows session is unavailable"
	connectors := []string{"copilot", "cursor", "opencode"}
	for _, name := range connectors {
		opts := enterprisehooks.InstallOptions{ConnectorName: name}
		deferred := enterprisehooks.ManifestTarget{Connector: name, SID: "S-1-5-21-1-2-3-1010", Deferred: true}

		// Signed out or disconnected (no active session): the upgrade's own
		// drift waits for the sign-in. No install is attempted without the
		// account's session.
		signedOut, installs, installErr = true, 0, nil
		_, repaired, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true)
		if !errors.Is(err, errEnterpriseHookAwaitingSignIn) || repaired || installs != 0 ||
			errors.Is(err, errEnterpriseHookProtectionRetired) ||
			!strings.Contains(err.Error(), "DefenseClaw 1.0.5 protected it") ||
			!strings.Contains(err.Error(), "not protected until then") ||
			!strings.Contains(err.Error(), "(verification: "+verifyErr.Error()+")") {
			t.Fatalf("%s signed out after an upgrade: err=%v repaired=%t installs=%d, want the sign-in wait", name, err, repaired, installs)
		}

		// The wait needs the machine policy that registers the hook to be in
		// force: without it, or when that cannot be proven, the account is not
		// covered and the failure stays.
		registered = false
		if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); err == nil ||
			errors.Is(err, errEnterpriseHookAwaitingSignIn) || !strings.HasPrefix(err.Error(), signedOutRepair) {
			t.Fatalf("%s without its machine policy: err=%v, want the signed-out repair failure", name, err)
		}
		registered, registrationErr = true, errors.New("machine policy is untrusted")
		if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); err == nil ||
			errors.Is(err, errEnterpriseHookAwaitingSignIn) || !strings.HasPrefix(err.Error(), signedOutRepair) {
			t.Fatalf("%s with an unreadable machine policy: err=%v, want the signed-out repair failure", name, err)
		}
		registrationErr = nil

		// A lock this release wrote changed while the account was signed out
		// (not the upgrade): that stays a failure.
		other = false
		if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); err == nil ||
			errors.Is(err, errEnterpriseHookAwaitingSignIn) || !strings.HasPrefix(err.Error(), signedOutRepair) {
			t.Fatalf("%s same-release lock: err=%v, want the signed-out repair failure", name, err)
		}
		// A lock that cannot be read cannot name the upgrade either.
		other, releaseErr = true, errors.New("hook contract lock is unreadable")
		if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); err == nil ||
			errors.Is(err, errEnterpriseHookAwaitingSignIn) || !strings.HasPrefix(err.Error(), signedOutRepair) {
			t.Fatalf("%s unreadable lock: err=%v, want the signed-out repair failure", name, err)
		}
		releaseErr = nil
		// A target the administrator authored without a deferral never waits.
		if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), enterprisehooks.ManifestTarget{Connector: name}, opts, true); err == nil ||
			errors.Is(err, errEnterpriseHookAwaitingSignIn) || !strings.HasPrefix(err.Error(), signedOutRepair) {
			t.Fatalf("%s non-deferred target: err=%v, want the signed-out repair failure", name, err)
		}

		// The wait is only for an account with no active session: with one,
		// the repair runs in its session, and a repair that fails still
		// fails the run (the existing behaviour, unchanged).
		signedOut, installs = false, 0
		installErr = errors.New("enterprise hooks: write managed hook runtime: access is denied")
		_, repaired, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true)
		if err == nil || !strings.Contains(err.Error(), "access is denied") || errors.Is(err, errEnterpriseHookAwaitingSignIn) ||
			repaired || installs != 1 {
			t.Fatalf("%s signed in, repair fails: err=%v repaired=%t installs=%d, want the install failure", name, err, repaired, installs)
		}
		installs, installErr = 0, nil
		_, repaired, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true)
		if err != nil || !repaired || installs != 1 {
			t.Fatalf("%s signed in, repair works: err=%v repaired=%t installs=%d, want a repair", name, err, repaired, installs)
		}
	}
}

// The connectors that register their hooks in the account's own agent
// configuration (Hermes, Amp, Devin, Antigravity, Kiro) have no machine policy
// to prove: an upgrade's drift stays a failure for a signed-out account, as
// before GAP-0980, whatever the lock says.
func TestEnterpriseHookVerifyOrRepairTargetKeepsTheFailureForConfigRegisteredConnectors(t *testing.T) {
	stubSecureClientSignInReconcile(t)
	previousRegistration := enterpriseHookReconcileMachineHookRegistration
	t.Cleanup(func() { enterpriseHookReconcileMachineHookRegistration = previousRegistration })
	enterpriseHookReconcileMachineHookRegistration = func(enterprisehooks.InstallOptions) (bool, error) { return true, nil }
	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{}, errors.New("lock drift")
	}
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return false, nil }
	enterpriseHookReconcileDeferredSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) {
		return false, errors.New("selected runtime")
	}
	enterpriseHookReconcileSecureClient = func() bool { return false }
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "1.0.5", true, nil }
	previousEarlier := enterpriseHookReconcileTargetEarlierMatrix
	t.Cleanup(func() { enterpriseHookReconcileTargetEarlierMatrix = previousEarlier })
	enterpriseHookReconcileTargetEarlierMatrix = func(enterprisehooks.InstallOptions) (bool, error) { return false, nil }
	for _, name := range []string{"hermes", "amp", "devin", "antigravity", "kiro"} {
		deferred := enterprisehooks.ManifestTarget{Connector: name, SID: "S-1-5-21-1-2-3-1014", Deferred: true}
		_, _, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, enterprisehooks.InstallOptions{ConnectorName: name}, true)
		if err == nil || errors.Is(err, errEnterpriseHookAwaitingSignIn) ||
			!strings.HasPrefix(err.Error(), "enterprise hooks: protected target requires repair but its exact active Windows session is unavailable") {
			t.Fatalf("%s: err=%v, want the signed-out repair failure", name, err)
		}
	}
}

// Claude Code and Codex keep the closed-registration proof: without it (no
// machine registration, or a runtime that does not fail closed) the upgrade's
// drift stays a failure, as before GAP-0980.
func TestEnterpriseHookVerifyOrRepairTargetKeepsTheClosedProofForClaudeCodeAndCodex(t *testing.T) {
	stubSecureClientSignInReconcile(t)
	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{}, errors.New("lock drift")
	}
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return false, nil }
	enterpriseHookReconcileDeferredSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) {
		return false, errors.New("selected runtime")
	}
	enterpriseHookReconcileSecureClient = func() bool { return false }
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "1.0.5", true, nil }
	closed := false
	previousClosed := enterpriseHookReconcileClosedMachineRegistration
	t.Cleanup(func() { enterpriseHookReconcileClosedMachineRegistration = previousClosed })
	enterpriseHookReconcileClosedMachineRegistration = func(enterprisehooks.InstallOptions) (bool, error) { return closed, nil }
	for _, name := range []string{"claudecode", "codex"} {
		opts := enterprisehooks.InstallOptions{ConnectorName: name}
		deferred := enterprisehooks.ManifestTarget{Connector: name, SID: "S-1-5-21-1-2-3-1013", Deferred: true}
		closed = false
		if _, _, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); err == nil ||
			errors.Is(err, errEnterpriseHookAwaitingSignIn) ||
			!strings.HasPrefix(err.Error(), "enterprise hooks: protected target requires repair but its exact active Windows session is unavailable") {
			t.Fatalf("%s without a closed registration: err=%v, want the signed-out repair failure", name, err)
		}
		closed = true
		if _, _, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); !errors.Is(err, errEnterpriseHookAwaitingSignIn) {
			t.Fatalf("%s with a closed registration: err=%v, want the sign-in wait", name, err)
		}
	}
}

// Secure Client keeps its own wait, word for word: the standalone branch of
// GAP-0980 sits behind it and changes nothing there.
func TestEnterpriseHookVerifyOrRepairTargetSecureClientUpgradeWaitIsUnchanged(t *testing.T) {
	stubSecureClientSignInReconcile(t)
	verifyErr := errors.New("lock drift")
	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{}, verifyErr
	}
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return false, nil }
	enterpriseHookReconcileSecureClient = func() bool { return true }
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "1.0.2", true, nil }
	opts := enterprisehooks.InstallOptions{ConnectorName: "copilot"}
	deferred := enterprisehooks.ManifestTarget{Connector: "copilot", SID: "S-1-5-21-1-2-3-1011", Deferred: true}
	_, _, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true)
	want := "enterprise hooks: protected target waits for its account's next sign-in: DefenseClaw 1.0.2 protected it, and this " +
		"release's hooks install only in the account's own Windows session; its exact active Windows session is unavailable, so " +
		"the guardian repairs it at the account's next sign-in (verification: lock drift)"
	if err == nil || err.Error() != want {
		t.Fatalf("Secure Client upgrade wait: err=%v, want %q", err, want)
	}
}

// The wait this branch makes is read as pending, never protected, by every
// surface: the failed row is excused (so the coverage gate and verify pass),
// status words it as pending until the account signs in and not protected,
// and the account's connector state is pending.
func TestEnterpriseHookUpgradeSignInWaitIsPendingNeverProtected(t *testing.T) {
	stubSecureClientSignInReconcile(t)
	previousCfg := cfg
	t.Cleanup(func() { cfg = previousCfg })
	cfg = &config.Config{
		DeploymentMode: string(managed.DeploymentModeManagedEnterprise),
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{}, errors.New("VS Code Local hooks are not current")
	}
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return false, nil }
	enterpriseHookReconcileDeferredSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) {
		return false, errors.New("selected runtime")
	}
	enterpriseHookReconcileSecureClient = func() bool { return false }
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "1.0.5", true, nil }
	previousRegistration := enterpriseHookReconcileMachineHookRegistration
	t.Cleanup(func() { enterpriseHookReconcileMachineHookRegistration = previousRegistration })
	enterpriseHookReconcileMachineHookRegistration = func(enterprisehooks.InstallOptions) (bool, error) { return true, nil }
	deferred := enterprisehooks.ManifestTarget{Connector: "copilot", SID: "S-1-5-21-1-2-3-1012", Deferred: true}
	_, _, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, enterprisehooks.InstallOptions{ConnectorName: "copilot"}, true)
	if err == nil {
		t.Fatal("no sign-in wait")
	}
	row := enterpriseHookReconcileRow{User: `HOST\dcw-std1`, SID: deferred.SID, Connector: "copilot", Error: err.Error()}
	if !enterpriseHookAwaitingSignInRow(row) || enterpriseHookEarlierMatrixRow(row) {
		t.Fatalf("row %+v is not read as a sign-in wait", row)
	}
	state := enterpriseHookGuardianState{Version: 1, TargetCount: 1, FailureCount: 1, Results: []enterpriseHookReconcileRow{row}}
	if removed, awaiting, linked := enterpriseHookExcusedFailures(state); removed != 0 || awaiting != 1 || linked != 0 {
		t.Fatalf("excused failures = %d removed, %d awaiting, %d linked; want 1 awaiting", removed, awaiting, linked)
	}
	issue := enterpriseHookGuardianFailureIssue(row)
	if !strings.Contains(issue, "copilot for ") || !strings.Contains(issue, "is pending until that account signs in") ||
		!strings.Contains(issue, "it is not protected until then") || strings.Contains(issue, "cannot repair") {
		t.Fatalf("status wording %q", issue)
	}
	accounts := windowsEnterpriseEnrollmentAccounts([]enterpriseHookReconcileRow{row})
	if len(accounts) != 1 || accounts[0].Connectors["copilot"] != "pending" || !strings.HasPrefix(accounts[0].Reason, "pending:") {
		t.Fatalf("enrollment accounts %+v, want copilot pending", accounts)
	}
}
