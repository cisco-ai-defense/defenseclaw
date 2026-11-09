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

// GAP-0980: an in-place Setup over a published 1.0.5 install rolled back with
// 1603 while an enrolled account was signed out: the account's Copilot and
// Antigravity targets failed this release's verification because their hook
// files hold the render of releases up to 1.0.6 (the Constrained Language
// fallback end that exited 0 when the launcher never started), only the
// account's own session writes the new one, and a runtime was still selected
// (so the GAP-0909 pending proof fails by design). A second, read-only verify
// that accepts the earlier release's render proves that is the only
// difference: the target then waits for the account's next sign-in, the
// previous release's hook keeps running for it, and the upgrade does not
// fail. Any other verify error keeps the failure; an account with an active
// session whose repair fails still fails the run.
type upgradeWaitFixture struct {
	signedOut     bool
	verifyErr     error
	staleRender   bool // the prior-render verify passes
	installs      int
	installErr    error
	priorVerifies int
}

func newUpgradeWaitFixture(t *testing.T) *upgradeWaitFixture {
	t.Helper()
	stubSecureClientSignInReconcile(t)
	previousCfg := cfg
	previousClosed := enterpriseHookReconcileClosedMachineRegistration
	previousRegistration := enterpriseHookReconcileMachineRegistration
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseHookReconcileClosedMachineRegistration = previousClosed
		enterpriseHookReconcileMachineRegistration = previousRegistration
	})
	cfg = &config.Config{
		DeploymentMode: string(managed.DeploymentModeManagedEnterprise),
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	f := &upgradeWaitFixture{
		signedOut: true,
		verifyErr: errors.New("enterprise hooks: connector antigravity hook verification failed: canonical hook matrix is absent"),
	}
	enterpriseHookReconcileVerifier = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if opts.AcceptPriorReleaseRender {
			f.priorVerifies++
			if f.staleRender {
				return enterprisehooks.InstallResult{Connector: opts.ConnectorName}, nil
			}
		}
		return enterprisehooks.InstallResult{}, f.verifyErr
	}
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return !f.signedOut, nil }
	// A runtime is still selected for the account: the GAP-0909 pending proof
	// does not hold, so the wait cannot come from that branch.
	enterpriseHookReconcileDeferredSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) {
		return false, errors.New("deferred target already has a selected runtime without protected Guardian authorization")
	}
	enterpriseHookReconcileClosedMachineRegistration = func(enterprisehooks.InstallOptions) (bool, error) { return false, nil }
	enterpriseHookReconcileMachineRegistration = func(enterprisehooks.InstallOptions) (bool, error) { return false, nil }
	enterpriseHookReconcileSecureClient = func() bool { return false }
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "1.0.5", true, nil }
	enterpriseHookReconcileInstaller = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		f.installs++
		if f.installErr != nil {
			return enterprisehooks.InstallResult{}, f.installErr
		}
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName}, nil
	}
	return f
}

const upgradeWaitSignedOutRepair = "enterprise hooks: protected target requires repair but its exact active Windows session is unavailable"

var upgradeWaitConnectors = []string{
	"copilot", "antigravity", "kiro", "amp", "devin", "hermes", "claudecode", "codex", "cursor", "opencode",
}

func TestEnterpriseHookVerifyOrRepairTargetWaitsForSignInWhenOnlyTheEarlierReleasesRenderDiffers(t *testing.T) {
	f := newUpgradeWaitFixture(t)
	f.staleRender = true
	for _, name := range upgradeWaitConnectors {
		f.installs = 0
		opts := enterprisehooks.InstallOptions{ConnectorName: name}
		deferred := enterprisehooks.ManifestTarget{Connector: name, SID: "S-1-5-21-1-2-3-1010", Deferred: true}
		_, repaired, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true)
		if !errors.Is(err, errEnterpriseHookAwaitingSignIn) || repaired || f.installs != 0 ||
			errors.Is(err, errEnterpriseHookProtectionRetired) ||
			!strings.Contains(err.Error(), enterpriseHookAwaitingSignInPriorRender) ||
			!strings.Contains(err.Error(), "DefenseClaw 1.0.5 protected it") ||
			!strings.Contains(err.Error(), "exact active Windows session is unavailable") ||
			!strings.Contains(err.Error(), "(verification: "+f.verifyErr.Error()+")") {
			t.Fatalf("%s: err=%v repaired=%t installs=%d, want the sign-in wait for the earlier release's render", name, err, repaired, f.installs)
		}
	}
}

// Any other verify error keeps the failure: the second verify fails too.
func TestEnterpriseHookVerifyOrRepairTargetKeepsTheFailureWhenSomethingBesideTheRenderIsWrong(t *testing.T) {
	f := newUpgradeWaitFixture(t)
	f.staleRender = false
	for _, name := range upgradeWaitConnectors {
		opts := enterprisehooks.InstallOptions{ConnectorName: name}
		deferred := enterprisehooks.ManifestTarget{Connector: name, SID: "S-1-5-21-1-2-3-1011", Deferred: true}
		_, _, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true)
		if err == nil || errors.Is(err, errEnterpriseHookAwaitingSignIn) || !strings.HasPrefix(err.Error(), upgradeWaitSignedOutRepair) {
			t.Fatalf("%s: err=%v, want the signed-out repair failure", name, err)
		}
	}
	if f.priorVerifies != len(upgradeWaitConnectors) {
		t.Fatalf("prior-render verifies = %d, want one per target", f.priorVerifies)
	}
}

// A lock this release wrote, a lock that cannot be read, a target without a
// deferral and an account with an active session never take the wait.
func TestEnterpriseHookVerifyOrRepairTargetUpgradeWaitNeedsAnEarlierReleaseAndNoSession(t *testing.T) {
	f := newUpgradeWaitFixture(t)
	f.staleRender = true
	released, releaseErr, other := "1.0.5", error(nil), true
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) {
		return released, other && releaseErr == nil, releaseErr
	}
	for _, name := range upgradeWaitConnectors {
		opts := enterprisehooks.InstallOptions{ConnectorName: name}
		deferred := enterprisehooks.ManifestTarget{Connector: name, SID: "S-1-5-21-1-2-3-1012", Deferred: true}
		// A lock this release wrote changed while the account was signed out.
		other = false
		if _, _, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); err == nil ||
			errors.Is(err, errEnterpriseHookAwaitingSignIn) || !strings.HasPrefix(err.Error(), upgradeWaitSignedOutRepair) {
			t.Fatalf("%s same-release lock: err=%v, want the signed-out repair failure", name, err)
		}
		// A lock that cannot be read cannot name the upgrade either.
		other, releaseErr = true, errors.New("hook contract lock is unreadable")
		if _, _, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); err == nil ||
			errors.Is(err, errEnterpriseHookAwaitingSignIn) || !strings.HasPrefix(err.Error(), upgradeWaitSignedOutRepair) {
			t.Fatalf("%s unreadable lock: err=%v, want the signed-out repair failure", name, err)
		}
		releaseErr = nil
		// A target the administrator authored without a deferral never waits.
		if _, _, err := enterpriseHookVerifyOrRepairTarget(context.Background(), enterprisehooks.ManifestTarget{Connector: name}, opts, true); err == nil ||
			errors.Is(err, errEnterpriseHookAwaitingSignIn) || !strings.HasPrefix(err.Error(), upgradeWaitSignedOutRepair) {
			t.Fatalf("%s non-deferred target: err=%v, want the signed-out repair failure", name, err)
		}
		// With an active session the repair runs in it, and a repair that
		// fails still fails the run: the existing behaviour, unchanged.
		f.signedOut, f.installs = false, 0
		f.installErr = errors.New("enterprise hooks: write managed hook runtime: access is denied")
		_, repaired, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true)
		if err == nil || !strings.Contains(err.Error(), "access is denied") || errors.Is(err, errEnterpriseHookAwaitingSignIn) ||
			repaired || f.installs != 1 {
			t.Fatalf("%s signed in, repair fails: err=%v repaired=%t installs=%d, want the install failure", name, err, repaired, f.installs)
		}
		f.installs, f.installErr = 0, nil
		_, repaired, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true)
		if err != nil || !repaired || f.installs != 1 {
			t.Fatalf("%s signed in, repair works: err=%v repaired=%t installs=%d, want a repair", name, err, repaired, f.installs)
		}
		f.signedOut = true
	}
}

// With the administrator's hook fail mode open, the closed-registration proof
// of Claude Code and Codex cannot hold; the registration without the closed
// requirement admits the wait, with its own words. A closed configuration and
// a registration that is not proven keep the failure.
func TestEnterpriseHookVerifyOrRepairTargetOpenFailModeWaitsOnTheRegistrationProof(t *testing.T) {
	f := newUpgradeWaitFixture(t)
	registered := true
	enterpriseHookReconcileMachineRegistration = func(enterprisehooks.InstallOptions) (bool, error) { return registered, nil }
	for _, name := range []string{"claudecode", "codex"} {
		deferred := enterprisehooks.ManifestTarget{Connector: name, SID: "S-1-5-21-1-2-3-1013", Deferred: true}
		open := enterprisehooks.InstallOptions{ConnectorName: name, HookFailMode: "open"}
		_, _, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, open, true)
		if !errors.Is(err, errEnterpriseHookAwaitingSignIn) || !strings.Contains(err.Error(), enterpriseHookAwaitingSignInOpenMode) ||
			f.installs != 0 {
			t.Fatalf("%s open mode: err=%v installs=%d, want the open-mode sign-in wait", name, err, f.installs)
		}
		closed := enterprisehooks.InstallOptions{ConnectorName: name, HookFailMode: "closed"}
		if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, closed, true); err == nil ||
			errors.Is(err, errEnterpriseHookAwaitingSignIn) || !strings.HasPrefix(err.Error(), upgradeWaitSignedOutRepair) {
			t.Fatalf("%s closed mode without the closed proof: err=%v, want the signed-out repair failure", name, err)
		}
		registered = false
		if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, open, true); err == nil ||
			errors.Is(err, errEnterpriseHookAwaitingSignIn) || !strings.HasPrefix(err.Error(), upgradeWaitSignedOutRepair) {
			t.Fatalf("%s open mode without a registration: err=%v, want the signed-out repair failure", name, err)
		}
		registered = true
	}
}

// Secure Client keeps its own wait, word for word: the standalone branch of
// GAP-0980 sits behind it and changes nothing there, and never asks for the
// prior-render verify.
func TestEnterpriseHookVerifyOrRepairTargetSecureClientUpgradeWaitIsUnchanged(t *testing.T) {
	f := newUpgradeWaitFixture(t)
	f.staleRender = true
	f.verifyErr = errors.New("lock drift")
	enterpriseHookReconcileSecureClient = func() bool { return true }
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "1.0.2", true, nil }
	opts := enterprisehooks.InstallOptions{ConnectorName: "copilot"}
	deferred := enterprisehooks.ManifestTarget{Connector: "copilot", SID: "S-1-5-21-1-2-3-1014", Deferred: true}
	_, _, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true)
	want := "enterprise hooks: protected target waits for its account's next sign-in: DefenseClaw 1.0.2 protected it, and this " +
		"release's hooks install only in the account's own Windows session; its exact active Windows session is unavailable, so " +
		"the guardian repairs it at the account's next sign-in (verification: lock drift)"
	if err == nil || err.Error() != want || f.priorVerifies != 0 {
		t.Fatalf("Secure Client upgrade wait: err=%v priorVerifies=%d, want %q", err, f.priorVerifies, want)
	}
}

// Claude Code and Codex keep their closed-registration proof, ahead of this one.
func TestEnterpriseHookVerifyOrRepairTargetClosedProofStillDecidesFirst(t *testing.T) {
	f := newUpgradeWaitFixture(t)
	f.staleRender = true
	enterpriseHookReconcileClosedMachineRegistration = func(enterprisehooks.InstallOptions) (bool, error) { return true, nil }
	for _, name := range []string{"claudecode", "codex"} {
		deferred := enterprisehooks.ManifestTarget{Connector: name, SID: "S-1-5-21-1-2-3-1015", Deferred: true}
		_, _, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, enterprisehooks.InstallOptions{ConnectorName: name}, true)
		if !errors.Is(err, errEnterpriseHookAwaitingSignIn) || strings.Contains(err.Error(), enterpriseHookAwaitingSignInKeepsRunning) ||
			f.priorVerifies != 0 {
			t.Fatalf("%s with a closed registration: err=%v priorVerifies=%d, want the closed-registration wait", name, err, f.priorVerifies)
		}
	}
}

// The wait is read as pending by every surface and says what the account
// really has: the previous release's hook keeps running. Nothing says
// protected, blocked or unguarded.
func TestEnterpriseHookUpgradeSignInWaitIsPendingAndSaysThePreviousHookKeepsRunning(t *testing.T) {
	f := newUpgradeWaitFixture(t)
	f.staleRender = true
	deferred := enterprisehooks.ManifestTarget{Connector: "copilot", SID: "S-1-5-21-1-2-3-1016", Deferred: true}
	_, _, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, enterprisehooks.InstallOptions{ConnectorName: "copilot"}, true)
	if err == nil {
		t.Fatal("no sign-in wait")
	}
	row := enterpriseHookReconcileRow{User: `HOST\dcw-std1`, SID: deferred.SID, Connector: "copilot", Error: err.Error()}
	other := enterpriseHookReconcileRow{User: row.User, SID: row.SID, Connector: "cursor", OK: true}
	if !enterpriseHookAwaitingSignInRow(row) || !enterpriseHookAwaitingSignInKeepsRunningRow(row) || enterpriseHookEarlierMatrixRow(row) {
		t.Fatalf("row %+v is not read as the previous release's hook still running", row)
	}
	state := enterpriseHookGuardianState{Version: 1, TargetCount: 1, FailureCount: 1, Results: []enterpriseHookReconcileRow{row}}
	if removed, awaiting, linked := enterpriseHookExcusedFailures(state); removed != 0 || awaiting != 1 || linked != 0 {
		t.Fatalf("excused failures = %d removed, %d awaiting, %d linked; want 1 awaiting", removed, awaiting, linked)
	}
	issue := enterpriseHookGuardianFailureIssue(row)
	if !strings.Contains(issue, "is pending until that account signs in") ||
		!strings.Contains(issue, "previous release's DefenseClaw hook keeps running for this account until it signs in and the guardian updates it") {
		t.Fatalf("status wording %q", issue)
	}
	accounts := windowsEnterpriseEnrollmentAccounts([]enterpriseHookReconcileRow{row, other})
	if len(accounts) != 1 || accounts[0].Connectors["copilot"] != "pending" || accounts[0].Connectors["cursor"] != "enrolled" ||
		!strings.HasPrefix(accounts[0].Reason, "pending: waiting for an active (connected) session of this account;") ||
		!strings.Contains(accounts[0].Reason, "the previous release's DefenseClaw hook keeps running until this account signs in and the guardian updates it: copilot") {
		t.Fatalf("enrollment accounts %+v, want copilot pending with the previous hook running", accounts)
	}
	// A never-enrolled connector of the same account keeps the generic reason.
	waiting := enterpriseHookReconcileRow{User: row.User, SID: row.SID, Connector: "devin", Pending: true}
	accounts = windowsEnterpriseEnrollmentAccounts([]enterpriseHookReconcileRow{row, waiting})
	if len(accounts) != 1 || accounts[0].Reason != windowsEnterpriseEnrollmentPending {
		t.Fatalf("mixed enrollment reason %+v, want the generic pending reason", accounts)
	}
	// The words of the wait itself claim nothing about protection.
	for _, text := range []string{issue, windowsEnterpriseEnrollmentPendingKeepsRunning} {
		for _, banned := range []string{"not guarded", "blocked until this account signs in", "protected until"} {
			if strings.Contains(text, banned) {
				t.Fatalf("text %q says %q", text, banned)
			}
		}
	}
}
