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

func stubSecureClientSignInReconcile(t *testing.T) {
	t.Helper()
	previousVerifier, previousSession, previousRelease := enterpriseHookReconcileVerifier, enterpriseHookReconcileSessionAvailable, enterpriseHookReconcileTargetRelease
	previousInstaller, previousDeferred := enterpriseHookReconcileInstaller, enterpriseHookReconcileDeferredSessionAvailable
	previousSecureClient, previousNotLocalSystem := enterpriseHookReconcileSecureClient, enterpriseHookSessionCheckNotLocalSystem
	t.Cleanup(func() {
		enterpriseHookReconcileVerifier, enterpriseHookReconcileSessionAvailable, enterpriseHookReconcileTargetRelease = previousVerifier, previousSession, previousRelease
		enterpriseHookReconcileInstaller, enterpriseHookReconcileDeferredSessionAvailable = previousInstaller, previousDeferred
		enterpriseHookReconcileSecureClient, enterpriseHookSessionCheckNotLocalSystem = previousSecureClient, previousNotLocalSystem
	})
}

// A non-purge Secure Client uninstall removes a protected target's machine
// enrollment and runtime selector but keeps its protected records in the
// retained StateRoot, so a reinstall found every signed-out account's
// target "protected" and drifted, and failed the whole Install (1603). With
// the pending proof (no runtime selected for it) such a deferred target is
// retired: the reconcile makes it pending like an account DefenseClaw never
// protected. A target that still has a runtime, a non-deferred target and
// the standalone profile keep the failure.
func TestEnterpriseHookVerifyOrRepairTargetSecureClientRetiredTargetIsPending(t *testing.T) {
	stubSecureClientSignInReconcile(t)
	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{}, errors.New("target SID is not registered in the Claude Code managed policy")
	}
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return false, nil }
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "", false, nil }
	installs := 0
	enterpriseHookReconcileInstaller = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		installs++
		return enterprisehooks.InstallResult{}, nil
	}
	var pendingProof error
	enterpriseHookReconcileDeferredSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return false, pendingProof }
	secureClient := true
	enterpriseHookReconcileSecureClient = func() bool { return secureClient }
	opts := enterprisehooks.InstallOptions{ConnectorName: "claudecode"}
	deferred := enterprisehooks.ManifestTarget{Connector: "claudecode", SID: "S-1-5-21-1-2-3-1008", Deferred: true}

	_, repaired, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true)
	if !errors.Is(err, errEnterpriseHookProtectionRetired) || !enterprisehooks.IsWindowsTargetSessionUnavailable(err) ||
		repaired || installs != 0 || !strings.Contains(err.Error(), "not registered in the Claude Code managed policy") {
		t.Fatalf("retired Secure Client target: err=%v repaired=%t installs=%d, want the retired session-unavailable error", err, repaired, installs)
	}

	signedOutRepair := "enterprise hooks: protected target requires repair but its exact active Windows session is unavailable"
	pendingProof = errors.New("managed runtime selector is present for the target")
	if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); err == nil ||
		errors.Is(err, errEnterpriseHookProtectionRetired) || !strings.HasPrefix(err.Error(), signedOutRepair) {
		t.Fatalf("target that still has a runtime: err=%v, want the signed-out repair failure", err)
	}
	pendingProof = nil
	if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), enterprisehooks.ManifestTarget{Connector: "claudecode"}, opts, true); err == nil ||
		errors.Is(err, errEnterpriseHookProtectionRetired) || !strings.HasPrefix(err.Error(), signedOutRepair) {
		t.Fatalf("non-deferred target: err=%v, want the signed-out repair failure", err)
	}
	secureClient = false
	if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); err == nil ||
		errors.Is(err, errEnterpriseHookProtectionRetired) || !strings.HasPrefix(err.Error(), signedOutRepair) {
		t.Fatalf("standalone same-release target: err=%v, want the signed-out repair failure", err)
	}

	// A Secure Client upgrade: an earlier release wrote the lock, so the
	// target waits for the sign-in (GAP-0644), on both profiles.
	secureClient = true
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "1.0.2", true, nil }
	if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); !errors.Is(err, errEnterpriseHookAwaitingSignIn) {
		t.Fatalf("earlier-release Secure Client target: err=%v, want the sign-in wait", err)
	}
}

// Status, verify and the lifecycle's coverage gate count a waiting row as
// pending on Secure Client as on the standalone profile, and nowhere else.
func TestEnterpriseHookAwaitingSignInRowCoversSecureClient(t *testing.T) {
	previousCfg := cfg
	t.Cleanup(func() { cfg = previousCfg })
	row := enterpriseHookReconcileRow{
		SID: "S-1-5-21-1-2-3-1008", Connector: "codex",
		Error: enterpriseHookAwaitingSignInPrefix + ": DefenseClaw 1.0.2 protected it",
	}
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		want bool
	}{
		{"secure client", &config.Config{DeploymentMode: string(managed.DeploymentModeManagedEnterprise), Enterprise: config.EnterpriseConfig{Profile: managed.ProfileSecureClient}}, true},
		{"standalone", &config.Config{DeploymentMode: string(managed.DeploymentModeManagedEnterprise), Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}, true},
		{"unmanaged", &config.Config{DeploymentMode: "local"}, false},
	} {
		cfg = tc.cfg
		if got := enterpriseHookAwaitingSignInRow(row); got != tc.want {
			t.Fatalf("%s: enterpriseHookAwaitingSignInRow = %t, want %t (profile %q)", tc.name, got, tc.want, tc.cfg.EnterpriseProfile())
		}
	}
}

// Setup's verify runs as the elevated administrator, which cannot query
// another account's session, so on Secure Client it accepts the guardian's
// fresh record of the wait; the guardian's own LocalSystem verify keeps the
// live session check, other session errors are unchanged, and the standalone
// profile reads the session list instead (GAP-2044).
func TestEnterpriseHookVerifyAwaitingSignInTrustsTheGuardianRecordOutsideLocalSystem(t *testing.T) {
	stubSecureClientSignInReconcile(t)
	notLocalSystem := errors.New("enterprise hooks: guardian is not LocalSystem")
	sessionErr := notLocalSystem
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return false, sessionErr }
	enterpriseHookSessionCheckNotLocalSystem = func(err error) bool { return errors.Is(err, notLocalSystem) }
	secureClient := true
	enterpriseHookReconcileSecureClient = func() bool { return secureClient }
	row := enterpriseHookReconcileRow{SID: "S-1-5-21-1-2-3-1008", Connector: "codex"}
	target := enterprisehooks.ManifestTarget{SID: row.SID, Connector: "codex", Deferred: true}
	awaiting := map[string]string{enterpriseHookProtectedTargetKey(row): enterpriseHookAwaitingSignInPrefix}

	if !enterpriseHookVerifyAwaitingSignIn(awaiting, target, row) {
		t.Fatal("Secure Client verify outside LocalSystem did not accept the guardian's wait record")
	}
	if enterpriseHookVerifyAwaitingSignIn(map[string]string{}, target, row) {
		t.Fatal("a row the guardian did not record as waiting was excused")
	}
	notDeferred := target
	notDeferred.Deferred = false
	if enterpriseHookVerifyAwaitingSignIn(awaiting, notDeferred, row) {
		t.Fatal("a non-deferred target was excused")
	}
	sessionErr = errors.New("enterprise hooks: WTS query failed: access is denied")
	if enterpriseHookVerifyAwaitingSignIn(awaiting, target, row) {
		t.Fatal("another session error was downgraded")
	}
	// Standalone checks the session list instead (GAP-2044): the wait is
	// excused only while the account has no active session, and never when
	// the list cannot be read.
	sessionErr, secureClient = notLocalSystem, false
	listSeam := enterpriseHookTargetHasNoSession
	t.Cleanup(func() { enterpriseHookTargetHasNoSession = listSeam })
	noSession, listErr := false, error(nil)
	enterpriseHookTargetHasNoSession = func(enterprisehooks.ManifestTarget) (bool, error) { return noSession, listErr }
	if enterpriseHookVerifyAwaitingSignIn(awaiting, target, row) {
		t.Fatal("the standalone profile excused the wait while the account has an active session")
	}
	noSession = true
	if !enterpriseHookVerifyAwaitingSignIn(awaiting, target, row) {
		t.Fatal("the standalone profile refused the wait of an account with no active session (GAP-2044)")
	}
	listErr = errors.New("enterprise hooks: list Windows sessions: access is denied")
	if enterpriseHookVerifyAwaitingSignIn(awaiting, target, row) {
		t.Fatal("the standalone profile excused the wait from a session list it could not read")
	}
}

// A retired Secure Client target is pending now, so the authorization and
// activation records must not carry its prior protected row forward; a
// pending or failed row without that mark keeps it, as before.
func TestMergeProtectedEnterpriseHookTargetsDropsRetiredRows(t *testing.T) {
	admin := enterpriseHookReconcileRow{SID: "S-1-5-21-1-2-3-500", Connector: "codex", OK: true}
	eval := enterpriseHookReconcileRow{SID: "S-1-5-21-1-2-3-1008", Connector: "codex", OK: true}
	previous := []enterpriseHookReconcileRow{admin, eval}
	current := []enterpriseHookReconcileRow{
		{SID: admin.SID, Connector: "codex", Pending: true, RevokeProtection: true},
		{SID: eval.SID, Connector: "codex", Error: "verify failed"},
	}
	merged := mergeProtectedEnterpriseHookTargets(previous, current)
	if len(merged) != 1 || merged[0].SID != eval.SID {
		t.Fatalf("merged = %+v, want only the failed target's carried-forward row", merged)
	}
}
