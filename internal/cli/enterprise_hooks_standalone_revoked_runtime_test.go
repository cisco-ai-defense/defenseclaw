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

// GAP-0909: a roster change makes the guardian revoke the runtime selection of
// a connector it removes. When the change is undone, the restored manifest
// names those targets again while no runtime is selected for them, and a
// signed-out account's row was a failure only its own sign-in could repair:
// every ensure and repair then refused, and the undo that needed the hook
// proof stopped the gateway. On the standalone profile such a target is
// pending until its account signs in; every other case keeps the failure.
func TestEnterpriseHookVerifyOrRepairTargetStandaloneRevokedRuntimeIsPending(t *testing.T) {
	stubSecureClientSignInReconcile(t)
	previousCfg := cfg
	t.Cleanup(func() { cfg = previousCfg })
	standalone := &config.Config{DeploymentMode: string(managed.DeploymentModeManagedEnterprise), Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
	cfg = standalone

	const absent = "enterprise hooks: managed runtime selector is absent: file does not exist"
	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{}, errors.New(absent)
	}
	sessionAvailable := false
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return sessionAvailable, nil }
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "", false, nil }
	installs := 0
	enterpriseHookReconcileInstaller = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		installs++
		return enterprisehooks.InstallResult{}, nil
	}
	var pendingProof error
	deferredAvailable, proofCalls := false, 0
	enterpriseHookReconcileDeferredSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) {
		proofCalls++
		return deferredAvailable, pendingProof
	}
	secureClient := false
	enterpriseHookReconcileSecureClient = func() bool { return secureClient }
	opts := enterprisehooks.InstallOptions{ConnectorName: "cursor"}
	deferred := enterprisehooks.ManifestTarget{Connector: "cursor", SID: "S-1-5-21-1-2-3-1007", Deferred: true}
	signedOutRepair := "enterprise hooks: protected target requires repair but its exact active Windows session is unavailable"

	_, repaired, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true)
	if !errors.Is(err, errEnterpriseHookProtectionRetired) || !enterprisehooks.IsWindowsTargetSessionUnavailable(err) ||
		repaired || installs != 0 || !strings.Contains(err.Error(), absent) {
		t.Fatalf("standalone target with no runtime selected: err=%v repaired=%t installs=%d, want the retired session-unavailable error", err, repaired, installs)
	}

	// A target that still has a runtime selected, whose state therefore
	// changed while the account was signed out, stays a failure.
	pendingProof = errors.New("managed runtime selector is present for the target")
	if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); err == nil ||
		errors.Is(err, errEnterpriseHookProtectionRetired) || !strings.HasPrefix(err.Error(), signedOutRepair) {
		t.Fatalf("target that still has a runtime: err=%v, want the signed-out repair failure", err)
	}
	pendingProof = nil
	// A target that is not deferred keeps the failure.
	if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), enterprisehooks.ManifestTarget{Connector: "cursor"}, opts, true); err == nil ||
		errors.Is(err, errEnterpriseHookProtectionRetired) || !strings.HasPrefix(err.Error(), signedOutRepair) {
		t.Fatalf("non-deferred target: err=%v, want the signed-out repair failure", err)
	}
	// The session came back between the checks: no pending claim is made.
	deferredAvailable = true
	if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); err == nil ||
		errors.Is(err, errEnterpriseHookProtectionRetired) {
		t.Fatalf("session available at the recheck: err=%v, want the signed-out repair failure", err)
	}
	deferredAvailable = false
	// Outside the standalone profile the failure is kept (the unmanaged and
	// unconfigured process).
	cfg = nil
	if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); err == nil ||
		errors.Is(err, errEnterpriseHookProtectionRetired) || !strings.HasPrefix(err.Error(), signedOutRepair) {
		t.Fatalf("no standalone config: err=%v, want the signed-out repair failure", err)
	}
	cfg = standalone

	// An account with an active session is repaired as before, and its
	// runtime selection is never consulted.
	sessionAvailable = true
	callsBefore := proofCalls
	if _, repaired, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); err != nil || !repaired || installs != 1 {
		t.Fatalf("signed-in account: err=%v repaired=%t installs=%d, want one repair", err, repaired, installs)
	}
	if proofCalls != callsBefore {
		t.Fatal("the pending proof was consulted for an account with an active session")
	}
	sessionAvailable = false

	// Secure Client pin: it keeps its own branch, with or without a
	// standalone-looking config, and its failure for a target that still has
	// a runtime.
	secureClient = true
	pendingProof = errors.New("managed runtime selector is present for the target")
	if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); err == nil ||
		errors.Is(err, errEnterpriseHookProtectionRetired) || !strings.HasPrefix(err.Error(), signedOutRepair) {
		t.Fatalf("Secure Client target with a runtime: err=%v, want the signed-out repair failure", err)
	}
	pendingProof = nil
	if _, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true); !errors.Is(err, errEnterpriseHookProtectionRetired) {
		t.Fatalf("Secure Client retired target: err=%v, want the retired error it always returned", err)
	}
}
