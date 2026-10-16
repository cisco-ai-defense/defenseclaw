// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-0644 fix-up: teardown prepare reads the guardian records of an
// upgrade whose accounts still wait for their next sign-in (raw 0/0/6). It
// takes those rows as active, carried-forward protected targets, so their
// enrollment is revoked as for any signed-out protected account, and refuses
// any other failed row or count.
func TestWindowsManagedHooksTeardownAcceptsTargetsAwaitingSignIn(t *testing.T) {
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	previousStateTrust, previousOwnership := enterpriseHookGuardianStateFileTrustCheck, enterpriseHookAuthorizationOwnershipSetter
	t.Cleanup(func() {
		enterpriseHookGuardianStateFileTrustCheck, enterpriseHookAuthorizationOwnershipSetter = previousStateTrust, previousOwnership
	})
	enterpriseHookGuardianStateFileTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	previousCfg := cfg
	t.Cleanup(func() { cfg = previousCfg })
	cfg = nil

	scope := t.TempDir()
	runtimeDir := filepath.Join(scope, "runtime")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	manifestPath := filepath.Join(scope, "targets.yaml")
	manifestSHA256 := strings.Repeat("a", 64)

	var targets []windowsManagedHooksTeardownTarget
	var protected, waiting []enterpriseHookReconcileRow
	for _, sid := range []string{"S-1-12-1-1-2-3-1001", "S-1-12-1-1-2-3-1002", "S-1-12-1-1-2-3-1003"} {
		home := filepath.Join(scope, sid)
		for _, connectorName := range []string{"claudecode", "codex"} {
			targets = append(targets, windowsManagedHooksTeardownTarget{
				Connector: connectorName, SID: sid, DataDir: filepath.Join(home, ".defenseclaw"), Deferred: true,
			})
			protected = append(protected, enterpriseHookReconcileRow{SID: sid, UserHome: home, Connector: connectorName, OK: true})
			waiting = append(waiting, enterpriseHookReconcileRow{
				SID: sid, UserHome: home, Connector: connectorName,
				Error: enterpriseHookAwaitingSignInPrefix + ": DefenseClaw 1.0.2-rc.3 protected it ... (verification: lock drift)",
			})
		}
	}
	// rc.3 protected the six targets; the upgraded guardian left them waiting.
	if err := writeEnterpriseHookGuardianState(runtimeDir, manifestPath, manifestSHA256, protected, 0, true); err != nil {
		t.Fatal(err)
	}
	if err := writeEnterpriseHookGuardianState(runtimeDir, manifestPath, manifestSHA256, waiting, len(waiting), true); err != nil {
		t.Fatal(err)
	}
	pendingTargets, err := windowsManagedHooksPendingTargetsFromGuardian(runtimeDir, manifestPath, manifestSHA256, targets)
	if err != nil {
		t.Fatalf("teardown refused raw 0/0/6 records waiting for a sign-in: %v", err)
	}
	if len(pendingTargets) != 0 {
		t.Fatalf("waiting rows were classified pending: %+v", pendingTargets)
	}
	for _, target := range targets {
		if !windowsManagedHooksTeardownSelectorExpected(target, pendingTargets, windowsManagedHooksActivated) {
			t.Fatalf("waiting target %+v is not torn down as an active target", target)
		}
	}

	activation, _, err := loadEnterpriseHookGuardianActivation(runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	authorization, _, err := loadEnterpriseHookGuardianAuthorization(runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err := loadEnterpriseHookGuardianState(runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := windowsManagedHooksLifecycleContext{manifestPath: manifestPath, targets: targets}
	refuse := func(name string, mutate func(*enterpriseHookGuardianActivation, *enterpriseHookGuardianAuthorization, *enterpriseHookGuardianState, *windowsManagedHooksLifecycleContext)) {
		t.Helper()
		a, z, s, c := activation, authorization, state, ctx
		a.ProtectedTargets = append([]enterpriseHookReconcileRow(nil), activation.ProtectedTargets...)
		z.ProtectedTargets = append([]enterpriseHookReconcileRow(nil), authorization.ProtectedTargets...)
		s.Results = append([]enterpriseHookReconcileRow(nil), state.Results...)
		c.targets = append([]windowsManagedHooksTeardownTarget(nil), ctx.targets...)
		mutate(&a, &z, &s, &c)
		if _, err := validateWindowsManagedHooksGuardianActivation(a, z, s, c, manifestSHA256); err == nil {
			t.Fatalf("%s: teardown accepted the records", name)
		}
	}
	refuse("another failure", func(_ *enterpriseHookGuardianActivation, _ *enterpriseHookGuardianAuthorization, s *enterpriseHookGuardianState, _ *windowsManagedHooksLifecycleContext) {
		s.Results[0].Error = "enterprise hooks: write managed Claude Code hook runtime: access is denied"
	})
	refuse("non-deferred target", func(_ *enterpriseHookGuardianActivation, _ *enterpriseHookGuardianAuthorization, _ *enterpriseHookGuardianState, c *windowsManagedHooksLifecycleContext) {
		c.targets[0].Deferred = false
	})
	refuse("runtime evidence", func(_ *enterpriseHookGuardianActivation, _ *enterpriseHookGuardianAuthorization, s *enterpriseHookGuardianState, _ *windowsManagedHooksLifecycleContext) {
		s.Results[0].Result = &enterprisehooks.InstallResult{Connector: "claudecode"}
	})
	refuse("failure count", func(a *enterpriseHookGuardianActivation, _ *enterpriseHookGuardianAuthorization, _ *enterpriseHookGuardianState, _ *windowsManagedHooksLifecycleContext) {
		a.FailureCount--
		a.SuccessCount++
	})
	refuse("claims OK", func(_ *enterpriseHookGuardianActivation, z *enterpriseHookGuardianAuthorization, _ *enterpriseHookGuardianState, _ *windowsManagedHooksLifecycleContext) {
		z.OK = true
	})
	refuse("protected row not carried forward", func(a *enterpriseHookGuardianActivation, _ *enterpriseHookGuardianAuthorization, _ *enterpriseHookGuardianState, _ *windowsManagedHooksLifecycleContext) {
		a.ProtectedTargets = a.ProtectedTargets[1:]
	})
}
