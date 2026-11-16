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
// enrollment is revoked as for any signed-out protected account. Any other
// failed row with an error is a failed target, torn down as possibly wired;
// a failed row with no error, or a wrong count, is refused.
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
	pendingTargets, failedTargets, err := windowsManagedHooksTargetsFromGuardian(runtimeDir, manifestPath, manifestSHA256, targets)
	if err != nil {
		t.Fatalf("teardown refused raw 0/0/6 records waiting for a sign-in: %v", err)
	}
	if len(pendingTargets) != 0 || len(failedTargets) != 0 {
		t.Fatalf("waiting rows were classified pending %+v or failed %+v", pendingTargets, failedTargets)
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
		if _, _, err := validateWindowsManagedHooksGuardianActivation(a, z, s, c, manifestSHA256); err == nil {
			t.Fatalf("%s: teardown accepted the records", name)
		}
	}
	// A row that is not waiting for a sign-in is a failed target of a
	// degraded guardian: accepted, and torn down as possibly wired.
	failed := func(name string, mutate func(*enterpriseHookGuardianState, *windowsManagedHooksLifecycleContext)) {
		t.Helper()
		s, c := state, ctx
		s.Results = append([]enterpriseHookReconcileRow(nil), state.Results...)
		c.targets = append([]windowsManagedHooksTeardownTarget(nil), ctx.targets...)
		mutate(&s, &c)
		_, failedTargets, err := validateWindowsManagedHooksGuardianActivation(activation, authorization, s, c, manifestSHA256)
		if err != nil {
			t.Fatalf("%s: teardown refused a failed target: %v", name, err)
		}
		if len(failedTargets) != 1 || failedTargets[0].Connector != s.Results[0].Connector ||
			!strings.EqualFold(failedTargets[0].SID, s.Results[0].SID) {
			t.Fatalf("%s: failed targets = %+v, want only %s/%s", name, failedTargets, s.Results[0].Connector, s.Results[0].SID)
		}
	}
	failed("another failure", func(s *enterpriseHookGuardianState, _ *windowsManagedHooksLifecycleContext) {
		s.Results[0].Error = "enterprise hooks: write managed Claude Code hook runtime: access is denied"
	})
	failed("non-deferred target", func(_ *enterpriseHookGuardianState, c *windowsManagedHooksLifecycleContext) {
		for index := range c.targets {
			if c.targets[index].Connector == state.Results[0].Connector && strings.EqualFold(c.targets[index].SID, state.Results[0].SID) {
				c.targets[index].Deferred = false
			}
		}
	})
	refuse("failed row without an error", func(_ *enterpriseHookGuardianActivation, _ *enterpriseHookGuardianAuthorization, s *enterpriseHookGuardianState, _ *windowsManagedHooksLifecycleContext) {
		s.Results[0].Error = ""
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

// #1105, GAP-0211: the 1.0.2 -> 1.0.3 upgrade classifies the 1.0.2
// guardian's records. A signed-out account whose only failure is its own
// DefenseClaw folder's permissions waits for its next sign-in, like a row
// an earlier release protected, and keeps its carried-forward protected
// row. Another account's folder, a connected account's row and a target not
// authorized for deferred enrollment are failed targets of a degraded
// guardian instead: accepted, and torn down as possibly wired.
func TestWindowsManagedHooksLegacyActivationAcceptsSignedOutUntrustedFolder(t *testing.T) {
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
	manifestSHA256 := strings.Repeat("b", 64)
	folderError := func(dataDir string) string {
		return "enterprise hooks: protected target requires repair but its exact active Windows session is unavailable " +
			"(verification: enterprise hooks: managed hook directory verification failed: enterprise hooks: managed Windows DACL on " +
			filepath.Join(dataDir, "hooks") + " has 8 ACEs, expected 7)"
	}

	var targets []windowsManagedHooksTeardownTarget
	var protected, failing []enterpriseHookReconcileRow
	for index, sid := range []string{"S-1-12-1-1-2-3-1017", "S-1-12-1-1-2-3-1123"} {
		home := filepath.Join(scope, sid)
		dataDir := filepath.Join(home, ".defenseclaw")
		targets = append(targets, windowsManagedHooksTeardownTarget{
			Connector: "claudecode", SID: sid, DataDir: dataDir, Deferred: true,
		})
		row := enterpriseHookReconcileRow{SID: sid, UserHome: home, Connector: "claudecode", OK: true}
		protected = append(protected, row)
		if index == 1 {
			row = enterpriseHookReconcileRow{SID: sid, UserHome: home, Connector: "claudecode", Error: folderError(dataDir)}
		}
		failing = append(failing, row)
	}
	// 1.0.2 protected both targets; its next reconcile found the signed-out
	// account's hooks folder loosened.
	if err := writeEnterpriseHookGuardianState(runtimeDir, manifestPath, manifestSHA256, protected, 0, true); err != nil {
		t.Fatal(err)
	}
	if err := writeEnterpriseHookGuardianState(runtimeDir, manifestPath, manifestSHA256, failing, 1, true); err != nil {
		t.Fatal(err)
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
	if err := validateLegacyWindowsManagedHooksGuardianActivation(activation, authorization, state, ctx, manifestSHA256); err != nil {
		t.Fatalf("the upgrade refused a signed-out account's untrusted folder: %v", err)
	}
	if _, failedTargets, err := validateWindowsManagedHooksGuardianActivation(activation, authorization, state, ctx, manifestSHA256); err != nil || len(failedTargets) != 0 {
		t.Fatalf("the waiting row was classified failed: %+v (%v)", failedTargets, err)
	}
	failed := func(name string, mutate func(*enterpriseHookGuardianState, *windowsManagedHooksLifecycleContext)) {
		t.Helper()
		s, c := state, ctx
		s.Results = append([]enterpriseHookReconcileRow(nil), state.Results...)
		c.targets = append([]windowsManagedHooksTeardownTarget(nil), ctx.targets...)
		mutate(&s, &c)
		if err := validateLegacyWindowsManagedHooksGuardianActivation(activation, authorization, s, c, manifestSHA256); err != nil {
			t.Fatalf("%s: the upgrade refused a failed target: %v", name, err)
		}
		_, failedTargets, err := validateWindowsManagedHooksGuardianActivation(activation, authorization, s, c, manifestSHA256)
		if err != nil || len(failedTargets) != 1 || !strings.EqualFold(failedTargets[0].SID, targets[1].SID) {
			t.Fatalf("%s: failed targets = %+v (%v), want only %s", name, failedTargets, err, targets[1].SID)
		}
	}
	failed("another account's folder", func(s *enterpriseHookGuardianState, _ *windowsManagedHooksLifecycleContext) {
		s.Results[1].Error = folderError(targets[0].DataDir)
	})
	failed("connected account", func(s *enterpriseHookGuardianState, _ *windowsManagedHooksLifecycleContext) {
		s.Results[1].Error = "enterprise hooks: managed hook directory verification failed: enterprise hooks: managed Windows DACL on " +
			filepath.Join(targets[1].DataDir, "hooks") + " has 8 ACEs, expected 7"
	})
	failed("non-deferred target", func(_ *enterpriseHookGuardianState, c *windowsManagedHooksLifecycleContext) {
		c.targets[1].Deferred = false
	})
	s := state
	s.Results = append([]enterpriseHookReconcileRow(nil), state.Results...)
	s.Results[1].Error = ""
	if err := validateLegacyWindowsManagedHooksGuardianActivation(activation, authorization, s, ctx, manifestSHA256); err == nil {
		t.Fatal("the upgrade accepted a failed row without an error")
	}
}
