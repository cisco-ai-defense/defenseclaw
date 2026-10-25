// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hermespath"
)

// GAP-1433: a managed Windows account that signs out unloads its registry
// hive, so the HERMES_HOME it selects cannot be read. The guardian's
// verification of its previously protected Hermes target failed and, with no
// session to repair in, became a host failure (Setup verify 1603). Its Hermes
// is unobservable, not changed: the target now waits for the account's next
// sign-in, reported NOT COVERED, and every other cause still fails.
func TestEnterpriseHookVerifyOrRepairTargetLeavesSignedOutHermesToTheNextSignIn(t *testing.T) {
	previousVerifier, previousInstaller := enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller
	previousSession, previousRelease := enterpriseHookReconcileSessionAvailable, enterpriseHookReconcileTargetRelease
	previousSecureClient, previousChange := enterpriseHookReconcileSecureClient, enterpriseHookReconcileTargetFailModeChange
	t.Cleanup(func() {
		enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller = previousVerifier, previousInstaller
		enterpriseHookReconcileSessionAvailable, enterpriseHookReconcileTargetRelease = previousSession, previousRelease
		enterpriseHookReconcileSecureClient, enterpriseHookReconcileTargetFailModeChange = previousSecureClient, previousChange
	})
	secureClient := false
	enterpriseHookReconcileSecureClient = func() bool { return secureClient }
	// This release wrote the lock, and the fail mode did not change: before
	// GAP-1433 such a target always failed while its account was signed out.
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "", false, nil }
	enterpriseHookReconcileTargetFailModeChange = func(enterprisehooks.InstallOptions) (string, string, error) { return "", "", nil }
	signedIn := false
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return signedIn, nil }
	signedOut := fmt.Errorf("enterprise hooks: connector hermes hook verification failed: hermes hooks not verified: "+
		"resolve the Hermes home of C:\\Users\\dcw-std2: %w: %w", hermespath.ErrAccountEnvironmentUnavailable, hermespath.ErrAccountSignedOut)
	verifyErr := signedOut
	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{}, verifyErr
	}
	installs := 0
	enterpriseHookReconcileInstaller = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		installs++
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName}, nil
	}
	hermes := enterprisehooks.ManifestTarget{SID: "S-1-5-21-1-2-3-1018", Connector: "hermes", Deferred: true}
	run := func(target enterprisehooks.ManifestTarget) (bool, error) {
		_, repaired, err := enterpriseHookVerifyOrRepairTarget(context.Background(), target,
			enterprisehooks.InstallOptions{ConnectorName: target.Connector}, true)
		return repaired, err
	}
	waits := func(err error) bool {
		return err != nil && strings.HasPrefix(err.Error(), enterpriseHookAwaitingSignInPrefix+": "+enterpriseHookAwaitingSignInHermesHome) &&
			errors.Is(err, errEnterpriseHookAwaitingSignIn) && strings.Contains(err.Error(), "NOT COVERED")
	}

	_, err := run(hermes)
	if !waits(err) || installs != 0 {
		t.Fatalf("signed-out Hermes: err=%v installs=%d, want the Hermes sign-in wait and no install", err, installs)
	}
	if cause := enterpriseHookAwaitingSignInCause(err.Error()); !strings.Contains(cause, "Hermes NOT COVERED") ||
		strings.Contains(cause, "earlier DefenseClaw release") {
		t.Fatalf("status cause = %q, want the Hermes signed-out reason", cause)
	}
	row := enterpriseHookReconcileRow{SID: hermes.SID, Connector: "hermes", Error: err.Error()}
	if !enterpriseHookAwaitingSignInError(row) {
		t.Fatalf("the guardian row %q is not a sign-in wait status and verify excuse", row.Error)
	}

	// The account signs in: the guardian repairs the target in its session.
	signedIn = true
	if repaired, err := run(hermes); err != nil || !repaired || installs != 1 {
		t.Fatalf("signed-in Hermes: repaired=%v err=%v installs=%d, want a repair", repaired, err, installs)
	}
	signedIn = false

	// Every other cause stays a failure.
	for name, tc := range map[string]struct {
		target enterprisehooks.ManifestTarget
		err    error
		sc     bool
	}{
		"owned hook removed": {hermes, errors.New("enterprise hooks: connector hermes hook verification failed: canonical hook matrix is absent"), false},
		"unreadable profile": {hermes, fmt.Errorf("resolve the Hermes home: %w: no profile names it", hermespath.ErrAccountEnvironmentUnavailable), false},
		"non-Hermes":         {enterprisehooks.ManifestTarget{SID: hermes.SID, Connector: "codex", Deferred: true}, signedOut, false},
		"not deferred":       {enterprisehooks.ManifestTarget{SID: hermes.SID, Connector: "hermes"}, signedOut, false},
		"Secure Client":      {hermes, signedOut, true},
	} {
		verifyErr, secureClient = tc.err, tc.sc
		if _, err := run(tc.target); err == nil || errors.Is(err, errEnterpriseHookAwaitingSignIn) {
			t.Fatalf("%s: err=%v, want the signed-out repair failure", name, err)
		}
	}
}

// One target's own guardian failure never fails another target's
// registration readiness (the hot-config undo and Setup readiness of the
// rest): readiness proves every other target from the consistent protected
// records of that pass and stays not ok for the failed one. Public verify
// keeps requiring a complete pass, and a record that does not match the
// current targets still refuses protected authorization.
func TestRegistrationReadinessScopesAnotherTargetsGuardianFailure(t *testing.T) {
	restoreEnterpriseHooksLifecycleTestState(t)
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	stubEnterpriseHookTokenSources(t)
	previousManifest, previousAPI, previousProxy := enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr
	previousVerifier, previousInstaller := enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller
	previousPublic, previousCleanup := enterpriseHookLivePublicVerifier, enterpriseForeignHookCleanup
	previousStateTrust, previousManifestTrust := enterpriseHookGuardianStateFileTrustCheck, enterpriseHookManifestFileTrustCheck
	t.Cleanup(func() {
		enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = previousManifest, previousAPI, previousProxy
		enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller = previousVerifier, previousInstaller
		enterpriseHookLivePublicVerifier, enterpriseForeignHookCleanup = previousPublic, previousCleanup
		enterpriseHookGuardianStateFileTrustCheck, enterpriseHookManifestFileTrustCheck = previousStateTrust, previousManifestTrust
	})
	enterpriseForeignHookCleanup = func(enterprisehooks.TargetCredentials, string, string) (enterprisepolicy.CleanupResult, error) {
		return enterprisepolicy.CleanupResult{}, nil
	}
	enterpriseHookGuardianStateFileTrustCheck = func(string) error { return nil }
	enterpriseHookManifestFileTrustCheck = func(string) error { return nil }

	scope := t.TempDir()
	dataDir := filepath.Join(scope, "runtime")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	accounts := []struct{ name, sid string }{
		{"Alice", "S-1-5-21-1-2-3-1017"},
		{"Bob", "S-1-5-21-1-2-3-1018"},
	}
	var manifestBody strings.Builder
	manifestBody.WriteString("version: 1\ntargets:\n")
	for _, account := range accounts {
		home := filepath.Join(scope, account.name)
		if err := os.MkdirAll(home, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, connectorName := range []string{"claudecode", "codex"} {
			fmt.Fprintf(&manifestBody,
				"  - user_home: %q\n    uid: %d\n    gid: %d\n    sid: %s\n    connector: %s\n    enabled: true\n",
				home, os.Getuid(), os.Getgid(), account.sid, connectorName)
		}
	}
	manifestPath := filepath.Join(scope, "targets.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifestBody.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = &config.Config{DataDir: dataDir, DeploymentMode: "local"}
	enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = manifestPath, "127.0.0.1:18970", "127.0.0.1:4000"
	failing := map[string]bool{accounts[1].sid + "/codex": true}
	result := func(opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if failing[opts.OwnerSID+"/"+opts.ConnectorName] {
			return enterprisehooks.InstallResult{}, errors.New("enterprise hooks: write managed Codex hook runtime: access is denied")
		}
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	enterpriseHookReconcileInstaller = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return result(opts)
	}
	enterpriseHookReconcileVerifier = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return result(opts)
	}
	enterpriseHookLivePublicVerifier = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return result(opts)
	}
	reconciled, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil || reconciled.StateErr != nil || reconciled.Failures != 1 {
		t.Fatalf("guardian pass: run=%+v err=%v, want exactly Bob's Codex failed", reconciled, err)
	}

	// Verification reads the scoped hook tokens the guardian published.
	for _, connectorName := range []string{"claudecode", "codex"} {
		if _, err := connector.EnsureHookAPIToken(dataDir, connectorName); err != nil {
			t.Fatal(err)
		}
		if scope, ok := connector.OTLPPathTokenScopeForConnector(connectorName); ok {
			if _, err := connector.EnsureOTLPPathToken(dataDir, scope); err != nil {
				t.Fatal(err)
			}
		}
	}
	readiness, err := runEnterpriseHookVerifyAttemptWithScope(context.Background(), true)
	if err != nil || readiness.AuthorizationErr != nil {
		t.Fatalf("readiness refused protected authorization for another target's failure: err=%v authorization=%v", err, readiness.AuthorizationErr)
	}
	proven, failed := 0, 0
	for _, row := range readiness.Rows {
		switch {
		case row.OK:
			proven++
		case row.SID == accounts[1].sid && row.Connector == "codex":
			failed++
		default:
			t.Fatalf("readiness row %+v, want only Bob's Codex failed", row)
		}
	}
	if proven != 3 || failed != 1 || readiness.Failures != 1 || len(readiness.Excused) != 0 {
		t.Fatalf("readiness = %d proven, %d failed, run %+v; want 3 proven and the failure kept", proven, failed, readiness)
	}
	public, err := runEnterpriseHookVerifyAttemptWithScope(context.Background(), false)
	if err != nil || public.AuthorizationErr == nil {
		t.Fatalf("public verify accepted an incomplete guardian pass: err=%v authorization=%v", err, public.AuthorizationErr)
	}

	// The failed target now verifies, but no protected record authorizes
	// it yet: readiness does not claim it until the guardian protects it.
	delete(failing, accounts[1].sid+"/codex")
	stale, err := runEnterpriseHookVerifyAttemptWithScope(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range stale.Rows {
		if row.SID == accounts[1].sid && row.Connector == "codex" && (row.OK || !strings.Contains(row.Error, "protected authorization does not cover target")) {
			t.Fatalf("readiness claimed a target no protected record authorizes: %+v", row)
		}
	}
	// A different target fails than the one the records name.
	failing[accounts[0].sid+"/claudecode"] = true
	if swapped, err := runEnterpriseHookVerifyAttemptWithScope(context.Background(), true); err != nil || swapped.AuthorizationErr == nil {
		t.Fatalf("readiness accepted a failure the protected records do not name: err=%v authorization=%v", err, swapped.AuthorizationErr)
	}
}

// GAP-1433 on the verify side: a managed Windows account that signs out
// leaves its previously protected Hermes target unobservable. Readiness and
// public verify report it pending until the account signs in (Hermes NOT
// COVERED) instead of failing the host, both before and after the guardian
// records the wait, and while its hive comes back for another logon. Any
// other failure of that target, and the same error for another connector,
// still fail.
func TestVerifyLeavesASignedOutHermesTargetToTheNextSignIn(t *testing.T) {
	restoreEnterpriseHooksLifecycleTestState(t)
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	stubEnterpriseHookTokenSources(t)
	previousManifest, previousAPI, previousProxy := enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr
	previousVerifier, previousInstaller := enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller
	previousPublic, previousRegistration := enterpriseHookLivePublicVerifier, enterpriseHookLiveRegistrationVerifier
	previousSession, previousDeferredSession := enterpriseHookReconcileSessionAvailable, enterpriseHookReconcileDeferredSessionAvailable
	previousRelease, previousChange := enterpriseHookReconcileTargetRelease, enterpriseHookReconcileTargetFailModeChange
	previousSecureClient, previousApplies := enterpriseHookReconcileSecureClient, enterpriseHookHermesSignedOutApplies
	previousCleanup := enterpriseForeignHookCleanup
	previousStateTrust, previousManifestTrust := enterpriseHookGuardianStateFileTrustCheck, enterpriseHookManifestFileTrustCheck
	previousStandaloneUnix := enterprisehooks.StandaloneUnix()
	t.Cleanup(func() {
		enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = previousManifest, previousAPI, previousProxy
		enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller = previousVerifier, previousInstaller
		enterpriseHookLivePublicVerifier, enterpriseHookLiveRegistrationVerifier = previousPublic, previousRegistration
		enterpriseHookReconcileSessionAvailable, enterpriseHookReconcileDeferredSessionAvailable = previousSession, previousDeferredSession
		enterpriseHookReconcileTargetRelease, enterpriseHookReconcileTargetFailModeChange = previousRelease, previousChange
		enterpriseHookReconcileSecureClient, enterpriseHookHermesSignedOutApplies = previousSecureClient, previousApplies
		enterpriseForeignHookCleanup = previousCleanup
		enterpriseHookGuardianStateFileTrustCheck, enterpriseHookManifestFileTrustCheck = previousStateTrust, previousManifestTrust
		enterprisehooks.SetStandaloneUnix(previousStandaloneUnix)
	})
	enterpriseForeignHookCleanup = func(enterprisehooks.TargetCredentials, string, string) (enterprisepolicy.CleanupResult, error) {
		return enterprisepolicy.CleanupResult{}, nil
	}
	enterpriseHookGuardianStateFileTrustCheck = func(string) error { return nil }
	enterpriseHookManifestFileTrustCheck = func(string) error { return nil }
	// The standalone Windows guardian and verify; off Windows only a
	// standalone manifest may carry deferred rows.
	enterprisehooks.SetStandaloneUnix(true)
	enterpriseHookReconcileSecureClient = func() bool { return false }
	enterpriseHookHermesSignedOutApplies = func() bool { return true }
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "", false, nil }
	enterpriseHookReconcileTargetFailModeChange = func(enterprisehooks.InstallOptions) (string, string, error) { return "", "", nil }

	scope := t.TempDir()
	dataDir := filepath.Join(scope, "runtime")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	alice, bob := "S-1-5-21-1-2-3-1017", "S-1-5-21-1-2-3-1018"
	var manifestBody strings.Builder
	manifestBody.WriteString("version: 1\ntargets:\n")
	for _, target := range []struct{ name, sid, connector string }{
		{"Alice", alice, "codex"}, {"Alice", alice, "hermes"}, {"Bob", bob, "codex"}, {"Bob", bob, "hermes"},
	} {
		home := filepath.Join(scope, target.name)
		if err := os.MkdirAll(home, 0o700); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&manifestBody,
			"  - user_home: %q\n    uid: %d\n    gid: %d\n    sid: %s\n    connector: %s\n    enabled: true\n    deferred: true\n",
			home, os.Getuid(), os.Getgid(), target.sid, target.connector)
	}
	manifestPath := filepath.Join(scope, "targets.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifestBody.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = &config.Config{DataDir: dataDir, DeploymentMode: "local"}
	enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = manifestPath, "127.0.0.1:18970", "127.0.0.1:4000"
	for _, connectorName := range []string{"codex", "hermes"} {
		if _, err := connector.EnsureHookAPIToken(dataDir, connectorName); err != nil {
			t.Fatal(err)
		}
		if scope, ok := connector.OTLPPathTokenScopeForConnector(connectorName); ok {
			if _, err := connector.EnsureOTLPPathToken(dataDir, scope); err != nil {
				t.Fatal(err)
			}
		}
	}
	signedIn := map[string]bool{alice: true, bob: true}
	enterpriseHookReconcileSessionAvailable = func(target enterprisehooks.ManifestTarget) (bool, error) { return signedIn[target.SID], nil }
	enterpriseHookReconcileDeferredSessionAvailable = enterpriseHookReconcileSessionAvailable
	signedOut := fmt.Errorf("enterprise hooks: connector hermes hook verification failed: hermes hooks not verified: "+
		"resolve the Hermes home: %w: %w", hermespath.ErrAccountEnvironmentUnavailable, hermespath.ErrAccountSignedOut)
	live := map[string]error{}
	result := func(opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if err := live[opts.OwnerSID+"/"+opts.ConnectorName]; err != nil {
			return enterprisehooks.InstallResult{}, err
		}
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	stub := func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return result(opts)
	}
	enterpriseHookReconcileInstaller, enterpriseHookReconcileVerifier = stub, stub
	enterpriseHookLivePublicVerifier, enterpriseHookLiveRegistrationVerifier = stub, stub
	reconcile := func(wantFailures int) {
		t.Helper()
		run, err := runEnterpriseHookReconcileOnce(context.Background())
		if err != nil || run.StateErr != nil || run.Failures != wantFailures {
			t.Fatalf("guardian pass: run=%+v err=%v, want %d failure(s)", run, err, wantFailures)
		}
	}
	check := func(name string, wantOK, bobWaits bool) {
		t.Helper()
		// Setup readiness and the hot-config undo read the registration
		// scope; public verify never attests a managed Hermes home (GAP-0766).
		for _, registration := range []bool{true} {
			run, err := runEnterpriseHookVerifyAttemptWithScope(context.Background(), registration)
			if err != nil {
				t.Fatalf("%s (registration=%t): %v", name, registration, err)
			}
			ok := run.Failures-len(run.Excused) == 0 && run.AuthorizationErr == nil
			if ok != wantOK {
				t.Fatalf("%s (registration=%t): ok=%t, want %t; authorization=%v rows=%+v", name, registration, ok, wantOK, run.AuthorizationErr, run.Rows)
			}
			if !wantOK {
				continue
			}
			for _, row := range run.Rows {
				if bobWaits && row.SID == bob && row.Connector == "hermes" {
					note := enterpriseHookVerifyExcusedNote(run, row)
					if row.OK || !enterpriseHookVerifyRowExcused(run, row) || !strings.Contains(note, "Hermes NOT COVERED") {
						t.Fatalf("%s (registration=%t): Bob's Hermes row %+v note %q, want pending until sign-in, NOT COVERED", name, registration, row, note)
					}
				} else if !row.OK {
					t.Fatalf("%s (registration=%t): row %+v failed", name, registration, row)
				}
			}
		}
	}

	reconcile(0)
	check("both signed in", true, false)

	// Bob signs out; the guardian has not run since.
	signedIn[bob] = false
	live[bob+"/hermes"] = signedOut
	check("signed out before the guardian pass", true, true)
	// The guardian records the wait.
	reconcile(1)
	check("signed out after the guardian pass", true, true)
	// Another logon loads Bob's hive: live verification passes, but the
	// guardian has not verified the target since he signed out.
	delete(live, bob+"/hermes")
	check("hive loaded while signed out", true, true)

	// GAP-1433 as observed: an upgrade from 1.0.2 while Bob is signed out
	// leaves his Hermes target waiting for his sign-in (an earlier release
	// protected it), and an elevated administrator's verify cannot query
	// his session. The LocalSystem guardian's record of the wait stands.
	previousNotLocalSystem := enterpriseHookSessionCheckNotLocalSystem
	t.Cleanup(func() { enterpriseHookSessionCheckNotLocalSystem = previousNotLocalSystem })
	errNotLocalSystem := errors.New("enterprise hooks: process is not LocalSystem")
	enterpriseHookSessionCheckNotLocalSystem = func(err error) bool { return errors.Is(err, errNotLocalSystem) }
	signedIn[bob] = true
	delete(live, bob+"/hermes")
	reconcile(0)
	signedIn[bob] = false
	live[bob+"/hermes"] = errors.New("enterprise hooks: connector hermes hook verification failed: canonical hook matrix is absent: owned hook command not present")
	enterpriseHookReconcileTargetRelease = func(opts enterprisehooks.InstallOptions) (string, bool, error) {
		return "1.0.2", opts.OwnerSID == bob && opts.ConnectorName == "hermes", nil
	}
	reconcile(1)
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "", false, nil }
	adminView := func(target enterprisehooks.ManifestTarget) (bool, error) {
		if target.SID == bob {
			return false, errNotLocalSystem
		}
		return true, nil
	}
	enterpriseHookReconcileSessionAvailable = adminView
	checkNote := func(name, want string) {
		t.Helper()
		run, err := runEnterpriseHookVerifyAttemptWithScope(context.Background(), true)
		if err != nil || run.AuthorizationErr != nil || run.Failures != len(run.Excused) {
			t.Fatalf("%s: err=%v authorization=%v rows=%+v", name, err, run.AuthorizationErr, run.Rows)
		}
		for _, row := range run.Rows {
			if row.SID == bob && row.Connector == "hermes" && !strings.Contains(enterpriseHookVerifyExcusedNote(run, row), want) {
				t.Fatalf("%s: note %q, want %q", name, enterpriseHookVerifyExcusedNote(run, row), want)
			}
		}
	}
	checkNote("earlier release, administrator verify", "an earlier DefenseClaw release protected it")
	// Bob signs in: until the guardian repairs his target, it fails.
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return true, nil }
	if run, err := runEnterpriseHookVerifyAttemptWithScope(context.Background(), true); err != nil ||
		run.Failures == len(run.Excused) {
		t.Fatalf("signed in before the repair: err=%v rows=%+v, want the target failing", err, run.Rows)
	}
	enterpriseHookReconcileSessionAvailable = func(target enterprisehooks.ManifestTarget) (bool, error) { return signedIn[target.SID], nil }

	// Controls: any other failure of that target, or the same error of
	// another connector, while the guardian last proved it.
	signedIn[bob] = true
	delete(live, bob+"/hermes")
	reconcile(0)
	signedIn[bob] = false
	live[bob+"/hermes"] = errors.New("enterprise hooks: connector hermes hook verification failed: canonical hook matrix is absent")
	check("owned hook removed", false, false)
	delete(live, bob+"/hermes")
	live[bob+"/codex"] = signedOut
	check("non-Hermes signed-out error", false, false)
}
