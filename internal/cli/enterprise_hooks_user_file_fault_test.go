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
)

// GAP-0031 (WC1d): when the only fault of a row is a file in the account's
// own profile (on Windows, Claude settings the migration cannot finish),
// verify fails that row and names the file, and nothing else: the guardian,
// whose readiness reports the file as a warning, recorded the row protected,
// so verify does not add "protected ... target dispositions do not match" as
// a second fault. Any other failure of a row the guardian recorded protected
// still reports the records as stale, and the fault excuses nothing the
// guardian itself recorded as failed.
func TestVerifyComparesAUserFileOnlyFaultAsProtected(t *testing.T) {
	f := newVerifyRecordedProtectionFixture(t)
	settings := filepath.Join(f.scope, "Bob", ".claude", "settings.json")
	userFile := fmt.Errorf("enterprise hooks: copilot VS Code Local hooks: %w", enterpriseHookUserFileFault{
		err: fmt.Errorf("DefenseClaw cannot check %s for its older per-user hooks (invalid character); until the file is valid JSON or removed, Copilot CLI in a project under the home and Cursor block their tool calls on it", settings),
	})
	bob, reconcile, verify := f.bob, f.reconcile, f.verify

	// The guardian's pass and Setup readiness record Bob protected (the
	// file is a warning there); public verify fails his row on the file.
	reconcile(0)
	f.verifyErr = userFile
	run := verify("user file only")
	if run.Failures != 1 || len(run.Excused) != 0 {
		t.Fatalf("user file only: failures=%d excused=%d, want Bob's row failed and not excused: %+v", run.Failures, len(run.Excused), run.Rows)
	}
	for _, row := range run.Rows {
		if (row.SID == bob) == row.OK || (row.SID == bob && !strings.Contains(row.Error, settings)) {
			t.Fatalf("user file only: row %+v, want only Bob's row failed, naming %s", row, settings)
		}
	}
	if run.AuthorizationErr != nil {
		t.Fatalf("user file only: the protected records are reported as a second fault: %v", run.AuthorizationErr)
	}

	// Control: another failure of a row the guardian recorded protected
	// still reports the records as not matching current verification.
	f.verifyErr = errors.New("enterprise hooks: connector codex hook verification failed: owned hook command not present")
	run = verify("other fault")
	if run.Failures != 1 || run.AuthorizationErr == nil || !strings.Contains(run.AuthorizationErr.Error(), "target dispositions do not match") {
		t.Fatalf("other fault: failures=%d authorization=%v, want the records reported as stale", run.Failures, run.AuthorizationErr)
	}

	// Control: the fault excuses nothing the guardian recorded as failed.
	f.guardianErr = errors.New("enterprise hooks: connector codex hook installation failed")
	reconcile(1)
	f.verifyErr = userFile
	run = verify("guardian recorded the row failed")
	if run.AuthorizationErr == nil {
		t.Fatalf("guardian recorded the row failed: verify accepted the records: rows=%+v", run.Rows)
	}
}

// rel-1-0-10 GAP-1256: an elevated Administrator's verify cannot read the
// route-only account files (only LocalSystem can), so the row fails with
// route_config_unverified, and that is all it reports: the protected
// activation and authorization the guardian (as SYSTEM) recorded for that
// target are compared as protected, not as "extra or stale target" or a
// disposition mismatch. Verify still fails on the row. Only the unverified
// target is compared so: a target the guardian recorded failed, or any
// other fault, still reports the records.
func TestVerifyComparesARouteOnlyUnverifiedTargetAsRecorded(t *testing.T) {
	f := newVerifyRecordedProtectionFixture(t)
	bob, reconcile, verify := f.bob, f.reconcile, f.verify

	reconcile(0)
	f.routeOnlyUnverified = true
	run := verify("route-only unverified")
	if run.Failures != 1 || len(run.Excused) != 0 {
		t.Fatalf("route-only unverified: failures=%d excused=%d, want Bob's row failed and not excused: %+v", run.Failures, len(run.Excused), run.Rows)
	}
	for _, row := range run.Rows {
		if (row.SID == bob) == row.OK || (row.SID == bob && !strings.Contains(row.Error, enterprisehooks.RouteConfigUnverifiedCode)) {
			t.Fatalf("route-only unverified: row %+v, want only Bob's row failed with %s", row, enterprisehooks.RouteConfigUnverifiedCode)
		}
	}
	if run.AuthorizationErr != nil {
		t.Fatalf("route-only unverified: the protected records are compared against the partial verification: %v", run.AuthorizationErr)
	}

	// Control: another fault of the same target still reports the records.
	f.routeOnlyUnverified = false
	f.verifyErr = errors.New("enterprise hooks: connector codex hook verification failed: owned hook command not present")
	run = verify("other fault")
	if run.Failures != 1 || run.AuthorizationErr == nil || !strings.Contains(run.AuthorizationErr.Error(), "target dispositions do not match") {
		t.Fatalf("other fault: failures=%d authorization=%v, want the records reported as stale", run.Failures, run.AuthorizationErr)
	}

	// Control: a target the guardian recorded failed is not excused.
	f.verifyErr = nil
	f.guardianErr = errors.New("enterprise hooks: connector codex hook installation failed")
	reconcile(1)
	f.routeOnlyUnverified = true
	run = verify("guardian recorded the row failed")
	if run.Failures != 1 || run.AuthorizationErr == nil {
		t.Fatalf("guardian recorded the row failed: failures=%d, verify accepted the records: rows=%+v", run.Failures, run.Rows)
	}
}

// verifyRecordedProtectionFixture is a two-account (Alice, Bob) codex
// manifest with a guardian pass and a live verify whose outcome for Bob the
// test sets: guardianErr fails his guardian row, verifyErr his live verify,
// and routeOnlyUnverified returns his result with route-only unverified.
type verifyRecordedProtectionFixture struct {
	scope, bob             string
	guardianErr, verifyErr error
	routeOnlyUnverified    bool
	reconcile              func(wantFailures int)
	verify                 func(name string) enterpriseHookVerifyRun
}

func newVerifyRecordedProtectionFixture(t *testing.T) *verifyRecordedProtectionFixture {
	t.Helper()
	f := &verifyRecordedProtectionFixture{}
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
	enterprisehooks.SetStandaloneUnix(true)
	enterpriseHookReconcileSecureClient = func() bool { return false }
	enterpriseHookHermesSignedOutApplies = func() bool { return false }
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "", false, nil }
	enterpriseHookReconcileTargetFailModeChange = func(enterprisehooks.InstallOptions) (string, string, error) { return "", "", nil }

	scope := t.TempDir()
	f.scope = scope
	dataDir := filepath.Join(scope, "runtime")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	alice, bob := "S-1-5-21-1-2-3-1017", "S-1-5-21-1-2-3-1018"
	var manifestBody strings.Builder
	manifestBody.WriteString("version: 1\ntargets:\n")
	for _, target := range []struct{ name, sid string }{{"Alice", alice}, {"Bob", bob}} {
		home := filepath.Join(scope, target.name)
		if err := os.MkdirAll(home, 0o700); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&manifestBody,
			"  - user_home: %q\n    uid: %d\n    gid: %d\n    sid: %s\n    connector: codex\n    enabled: true\n    deferred: true\n",
			home, os.Getuid(), os.Getgid(), target.sid)
	}
	manifestPath := filepath.Join(scope, "targets.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifestBody.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = &config.Config{DataDir: dataDir, DeploymentMode: "local"}
	enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = manifestPath, "127.0.0.1:18970", "127.0.0.1:4000"
	if _, err := connector.EnsureHookAPIToken(dataDir, "codex"); err != nil {
		t.Fatal(err)
	}
	if scope, ok := connector.OTLPPathTokenScopeForConnector("codex"); ok {
		if _, err := connector.EnsureOTLPPathToken(dataDir, scope); err != nil {
			t.Fatal(err)
		}
	}
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return true, nil }
	enterpriseHookReconcileDeferredSessionAvailable = enterpriseHookReconcileSessionAvailable
	f.bob = bob
	stub := func(err *error, live bool) func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
			if opts.OwnerSID == bob && *err != nil {
				return enterprisehooks.InstallResult{}, *err
			}
			result := enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}
			if live && opts.OwnerSID == bob && f.routeOnlyUnverified {
				result.RouteOnly = enterprisehooks.RouteOnlyUnverified
			}
			return result, nil
		}
	}
	enterpriseHookReconcileInstaller, enterpriseHookReconcileVerifier = stub(&f.guardianErr, false), stub(&f.guardianErr, false)
	enterpriseHookLivePublicVerifier, enterpriseHookLiveRegistrationVerifier = stub(&f.verifyErr, true), stub(&f.verifyErr, true)
	f.reconcile = func(wantFailures int) {
		t.Helper()
		run, err := runEnterpriseHookReconcileOnce(context.Background())
		if err != nil || run.StateErr != nil || run.Failures != wantFailures {
			t.Fatalf("guardian pass: run=%+v err=%v, want %d failure(s)", run, err, wantFailures)
		}
	}
	f.verify = func(name string) enterpriseHookVerifyRun {
		t.Helper()
		run, err := runEnterpriseHookVerifyAttemptWithScope(context.Background(), false)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return run
	}
	return f
}
