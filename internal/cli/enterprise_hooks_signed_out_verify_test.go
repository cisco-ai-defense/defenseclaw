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

// GAP-2516 (real path, live red on 5b78f1e3cf): the guardian last proved the
// Codex and Copilot targets of a signed-out account, then that account's own
// hooks folder lost its protected DACL. Setup's live readiness verify failed
// those rows (managed runtime generation directory is untrusted) while the
// guardian's records said protected, so the dispositions did not match, Setup
// failed 1603 and its rollback left the gateway and enumerator stopped for
// every user. The live verify now treats that one failure of a signed-out
// account's own folder like the guardian does: pending until the account
// signs in, compared with the records as protected. Every other case fails.
func TestVerifyLeavesASignedOutAccountsOwnFolderDriftToTheNextSignIn(t *testing.T) {
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
	previousNotLocalSystem, previousHasNoSession := enterpriseHookSessionCheckNotLocalSystem, enterpriseHookTargetHasNoSession
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
		enterpriseHookSessionCheckNotLocalSystem, enterpriseHookTargetHasNoSession = previousNotLocalSystem, previousHasNoSession
		enterprisehooks.SetStandaloneUnix(previousStandaloneUnix)
	})
	enterpriseForeignHookCleanup = func(enterprisehooks.TargetCredentials, string, string) (enterprisepolicy.CleanupResult, error) {
		return enterprisepolicy.CleanupResult{}, nil
	}
	enterpriseHookGuardianStateFileTrustCheck = func(string) error { return nil }
	enterpriseHookManifestFileTrustCheck = func(string) error { return nil }
	enterprisehooks.SetStandaloneUnix(true)
	secureClient, applies := false, true
	enterpriseHookReconcileSecureClient = func() bool { return secureClient }
	enterpriseHookHermesSignedOutApplies = func() bool { return applies }
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "", false, nil }
	enterpriseHookReconcileTargetFailModeChange = func(enterprisehooks.InstallOptions) (string, string, error) { return "", "", nil }

	scope := t.TempDir()
	dataDir := filepath.Join(scope, "runtime")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	alice, bob := "S-1-5-21-1-2-3-1017", "S-1-5-21-1-2-3-1018"
	folders := map[string]string{}
	var manifestBody strings.Builder
	manifestBody.WriteString("version: 1\ntargets:\n")
	for _, target := range []struct{ name, sid, connector string }{
		{"Alice", alice, "codex"}, {"Alice", alice, "copilot"}, {"Bob", bob, "codex"}, {"Bob", bob, "copilot"},
	} {
		home := filepath.Join(scope, target.name)
		folders[target.sid] = filepath.Join(home, ".defenseclaw")
		if err := os.MkdirAll(folders[target.sid], 0o700); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&manifestBody,
			"  - user_home: %q\n    uid: %d\n    gid: %d\n    sid: %s\n    connector: %s\n    data_dir: %q\n    enabled: true\n    deferred: true\n",
			home, os.Getuid(), os.Getgid(), target.sid, target.connector, folders[target.sid])
	}
	manifestPath := filepath.Join(scope, "targets.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifestBody.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = &config.Config{DataDir: dataDir, DeploymentMode: "local"}
	enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = manifestPath, "127.0.0.1:18970", "127.0.0.1:4000"
	for _, connectorName := range []string{"codex", "copilot"} {
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
	sessionErr := map[string]error{}
	enterpriseHookReconcileSessionAvailable = func(target enterprisehooks.ManifestTarget) (bool, error) {
		if err := sessionErr[target.SID]; err != nil {
			return false, err
		}
		return signedIn[target.SID], nil
	}
	enterpriseHookReconcileDeferredSessionAvailable = enterpriseHookReconcileSessionAvailable
	errNotLocalSystem := errors.New("enterprise hooks: process is not LocalSystem")
	enterpriseHookSessionCheckNotLocalSystem = func(err error) bool { return errors.Is(err, errNotLocalSystem) }
	var listErr error
	enterpriseHookTargetHasNoSession = func(target enterprisehooks.ManifestTarget) (bool, error) {
		return !signedIn[target.SID], listErr
	}
	live := map[string]error{}
	stub := func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if err := live[opts.OwnerSID+"/"+opts.ConnectorName]; err != nil {
			return enterprisehooks.InstallResult{}, err
		}
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
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
	untrusted := func(folder string) error {
		return fmt.Errorf("enterprise hooks: managed runtime generation directory is untrusted: "+
			"enterprise hooks: managed Windows DACL is not protected on %s", filepath.Join(folder, "hooks"))
	}
	check := func(name string, wantOK bool) {
		t.Helper()
		for _, registration := range []bool{true, false} {
			run, err := runEnterpriseHookVerifyAttemptWithScope(context.Background(), registration)
			if err != nil {
				t.Fatalf("%s (registration=%t): %v", name, registration, err)
			}
			ok := run.Failures-len(run.Excused) == 0 && run.AuthorizationErr == nil
			if ok != wantOK {
				t.Fatalf("%s (registration=%t): ok=%t, want %t; authorization=%v rows=%+v",
					name, registration, ok, wantOK, run.AuthorizationErr, run.Rows)
			}
			if !wantOK {
				continue
			}
			for _, row := range run.Rows {
				if live[row.SID+"/"+row.Connector] == nil {
					if !row.OK {
						t.Fatalf("%s (registration=%t): row %+v failed", name, registration, row)
					}
					continue
				}
				note := enterpriseHookVerifyExcusedNote(run, row)
				if row.OK || !enterpriseHookVerifyRowExcused(run, row) ||
					!strings.Contains(note, "pending until the account signs in") ||
					!strings.Contains(note, strings.ReplaceAll(filepath.Join(folders[bob], "hooks"), "/", `\`)) {
					t.Fatalf("%s (registration=%t): row %+v note %q, want pending until sign-in naming the folder",
						name, registration, row, note)
				}
			}
		}
	}

	reconcile(0)
	check("everyone signed in", true)

	// Bob signs out and his own hooks folder loses its protected DACL after
	// the guardian last proved his targets (the live red).
	signedIn[bob] = false
	live[bob+"/codex"], live[bob+"/copilot"] = untrusted(folders[bob]), untrusted(folders[bob])
	check("signed out, own hooks folder drifted since the guardian pass", true)
	// An elevated administrator cannot query his session; the session list
	// shows him signed out.
	sessionErr[bob] = errNotLocalSystem
	check("administrator verify, session list signed out", true)
	listErr = errors.New("access denied")
	check("administrator verify, session list unreadable", false)
	listErr = nil
	delete(sessionErr, bob)

	// Controls: signed in, another account's folder, another failure,
	// Secure Client.
	signedIn[bob] = true
	check("signed in with the drift", false)
	signedIn[bob] = false
	live[bob+"/codex"] = untrusted(folders[alice])
	check("another account's folder", false)
	live[bob+"/codex"] = errors.New("enterprise hooks: connector codex hook verification failed: canonical hook matrix is absent: owned hook command not present")
	check("another failure", false)
	live[bob+"/codex"] = untrusted(folders[bob])
	applies = false
	check("not the standalone Windows deployment", false)
	applies = true

	// The guardian then sees the drift and records the sign-in wait itself
	// (TestEnterpriseHookVerifyOrRepairTargetLeavesASignedOutUntrustedFolderToTheNextSignIn);
	// verify reads that record through the standalone profile.
	reconcile(2)
	for _, row := range loadEnterpriseHookGuardianRecords(dataDir).State.Results {
		if row.SID == bob && (!enterpriseHookAwaitingSignInError(row) ||
			!strings.Contains(row.Error, enterpriseHookAwaitingSignInUntrustedFolder)) {
			t.Fatalf("guardian row %+v, want the own-folder sign-in wait", row)
		}
	}
	// With that record the guardian no longer says protected: the live rule
	// does not apply, and the generic sign-in wait (standalone profile only)
	// decides.
	check("after the guardian pass, not the standalone profile", false)
}
