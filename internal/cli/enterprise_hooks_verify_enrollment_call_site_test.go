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
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// verifyEnrollmentLab is two accounts (alice, bob) with two connectors each,
// a Guardian that has recorded its pass, and a live verify that runs the real
// verify loop. enterpriseHookManagedEnrollmentVerifier is replaced with the
// Windows rule: the set the Guardian published must equal the set verify
// expects, exactly.
type verifyEnrollmentLab struct {
	t              *testing.T
	dataDir        string
	aliceHome      string
	installErr     map[string]error
	published      map[string]struct{}
	expectedByLoop []string
}

const (
	labAlice = "S-1-5-21-1-2-3-1017"
	labBob   = "S-1-5-21-1-2-3-1018"
)

func newVerifyEnrollmentLab(t *testing.T) *verifyEnrollmentLab {
	t.Helper()
	restoreEnterpriseHooksLifecycleTestState(t)
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	stubEnterpriseHookTokenSources(t)
	previousManifest, previousAPI, previousProxy := enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr
	previousVerifier, previousInstaller := enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller
	previousPublic, previousRegistration := enterpriseHookLivePublicVerifier, enterpriseHookLiveRegistrationVerifier
	previousSession, previousDeferredSession := enterpriseHookReconcileSessionAvailable, enterpriseHookReconcileDeferredSessionAvailable
	previousRelease, previousChange := enterpriseHookReconcileTargetRelease, enterpriseHookReconcileTargetFailModeChange
	previousSecureClient := enterpriseHookReconcileSecureClient
	previousCleanup := enterpriseForeignHookCleanup
	previousStateTrust, previousManifestTrust := enterpriseHookGuardianStateFileTrustCheck, enterpriseHookManifestFileTrustCheck
	previousForeign, previousOwned := enterpriseHookForeignDataDirLink, enterpriseHookAccountOwnedDataDirLink
	previousEnrollment := enterpriseHookManagedEnrollmentVerifier
	previousCfg := cfg
	previousStandaloneUnix := enterprisehooks.StandaloneUnix()
	t.Cleanup(func() {
		enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = previousManifest, previousAPI, previousProxy
		enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller = previousVerifier, previousInstaller
		enterpriseHookLivePublicVerifier, enterpriseHookLiveRegistrationVerifier = previousPublic, previousRegistration
		enterpriseHookReconcileSessionAvailable, enterpriseHookReconcileDeferredSessionAvailable = previousSession, previousDeferredSession
		enterpriseHookReconcileTargetRelease, enterpriseHookReconcileTargetFailModeChange = previousRelease, previousChange
		enterpriseHookReconcileSecureClient = previousSecureClient
		enterpriseForeignHookCleanup = previousCleanup
		enterpriseHookGuardianStateFileTrustCheck, enterpriseHookManifestFileTrustCheck = previousStateTrust, previousManifestTrust
		enterpriseHookForeignDataDirLink, enterpriseHookAccountOwnedDataDirLink = previousForeign, previousOwned
		enterpriseHookManagedEnrollmentVerifier = previousEnrollment
		cfg = previousCfg
		enterprisehooks.SetStandaloneUnix(previousStandaloneUnix)
	})
	enterpriseForeignHookCleanup = func(enterprisehooks.TargetCredentials, string, string) (enterprisepolicy.CleanupResult, error) {
		return enterprisepolicy.CleanupResult{}, nil
	}
	enterpriseHookGuardianStateFileTrustCheck = func(string) error { return nil }
	enterpriseHookManifestFileTrustCheck = func(string) error { return nil }
	enterprisehooks.SetStandaloneUnix(true)
	enterpriseHookReconcileSecureClient = func() bool { return false }
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "", false, nil }
	enterpriseHookReconcileTargetFailModeChange = func(enterprisehooks.InstallOptions) (string, string, error) { return "", "", nil }

	scope := t.TempDir()
	lab := &verifyEnrollmentLab{t: t, dataDir: filepath.Join(scope, "runtime"),
		installErr: map[string]error{}}
	if err := os.MkdirAll(lab.dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	var manifestBody strings.Builder
	manifestBody.WriteString("version: 1\ntargets:\n")
	for _, target := range []struct{ name, sid, connector string }{
		{"Alice", labAlice, "codex"}, {"Alice", labAlice, "copilot"}, {"Bob", labBob, "codex"}, {"Bob", labBob, "copilot"},
	} {
		home := filepath.Join(scope, target.name)
		folder := filepath.Join(home, ".defenseclaw")
		if err := os.MkdirAll(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		if target.name == "Alice" {
			lab.aliceHome = home
		}
		fmt.Fprintf(&manifestBody,
			"  - user_home: %q\n    uid: %d\n    gid: %d\n    sid: %s\n    connector: %s\n    data_dir: %q\n    enabled: true\n    deferred: true\n",
			home, os.Getuid(), os.Getgid(), target.sid, target.connector, folder)
	}
	manifestPath := filepath.Join(scope, "targets.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifestBody.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = manifestPath, "127.0.0.1:18970", "127.0.0.1:4000"
	for _, connectorName := range []string{"codex", "copilot"} {
		if _, err := connector.EnsureHookAPIToken(lab.dataDir, connectorName); err != nil {
			t.Fatal(err)
		}
		if scope, ok := connector.OTLPPathTokenScopeForConnector(connectorName); ok {
			if _, err := connector.EnsureOTLPPathToken(lab.dataDir, scope); err != nil {
				t.Fatal(err)
			}
		}
	}
	signedIn := func(enterprisehooks.ManifestTarget) (bool, error) { return true, nil }
	enterpriseHookReconcileSessionAvailable, enterpriseHookReconcileDeferredSessionAvailable = signedIn, signedIn
	stub := func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if err := lab.installErr[opts.OwnerSID]; err != nil {
			return enterprisehooks.InstallResult{}, err
		}
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	enterpriseHookReconcileInstaller, enterpriseHookReconcileVerifier = stub, stub
	enterpriseHookLivePublicVerifier, enterpriseHookLiveRegistrationVerifier = stub, stub
	// The Windows rule: the published set must equal the expected set.
	enterpriseHookManagedEnrollmentVerifier = func(expected enterprisehooks.Manifest, _ string) error {
		lab.expectedByLoop = lab.expectedByLoop[:0]
		got := map[string]struct{}{}
		for _, target := range expected.Targets {
			if target.IsEnabled() {
				unit := enterpriseHookEnrollmentUnit(target)
				got[unit] = struct{}{}
				lab.expectedByLoop = append(lab.expectedByLoop, unit)
			}
		}
		sort.Strings(lab.expectedByLoop)
		if len(got) != len(lab.published) {
			return fmt.Errorf("published %d enrollments, verify expects %d", len(lab.published), len(got))
		}
		for unit := range got {
			if _, ok := lab.published[unit]; !ok {
				return fmt.Errorf("enrollment %s is not published", unit)
			}
		}
		return nil
	}
	return lab
}

func (l *verifyEnrollmentLab) publish(units ...string) {
	l.published = map[string]struct{}{}
	for _, unit := range units {
		l.published[unit] = struct{}{}
	}
}

// guardianPass runs the Guardian once on the local deployment and records its
// state, then makes the deployment the standalone profile verify excuses
// links on.
func (l *verifyEnrollmentLab) guardianPass(wantFailures int) {
	l.t.Helper()
	cfg = &config.Config{DataDir: l.dataDir, DeploymentMode: "local"}
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil || run.StateErr != nil || run.Failures != wantFailures {
		l.t.Fatalf("guardian pass: run=%+v err=%v, want %d failure(s)", run, err, wantFailures)
	}
	cfg = &config.Config{DataDir: l.dataDir, DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
}

func (l *verifyEnrollmentLab) foreignLinkAtAlice() {
	enterpriseHookAccountOwnedDataDirLink = func(string, string) bool { return false }
	enterpriseHookForeignDataDirLink = func(home, sid string) bool { return home == l.aliceHome && sid == labAlice }
	l.installErr[labAlice] = errors.New(enterpriseHookAccountForeignLinkFailure)
}

func (l *verifyEnrollmentLab) verify(registrationOnly bool) enterpriseHookVerifyRun {
	l.t.Helper()
	run, err := runEnterpriseHookVerifyAttemptRows(context.Background(), registrationOnly)
	if err != nil {
		l.t.Fatalf("verify (registration=%t): %v", registrationOnly, err)
	}
	return run
}

func verifyOK(run enterpriseHookVerifyRun) bool {
	return run.Failures-len(run.Excused) == 0 && run.AuthorizationErr == nil
}

const (
	aliceCodex   = "codex@" + labAlice
	aliceCopilot = "copilot@" + labAlice
	bobCodex     = "codex@" + labBob
	bobCopilot   = "copilot@" + labBob
)

// GAP-0790 (the live red of the Setup /ensure readiness check): one account
// whose DefenseClaw folder is a link an administrator owns is left out of
// the protected enrollment set the Guardian publishes and is excused by every
// other stage. Verify, through the real verify loop, must expect the set the
// Guardian published, not the whole manifest, and must still fail when an
// ordinary account is missing from it, when the skipped account is still
// enrolled, or when the account was protected before the link appeared.
func TestVerifyLoopExpectsTheEnrollmentSetOfAForeignLinkedAccountsSkip(t *testing.T) {
	lab := newVerifyEnrollmentLab(t)
	lab.foreignLinkAtAlice()
	lab.guardianPass(2)

	lab.publish(bobCodex, bobCopilot)
	for _, registration := range []bool{true, false} {
		run := lab.verify(registration)
		if !verifyOK(run) {
			t.Fatalf("registration=%t: skipped account failed the machine: authorization=%v failures=%d excused=%d",
				registration, run.AuthorizationErr, run.Failures, len(run.Excused))
		}
		if got := strings.Join(lab.expectedByLoop, ","); got != bobCodex+","+bobCopilot {
			t.Fatalf("registration=%t: verify expected %q, want only the ordinary account", registration, got)
		}
	}

	// Fail-closed controls.
	for name, published := range map[string][]string{
		"an ordinary account is missing one enrollment": {bobCodex},
		"the skipped account is still enrolled":         {aliceCodex, aliceCopilot, bobCodex, bobCopilot},
		"nothing is published":                          {},
	} {
		lab.publish(published...)
		run := lab.verify(false)
		if verifyOK(run) || run.AuthorizationErr == nil || !strings.Contains(run.AuthorizationErr.Error(), "protected enrollment set is not exact") {
			t.Fatalf("%s: verify passed (authorization=%v)", name, run.AuthorizationErr)
		}
	}
}

// Benign twin: no skipped account, every account enrolled and published.
func TestVerifyLoopExpectsEveryAccountWhenNoneIsSkipped(t *testing.T) {
	lab := newVerifyEnrollmentLab(t)
	lab.guardianPass(0)
	lab.publish(aliceCodex, aliceCopilot, bobCodex, bobCopilot)
	if run := lab.verify(false); !verifyOK(run) {
		t.Fatalf("healthy machine failed verify: authorization=%v failures=%d", run.AuthorizationErr, run.Failures)
	}
	lab.publish(bobCodex, bobCopilot)
	if run := lab.verify(false); verifyOK(run) {
		t.Fatal("an unenrolled ordinary account passed verify")
	}
}

// An account an earlier pass protected keeps the enrollment the Guardian
// published for it even when its folder is now a foreign link, so verify
// still expects it (the Guardian leaves out only a target never protected).
func TestVerifyLoopKeepsExpectingAPreviouslyProtectedLinkedAccount(t *testing.T) {
	lab := newVerifyEnrollmentLab(t)
	lab.guardianPass(0)
	lab.foreignLinkAtAlice()
	lab.guardianPass(2)
	lab.publish(aliceCodex, aliceCopilot, bobCodex, bobCopilot)
	if run := lab.verify(false); !verifyOK(run) {
		t.Fatalf("previously protected account: authorization=%v failures=%d excused=%d", run.AuthorizationErr, run.Failures, len(run.Excused))
	}
	lab.publish(bobCodex, bobCopilot)
	if run := lab.verify(false); verifyOK(run) {
		t.Fatal("verify accepted a previously protected account missing from the published set")
	}
}
