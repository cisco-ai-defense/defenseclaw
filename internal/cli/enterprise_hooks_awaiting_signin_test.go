// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/spf13/cobra"
)

// GAP-0644: an in-place upgrade of a managed standalone Windows 11 host
// whose enrolled Entra users are signed out rolled back (Setup 1603): every
// target an earlier release protected failed this release's verification
// (its hook-contract lock has no gateway service binding), the repair needs
// the account's own session, and the guardian published no required
// coverage. Such a target now waits for its account's next sign-in: status
// reports it pending (not protected) and stays healthy, so the lifecycle's
// coverage gate passes. The Windows guardian's reconcile is this loop; the
// platform calls it makes are stubbed here.
func TestEnterpriseHookReconcileLeavesEarlierReleaseTargetsToTheNextSignIn(t *testing.T) {
	restoreEnterpriseHooksLifecycleTestState(t)
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	stubEnterpriseHookTokenSources(t)
	previousManifest, previousAPI, previousProxy := enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr
	previousVerifier, previousInstaller := enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller
	previousSession, previousCleanup := enterpriseHookReconcileSessionAvailable, enterpriseForeignHookCleanup
	previousRelease, previousJSON := enterpriseHookReconcileTargetRelease, enterpriseHookJSON
	previousStateTrust, previousManifestTrust := enterpriseHookGuardianStateFileTrustCheck, enterpriseHookManifestFileTrustCheck
	t.Cleanup(func() {
		enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = previousManifest, previousAPI, previousProxy
		enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller = previousVerifier, previousInstaller
		enterpriseHookReconcileSessionAvailable, enterpriseForeignHookCleanup = previousSession, previousCleanup
		enterpriseHookReconcileTargetRelease, enterpriseHookJSON = previousRelease, previousJSON
		enterpriseHookGuardianStateFileTrustCheck, enterpriseHookManifestFileTrustCheck = previousStateTrust, previousManifestTrust
	})
	enterpriseForeignHookCleanup = func(enterprisehooks.TargetCredentials, string, string) (enterprisepolicy.CleanupResult, error) {
		return enterprisepolicy.CleanupResult{}, nil
	}
	enterpriseHookGuardianStateFileTrustCheck = func(string) error { return nil }
	enterpriseHookManifestFileTrustCheck = func(string) error { return nil }
	// The standalone Windows guardian: a same-release target keeps failing.
	previousSecureClient := enterpriseHookReconcileSecureClient
	t.Cleanup(func() { enterpriseHookReconcileSecureClient = previousSecureClient })
	enterpriseHookReconcileSecureClient = func() bool { return false }
	// Off Windows only a standalone manifest may carry deferred rows; the
	// rows here are the Windows standalone enumerator's.
	previousStandaloneUnix := enterprisehooks.StandaloneUnix()
	t.Cleanup(func() { enterprisehooks.SetStandaloneUnix(previousStandaloneUnix) })
	enterprisehooks.SetStandaloneUnix(true)

	scope := t.TempDir()
	dataDir := filepath.Join(scope, "runtime")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	accounts := []struct{ name, sid string }{
		{"EntraAlice", "S-1-12-1-1-2-3-1001"},
		{"EntraBob", "S-1-12-1-1-2-3-1002"},
		{"EntraCarol", "S-1-12-1-1-2-3-1003"},
	}
	var manifestBody strings.Builder
	manifestBody.WriteString("version: 1\ntargets:\n")
	var protected []enterpriseHookReconcileRow
	for _, account := range accounts {
		home := filepath.Join(scope, account.name)
		if err := os.MkdirAll(home, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, connectorName := range []string{"claudecode", "codex"} {
			fmt.Fprintf(&manifestBody,
				"  - user_home: %q\n    uid: %d\n    gid: %d\n    sid: %s\n    connector: %s\n    enabled: true\n    deferred: true\n",
				home, os.Getuid(), os.Getgid(), account.sid, connectorName)
			protected = append(protected, enterpriseHookReconcileRow{UserHome: home, SID: account.sid, Connector: connectorName, OK: true})
		}
	}
	manifestPath := filepath.Join(scope, "targets.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifestBody.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	_, manifestSHA256, err := enterprisehooks.LoadManifestWithSHA256(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	reconcileCfg := &config.Config{DataDir: dataDir, DeploymentMode: "local"}
	statusCfg := &config.Config{
		DataDir:        dataDir,
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	cfg = reconcileCfg
	enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = manifestPath, "127.0.0.1:18970", "127.0.0.1:4000"
	// rc.3 protected all six targets.
	if err := writeEnterpriseHookGuardianState(dataDir, manifestPath, manifestSHA256, protected, 0, true); err != nil {
		t.Fatal(err)
	}

	// Every rc.3 lock fails this release's verification; the lock names
	// rc.3 unless sameRelease says this release wrote it.
	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{}, errors.New(
			"enterprise hooks: managed Claude gateway binding: persisted managed gateway service identity: gateway service name \"\" is invalid")
	}
	sameRelease := false
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) {
		return "1.0.2-rc.3", !sameRelease, nil
	}
	signedIn := map[string]bool{}
	enterpriseHookReconcileSessionAvailable = func(target enterprisehooks.ManifestTarget) (bool, error) {
		return signedIn[target.SID], nil
	}
	var installErr error
	installs := []string{}
	enterpriseHookReconcileInstaller = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		installs = append(installs, opts.OwnerSID+"/"+opts.ConnectorName)
		if installErr != nil {
			return enterprisehooks.InstallResult{}, installErr
		}
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}

	status := func() (enterpriseHookStatusReport, error) {
		t.Helper()
		cfg, enterpriseHookJSON = statusCfg, true
		defer func() { cfg, enterpriseHookJSON = reconcileCfg, false }()
		var stdout bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&stdout)
		statusErr := runEnterpriseHooksStatus(cmd, nil)
		var report enterpriseHookStatusReport
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatalf("decode status report %q: %v", stdout.String(), err)
		}
		return report, statusErr
	}
	pendingStates := func(report enterpriseHookStatusReport) (pending, enrolled, failed int) {
		for _, account := range report.Enrollment {
			for _, connector := range account.Connectors {
				switch connector.State {
				case "pending":
					pending++
				case "enrolled":
					enrolled++
				default:
					failed++
				}
			}
		}
		return pending, enrolled, failed
	}

	// All three accounts are signed out: no repair is attempted, every
	// target waits for its account, and status stays healthy.
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil || run.StateErr != nil || run.Failures != 6 || len(installs) != 0 {
		t.Fatalf("all signed out: run=%+v installs=%v err=%v", run, installs, err)
	}
	for _, row := range run.Rows {
		if row.OK || !strings.HasPrefix(row.Error, enterpriseHookAwaitingSignInPrefix) ||
			!strings.Contains(row.Error, "exact active Windows session is unavailable") ||
			!strings.Contains(row.Error, "1.0.2-rc.3") || !strings.Contains(row.Error, "gateway binding") {
			t.Fatalf("all signed out: row %+v, want a sign-in wait naming rc.3 and the verification", row)
		}
	}
	report, err := status()
	if err != nil || !report.OK || len(report.Errors) != 0 || report.AwaitingSignInFailures != 6 ||
		report.RemovedAccountFailures != 0 || len(report.Warnings) != 6 {
		t.Fatalf("all signed out: status err=%v report=%+v", err, report)
	}
	for _, warning := range report.Warnings {
		if !strings.Contains(warning, "is pending until that account signs in") || !strings.Contains(warning, "not protected") {
			t.Fatalf("all signed out: warning %q", warning)
		}
	}
	if pending, enrolled, failed := pendingStates(report); pending != 6 || enrolled != 0 || failed != 0 {
		t.Fatalf("all signed out: enrollment %d pending, %d enrolled, %d failed; want 6 pending", pending, enrolled, failed)
	}
	// Nothing claims them protected: the records keep them unrepaired.
	if report.State == nil || report.State.SuccessCount != 0 || report.State.FailureCount != 6 {
		t.Fatalf("all signed out: state %+v, want 0 succeeded", report.State)
	}
	for _, account := range windowsEnterpriseEnrollmentAccounts(report.State.Results) {
		if !strings.HasPrefix(account.Reason, "pending:") || strings.Contains(account.Reason, "failed:") {
			t.Fatalf("all signed out: account %+v, want pending without a failure", account)
		}
	}

	// Alice signs in: her two targets are repaired in her session, Bob's and
	// Carol's still wait, and status stays healthy.
	signedIn[accounts[0].sid] = true
	run, err = runEnterpriseHookReconcileOnce(context.Background())
	if err != nil || run.StateErr != nil || run.Failures != 4 || run.Repairs != 2 || len(installs) != 2 {
		t.Fatalf("Alice signed in: run=%+v installs=%v err=%v", run, installs, err)
	}
	report, err = status()
	if err != nil || !report.OK || report.AwaitingSignInFailures != 4 || len(report.Warnings) != 4 {
		t.Fatalf("Alice signed in: status err=%v report=%+v", err, report)
	}
	if pending, enrolled, failed := pendingStates(report); pending != 4 || enrolled != 2 || failed != 0 {
		t.Fatalf("Alice signed in: enrollment %d pending, %d enrolled, %d failed; want 4 and 2", pending, enrolled, failed)
	}

	// A real repair failure of the signed-in account still fails the host.
	installs = installs[:0]
	installErr = errors.New("enterprise hooks: write managed Claude Code hook runtime: access is denied")
	run, err = runEnterpriseHookReconcileOnce(context.Background())
	if err != nil || run.Failures != 6 || len(installs) != 2 {
		t.Fatalf("unwritable target: run=%+v installs=%v err=%v", run, installs, err)
	}
	report, err = status()
	if err == nil || report.OK || report.AwaitingSignInFailures != 0 ||
		!strings.Contains(strings.Join(report.Errors, "\n"), "access is denied") {
		t.Fatalf("unwritable target: status err=%v report=%+v, want unhealthy", err, report)
	}

	// A signed-out target whose lock this release wrote changed while its
	// account was signed out: that stays a failure.
	signedIn[accounts[0].sid], installErr, sameRelease = false, nil, true
	run, err = runEnterpriseHookReconcileOnce(context.Background())
	if err != nil || run.Failures != 6 {
		t.Fatalf("same release: run=%+v err=%v", run, err)
	}
	for _, row := range run.Rows {
		if strings.HasPrefix(row.Error, enterpriseHookAwaitingSignInPrefix) ||
			!strings.HasPrefix(row.Error, "enterprise hooks: protected target requires repair but its exact active Windows session is unavailable") {
			t.Fatalf("same release: row %+v, want the signed-out repair failure", row)
		}
	}
	if report, err = status(); err == nil || report.OK || report.AwaitingSignInFailures != 0 {
		t.Fatalf("same release: status err=%v report=%+v, want unhealthy", err, report)
	}
}

// GAP-0644: only a standalone deferred target waits for the sign-in; the
// release check is not asked for another target, and a failed check keeps
// the signed-out failure.
func TestEnterpriseHookVerifyOrRepairTargetWaitsForSignInOnlyForDeferredEarlierRelease(t *testing.T) {
	previousVerifier, previousSession, previousRelease := enterpriseHookReconcileVerifier, enterpriseHookReconcileSessionAvailable, enterpriseHookReconcileTargetRelease
	previousSecureClient := enterpriseHookReconcileSecureClient
	t.Cleanup(func() {
		enterpriseHookReconcileVerifier, enterpriseHookReconcileSessionAvailable, enterpriseHookReconcileTargetRelease = previousVerifier, previousSession, previousRelease
		enterpriseHookReconcileSecureClient = previousSecureClient
	})
	enterpriseHookReconcileSecureClient = func() bool { return false }
	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{}, errors.New("lock drift")
	}
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return false, nil }
	asked := 0
	var releaseErr error
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) {
		asked++
		return "1.0.2-rc.3", releaseErr == nil, releaseErr
	}
	opts := enterprisehooks.InstallOptions{ConnectorName: "codex"}
	_, _, err := enterpriseHookVerifyOrRepairTarget(context.Background(), enterprisehooks.ManifestTarget{Connector: "codex"}, opts, true)
	if err == nil || strings.HasPrefix(err.Error(), enterpriseHookAwaitingSignInPrefix) || asked != 0 ||
		!strings.Contains(err.Error(), "(verification: lock drift)") {
		t.Fatalf("non-deferred target: err=%v asked=%d, want the signed-out failure", err, asked)
	}
	deferred := enterprisehooks.ManifestTarget{Connector: "codex", Deferred: true}
	_, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true)
	if err == nil || !strings.HasPrefix(err.Error(), enterpriseHookAwaitingSignInPrefix) || asked != 1 {
		t.Fatalf("deferred earlier-release target: err=%v asked=%d, want the sign-in wait", err, asked)
	}
	releaseErr = errors.New("hook contract lock is unreadable")
	_, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true)
	if err == nil || strings.HasPrefix(err.Error(), enterpriseHookAwaitingSignInPrefix) {
		t.Fatalf("unreadable lock: err=%v, want the signed-out failure", err)
	}
}

// GAP-0644: verify excuses a row the guardian left waiting for a sign-in
// only while that account is still signed out, and names it pending.
func TestEnterpriseHookVerifyAwaitingSignInNeedsTheAccountSignedOut(t *testing.T) {
	previousSession := enterpriseHookReconcileSessionAvailable
	t.Cleanup(func() { enterpriseHookReconcileSessionAvailable = previousSession })
	row := enterpriseHookReconcileRow{SID: "S-1-12-1-1-2-3-1002", Connector: "codex", Error: "verify failed"}
	target := enterprisehooks.ManifestTarget{SID: row.SID, Connector: "codex", Deferred: true}
	awaiting := map[string]struct{}{enterpriseHookProtectedTargetKey(row): {}}
	signedIn := false
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return signedIn, nil }
	if !enterpriseHookVerifyAwaitingSignIn(awaiting, target, row) {
		t.Fatal("a signed-out account's waiting row was not excused")
	}
	run := enterpriseHookVerifyRun{Excused: []enterpriseHookReconcileRow{row}, AwaitingSignIn: []enterpriseHookReconcileRow{row}}
	if note := enterpriseHookVerifyExcusedNote(run, row); note != enterpriseHookAwaitingSignInNote {
		t.Fatalf("note = %q, want the sign-in note", note)
	}
	if enterpriseHookVerifyAwaitingSignIn(map[string]struct{}{}, target, row) {
		t.Fatal("a row the guardian did not leave waiting was excused")
	}
	target.Deferred = false
	if enterpriseHookVerifyAwaitingSignIn(awaiting, target, row) {
		t.Fatal("a non-deferred target was excused")
	}
	target.Deferred, signedIn = true, true
	if enterpriseHookVerifyAwaitingSignIn(awaiting, target, row) {
		t.Fatal("a signed-in account's waiting row was excused before the guardian repaired it")
	}
}
