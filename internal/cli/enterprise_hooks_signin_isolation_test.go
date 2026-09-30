// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

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
)

// signInIsolationTarget is one manifest row of the #894 reconcile fixture.
type signInIsolationTarget struct {
	name      string
	sid       string
	connector string
	// installErr is what the (stubbed) per-target install returns; nil means
	// the target is protected by this reconcile.
	installErr error
	// awaitingSignIn is what the (stubbed) platform classifier reports for
	// the target: no active session for its SID and no selected runtime.
	awaitingSignIn bool
	// deferred writes the row as `deferred: true` (Windows-only schema).
	deferred bool
}

type signInIsolationOptions struct {
	// homes reuses profile directories from an earlier run so the protected
	// authorization ledger identity matches.
	homes map[string]string
	// realClassifier keeps the production platform sign-in classifier
	// instead of the per-target awaitingSignIn stub.
	realClassifier bool
}

type signInIsolationPublication struct {
	exact   bool
	targets []string
}

type signInIsolationFixture struct {
	homes        map[string]string
	staged       [][]string
	publications []signInIsolationPublication
	classified   []string
}

func publicationTargetNames(f *signInIsolationFixture, manifest enterprisehooks.Manifest) []string {
	names := make([]string, 0, len(manifest.Targets))
	for _, target := range manifest.Targets {
		for name, home := range f.homes {
			if home == target.UserHome {
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}

// runSignInIsolationReconcile writes a manifest for targets and runs the real
// runEnterpriseHookReconcileOnce with only the per-target install, token
// minting, platform sign-in classifier, and the Windows machine-policy
// staging/publication calls replaced, so the enrollment-publication gate is
// exercised exactly as production computes it.
func runSignInIsolationReconcile(
	t *testing.T,
	targets []signInIsolationTarget,
) (*signInIsolationFixture, enterpriseHookReconcileRun) {
	t.Helper()
	return runSignInIsolationReconcileWithOptions(t, targets, signInIsolationOptions{})
}

func runSignInIsolationReconcileWithOptions(
	t *testing.T,
	targets []signInIsolationTarget,
	options signInIsolationOptions,
) (*signInIsolationFixture, enterpriseHookReconcileRun) {
	t.Helper()
	homes := options.homes
	fixture := &signInIsolationFixture{homes: map[string]string{}}
	root := t.TempDir()
	var manifest strings.Builder
	manifest.WriteString("version: 1\ntargets:\n")
	byHome := map[string]signInIsolationTarget{}
	for _, target := range targets {
		home := homes[target.name]
		if home == "" {
			home = filepath.Join(root, target.name)
			if err := os.MkdirAll(home, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		fixture.homes[target.name] = home
		byHome[home] = target
		fmt.Fprintf(
			&manifest,
			"  - user_home: %q\n    sid: %s\n    connector: %s\n    agent_version: 99.0.0\n",
			home, target.sid, target.connector,
		)
		if target.deferred {
			manifest.WriteString("    deferred: true\n")
		}
	}
	manifestPath := filepath.Join(root, "targets.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifest.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	enterpriseHookManifest = manifestPath

	enterpriseHookScopedTokenMinter = func(string, string) (string, error) { return "token", nil }
	enterpriseHookScopedOTLPTokenMinter = func(string, string) (string, error) { return "otlp", nil }
	install := func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		target := byHome[opts.UserHome]
		if target.installErr != nil {
			return enterprisehooks.InstallResult{}, target.installErr
		}
		return enterprisehooks.InstallResult{
			Connector:                  opts.ConnectorName,
			UserHome:                   opts.UserHome,
			HookContractLockUpdatedAt:  "2026-09-26T12:00:00.000000001Z",
			HookContractEntryUpdatedAt: "2026-09-26T12:00:00.000000000Z",
		}, nil
	}
	// Never-protected targets install; protected targets verify and, on a
	// verification failure with a session, repair through the installer.
	enterpriseHookReconcileInstaller = install
	enterpriseHookReconcileVerifier = install
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) {
		return true, nil
	}
	classify := func(target enterprisehooks.ManifestTarget) bool {
		return byHome[target.UserHome].awaitingSignIn
	}
	if options.realClassifier {
		classify = enterpriseHookTargetAwaitingFirstSignIn
	}
	enterpriseHookReconcileAwaitingFirstSignIn = func(target enterprisehooks.ManifestTarget) bool {
		fixture.classified = append(fixture.classified, byHome[target.UserHome].name)
		return classify(target)
	}
	enterpriseHookReconcileStageDeferred = func(
		manifest enterprisehooks.Manifest,
		_ []enterprisehooks.ManifestTarget,
		_ string,
	) error {
		fixture.staged = append(fixture.staged, publicationTargetNames(fixture, manifest))
		return nil
	}
	enterpriseHookReconcileSyncEnrollments = func(
		manifest enterprisehooks.Manifest,
		_ string,
		exact bool,
	) error {
		fixture.publications = append(fixture.publications, signInIsolationPublication{
			exact:   exact,
			targets: publicationTargetNames(fixture, manifest),
		})
		return nil
	}

	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	return fixture, run
}

func stubSignInIsolationReconcile(t *testing.T) {
	t.Helper()
	restoreEnterpriseHooksLifecycleTestState(t)
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	previousManifest := enterpriseHookManifest
	previousInstaller := enterpriseHookReconcileInstaller
	previousVerifier := enterpriseHookReconcileVerifier
	previousSession := enterpriseHookReconcileSessionAvailable
	previousAwaiting := enterpriseHookReconcileAwaitingFirstSignIn
	previousStage := enterpriseHookReconcileStageDeferred
	previousSync := enterpriseHookReconcileSyncEnrollments
	previousOwnership := enterpriseHookAuthorizationOwnershipSetter
	previousStateTrust := enterpriseHookGuardianStateFileTrustCheck
	t.Cleanup(func() {
		enterpriseHookManifest = previousManifest
		enterpriseHookReconcileInstaller = previousInstaller
		enterpriseHookReconcileVerifier = previousVerifier
		enterpriseHookReconcileSessionAvailable = previousSession
		enterpriseHookReconcileAwaitingFirstSignIn = previousAwaiting
		enterpriseHookReconcileStageDeferred = previousStage
		enterpriseHookReconcileSyncEnrollments = previousSync
		enterpriseHookAuthorizationOwnershipSetter = previousOwnership
		enterpriseHookGuardianStateFileTrustCheck = previousStateTrust
	})
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	enterpriseHookGuardianStateFileTrustCheck = func(string) error { return nil }
	dataDir := t.TempDir()
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(hookGuardianAuthorizationDirEnv, t.TempDir())
	cfg = &config.Config{DataDir: dataDir}
}

func exactPublications(f *signInIsolationFixture) [][]string {
	var exact [][]string
	for _, publication := range f.publications {
		if publication.exact {
			exact = append(exact, publication.targets)
		}
	}
	return exact
}

var errSignInIsolationNoSession = &enterprisehooks.WindowsTargetSessionUnavailableError{
	SID: "S-1-5-21-1000-2000-3000-1105",
}

// TestReconcilePublishesEnrollmentsPastTargetsAwaitingFirstSignIn is the
// reconcile-level #894 regression. A never-protected target whose user is
// signed out (and so cannot be protected yet) used to count as a failure that
// skipped deferred-policy staging and the exact protected enrollment
// publication for every other SID. It is still reported as a failure, but the
// publication now runs for everyone else, without that target. bob is written
// non-deferred, the way older enumerators wrote every new row, so hosts that
// already carry such rows recover without a manifest migration.
func TestReconcilePublishesEnrollmentsPastTargetsAwaitingFirstSignIn(t *testing.T) {
	stubSignInIsolationReconcile(t)
	fixture, run := runSignInIsolationReconcile(t, []signInIsolationTarget{
		{name: "alice", sid: "S-1-5-21-1000-2000-3000-1101", connector: "claudecode"},
		{name: "bob", sid: "S-1-5-21-1000-2000-3000-1105", connector: "claudecode", installErr: errSignInIsolationNoSession, awaitingSignIn: true},
		{name: "carol", sid: "S-1-5-21-1000-2000-3000-1102", connector: "codex"},
	})
	if run.Failures != 1 || run.StateErr != nil {
		t.Fatalf("run failures=%d state_err=%v, want the signed-out target as the only failure", run.Failures, run.StateErr)
	}
	if got := exactPublications(fixture); len(got) != 1 || strings.Join(got[0], ",") != "alice,carol" {
		t.Fatalf("exact enrollment publications = %v, want one publication of alice,carol", got)
	}
	if len(fixture.staged) != 1 || strings.Join(fixture.staged[0], ",") != "alice,carol" {
		t.Fatalf("deferred staging = %v, want one staging over alice,carol", fixture.staged)
	}
	if strings.Join(fixture.classified, ",") != "bob" {
		t.Fatalf("sign-in classifier consulted for %v, want only the failed target", fixture.classified)
	}
	var bob enterpriseHookReconcileRow
	for _, row := range run.Rows {
		if row.UserHome == fixture.homes["bob"] {
			bob = row
		}
	}
	if bob.OK || bob.Pending || !strings.Contains(bob.Error, "no active interactive session") {
		t.Fatalf("signed-out row = %+v, want a reported failure", bob)
	}
}

func TestReconcileStillWithholdsPublicationForOtherFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		targets []signInIsolationTarget
	}{
		{
			name: "signed_in_or_selected_target_failed",
			targets: []signInIsolationTarget{
				{name: "alice", sid: "S-1-5-21-1000-2000-3000-1101", connector: "claudecode"},
				{name: "bob", sid: "S-1-5-21-1000-2000-3000-1105", connector: "claudecode", installErr: errors.New("managed runtime ACL is noncanonical")},
			},
		},
		{
			name: "one_of_two_failures_awaits_sign_in",
			targets: []signInIsolationTarget{
				{name: "alice", sid: "S-1-5-21-1000-2000-3000-1101", connector: "claudecode"},
				{name: "bob", sid: "S-1-5-21-1000-2000-3000-1105", connector: "claudecode", installErr: errSignInIsolationNoSession, awaitingSignIn: true},
				{name: "dave", sid: "S-1-5-21-1000-2000-3000-1106", connector: "claudecode", installErr: errors.New("hook contract drift")},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubSignInIsolationReconcile(t)
			fixture, run := runSignInIsolationReconcile(t, tc.targets)
			if run.Failures == 0 {
				t.Fatal("fixture produced no failure")
			}
			if got := exactPublications(fixture); len(got) != 0 {
				t.Fatalf("exact enrollment published %v despite a failure that is not awaiting sign-in", got)
			}
			if len(fixture.staged) != 0 {
				t.Fatalf("deferred policies staged %v despite a failure that is not awaiting sign-in", fixture.staged)
			}
		})
	}
}

// TestReconcileNeverEmptiesAConnectorForTargetsAwaitingSignIn pins the
// fail-open guard: leaving a connector's only targets out of the exact
// publication would publish an empty set for it, which tears down that
// connector's machine-wide hook policy. Staging still runs for everyone else.
func TestReconcileNeverEmptiesAConnectorForTargetsAwaitingSignIn(t *testing.T) {
	stubSignInIsolationReconcile(t)
	fixture, run := runSignInIsolationReconcile(t, []signInIsolationTarget{
		{name: "alice", sid: "S-1-5-21-1000-2000-3000-1101", connector: "claudecode"},
		{name: "erin", sid: "S-1-5-21-1000-2000-3000-1107", connector: "codex", installErr: errSignInIsolationNoSession, awaitingSignIn: true},
	})
	if run.Failures != 1 {
		t.Fatalf("run failures = %d, want 1", run.Failures)
	}
	if got := exactPublications(fixture); len(got) != 0 {
		t.Fatalf("exact enrollment published %v, which would empty the codex set", got)
	}
	if len(fixture.staged) != 1 || strings.Join(fixture.staged[0], ",") != "alice" {
		t.Fatalf("deferred staging = %v, want one staging over alice", fixture.staged)
	}
}

// TestReconcileAwaitingSignInNeverAppliesToProtectedTargets pins that a
// target the guardian has already protected keeps withholding the exact
// publication when it fails: leaving it out would revoke a protected SID.
func TestReconcileAwaitingSignInNeverAppliesToProtectedTargets(t *testing.T) {
	stubSignInIsolationReconcile(t)
	targets := []signInIsolationTarget{
		{name: "alice", sid: "S-1-5-21-1000-2000-3000-1101", connector: "claudecode"},
		{name: "bob", sid: "S-1-5-21-1000-2000-3000-1105", connector: "claudecode"},
	}
	fixture, run := runSignInIsolationReconcile(t, targets)
	if run.Failures != 0 || run.StateErr != nil {
		t.Fatalf("clean reconcile failures=%d state_err=%v", run.Failures, run.StateErr)
	}
	if got := exactPublications(fixture); len(got) != 1 || strings.Join(got[0], ",") != "alice,bob" {
		t.Fatalf("clean exact publication = %v, want alice,bob", got)
	}
	if len(fixture.classified) != 0 {
		t.Fatalf("sign-in classifier consulted on a clean reconcile: %v", fixture.classified)
	}

	// bob is now in the protected authorization ledger; the same homes are
	// reused so the ledger identity matches.
	homes := fixture.homes
	targets[1].installErr = errSignInIsolationNoSession
	targets[1].awaitingSignIn = true
	second, run := runSignInIsolationReconcileWithOptions(t, targets, signInIsolationOptions{homes: homes})
	if run.Failures != 1 {
		t.Fatalf("second reconcile failures = %d, want 1", run.Failures)
	}
	if got := exactPublications(second); len(got) != 0 {
		t.Fatalf("exact enrollment published %v without a previously protected target", got)
	}
	if len(second.classified) != 0 {
		t.Fatalf("sign-in classifier consulted for a previously protected target: %v", second.classified)
	}
	for _, row := range run.Rows {
		if row.UserHome == homes["bob"] && !strings.Contains(row.Error, "no active interactive session") {
			t.Fatalf("protected target failed for an unexpected reason: %+v", row)
		}
	}
}
