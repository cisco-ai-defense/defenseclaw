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
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// awaitingSignInEnrollmentStore models the protected machine enrollment of
// the Windows guardian: connector -> enrolled SIDs. Staging and a new
// install enroll a SID; the non-exact sync keeps only enrolled SIDs the
// manifest still enables; the exact publication refuses a SID nothing
// enrolled (as the Claude exact-set publication does) and leaves exactly the
// enabled set, which is what verify compares.
type awaitingSignInEnrollmentStore map[string]map[string]bool

func (store awaitingSignInEnrollmentStore) enroll(connectorName, sid string) {
	connectorName = strings.ToLower(connectorName)
	if store[connectorName] == nil {
		store[connectorName] = map[string]bool{}
	}
	store[connectorName][strings.ToUpper(sid)] = true
}

func (store awaitingSignInEnrollmentStore) sorted(connectorName string) []string {
	out := []string{}
	for sid := range store[connectorName] {
		out = append(out, sid)
	}
	sort.Strings(out)
	return out
}

// verify is verifyEnterpriseHookManagedEnrollments' exact-set comparison.
func (store awaitingSignInEnrollmentStore) verify(desired awaitingSignInEnrollmentStore) error {
	for _, connectorName := range []string{"claudecode", "codex"} {
		if got, want := strings.Join(store.sorted(connectorName), ","), strings.Join(desired.sorted(connectorName), ","); got != want {
			return fmt.Errorf("%s protected SID enrollment %q does not match the enabled manifest %q", connectorName, got, want)
		}
	}
	return nil
}

// GAP-0644 fix-up: while accounts an earlier release protected wait for
// their next sign-in (raw 0/0/6 guardian records), a new pending target is
// still staged and the exact enrollment set is still published, so a new
// target is enrolled and verify's exact-set check passes. A real failure
// still blocks both.
func TestEnterpriseHookReconcilePublishesExactEnrollmentWhileAccountsAwaitSignIn(t *testing.T) {
	restoreEnterpriseHooksLifecycleTestState(t)
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	stubEnterpriseHookTokenSources(t)
	awaitingSignInTestPlatformSetup(t)
	previousManifest, previousAPI, previousProxy := enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr
	previousVerifier, previousInstaller := enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller
	previousSession, previousCleanup := enterpriseHookReconcileSessionAvailable, enterpriseForeignHookCleanup
	previousRelease, previousDeferredSession := enterpriseHookReconcileTargetRelease, enterpriseHookReconcileDeferredSessionAvailable
	previousStage, previousSync := enterpriseHookReconcileStageDeferredPolicies, enterpriseHookReconcileSyncEnrollments
	previousStateTrust, previousManifestTrust := enterpriseHookGuardianStateFileTrustCheck, enterpriseHookManifestFileTrustCheck
	previousOwnership := enterpriseHookAuthorizationOwnershipSetter
	t.Cleanup(func() {
		enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = previousManifest, previousAPI, previousProxy
		enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller = previousVerifier, previousInstaller
		enterpriseHookReconcileSessionAvailable, enterpriseForeignHookCleanup = previousSession, previousCleanup
		enterpriseHookReconcileTargetRelease, enterpriseHookReconcileDeferredSessionAvailable = previousRelease, previousDeferredSession
		enterpriseHookReconcileStageDeferredPolicies, enterpriseHookReconcileSyncEnrollments = previousStage, previousSync
		enterpriseHookGuardianStateFileTrustCheck, enterpriseHookManifestFileTrustCheck = previousStateTrust, previousManifestTrust
		enterpriseHookAuthorizationOwnershipSetter = previousOwnership
	})
	enterpriseForeignHookCleanup = func(enterprisehooks.TargetCredentials, string, string) (enterprisepolicy.CleanupResult, error) {
		return enterprisepolicy.CleanupResult{}, nil
	}
	enterpriseHookGuardianStateFileTrustCheck = func(string) error { return nil }
	enterpriseHookManifestFileTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }

	scope := t.TempDir()
	dataDir := filepath.Join(scope, "runtime")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	type account struct{ name, sid string }
	alice := account{"EntraAlice", "S-1-12-1-1-2-3-1001"}
	bob := account{"EntraBob", "S-1-12-1-1-2-3-1002"}
	carol := account{"EntraCarol", "S-1-12-1-1-2-3-1003"}
	dave := account{"EntraDave", "S-1-12-1-1-2-3-1004"}
	erin := account{"EntraErin", "S-1-12-1-1-2-3-1005"}
	homes := map[string]string{}
	for _, a := range []account{alice, bob, carol, dave, erin} {
		homes[a.sid] = filepath.Join(scope, a.name)
		if err := os.MkdirAll(homes[a.sid], 0o700); err != nil {
			t.Fatal(err)
		}
	}
	type target struct {
		account
		connector string
	}
	upgraded := []target{
		{alice, "claudecode"}, {alice, "codex"},
		{bob, "claudecode"}, {bob, "codex"},
		{carol, "claudecode"}, {carol, "codex"},
	}
	manifestPath := filepath.Join(scope, "targets.yaml")
	writeManifest := func(targets []target) (enterprisehooks.Manifest, string) {
		t.Helper()
		var body strings.Builder
		body.WriteString("version: 1\ntargets:\n")
		for _, tg := range targets {
			body.WriteString(awaitingSignInManifestTarget(homes[tg.sid], tg.sid, tg.connector))
		}
		if err := os.WriteFile(manifestPath, []byte(body.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		manifest, sha, err := enterprisehooks.LoadManifestWithSHA256(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		return manifest, sha
	}
	manifest, manifestSHA256 := writeManifest(upgraded)
	cfg = &config.Config{DataDir: dataDir, DeploymentMode: "local"}
	enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = manifestPath, "127.0.0.1:18970", "127.0.0.1:4000"

	// rc.3 protected and enrolled the six targets.
	store := awaitingSignInEnrollmentStore{}
	var protected []enterpriseHookReconcileRow
	for _, tg := range upgraded {
		store.enroll(tg.connector, tg.sid)
		protected = append(protected, enterpriseHookReconcileRow{UserHome: homes[tg.sid], SID: tg.sid, Connector: tg.connector, OK: true})
	}
	if err := writeEnterpriseHookGuardianState(dataDir, manifestPath, manifestSHA256, protected, 0, true); err != nil {
		t.Fatal(err)
	}

	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{}, errors.New("managed gateway binding: gateway service name \"\" is invalid")
	}
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) {
		return "1.0.2-rc.3", true, nil
	}
	signedIn := map[string]bool{erin.sid: true}
	enterpriseHookReconcileSessionAvailable = func(tg enterprisehooks.ManifestTarget) (bool, error) {
		return signedIn[tg.SID], nil
	}
	enterpriseHookReconcileDeferredSessionAvailable = enterpriseHookReconcileSessionAvailable
	var installErr error
	enterpriseHookReconcileInstaller = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if installErr != nil {
			return enterprisehooks.InstallResult{}, installErr
		}
		store.enroll(opts.ConnectorName, opts.OwnerSID)
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	staged := []string{}
	exactPublications := 0
	enterpriseHookReconcileStageDeferredPolicies = func(_ enterprisehooks.Manifest, pending []enterprisehooks.ManifestTarget, _ string) error {
		for _, tg := range pending {
			staged = append(staged, tg.SID+"/"+tg.Connector)
			store.enroll(tg.Connector, tg.SID)
		}
		return nil
	}
	enterpriseHookReconcileSyncEnrollments = func(m enterprisehooks.Manifest, _ string, publishExact bool) error {
		desired := awaitingSignInDesiredEnrollment(t, m)
		for connectorName, sids := range store {
			for sid := range sids {
				if !desired[connectorName][sid] {
					delete(sids, sid)
				}
			}
		}
		if !publishExact {
			return nil
		}
		exactPublications++
		for connectorName, sids := range desired {
			for sid := range sids {
				if !store[connectorName][sid] {
					return fmt.Errorf("refusing to add unverified %s target SID %s through exact-set publication", connectorName, sid)
				}
			}
		}
		return nil
	}
	excused := func() (removed, awaiting int, state enterpriseHookGuardianState) {
		t.Helper()
		state, exists, err := loadEnterpriseHookGuardianState(dataDir)
		if err != nil || !exists {
			t.Fatalf("load guardian state: exists=%v err=%v", exists, err)
		}
		reconcileCfg := cfg
		cfg = &config.Config{
			DataDir:        dataDir,
			DeploymentMode: managed.DeploymentModeManagedEnterprise,
			Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
		}
		defer func() { cfg = reconcileCfg }()
		removed, awaiting = enterpriseHookExcusedFailures(state)
		return removed, awaiting, state
	}

	// The upgrade: all three accounts are signed out, the six targets wait,
	// and the exact set rc.3 published is published again.
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil || run.StateErr != nil || run.Failures != 6 || exactPublications != 1 || len(staged) != 0 {
		t.Fatalf("upgrade: failures=%d pending=%d stateErr=%v exact=%d staged=%v err=%v", run.Failures, run.Pending, run.StateErr, exactPublications, staged, err)
	}
	if err := store.verify(awaitingSignInDesiredEnrollment(t, manifest)); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if removed, awaiting, state := excused(); removed != 0 || awaiting != 6 || state.SuccessCount != 0 ||
		state.PendingCount != 0 || state.FailureCount != 6 {
		t.Fatalf("upgrade: excused %d/%d state %+v, want raw 0/0/6 records all waiting", removed, awaiting, state)
	}

	// While they still wait: Dave is a new signed-out target (pending) and
	// Erin a new signed-in one. Dave is staged, Erin installed, and the
	// exact set covers both and keeps the waiting SIDs enrolled.
	manifest, _ = writeManifest(append(append([]target(nil), upgraded...), target{dave, "claudecode"}, target{erin, "codex"}))
	run, err = runEnterpriseHookReconcileOnce(context.Background())
	if err != nil || run.StateErr != nil || run.Failures != 6 || run.Pending != 1 || exactPublications != 2 ||
		strings.Join(staged, ",") != dave.sid+"/claudecode" {
		t.Fatalf("new targets: failures=%d pending=%d stateErr=%v exact=%d staged=%v err=%v", run.Failures, run.Pending, run.StateErr, exactPublications, staged, err)
	}
	if err := store.verify(awaitingSignInDesiredEnrollment(t, manifest)); err != nil {
		t.Fatalf("new targets: %v", err)
	}
	for _, sid := range []string{alice.sid, bob.sid, carol.sid, dave.sid} {
		if !store["claudecode"][strings.ToUpper(sid)] {
			t.Fatalf("new targets: Claude enrollment %v lacks %s", store.sorted("claudecode"), sid)
		}
	}
	if removed, awaiting, state := excused(); removed != 0 || awaiting != 6 || state.SuccessCount != 1 ||
		state.PendingCount != 1 || state.FailureCount != 6 {
		t.Fatalf("new targets: excused %d/%d state %+v", removed, awaiting, state)
	}

	// A real failure (Erin's repair is denied) still blocks staging and the
	// exact publication.
	installErr = errors.New("write managed Codex hook runtime: access is denied")
	staged = staged[:0]
	run, err = runEnterpriseHookReconcileOnce(context.Background())
	if err != nil || run.Failures != 7 || exactPublications != 2 || len(staged) != 0 {
		t.Fatalf("real failure: failures=%d pending=%d stateErr=%v exact=%d staged=%v err=%v", run.Failures, run.Pending, run.StateErr, exactPublications, staged, err)
	}
	if removed, awaiting, _ := excused(); removed != 0 || awaiting != 0 {
		t.Fatalf("real failure: excused %d/%d, want none", removed, awaiting)
	}
}
