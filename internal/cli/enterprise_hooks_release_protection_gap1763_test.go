// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// gap1763Guardian drives guardian passes for one signed-out codex target and
// asks whether its other-release wait is allowed, as the GAP-1762 test does.
type gap1763Guardian struct {
	t                *testing.T
	dataDir          string
	authorizationDir string
	recordPath       string
	secureClient     *bool
	installs         *int
}

const gap1763SID = "S-1-5-21-1-2-3-1001"

func newGAP1763Guardian(t *testing.T) *gap1763Guardian {
	t.Helper()
	stubSecureClientSignInReconcile(t)
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	previousOwner, previousRecorded, previousLock := enterpriseHookAuthorizationOwnershipSetter, enterpriseHookReleaseProtectionRecorded, enterpriseHookReconcileTargetLockRelease
	previousClosed, previousChange, previousRetire := enterpriseHookReconcileClosedMachineRegistration, enterpriseHookReconcileTargetFailModeChange, enterpriseHookReconcileTargetRetireRender
	previousEarlier, previousCfg := enterpriseHookReconcileTargetEarlierMatrix, cfg
	t.Cleanup(func() {
		enterpriseHookAuthorizationOwnershipSetter, enterpriseHookReleaseProtectionRecorded, enterpriseHookReconcileTargetLockRelease = previousOwner, previousRecorded, previousLock
		enterpriseHookReconcileClosedMachineRegistration, enterpriseHookReconcileTargetFailModeChange, enterpriseHookReconcileTargetRetireRender = previousClosed, previousChange, previousRetire
		enterpriseHookReconcileTargetEarlierMatrix, cfg = previousEarlier, previousCfg
	})
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	g := &gap1763Guardian{t: t, dataDir: t.TempDir(), secureClient: new(bool), installs: new(int)}
	g.authorizationDir = filepath.Join(t.TempDir(), "hook-guardian-state")
	g.recordPath = filepath.Join(g.authorizationDir, enterpriseHookReleaseProtectionFile)
	t.Setenv(hookGuardianAuthorizationDirEnv, g.authorizationDir)
	cfg = &config.Config{DataDir: g.dataDir}
	enterpriseHookReconcileTargetRelease = enterpriseHookTargetReleaseNotProtectedHere
	// The account's lock names 1.0.10: legit or edited, it reads the same.
	enterpriseHookReconcileTargetLockRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "1.0.10", true, nil }
	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{}, errors.New("enterprise hooks: connector codex hook verification failed: owned hook command not present")
	}
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return false, nil }
	enterpriseHookReconcileDeferredSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return true, nil }
	enterpriseHookReconcileClosedMachineRegistration = func(enterprisehooks.InstallOptions) (bool, error) { return true, nil }
	enterpriseHookReconcileTargetFailModeChange = func(enterprisehooks.InstallOptions) (string, string, error) { return "", "", nil }
	enterpriseHookReconcileTargetRetireRender = func(enterprisehooks.InstallOptions) (string, bool, error) { return "", false, nil }
	enterpriseHookReconcileTargetEarlierMatrix = func(enterprisehooks.InstallOptions) (bool, error) { return false, nil }
	installs := g.installs
	enterpriseHookReconcileInstaller = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		*installs++
		return enterprisehooks.InstallResult{}, nil
	}
	secureClient := g.secureClient
	enterpriseHookReconcileSecureClient = func() bool { return *secureClient }
	return g
}

// pass publishes one guardian pass as this release's guardian (recorded)
// or another release's. ok is the row's outcome; lockUpdatedAt, when set,
// is the result's lock and entry time (a failed row with a result is an
// install whose row failed afterwards).
func (g *gap1763Guardian) pass(label string, recorded, ok bool, lockUpdatedAt string) error {
	g.t.Helper()
	enterpriseHookReleaseProtectionRecorded = func() bool { return recorded }
	defer func() { enterpriseHookReleaseProtectionRecorded = func() bool { return true } }()
	row := enterpriseHookReconcileRow{SID: gap1763SID, UserHome: `C:\Users\alice`, Connector: "codex", OK: ok}
	failures := 0
	if lockUpdatedAt != "" {
		row.Result = &enterprisehooks.InstallResult{
			Connector: "codex", UserHome: `C:\Users\alice`,
			HookContractLockUpdatedAt: lockUpdatedAt, HookContractEntryUpdatedAt: lockUpdatedAt,
		}
	}
	if !ok {
		row.Error, failures = "protected target requires repair", 1
	}
	enterpriseHookGuardianPublishedByProcess.Store(false)
	return writeEnterpriseHookGuardianState(g.dataDir, "targets.yaml", testEnterpriseHookManifestSHA256,
		[]enterpriseHookReconcileRow{row}, failures, true)
}

func (g *gap1763Guardian) mustPass(label string, recorded, ok bool, lockUpdatedAt string) {
	g.t.Helper()
	if err := g.pass(label, recorded, ok, lockUpdatedAt); err != nil {
		g.t.Fatalf("%s: publish the pass: %v", label, err)
	}
}

func (g *gap1763Guardian) expect(label string, wantWait bool) {
	g.t.Helper()
	target := enterprisehooks.ManifestTarget{Connector: "codex", SID: gap1763SID, Deferred: true}
	opts := enterprisehooks.InstallOptions{ConnectorName: "codex", OwnerSID: gap1763SID, UserHome: `C:\Users\alice`}
	for _, profile := range []bool{true, false} {
		*g.secureClient = profile
		_, repaired, err := enterpriseHookVerifyOrRepairTarget(context.Background(), target, opts, true)
		if repaired || *g.installs != 0 {
			g.t.Fatalf("%s (secure client %t): repaired=%t installs=%d, want no install as SYSTEM", label, profile, repaired, *g.installs)
		}
		if waited := errors.Is(err, errEnterpriseHookAwaitingSignIn); waited != wantWait || err == nil {
			g.t.Fatalf("GAP-1763: %s (secure client %t): awaiting sign-in = %t (err=%v), want %t", label, profile, waited, err, wantWait)
		}
	}
}

// GAP-1763 (a): the release protection record was written after the ledger
// and the activation receipt, so a record write that failed left a
// published generation the record did not cover. The record is written
// first: a pass whose record write fails publishes no new generation.
func TestGAP1763ReleaseRecordIsWrittenBeforeTheLedger(t *testing.T) {
	g := newGAP1763Guardian(t)
	g.mustPass("1.0.11 protects", true, true, "2026-11-23T08:00:00Z")
	before, _, err := loadEnterpriseHookGuardianAuthorization(g.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	enterpriseHookAuthorizationOwnershipSetter = func(path string) error {
		if path == g.recordPath {
			return errors.New("access denied")
		}
		return nil
	}
	if err := g.pass("record write fails", true, true, "2026-11-23T09:00:00Z"); err == nil {
		t.Fatal("a pass whose release protection record write failed reported success")
	}
	after, _, err := loadEnterpriseHookGuardianAuthorization(g.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if after.UpdatedAt != before.UpdatedAt {
		t.Fatalf("GAP-1763: the ledger was published (%s -> %s) although the release protection record write failed", before.UpdatedAt, after.UpdatedAt)
	}
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	// The next pass publishes both, and the record written for the failed
	// generation does not drop the target.
	g.mustPass("1.0.11 finds it drifted", true, false, "")
	g.expect("protected by this release after a failed record write, lock edited to 1.0.10", false)
}

// GAP-1763 (b): a record that did not read back was rebuilt from the
// targets OK in this pass only, so a protected target failing now lost its
// entry and its edited lock could wait. Every protected ledger row is kept.
func TestGAP1763RebuiltRecordKeepsFailingTargets(t *testing.T) {
	g := newGAP1763Guardian(t)
	g.mustPass("1.0.11 protects", true, true, "2026-11-23T08:00:00Z")
	if err := os.WriteFile(g.recordPath, []byte("{\"schema_version\":1,\"release\":\"x\",\"targets\":[],\"extra\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g.mustPass("1.0.11 finds it drifted, record malformed", true, false, "")
	g.expect("a failing protected target after a rebuilt record, lock edited to 1.0.10", false)
}

// GAP-1763 (c): 1.0.10 (after a rollback) re-rendered an account whose lock
// entry was deleted with the recovery times, the ones this release's record
// holds, so the ledger row matched and the account's lock, which rightly
// names 1.0.10, failed instead of waiting. The record counts only for the
// ledger generation it was written for.
func TestGAP1763RecordCountsOnlyForItsLedgerGeneration(t *testing.T) {
	g := newGAP1763Guardian(t)
	g.mustPass("1.0.11 protects", true, true, "2026-11-23T08:00:00Z")
	g.mustPass("1.0.10 re-renders with the recovery times", false, true, "2026-11-23T08:00:00Z")
	g.expect("a rollback round trip that re-rendered with the same times", true)
	// This release's next pass protects it again from then on.
	g.mustPass("1.0.11 protects again", true, true, "2026-11-25T08:00:00Z")
	g.mustPass("1.0.11 finds it drifted", true, false, "")
	g.expect("protected again by this release, lock edited to 1.0.10", false)
}

// GAP-1763 (d): an install that wrote this release's lock but whose row
// then failed was not recorded, so the account could edit its lock to the
// release before and wait. It is recorded, bound to the protection the
// ledger carries for it.
func TestGAP1763InstallWhoseRowFailedIsRecorded(t *testing.T) {
	g := newGAP1763Guardian(t)
	g.mustPass("1.0.10 protects", false, true, "2026-11-01T10:00:00Z")
	g.expect("a legit upgrade with an account 1.0.11 never protected", true)
	g.mustPass("1.0.11 installs, the row fails", true, false, "2026-11-23T08:00:00Z")
	g.expect("installed by this release, row failed, lock edited to 1.0.10", false)
}
