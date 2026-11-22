// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-1762 (review RV-W111J of GAP-1537): the machine release history proves
// the computer ran a release, not that this account's lock came from it.
// After a 1.0.10 -> 1.0.11 upgrade (history [1.0.10]) an account the 1.0.11
// guardian already protected edited its lock's defenseclaw_version back to
// 1.0.10, stripped its hooks and signed out: the Secure Client branch (and on
// the standalone profile the closed-registration proof) returned "awaiting
// sign-in". The lock's release now counts only for a target this release has
// not protected yet: the guardian records each target it protects with the
// lock times of its result (release_protection.json, SYSTEM-only, beside the
// ledger), and the wait needs the ledger's row to be another guardian's. A
// legit upgrade with a still-signed-out account (never protected by 1.0.11)
// and a rollback round trip that an earlier guardian re-rendered still wait.
// Fails on f29b6f6617: the edited lock read as awaiting sign-in on both
// profiles.
func TestGAP1762OtherReleaseWaitIsBoundToTheTarget(t *testing.T) {
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
	dataDir := t.TempDir()
	authorizationDir := filepath.Join(t.TempDir(), "hook-guardian-state")
	t.Setenv(hookGuardianAuthorizationDirEnv, authorizationDir)
	cfg = &config.Config{DataDir: dataDir}

	const sid = "S-1-5-21-1-2-3-1001"
	enterpriseHookReconcileTargetRelease = enterpriseHookTargetReleaseNotProtectedHere
	// The account's lock names 1.0.10 (the replaced release, which the
	// standalone machine release history names): legit or edited, it reads
	// the same.
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
	installs := 0
	enterpriseHookReconcileInstaller = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		installs++
		return enterprisehooks.InstallResult{}, nil
	}
	secureClient := false
	enterpriseHookReconcileSecureClient = func() bool { return secureClient }

	// pass publishes one guardian pass for the target, as this release's
	// guardian (recorded) or another release's (not recorded).
	pass := func(label string, recorded, ok bool, lockUpdatedAt string) {
		t.Helper()
		enterpriseHookReleaseProtectionRecorded = func() bool { return recorded }
		row := enterpriseHookReconcileRow{SID: sid, UserHome: `C:\Users\alice`, Connector: "codex", OK: ok}
		failures := 0
		if ok {
			row.Result = &enterprisehooks.InstallResult{
				Connector: "codex", UserHome: `C:\Users\alice`,
				HookContractLockUpdatedAt: lockUpdatedAt, HookContractEntryUpdatedAt: lockUpdatedAt,
			}
		} else {
			row.Error, failures = "protected target requires repair", 1
		}
		if err := writeEnterpriseHookGuardianState(dataDir, "targets.yaml", testEnterpriseHookManifestSHA256,
			[]enterpriseHookReconcileRow{row}, failures, true); err != nil {
			t.Fatalf("%s: publish the pass: %v", label, err)
		}
		enterpriseHookReleaseProtectionRecorded = func() bool { return true }
	}
	target := enterprisehooks.ManifestTarget{Connector: "codex", SID: sid, Deferred: true}
	opts := enterprisehooks.InstallOptions{ConnectorName: "codex", OwnerSID: sid, UserHome: `C:\Users\alice`}
	expect := func(label string, wantWait bool) {
		t.Helper()
		for _, profile := range []bool{true, false} {
			secureClient = profile
			_, repaired, err := enterpriseHookVerifyOrRepairTarget(context.Background(), target, opts, true)
			if repaired || installs != 0 {
				t.Fatalf("%s (secure client %t): repaired=%t installs=%d, want no install as SYSTEM", label, profile, repaired, installs)
			}
			if waited := errors.Is(err, errEnterpriseHookAwaitingSignIn); waited != wantWait || err == nil {
				t.Fatalf("GAP-1762: %s (secure client %t): awaiting sign-in = %t (err=%v), want %t", label, profile, waited, err, wantWait)
			}
		}
	}

	// 1.0.10 protected the account, which is signed out across the upgrade.
	pass("1.0.10 protects", false, true, "2026-11-01T10:00:00Z")
	expect("a legit upgrade with an account 1.0.11 never protected", true)

	// 1.0.11 protects it at the account's sign-in; then the account edits
	// its lock back to 1.0.10, strips its hooks and signs out.
	pass("1.0.11 protects", true, true, "2026-11-23T08:00:00Z")
	pass("1.0.11 finds it drifted", true, false, "")
	expect("history [1.0.10], target already protected by this release, lock edited to 1.0.10", false)

	// A record an account could have written is not read: no wait.
	recordPath := filepath.Join(authorizationDir, enterpriseHookReleaseProtectionFile)
	enterpriseHookAuthorizationFileTrustCheck = func(path string) error {
		if path == recordPath {
			return errors.New("untrusted write ACE")
		}
		return nil
	}
	expect("an untrusted release protection record", false)
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }

	// A rollback round trip: 1.0.10 ran again and re-rendered the account at
	// its sign-in (new lock times in the ledger), and the account is signed
	// out at the upgrade back: its lock rightly names 1.0.10.
	pass("1.0.10 re-renders after a rollback", false, true, "2026-11-24T09:00:00Z")
	expect("a rollback round trip that an earlier guardian re-rendered", true)

	// A record of another release does not count.
	body, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := loadEnterpriseHookReleaseProtection(authorizationDir)
	if err != nil || len(record.Targets) != 1 || record.Targets[0].SID != sid || record.Targets[0].LockUpdatedAt != "2026-11-23T08:00:00Z" {
		t.Fatalf("record = %+v err=%v, want this release's protection of %s at 2026-11-23T08:00:00Z", record, err, sid)
	}
	other := strings.Replace(string(body), `"release": "`+enterpriseHookThisRelease()+`"`, `"release": "0.0.0-other"`, 1)
	other = strings.ReplaceAll(other, "2026-11-23T08:00:00Z", "2026-11-24T09:00:00Z")
	if other == string(body) {
		t.Fatalf("could not rewrite the record: %s", body)
	}
	if err := os.WriteFile(recordPath, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	expect("a record of another release", true)

	// The next pass of this release starts a fresh record, and a malformed
	// one is an error: no wait.
	pass("1.0.11 protects again", true, true, "2026-11-25T10:00:00Z")
	if record, _, err = loadEnterpriseHookReleaseProtection(authorizationDir); err != nil || record.Release != enterpriseHookThisRelease() ||
		len(record.Targets) != 1 || record.Targets[0].LockUpdatedAt != "2026-11-25T10:00:00Z" {
		t.Fatalf("record after another release's = %+v err=%v", record, err)
	}
	expect("protected again by this release", false)
	if err := os.WriteFile(recordPath, []byte(`{"schema_version":1,"release":"x","targets":[],"extra":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	expect("a malformed release protection record", false)
}
