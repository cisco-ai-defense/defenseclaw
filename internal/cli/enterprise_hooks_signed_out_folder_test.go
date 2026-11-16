// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// #1105, GAP-0211: the 1.0.2 -> 1.0.3 upgrade with a signed-out account
// whose hooks folder had one extra permission entry returned 1603 twice.
// Only that exact failure of the account's own DefenseClaw folder or hooks
// folder, while it is signed out, waits for the next sign-in; everything
// else stays a failure.
func TestEnterpriseHookSignedOutUntrustedFolder(t *testing.T) {
	const (
		dataDir   = `C:\Users\r103gb13-u1\.defenseclaw`
		unavail   = "enterprise hooks: protected target requires repair but its exact active Windows session is unavailable (verification: "
		hookCheck = "enterprise hooks: managed hook directory verification failed: "
		dataCheck = "enterprise hooks: managed data directory verification failed: "
		genCheck  = "enterprise hooks: managed runtime generation directory is untrusted: "
	)
	// The error the live T2 cell recorded (TST-2076).
	live := unavail + hookCheck + `enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw\hooks has 8 ACEs, expected 7)`
	for _, tc := range []struct {
		name   string
		row    enterpriseHookReconcileRow
		folder string
	}{
		{name: "live hooks folder", row: enterpriseHookReconcileRow{Error: live}, folder: dataDir + `\hooks`},
		{name: "case and trailing separator", row: enterpriseHookReconcileRow{Error: unavail + hookCheck +
			`enterprise hooks: managed Windows DACL is not protected on c:\users\R103GB13-U1\.defenseclaw\hooks\)`}, folder: dataDir + `\hooks`},
		{name: "data folder owner", row: enterpriseHookReconcileRow{Error: unavail + dataCheck +
			`enterprise hooks: owner SID S-1-5-32-545 does not match target SID S-1-5-21-1-2-3-1123 on C:\Users\r103gb13-u1\.defenseclaw)`}, folder: dataDir},
		{name: "unexpected entry", row: enterpriseHookReconcileRow{Error: unavail + hookCheck +
			`enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw\hooks contains unexpected or duplicate ACE for principal S-1-5-11 (mask 0x1301bf, inheritance 0x3))`}, folder: dataDir + `\hooks`},
		{name: "non-canonical entry", row: enterpriseHookReconcileRow{Error: unavail + hookCheck +
			`enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw\hooks contains non-canonical ACE type at index 2)`}, folder: dataDir + `\hooks`},
		{name: "unreadable DACL", row: enterpriseHookReconcileRow{Error: unavail + dataCheck +
			`enterprise hooks: null or unreadable Windows DACL on C:\Users\r103gb13-u1\.defenseclaw)`}, folder: dataDir},

		// GAP-2516 green upg2-g1: the Codex and Copilot rows of the same
		// signed-out account fail the runtime generation check on the same
		// hooks folder.
		{name: "runtime generation hooks folder", row: enterpriseHookReconcileRow{Error: unavail + genCheck +
			`enterprise hooks: managed Windows DACL is not protected on C:\Users\r103gb13-u1\.defenseclaw\hooks)`}, folder: dataDir + `\hooks`},
		{name: "runtime generation data folder", row: enterpriseHookReconcileRow{Error: unavail + genCheck +
			`enterprise hooks: owner SID S-1-5-32-545 does not match target SID S-1-5-21-1-2-3-1123 on C:\Users\r103gb13-u1\.defenseclaw)`}, folder: dataDir},
		// GAP-2516 residual live (cap-ewin4, deny ACE drift): the Hermes
		// footprint check and the current ACE type text.
		{name: "footprint deny entry", row: enterpriseHookReconcileRow{Error: unavail +
			`enterprise hooks: footprint directory trust check failed: enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw\hooks contains non-canonical ACE type 1 at index 0 (principal S-1-5-32-544))`}, folder: dataDir + `\hooks`},
		{name: "runtime generation deny entry", row: enterpriseHookReconcileRow{Error: unavail + genCheck +
			`enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw\hooks contains non-canonical ACE type 1 at index 0 (principal S-1-5-32-544))`}, folder: dataDir + `\hooks`},
		{name: "footprint another folder", row: enterpriseHookReconcileRow{Error: unavail +
			`enterprise hooks: footprint directory trust check failed: enterprise hooks: managed Windows DACL is not protected on C:\Users\r103gb13-u1\.hermes)`}},
		{name: "runtime generation below hooks", row: enterpriseHookReconcileRow{Error: unavail + genCheck +
			`enterprise hooks: managed Windows DACL is not protected on C:\Users\r103gb13-u1\.defenseclaw\hooks\codex)`}},
		{name: "runtime generation another account", row: enterpriseHookReconcileRow{Error: unavail + genCheck +
			`enterprise hooks: managed Windows DACL is not protected on C:\Users\other\.defenseclaw\hooks)`}},
		{name: "runtime generation other cause", row: enterpriseHookReconcileRow{Error: unavail + genCheck +
			`enterprise hooks: symlinks, junctions, and reparse points are not allowed: C:\Users\r103gb13-u1\.defenseclaw\hooks)`}},
		{name: "connected account", row: enterpriseHookReconcileRow{Error: hookCheck +
			`enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw\hooks has 8 ACEs, expected 7`}},
		{name: "another account's folder", row: enterpriseHookReconcileRow{Error: unavail + hookCheck +
			`enterprise hooks: managed Windows DACL on C:\Users\other\.defenseclaw\hooks has 8 ACEs, expected 7)`}},
		{name: "hook check naming the data folder", row: enterpriseHookReconcileRow{Error: unavail + hookCheck +
			`enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw has 8 ACEs, expected 7)`}},
		{name: "a folder below hooks", row: enterpriseHookReconcileRow{Error: unavail + hookCheck +
			`enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw\hooks\x has 8 ACEs, expected 7)`}},
		{name: "junction", row: enterpriseHookReconcileRow{Error: unavail + hookCheck +
			`enterprise hooks: symlinks, junctions, and reparse points are not allowed: C:\Users\r103gb13-u1\.defenseclaw\hooks)`}},
		{name: "runtime file", row: enterpriseHookReconcileRow{Error: unavail +
			`enterprise hooks: required managed runtime verification failed for C:\Users\r103gb13-u1\.defenseclaw\hooks\.hookcfg: ` +
			`enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw\hooks\.hookcfg has 8 ACEs, expected 7)`}},
		{name: "token mismatch", row: enterpriseHookReconcileRow{Error: unavail + "enterprise hooks: per-user connector-scoped token does not match)"}},
		{name: "text after the folder failure", row: enterpriseHookReconcileRow{Error: live + "; and more"}},
		{name: "waiting row", row: enterpriseHookReconcileRow{Error: enterpriseHookAwaitingSignInPrefix + ": " + live}},
		{name: "succeeded", row: enterpriseHookReconcileRow{OK: true, Error: live}},
		{name: "pending", row: enterpriseHookReconcileRow{Pending: true, Error: live}},
		{name: "runtime evidence", row: enterpriseHookReconcileRow{Error: live, Result: &enterprisehooks.InstallResult{}}},
	} {
		folder, ok := enterpriseHookSignedOutUntrustedFolder(tc.row, dataDir)
		if ok != (tc.folder != "") || folder != tc.folder {
			t.Errorf("%s: got %q, %t; want %q", tc.name, folder, ok, tc.folder)
		}
	}
	if _, ok := enterpriseHookSignedOutUntrustedFolder(enterpriseHookReconcileRow{Error: live}, ""); ok {
		t.Fatal("a target without a DefenseClaw folder matched")
	}
}

// GAP-2516: a managed Windows Setup /upgrade over a signed-out account whose
// hooks folder lost its protected DACL failed 1603, and so did its rollback,
// which left the gateway and the hook enumerator stopped and disabled for
// every user: the guardian failed the target, and only the account's own
// Windows session can reset the folder. That exact failure (#1105, GAP-0211)
// now waits for the account's next sign-in, naming the folder; every other
// failure of a signed-out account stays a failure.
func TestEnterpriseHookVerifyOrRepairTargetLeavesASignedOutUntrustedFolderToTheNextSignIn(t *testing.T) {
	previousVerifier, previousInstaller := enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller
	previousSession, previousRelease := enterpriseHookReconcileSessionAvailable, enterpriseHookReconcileTargetRelease
	previousSecureClient, previousChange := enterpriseHookReconcileSecureClient, enterpriseHookReconcileTargetFailModeChange
	previousDeferred := enterpriseHookReconcileDeferredSessionAvailable
	t.Cleanup(func() {
		enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller = previousVerifier, previousInstaller
		enterpriseHookReconcileSessionAvailable, enterpriseHookReconcileTargetRelease = previousSession, previousRelease
		enterpriseHookReconcileSecureClient, enterpriseHookReconcileTargetFailModeChange = previousSecureClient, previousChange
		enterpriseHookReconcileDeferredSessionAvailable = previousDeferred
	})
	secureClient := false
	enterpriseHookReconcileSecureClient = func() bool { return secureClient }
	enterpriseHookReconcileDeferredSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return true, nil }
	// This release wrote the lock and the fail mode did not change.
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "", false, nil }
	enterpriseHookReconcileTargetFailModeChange = func(enterprisehooks.InstallOptions) (string, string, error) { return "", "", nil }
	signedIn := false
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return signedIn, nil }
	const (
		dataDir = `C:\Users\dcw-disp1\.defenseclaw`
		hookDir = `enterprise hooks: managed hook directory verification failed: enterprise hooks: `
	)
	// The guardian's verification error of the live cell (TST-43664).
	live := errors.New(hookDir + `managed Windows DACL is not protected on C:\Users\dcw-disp1\.defenseclaw\hooks`)
	verifyErr := live
	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{}, verifyErr
	}
	installs := 0
	enterpriseHookReconcileInstaller = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		installs++
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName}, nil
	}
	target := enterprisehooks.ManifestTarget{SID: "S-1-5-21-1-2-3-1002", Connector: "claudecode", Deferred: true, DataDir: dataDir}
	run := func(target enterprisehooks.ManifestTarget) (bool, error) {
		_, repaired, err := enterpriseHookVerifyOrRepairTarget(context.Background(), target,
			enterprisehooks.InstallOptions{ConnectorName: target.Connector}, true)
		return repaired, err
	}

	_, err := run(target)
	if err == nil || !errors.Is(err, errEnterpriseHookAwaitingSignIn) || installs != 0 ||
		!strings.Contains(err.Error(), dataDir+`\hooks`) {
		t.Fatalf("signed-out untrusted hooks folder: err=%v installs=%d, want the sign-in wait naming the folder", err, installs)
	}
	row := enterpriseHookReconcileRow{SID: target.SID, Connector: target.Connector, Error: err.Error()}
	if !enterpriseHookAwaitingSignInError(row) || enterpriseHookEarlierMatrixRow(row) {
		t.Fatalf("the guardian row %q is not a plain sign-in wait", row.Error)
	}
	if cause := enterpriseHookAwaitingSignInCause(err.Error()); !strings.Contains(cause, dataDir+`\hooks are not the ones`) ||
		!strings.Contains(cause, "Inspect that folder") || strings.Contains(cause, "earlier DefenseClaw release") {
		t.Fatalf("status cause = %q, want the folder and the next step", cause)
	}

	// The account signs in: the guardian repairs the target in its session.
	signedIn = true
	if repaired, err := run(target); err != nil || !repaired || installs != 1 {
		t.Fatalf("signed in: repaired=%v err=%v installs=%d, want a repair", repaired, err, installs)
	}
	signedIn = false

	// Every other failure of a signed-out account stays a failure.
	for name, tc := range map[string]struct {
		target enterprisehooks.ManifestTarget
		err    error
		sc     bool
	}{
		"another account's folder": {target, errors.New(hookDir + `managed Windows DACL is not protected on C:\Users\other\.defenseclaw\hooks`), false},
		"a runtime file": {target, errors.New(`enterprise hooks: required managed runtime verification failed for ` +
			dataDir + `\hooks\.hookcfg: enterprise hooks: managed Windows DACL on ` + dataDir + `\hooks\.hookcfg has 8 ACEs, expected 7`), false},
		"a junction":    {target, errors.New(hookDir + `symlinks, junctions, and reparse points are not allowed: ` + dataDir + `\hooks`), false},
		"not deferred":  {enterprisehooks.ManifestTarget{SID: target.SID, Connector: target.Connector, DataDir: dataDir}, live, false},
		"Secure Client": {target, live, true},
	} {
		verifyErr, secureClient = tc.err, tc.sc
		if _, err := run(tc.target); err == nil || errors.Is(err, errEnterpriseHookAwaitingSignIn) {
			t.Fatalf("%s: err=%v, want the signed-out repair failure", name, err)
		}
	}
}
