// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// gap1733Pass runs one guardian pass with the Windows per-row rules of the
// standalone profile and records it. On Linux a standalone config routes the
// whole pass to the standalone Unix reconcile, so the pass starts on the local
// profile. The connector gate switches each row to the standalone profile for
// its checks, and the row's verifier or installer switches it back. calls
// counts the verifications and installs per account. An account in drift
// fails verification until it is installed again (the user stripped its
// hooks).
func (l *verifyEnrollmentLab) gap1733Pass(calls map[string]int, drift map[string]bool) {
	l.t.Helper()
	local := &config.Config{DataDir: l.dataDir, DeploymentMode: "local"}
	standalone := &config.Config{DataDir: l.dataDir, DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
	previousGate := enterpriseHookReconcileConnectorEnabled
	previousVerifier, previousInstaller := enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller
	defer func() {
		enterpriseHookReconcileConnectorEnabled = previousGate
		enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller = previousVerifier, previousInstaller
	}()
	enterpriseHookReconcileConnectorEnabled = func(string) error {
		cfg = standalone
		return nil
	}
	enterpriseHookReconcileVerifier = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		cfg = local
		calls["verify@"+opts.OwnerSID]++
		if drift[opts.OwnerSID+"/"+opts.ConnectorName] {
			return enterprisehooks.InstallResult{}, errors.New("enterprise hooks: the user-level hook config no longer registers the DefenseClaw hook")
		}
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	enterpriseHookReconcileInstaller = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		cfg = local
		calls["install@"+opts.OwnerSID]++
		delete(drift, opts.OwnerSID+"/"+opts.ConnectorName)
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	cfg = local
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil || run.StateErr != nil {
		l.t.Fatalf("guardian pass: run=%+v err=%v", run, err)
	}
	cfg = standalone
}

func (l *verifyEnrollmentLab) gap1733State() enterpriseHookGuardianState {
	l.t.Helper()
	state, exists, err := loadEnterpriseHookGuardianState(l.dataDir)
	if err != nil || !exists {
		l.t.Fatalf("load guardian state: exists=%v err=%v", exists, err)
	}
	return state
}

func (l *verifyEnrollmentLab) plantPerUserEntryAtAlice() {
	enterpriseHookAccountOwnedDataDirLink = func(string, string) bool { return false }
	enterpriseHookForeignDataDirLink = func(string, string) bool { return false }
	enterpriseHookPerUserInstallFolder = func(home, sid string) bool { return home == l.aliceHome && sid == labAlice }
}

// GAP-1733 review P1: the managed folder of an enrolled account is writable
// by that account, so a standard user can create an empty
// %USERPROFILE%\.defenseclaw\installer there. When that entry was read as a
// per-user install, it failed only that account's rows, before repair and
// watch. The account stayed enrolled, and verify excused the rows. The user
// could then strip the user-level hooks, and verify stayed green. On an
// account DefenseClaw protects, the entry is tamper. The guardian still
// repairs the hooks, and the account keeps its protection. Status and verify
// are red and excuse nothing.
func TestGAP1733PlantedPerUserEntryOnAnEnrolledAccountIsRepairedAndNotExcused(t *testing.T) {
	previousFolder := enterpriseHookPerUserInstallFolder
	t.Cleanup(func() { enterpriseHookPerUserInstallFolder = previousFolder })
	lab := newVerifyEnrollmentLab(t)
	lab.guardianPass(0)
	lab.plantPerUserEntryAtAlice()
	calls := map[string]int{}
	drift := map[string]bool{labAlice + "/codex": true, labAlice + "/copilot": true}
	lab.gap1733Pass(calls, drift)
	if calls["verify@"+labAlice] != 2 || calls["install@"+labAlice] != 2 || len(drift) != 0 {
		t.Fatalf("the enrolled account's stripped hooks were not repaired: calls=%v drift=%v", calls, drift)
	}
	state := lab.gap1733State()
	tampered := 0
	for _, row := range state.Results {
		if row.SID != labAlice {
			if !row.OK {
				t.Fatalf("another account failed: %+v", row)
			}
			continue
		}
		if row.OK || row.Error == enterpriseHookAccountPerUserInstallFailure || !strings.Contains(row.Error, "tamper") ||
			!strings.Contains(row.Error, lab.aliceHome) {
			t.Fatalf("enrolled account row = %+v, want a tamper failure naming its folder", row)
		}
		tampered++
	}
	if tampered != 2 {
		t.Fatalf("tampered rows = %d, want 2: %+v", tampered, state.Results)
	}
	if removed, awaiting, linked := enterpriseHookExcusedFailures(state); removed+awaiting+linked != 0 {
		t.Fatalf("status excused the tamper: %d removed, %d awaiting, %d linked", removed, awaiting, linked)
	}
	for _, connectorName := range []string{"codex", "copilot"} {
		if protected, err := previousEnterpriseHookSuccess(lab.dataDir, "", lab.aliceHome, labAlice, connectorName); err != nil || !protected {
			t.Fatalf("the enrolled account lost its %s protection: protected=%v err=%v", connectorName, protected, err)
		}
	}
	lab.publish(aliceCodex, aliceCopilot, bobCodex, bobCopilot)
	run := lab.verify(false)
	if verifyOK(run) {
		t.Fatalf("verify was green with the tamper: failures=%d excused=%d", run.Failures, len(run.Excused))
	}
	for _, row := range run.Excused {
		if row.SID == labAlice {
			t.Fatalf("verify excused the enrolled account: %+v", row)
		}
	}
}

// The first adoption is unchanged: an account DefenseClaw never protected,
// whose folder holds a per-user install, is skipped and its folder is left as
// found. Its rows are never verified or installed. Status and verify excuse
// exactly those rows, and verify expects the account out of the enrollment set.
func TestGAP1733PerUserInstallOfANeverProtectedAccountIsStillSkipped(t *testing.T) {
	previousFolder := enterpriseHookPerUserInstallFolder
	t.Cleanup(func() { enterpriseHookPerUserInstallFolder = previousFolder })
	lab := newVerifyEnrollmentLab(t)
	lab.plantPerUserEntryAtAlice()
	calls := map[string]int{}
	lab.gap1733Pass(calls, map[string]bool{})
	if calls["verify@"+labAlice]+calls["install@"+labAlice] != 0 || calls["install@"+labBob] != 2 {
		t.Fatalf("calls = %v, want the per-user account untouched and the other installed", calls)
	}
	state := lab.gap1733State()
	for _, row := range state.Results {
		if row.SID == labAlice && row.Error != enterpriseHookAccountPerUserInstallFailure {
			t.Fatalf("never-protected account row = %+v, want the per-user install skip", row)
		}
	}
	if removed, awaiting, linked := enterpriseHookExcusedFailures(state); removed != 0 || awaiting != 0 || linked != 2 {
		t.Fatalf("excused = %d removed, %d awaiting, %d linked, want the 2 skipped rows", removed, awaiting, linked)
	}
	lab.publish(bobCodex, bobCopilot)
	if run := lab.verify(false); !verifyOK(run) {
		t.Fatalf("verify: authorization=%v failures=%d excused=%d", run.AuthorizationErr, run.Failures, len(run.Excused))
	}
}
