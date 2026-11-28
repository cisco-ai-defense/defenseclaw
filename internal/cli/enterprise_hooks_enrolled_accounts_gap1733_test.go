// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// writeManifestWithout writes the lab manifest without the rows of sid, as the
// enumerator publishes it once an account's rows are dropped.
func (l *verifyEnrollmentLab) writeManifestWithout(sid string, full []byte) {
	l.t.Helper()
	header, rest, ok := strings.Cut(string(full), "targets:\n")
	if !ok {
		l.t.Fatal("lab manifest has no targets")
	}
	var kept strings.Builder
	kept.WriteString(header + "targets:\n")
	for _, block := range strings.SplitAfter(rest, "    deferred: true\n") {
		if strings.TrimSpace(block) != "" && !strings.Contains(block, "sid: "+sid+"\n") {
			kept.WriteString(block)
		}
	}
	if err := os.WriteFile(enterpriseHookManifest, []byte(kept.String()), 0o600); err != nil {
		l.t.Fatal(err)
	}
}

func (l *verifyEnrollmentLab) ledgerHolds(sid string) bool {
	l.t.Helper()
	authorization, _, err := loadEnterpriseHookGuardianAuthorization(l.dataDir)
	if err != nil {
		l.t.Fatalf("load ledger: %v", err)
	}
	for _, row := range authorization.ProtectedTargets {
		if strings.EqualFold(row.SID, sid) {
			return true
		}
	}
	return false
}

// assertAliceTamper checks one pass over alice's planted entry: her stripped
// hooks were repaired, every row of hers is the tamper failure, and none was
// skipped as a per-user install.
func (l *verifyEnrollmentLab) assertAliceTamper(pass string, calls map[string]int, drift map[string]bool) {
	l.t.Helper()
	if calls["install@"+labAlice] != 2 || len(drift) != 0 {
		l.t.Fatalf("%s: the enrolled account was skipped as a first adoption, its stripped hooks not repaired: calls=%v drift=%v", pass, calls, drift)
	}
	seen := 0
	for _, row := range l.gap1733State().Results {
		if row.SID != labAlice {
			continue
		}
		seen++
		if row.OK || row.Error == enterpriseHookAccountPerUserInstallFailure || !strings.Contains(row.Error, "tamper") {
			l.t.Fatalf("%s: enrolled account row = %+v, want the tamper failure", pass, row)
		}
	}
	if seen != 2 {
		l.t.Fatalf("%s: %d rows of the enrolled account, want 2", pass, seen)
	}
}

// GAP-1733 review 2 (P1): "first adoption" was decided from the account's
// current ledger rows. The ledger keeps only the rows of current manifest
// targets, so an enrolled account whose rows the enumerator dropped (the user
// moved a per-user connector's agent aside, and admission failed) lost its
// rows at the next publish. The user then planted the per-user install entry
// in the managed folder and restored the agent: the account read as never
// protected and was skipped, unprotected, with verify green. The account
// stays enrolled once protected, whatever its rows are.
func TestGAP1733AnAccountThatLostItsLastLedgerRowIsStillEnrolled(t *testing.T) {
	previousFolder := enterpriseHookPerUserInstallFolder
	t.Cleanup(func() { enterpriseHookPerUserInstallFolder = previousFolder })
	lab := newVerifyEnrollmentLab(t)
	lab.guardianPass(0)
	full, err := os.ReadFile(enterpriseHookManifest)
	if err != nil {
		t.Fatal(err)
	}
	lab.writeManifestWithout(labAlice, full)
	lab.guardianPass(0)
	if lab.ledgerHolds(labAlice) || !lab.ledgerHolds(labBob) {
		t.Fatalf("precondition: the publish after the rows were dropped must keep only bob's ledger rows (alice=%v bob=%v)",
			lab.ledgerHolds(labAlice), lab.ledgerHolds(labBob))
	}
	lab.plantPerUserEntryAtAlice()
	if err := os.WriteFile(enterpriseHookManifest, full, 0o600); err != nil {
		t.Fatal(err)
	}
	calls := map[string]int{}
	drift := map[string]bool{labAlice + "/codex": true, labAlice + "/copilot": true}
	lab.gap1733Pass(calls, drift)
	lab.assertAliceTamper("after the rows came back", calls, drift)
	if status := newEnterpriseHookPerUserInstallPass(lab.dataDir); !status.accountProtected(labAlice) {
		t.Fatal("status reads the account that lost its rows as never protected")
	}
}

// GAP-1733 review 2 (P2): with the ledger removed and the guardian state
// present, every account counts as enrolled, so a planted entry is tamper.
// That decision lasted one pass: the tamper row of an account with no
// earlier ledger row was not protected, so the account was unenrolled and
// left out of the ledger the pass wrote, and on the next pass it read as a
// first adoption and was skipped for good. A tamper row keeps its account
// enrolled and carries it into the next pass. The record of enrolled accounts
// is removed with the ledger, as on a host upgraded from a release that never
// wrote one.
func TestGAP1733MissingLedgerTamperOutlastsItsPass(t *testing.T) {
	previousFolder := enterpriseHookPerUserInstallFolder
	previousSync := enterpriseHookReconcileSyncEnrollments
	t.Cleanup(func() {
		enterpriseHookPerUserInstallFolder = previousFolder
		enterpriseHookReconcileSyncEnrollments = previousSync
	})
	lab := newVerifyEnrollmentLab(t)
	lab.guardianPass(0)
	authorizationDir := managed.HookGuardianAuthorizationDir(lab.dataDir)
	if err := os.Remove(managed.HookGuardianAuthorizationPath(lab.dataDir)); err != nil {
		t.Fatalf("remove the ledger: %v", err)
	}
	if err := os.Remove(filepath.Join(authorizationDir, "enrolled-accounts.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove the enrolled-accounts record: %v", err)
	}
	var enrolled map[string]bool
	enterpriseHookReconcileSyncEnrollments = func(m enterprisehooks.Manifest, _ string, _ bool) error {
		enrolled = map[string]bool{}
		for _, target := range m.Targets {
			if target.IsEnabled() {
				enrolled[enterpriseHookEnrollmentUnit(target)] = true
			}
		}
		return nil
	}
	lab.plantPerUserEntryAtAlice()
	aliceUnits := 0
	for _, pass := range []string{"pass 1", "pass 2"} {
		calls := map[string]int{}
		drift := map[string]bool{labAlice + "/codex": true, labAlice + "/copilot": true}
		enrolled = nil
		lab.gap1733Pass(calls, drift)
		lab.assertAliceTamper(pass, calls, drift)
		aliceUnits = 0
		for unit := range enrolled {
			if strings.Contains(strings.ToUpper(unit), strings.ToUpper(labAlice)) {
				aliceUnits++
			}
		}
		if enrolled == nil || aliceUnits == 0 {
			t.Fatalf("%s: the tamper account was unenrolled from the published enrollment set %v", pass, enrolled)
		}
	}
	if !newEnterpriseHookPerUserInstallPass(lab.dataDir).accountProtected(labAlice) {
		t.Fatal("after two passes, status reads the tamper account as never protected")
	}
}
