// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1733 review (live k2c, TST-11933): the "first adoption" decision read a
// missing protection ledger as "no account was ever protected". On a host the
// guardian has already published on, a missing ledger means the ledger was
// removed (or read at the wrong path), so the skip applied to every account
// and a planted per-user install entry on an enrolled account turned off its
// repair. Once the guardian has published, a missing ledger counts every
// account as enrolled: the planted entry is tamper, and the stripped hooks
// are repaired.
func TestGAP1733MissingLedgerAfterAPublishStillCountsEveryAccountAsEnrolled(t *testing.T) {
	previousFolder := enterpriseHookPerUserInstallFolder
	t.Cleanup(func() { enterpriseHookPerUserInstallFolder = previousFolder })
	lab := newVerifyEnrollmentLab(t)
	if newEnterpriseHookPerUserInstallPass(lab.dataDir).accountProtected(labAlice) {
		t.Fatal("before any publish, an account counted as enrolled: the first adoption would never be skipped")
	}
	lab.guardianPass(0)
	ledger := managed.HookGuardianAuthorizationPath(lab.dataDir)
	if err := os.Remove(ledger); err != nil {
		t.Fatalf("remove the ledger: %v", err)
	}
	const stranger = "S-1-5-21-9-9-9-4242"
	pass := newEnterpriseHookPerUserInstallPass(lab.dataDir)
	if !pass.accountProtected(labAlice) || !pass.accountProtected(stranger) {
		t.Fatalf("with the ledger %s removed after a publish, accounts read as never protected (alice=%v other=%v)",
			ledger, pass.accountProtected(labAlice), pass.accountProtected(stranger))
	}
	// The guardian state alone also proves an earlier publish.
	activation := filepath.Join(managed.HookGuardianAuthorizationDir(lab.dataDir), hookGuardianActivationFile)
	if err := os.Remove(activation); err != nil {
		t.Fatalf("remove the activation record: %v", err)
	}
	if !newEnterpriseHookPerUserInstallPass(lab.dataDir).accountProtected(stranger) {
		t.Fatal("with only the guardian state left, an account read as never protected")
	}

	lab.plantPerUserEntryAtAlice()
	calls := map[string]int{}
	drift := map[string]bool{labAlice + "/codex": true, labAlice + "/copilot": true}
	lab.gap1733Pass(calls, drift)
	if calls["install@"+labAlice] != 2 || len(drift) != 0 {
		t.Fatalf("with the ledger removed, the enrolled account's stripped hooks were skipped, not repaired: calls=%v drift=%v", calls, drift)
	}
	for _, row := range lab.gap1733State().Results {
		if row.SID == labAlice && (row.OK || row.Error == enterpriseHookAccountPerUserInstallFailure || !strings.Contains(row.Error, "tamper")) {
			t.Fatalf("enrolled account row = %+v, want the tamper failure", row)
		}
	}
}
