// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-10 GAP-1885 (review note P4-1 of GAP-1763): a pass whose record
// was written and whose ledger write then failed (a crash, or a failure
// inside the replace) left a record ahead of the ledger. The record counted
// only for the generation it was written for, so for the next pass an
// account that had edited its lock to the earlier release and stripped its
// hooks read as awaiting sign-in. The record also counts for the generation
// it was built on: its targets were carried or added only from rows bound to
// that ledger, and the lock and entry times must still match its rows.
func TestGAP1885RecordAheadOfItsLedgerStillCounts(t *testing.T) {
	g := newGAP1763Guardian(t)
	g.mustPass("1.0.11 protects", true, true, "2026-11-23T08:00:00Z")
	ledger := filepath.Join(g.authorizationDir, hookGuardianAuthorizationFile)
	aside := ledger + ".aside"
	enterpriseHookAuthorizationOwnershipSetter = func(path string) error {
		if path != g.recordPath {
			return nil
		}
		// The record is written: the ledger write that follows fails.
		if err := os.Rename(ledger, aside); err != nil {
			return err
		}
		return os.Mkdir(ledger, 0o700)
	}
	if err := g.pass("the ledger write fails", true, true, "2026-11-23T08:00:00Z"); err == nil {
		t.Fatal("a pass whose ledger write failed reported success")
	}
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	if err := os.Remove(ledger); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(aside, ledger); err != nil {
		t.Fatal(err)
	}
	record, _, err := loadEnterpriseHookReleaseProtection(g.authorizationDir)
	if err != nil {
		t.Fatal(err)
	}
	published, _, err := loadEnterpriseHookGuardianAuthorization(g.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if record.Generation == published.UpdatedAt || record.BaseGeneration != published.UpdatedAt {
		t.Fatalf("fixture precondition: want a record ahead of the ledger, built on it (record %s on %s, ledger %s)",
			record.Generation, record.BaseGeneration, published.UpdatedAt)
	}
	g.expect("record ahead of its ledger, lock edited to 1.0.10", false)
}
