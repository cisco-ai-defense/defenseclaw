// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// TestT20DPackTablesAreTheGenerationsOwn (DET111 T19 review P3-4, T20
// review): the tier table a build read is live only when that build's
// generation publishes. A build that never publishes (superseded) left its
// note in one process-global pending map, which the next build's publish
// made live; and the fallback read of a directory was never invalidated.
// Now a note is keyed by its pack, a publish takes the notes of its own
// packs, and a directory the live generation does not load reads its
// tiers.yaml again after each publish. At 279da61428 the superseded build's
// table went live (zz probe t20d-red5d).
func TestT20DPackTablesAreTheGenerationsOwn(t *testing.T) {
	t.Cleanup(func() { publishPackTables(liveGeneration.Load()) })
	dir := t.TempDir()
	write := func(column string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, decide.TiersFile), []byte(column), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	parse := func(column string) *decide.Column {
		t.Helper()
		col, err := decide.ParseColumn([]byte(column))
		if err != nil {
			t.Fatal(err)
		}
		return col
	}
	const permissive = "version: 1\ntier: permissive\nrows:\n  - id: tiered-strict\n    per_user:\n      floor: allow\n    managed:\n      floor: allow\n"
	write("version: 1\ntier: default\n")

	// Build A reads a column for dir and is superseded; build B loads
	// another pack and publishes.
	packA, packB := &guardrail.RulePack{}, &guardrail.RulePack{}
	notePackTable(packA, dir, parse(permissive))
	notePackTable(packB, t.TempDir(), nil)
	publishPackTables(&Generation{RulePacks: map[string]*guardrail.RulePack{"global": packB}})
	if packTableHasTestColumn(packTable(dir)) {
		t.Fatalf("a superseded build's table went live for %s", dir)
	}

	// The generation that loaded packA makes its table live.
	publishPackTables(&Generation{RulePacks: map[string]*guardrail.RulePack{"global": packA}})
	tableA := packTable(dir)
	if !packTableHasTestColumn(tableA) {
		t.Fatal("the published generation's pack table is not live")
	}

	// A later generation without dir drops it; the fallback reads the file
	// as it is now, and a publish drops that read too.
	publishPackTables(&Generation{RulePacks: map[string]*guardrail.RulePack{"global": packB}})
	if packTableHasTestColumn(packTable(dir)) {
		t.Fatal("a directory the live generation does not load kept its old table")
	}
	write(permissive)
	publishPackTables(&Generation{RulePacks: map[string]*guardrail.RulePack{"global": packB}})
	if !packTableHasTestColumn(packTable(dir)) {
		t.Fatal("the fallback read of a directory was not invalidated by a publish")
	}

	// Notes, publishes and reads race freely (-race).
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				pack := &guardrail.RulePack{}
				notePackTable(pack, dir, parse(permissive))
				publishPackTables(&Generation{RulePacks: map[string]*guardrail.RulePack{"global": pack}})
				_ = packTable(dir)
			}
		}()
	}
	wg.Wait()
}

// packTableHasTestColumn: the table holds the permissive column of the test
// (tiered-strict enforced in a permissive request, as in
// TestTierGateReadsThePackTierAndTable).
func packTableHasTestColumn(table *decide.Table) bool {
	return trustedActionRequest{PolicyTier: decide.TierPermissive, Tiers: table}.tierEnforces(tierGateStrict)
}
