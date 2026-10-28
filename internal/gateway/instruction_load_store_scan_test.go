// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-1298: every hook call of a session the gateway has not seen saves its
// first sighting under storeMu, which every hook call takes. With the store
// at its record bound, a scan of every record, a prune of one and a rewrite
// of the whole pruned index on every save held the hook path long enough
// that a 10 calls a second load queued past the answer budget. A store at
// its bound is scanned once per instructionLoadRescanSaves saves, a prune
// goes down to instructionLoadStoreKeep, and the oldest sessions still lose
// their records first, into the pruned index.
func TestInstructionLoadStoreAtItsBoundIsNotScannedOnEverySave(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-time.Hour)
	write := func(index int, at time.Time) string {
		t.Helper()
		name := filepath.Join(dir, fmt.Sprintf("%064x.json", index))
		if err := os.WriteFile(name, []byte(`{"startup_known":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(name, at, at); err != nil {
			t.Fatal(err)
		}
		return name
	}
	for index := range maxInstructionLoadRecords {
		write(index+1, old.Add(time.Duration(index)*time.Millisecond))
	}
	oldest := filepath.Join(dir, fmt.Sprintf("%064x.json", 1))

	scans := 0
	instructionLoadStoreScanned = func() { scans++ }
	t.Cleanup(func() { instructionLoadStoreScanned = nil })

	cache := &activeAgentContextCache{}
	const saves = 1024
	for index := range saves {
		name := write(maxInstructionLoadRecords+1+index, time.Now())
		info, err := os.Lstat(name)
		if err != nil {
			t.Fatal(err)
		}
		cache.storeMu.Lock()
		cache.recordSavedLocked(dir, false, 0, info.Size())
		cache.storeMu.Unlock()
	}

	if limit := saves/instructionLoadRescanSaves + 4; scans > limit {
		t.Fatalf("the store was scanned %d times for %d saves, want at most %d", scans, saves, limit)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	records := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			records++
		}
	}
	if records > maxInstructionLoadRecords {
		t.Fatalf("the store holds %d records, past its bound %d", records, maxInstructionLoadRecords)
	}
	if _, err := os.Lstat(oldest); !os.IsNotExist(err) {
		t.Fatalf("the oldest record was kept past the bound: %v", err)
	}
	newest := filepath.Join(dir, fmt.Sprintf("%064x.json", maxInstructionLoadRecords+saves))
	if _, err := os.Lstat(newest); err != nil {
		t.Fatalf("the newest record was pruned: %v", err)
	}
	index, err := os.ReadFile(filepath.Join(dir, instructionLoadPrunedName))
	if err != nil || !strings.Contains(string(index), fmt.Sprintf("%064x", 1)) {
		t.Fatalf("the pruned index does not list the oldest session: %v", err)
	}
}
