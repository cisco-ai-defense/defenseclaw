// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// GAP-1129: a journal slot torn by a crash is ignored. The slot written before
// it still holds the earlier totals, and the next write reuses the torn slot.
func TestLocalWriteLossJournalIgnoresATornSlot(t *testing.T) {
	path := filepath.Join(t.TempDir(), LocalWriteLossJournalFile)
	clock := time.Unix(1_800_000_000, 0)
	now := func() time.Time { return clock }
	journal := newLocalWriteLossJournal(path, now)
	journal.add(audit.EventHistorySQLiteFull)
	clock = clock.Add(2 * localWriteLossCoalesce)
	journal.add(audit.EventHistorySQLiteFull)
	journal.close()

	data, err := os.ReadFile(path)
	if err != nil || len(data) != localWriteLossJournalSize {
		t.Fatalf("journal size %d, error %v", len(data), err)
	}
	for index := localWriteLossSlotSize + 100; index < 2*localWriteLossSlotSize; index++ {
		data[index] = 0 // the second write stopped part way
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened := newLocalWriteLossJournal(path, now)
	defer reopened.close()
	if losses := reopened.pending(); losses.Records != 1 || len(losses.Reasons) != 1 ||
		losses.Reasons[0].Reason != audit.EventHistorySQLiteFull || reopened.nextSlot != 1 {
		t.Fatalf("after a torn slot: losses %+v, next slot %d; want 1 full record, slot 1", losses, reopened.nextSlot)
	}
	if health := reopened.health(); health.State != LocalWriteLossJournalOK {
		t.Fatalf("journal health %+v", health)
	}
}

// GAP-1319: reporting a generation while newer losses wait writes one slot.
// When that write is torn, the earlier unreported totals come back; a consumed
// marker must never be left as the newest state that hides the newer losses.
func TestLocalWriteLossJournalTornWriteAfterConsumeKeepsNewerLosses(t *testing.T) {
	path := filepath.Join(t.TempDir(), LocalWriteLossJournalFile)
	clock := time.Unix(1_800_000_000, 0)
	now := func() time.Time { return clock }
	journal := newLocalWriteLossJournal(path, now)
	journal.add(audit.EventHistorySQLiteFull)
	reported := journal.pending()
	clock = clock.Add(2 * localWriteLossCoalesce)
	journal.add(audit.EventHistorySQLiteIO) // lost after pending returned
	clock = clock.Add(2 * localWriteLossCoalesce)
	journal.consume(reported)
	lastWritten := (journal.nextSlot + localWriteLossSlots - 1) % localWriteLossSlots
	journal.close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	intact := newLocalWriteLossJournal(path, now)
	if losses := intact.pending(); losses.Records != 1 || losses.Reasons[0].Reason != audit.EventHistorySQLiteIO {
		t.Fatalf("after consume: losses %+v; want the one newer io record", losses)
	}
	intact.close()
	for index := lastWritten*localWriteLossSlotSize + 100; index < (lastWritten+1)*localWriteLossSlotSize; index++ {
		data[index] = 0 // the last write stopped part way
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened := newLocalWriteLossJournal(path, now)
	defer reopened.close()
	losses := reopened.pending()
	sawIO := false
	for _, reason := range losses.Reasons {
		sawIO = sawIO || reason.Reason == audit.EventHistorySQLiteIO
	}
	if !sawIO {
		t.Fatalf("after a torn write: losses %+v; the newer io loss is hidden", losses)
	}
}
