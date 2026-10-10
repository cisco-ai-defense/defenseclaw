// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
)

// LocalWriteLossJournalFile is the reserved file in the gateway data
// directory that counts the log records whose mandatory SQLite append failed
// and that no sqlite.write_failed record has reported yet. A count kept only
// in memory was gone after a crash or restart before writes recovered, so the
// gap in the local history went silent (GAP-1129). The file holds counts,
// times and reason codes, never record content.
const LocalWriteLossJournalFile = "local-write-losses.journal"

// The journal is written at its full size when it is created, so recording a
// loss rewrites bytes the file already owns and a full disk cannot refuse it.
// It is a ring of fixed-size slots rewritten in place (an O_APPEND write would
// grow the file past the reserved space). Each slot holds the running totals
// of one loss generation, a sequence number and a CRC-32C. The valid slot with
// the highest sequence is the journal state: a slot torn by a crash fails its
// check, and the slot written before it still holds the earlier totals. A
// consumed slot marks a generation that has been reported.
const (
	localWriteLossJournalSize = 64 << 10
	localWriteLossSlotSize    = 256
	localWriteLossSlots       = localWriteLossJournalSize / localWriteLossSlotSize
	localWriteLossMagic       = "DCLWLJ01"
	localWriteLossConsumed    = 1
	localWriteLossTotalsAt    = 40
	localWriteLossChecked     = localWriteLossSlotSize - 4
	// localWriteLossCoalesce bounds journal writes to one a second: a burst
	// of failed appends is written as one slot with the running totals.
	localWriteLossCoalesce = time.Second
)

// localWriteLossReasons are the reason codes in slot order: the SQLite
// classes that event-history health reports.
var localWriteLossReasons = [...]audit.EventHistorySQLiteClass{
	audit.EventHistorySQLiteFull,
	audit.EventHistorySQLiteIO,
	audit.EventHistorySQLiteReadOnlyCantOpen,
	audit.EventHistorySQLiteBusyLocked,
	audit.EventHistorySQLiteDeadline,
	audit.EventHistorySQLiteConstraintCorrupt,
	audit.EventHistorySQLiteUnavailable,
	audit.EventHistorySQLiteOther,
}

var localWriteLossCRC = crc32.MakeTable(crc32.Castagnoli)

// Journal states reported by LocalWriteLossJournalHealth.
const (
	LocalWriteLossJournalOK      = "ok"
	LocalWriteLossJournalFailing = "failing"
)

// LocalWriteLossReason is one reason share of the unreported losses.
type LocalWriteLossReason struct {
	Reason  audit.EventHistorySQLiteClass
	Records uint64
	First   time.Time
	Last    time.Time
}

// LocalWriteLosses are the log records local history is missing that no
// sqlite.write_failed record has reported yet. Generation names them both in
// the journal and in the record that reports them.
type LocalWriteLosses struct {
	Generation string
	Records    uint64
	Reasons    []LocalWriteLossReason

	generation [16]byte
	totals     localWriteLossTotals
}

// LocalWriteLossJournalHealth is empty without a journal (Secure Client).
// State is "failing" while the journal cannot be opened or written; the
// losses are then counted in memory only and a restart would lose them.
type LocalWriteLossJournalHealth struct {
	State        string
	FailedWrites uint64
}

type localWriteLossTotal struct {
	count       uint64
	first, last int64 // Unix nanoseconds
}

func (total localWriteLossTotal) merged(other localWriteLossTotal) localWriteLossTotal {
	switch {
	case other.count == 0:
		return total
	case total.count == 0:
		return other
	}
	return localWriteLossTotal{
		count: total.count + other.count, first: min(total.first, other.first), last: max(total.last, other.last),
	}
}

type localWriteLossTotals [len(localWriteLossReasons)]localWriteLossTotal

type localWriteLossSlot struct {
	generation [16]byte
	sequence   uint64
	consumed   bool
	totals     localWriteLossTotals
}

func (slot localWriteLossSlot) encode() []byte {
	buf := make([]byte, localWriteLossSlotSize)
	copy(buf, localWriteLossMagic)
	copy(buf[8:24], slot.generation[:])
	binary.LittleEndian.PutUint64(buf[24:32], slot.sequence)
	if slot.consumed {
		buf[32] = localWriteLossConsumed
	}
	for index, total := range slot.totals {
		at := localWriteLossTotalsAt + index*24
		binary.LittleEndian.PutUint64(buf[at:], total.count)
		binary.LittleEndian.PutUint64(buf[at+8:], uint64(total.first))
		binary.LittleEndian.PutUint64(buf[at+16:], uint64(total.last))
	}
	binary.LittleEndian.PutUint32(buf[localWriteLossChecked:], crc32.Checksum(buf[:localWriteLossChecked], localWriteLossCRC))
	return buf
}

func decodeLocalWriteLossSlot(buf []byte) (localWriteLossSlot, bool) {
	if len(buf) != localWriteLossSlotSize || string(buf[:8]) != localWriteLossMagic || buf[32]&^localWriteLossConsumed != 0 ||
		binary.LittleEndian.Uint32(buf[localWriteLossChecked:]) != crc32.Checksum(buf[:localWriteLossChecked], localWriteLossCRC) {
		return localWriteLossSlot{}, false
	}
	slot := localWriteLossSlot{sequence: binary.LittleEndian.Uint64(buf[24:32]), consumed: buf[32] == localWriteLossConsumed}
	copy(slot.generation[:], buf[8:24])
	if slot.sequence == 0 || slot.generation == ([16]byte{}) {
		return localWriteLossSlot{}, false
	}
	for index := range slot.totals {
		at := localWriteLossTotalsAt + index*24
		slot.totals[index] = localWriteLossTotal{
			count: binary.LittleEndian.Uint64(buf[at:]),
			first: int64(binary.LittleEndian.Uint64(buf[at+8:])),
			last:  int64(binary.LittleEndian.Uint64(buf[at+16:])),
		}
	}
	return slot, true
}

func localWriteLossReasonIndex(reason audit.EventHistorySQLiteClass) int {
	for index, known := range localWriteLossReasons {
		if known == reason {
			return index
		}
	}
	return len(localWriteLossReasons) - 1
}

// localWriteFailureReason is the SQLite class of a failed mandatory append.
func localWriteFailureReason(err error) audit.EventHistorySQLiteClass {
	var pipelineErr *pipeline.Error
	if errors.As(err, &pipelineErr) {
		return pipelineErr.SQLiteClass()
	}
	return audit.EventHistorySQLiteOther
}

func newLocalWriteLossGeneration() [16]byte {
	var generation [16]byte
	_, _ = rand.Read(generation[:])
	generation[0] |= 1 // never the zero "no generation" value
	return generation
}

// localWriteLossJournal counts failed local writes in memory and, when it has
// a path, keeps the counts in the reserved journal file. The runtime owns one
// for the whole process; every graph generation shares it.
type localWriteLossJournal struct {
	mu   sync.Mutex
	path string
	now  func() time.Time

	file     *os.File
	nextSlot int
	nextSeq  uint64

	generation [16]byte
	totals     localWriteLossTotals
	dirty      bool
	marker     *localWriteLossSlot

	lastWrite time.Time
	timer     *time.Timer
	failing   bool
	failed    uint64
	closed    bool
}

func newLocalWriteLossJournal(path string, now func() time.Time) *localWriteLossJournal {
	journal := &localWriteLossJournal{path: path, now: now, nextSeq: 1}
	if path != "" {
		journal.mu.Lock()
		if err := journal.openLocked(); err != nil {
			journal.noteFailureLocked(err)
		}
		journal.mu.Unlock()
	}
	return journal
}

// openLocked opens the journal, first writing a reserved one when it is
// missing or has another size, and takes in the losses it holds.
func (journal *localWriteLossJournal) openLocked() error {
	info, err := os.Lstat(journal.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", journal.path)
	}
	if err != nil || info.Size() != localWriteLossJournalSize {
		// A managed gateway publishes it like its other runtime files, under
		// the runtime folder's access list: a private DACL of the service
		// account and SYSTEM left the elevated repair unable to open it
		// (GAP-1220).
		if err := managed.WriteServiceRuntimeFile(
			managed.PinnedDeploymentMode(), journal.path, "local write loss journal",
			make([]byte, localWriteLossJournalSize),
		); err != nil {
			return err
		}
		if info, err = os.Lstat(journal.path); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(journal.path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	opened, err := file.Stat()
	if err == nil && (!opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != localWriteLossJournalSize) {
		err = fmt.Errorf("%s changed while it was opened", journal.path)
	}
	data := make([]byte, localWriteLossJournalSize)
	if err == nil {
		_, err = file.ReadAt(data, 0)
	}
	if err != nil {
		_ = file.Close()
		return err
	}
	journal.file = file
	journal.loadLocked(data)
	return nil
}

// loadLocked takes the newest valid slot as the journal state and adds its
// unreported totals to what this process has counted.
func (journal *localWriteLossJournal) loadLocked(data []byte) {
	newestAt := -1
	var newest localWriteLossSlot
	for index := range localWriteLossSlots {
		slot, ok := decodeLocalWriteLossSlot(data[index*localWriteLossSlotSize : (index+1)*localWriteLossSlotSize])
		if ok && (newestAt < 0 || slot.sequence > newest.sequence) {
			newest, newestAt = slot, index
		}
	}
	if newestAt < 0 {
		journal.nextSlot, journal.nextSeq = 0, 1
		return
	}
	journal.nextSlot, journal.nextSeq = (newestAt+1)%localWriteLossSlots, newest.sequence+1
	if newest.consumed {
		return
	}
	if journal.generation == ([16]byte{}) {
		journal.generation = newest.generation
	} else {
		journal.dirty = true
	}
	for index := range journal.totals {
		journal.totals[index] = journal.totals[index].merged(newest.totals[index])
	}
}

// add counts one record whose mandatory SQLite append failed.
func (journal *localWriteLossJournal) add(reason audit.EventHistorySQLiteClass) {
	if journal == nil {
		return
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	now := journal.now()
	if journal.generation == ([16]byte{}) {
		journal.generation = newLocalWriteLossGeneration()
	}
	at := now.UnixNano()
	journal.totals[localWriteLossReasonIndex(reason)] = journal.totals[localWriteLossReasonIndex(reason)].merged(
		localWriteLossTotal{count: 1, first: at, last: at},
	)
	journal.dirty = true
	if journal.path == "" || journal.closed || journal.timer != nil {
		return
	}
	if wait := journal.lastWrite.Add(localWriteLossCoalesce).Sub(now); wait > 0 {
		journal.timer = time.AfterFunc(wait, journal.flushAfterDelay)
		return
	}
	journal.flushLocked(now)
}

func (journal *localWriteLossJournal) flushAfterDelay() {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	journal.timer = nil
	journal.flushLocked(journal.now())
}

// flushLocked writes a pending consumed slot, then the running totals. A
// journal that could not be opened is opened again first.
func (journal *localWriteLossJournal) flushLocked(now time.Time) {
	if journal.path == "" || journal.closed ||
		!journal.dirty && journal.marker == nil && (journal.file != nil || !journal.failing) {
		return
	}
	journal.lastWrite = now
	if journal.file == nil {
		if err := journal.openLocked(); err != nil {
			journal.noteFailureLocked(err)
			return
		}
	}
	if journal.marker != nil {
		if err := journal.writeSlotLocked(*journal.marker); err != nil {
			journal.noteFailureLocked(err)
			return
		}
		journal.marker = nil
	}
	if journal.dirty && journal.generation != ([16]byte{}) {
		if err := journal.writeSlotLocked(localWriteLossSlot{generation: journal.generation, totals: journal.totals}); err != nil {
			journal.noteFailureLocked(err)
			return
		}
	}
	journal.dirty = false
	if journal.failing {
		journal.failing = false
		fmt.Fprintf(os.Stderr, "[observability] the local-write loss journal %s can be written again\n", journal.path)
	}
}

func (journal *localWriteLossJournal) writeSlotLocked(slot localWriteLossSlot) error {
	slot.sequence = journal.nextSeq
	if _, err := journal.file.WriteAt(slot.encode(), int64(journal.nextSlot)*localWriteLossSlotSize); err != nil {
		return err
	}
	if err := journal.file.Sync(); err != nil {
		return err
	}
	journal.nextSlot = (journal.nextSlot + 1) % localWriteLossSlots
	journal.nextSeq++
	return nil
}

func (journal *localWriteLossJournal) noteFailureLocked(err error) {
	journal.failed++
	if !journal.failing {
		journal.failing = true
		fmt.Fprintf(os.Stderr, "[observability] cannot write the local-write loss journal %s: %v; "+
			"records missing from the local history are counted in memory only until it can be written\n", journal.path, err)
	}
}

// pending returns the unreported losses. A failing journal is tried again
// first, so one that could not be written on a full disk recovers when the
// audit writes do.
func (journal *localWriteLossJournal) pending() LocalWriteLosses {
	if journal == nil {
		return LocalWriteLosses{}
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.failing {
		journal.flushLocked(journal.now())
	}
	if journal.generation == ([16]byte{}) {
		return LocalWriteLosses{}
	}
	losses := LocalWriteLosses{
		Generation: hex.EncodeToString(journal.generation[:]), generation: journal.generation, totals: journal.totals,
	}
	for index, total := range journal.totals {
		if total.count == 0 {
			continue
		}
		losses.Records += total.count
		losses.Reasons = append(losses.Reasons, LocalWriteLossReason{
			Reason: localWriteLossReasons[index], Records: total.count,
			First: time.Unix(0, total.first).UTC(), Last: time.Unix(0, total.last).UTC(),
		})
	}
	return losses
}

// consume marks losses that pending returned as reported. Records lost after
// pending returned start a new generation.
func (journal *localWriteLossJournal) consume(losses LocalWriteLosses) {
	if journal == nil || losses.Records == 0 {
		return
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.generation != losses.generation {
		return
	}
	var rest localWriteLossTotals
	remaining := false
	for index, total := range journal.totals {
		if total.count > losses.totals[index].count {
			rest[index] = localWriteLossTotal{count: total.count - losses.totals[index].count, first: total.last, last: total.last}
			remaining = true
		}
	}
	if journal.path != "" {
		journal.marker = &localWriteLossSlot{generation: journal.generation, consumed: true, totals: losses.totals}
	}
	journal.generation, journal.totals, journal.dirty = [16]byte{}, rest, false
	if remaining {
		journal.generation, journal.dirty = newLocalWriteLossGeneration(), true
	}
	journal.flushLocked(journal.now())
}

// close writes the totals still waiting for the coalescing delay, so a normal
// stop keeps every counted loss, and closes the file.
func (journal *localWriteLossJournal) close() {
	if journal == nil {
		return
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.closed {
		return
	}
	if journal.timer != nil {
		journal.timer.Stop()
		journal.timer = nil
	}
	journal.flushLocked(journal.now())
	journal.closed = true
	if journal.file != nil {
		_ = journal.file.Close()
		journal.file = nil
	}
}

func (journal *localWriteLossJournal) health() LocalWriteLossJournalHealth {
	if journal == nil || journal.path == "" {
		return LocalWriteLossJournalHealth{}
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	state := LocalWriteLossJournalOK
	if journal.failing {
		state = LocalWriteLossJournalFailing
	}
	return LocalWriteLossJournalHealth{State: state, FailedWrites: journal.failed}
}
