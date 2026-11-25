// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// captureAuditStderr returns what fn wrote to os.Stderr.
func captureAuditStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	var buf strings.Builder
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b, _ := io.ReadAll(r)
		buf.Write(b)
	}()
	defer func() {
		_ = w.Close()
		wg.Wait()
		os.Stderr = orig
	}()
	fn()
	_ = w.Close()
	wg.Wait()
	os.Stderr = orig
	return buf.String()
}

// substrate-1:GAP-0554: every error class a full volume produces is one
// class, and nothing else is.
func TestIsStoreFullErrorNamesEveryDiskFullClass(t *testing.T) {
	for _, err := range []error{
		fmt.Errorf("audit: copy SQLite WAL: %w", errors.New("database or disk is full (13)")),
		&eventHistoryWriteError{cause: errors.New("database or disk is full (13)")},
		fmt.Errorf("audit: commit correlation transaction: %w", errors.New("database or disk is full (13)")),
		fmt.Errorf("write audit.db-wal: %w", &os.PathError{Op: "write", Path: "audit.db-wal", Err: syscall.ENOSPC}),
		fmt.Errorf("write: %w", syscall.EDQUOT),
		errors.New("write audit.db-wal: no space left on device"),
		errors.New("There is not enough space on the disk."),
		errors.Join(errGroupedTxLost, errors.New("database or disk is full")),
	} {
		if !IsStoreFullError(err) {
			t.Errorf("IsStoreFullError(%v) = false, want true", err)
		}
	}
	for _, err := range []error{nil, errors.New("database is locked (5)"), context.DeadlineExceeded,
		errors.New("disk I/O error (10)"), syscall.EFBIG} {
		if IsStoreFullError(err) {
			t.Errorf("IsStoreFullError(%v) = true, want false", err)
		}
	}
}

// One ALERT line per full episode, at most one a minute however many writes
// fail, one cleared line when a write commits again, and no line at all for
// a failure that is not a full volume.
func TestStoreFullAlertIsOneRateLimitedLine(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	storeFullAlertClock = func() time.Time { return now }
	t.Cleanup(func() { storeFullAlertClock = time.Now })
	store := &Store{dbPath: "/data/audit.db"}
	full := errors.New("database or disk is full (13)")
	out := captureAuditStderr(t, func() {
		if store.NoteWriteError("hook_call_transaction", errors.New("database is locked (5)")) {
			t.Error("a busy store was reported full")
		}
		for i := 0; i < 50; i++ {
			store.NoteWriteError("v8_event_history_transaction", full)
			now = now.Add(time.Second)
		}
		store.NoteWriteError("WAL checkpoint", full) // 50 s in: still the first minute
		now = now.Add(11 * time.Second)
		store.NoteWriteError("WAL checkpoint", full) // past a minute, still full: once more
		store.noteWriteOK()
		store.noteWriteOK()
	})
	if n := strings.Count(out, "ALERT audit_store_full"); n != 2 {
		t.Fatalf("%d ALERT lines, want 2 (the first and one a minute later):\n%s", n, out)
	}
	if n := strings.Count(out, "audit_store_full cleared"); n != 1 {
		t.Fatalf("%d cleared lines, want 1:\n%s", n, out)
	}
	for _, want := range []string{"(v8_event_history_transaction: database or disk is full (13))", "fail closed",
		"max_store_mb", "/data/audit.db"} {
		if !strings.Contains(out, want) {
			t.Fatalf("alert output lacks %q:\n%s", want, out)
		}
	}
}

// substrate-1:GAP-0554 on a real full volume: the store's WAL checkpoint, its
// event-history writes and a correlation commit all fail with the kernel's
// ENOSPC through SQLite, and the operator gets one ALERT line whichever fails
// first, then one cleared line when the volume has room again.
func TestRealFullStoreLogsOneAlertForEveryWritePath(t *testing.T) {
	dir := testenv.RealSmallFilesystem(t, 40)
	store, err := NewStore(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	event := func(i int) Event {
		return Event{Timestamp: time.Now().UTC(), Action: "scan", Target: fmt.Sprintf("/skills/%d-%s", i, strings.Repeat("x", 2000)), Severity: "INFO"}
	}
	if err := store.LogEvent(event(0)); err != nil {
		t.Fatalf("store with room: %v", err)
	}
	release := testenv.FillFilesystem(t, dir)
	var writeErr, checkpointErr error
	out := captureAuditStderr(t, func() {
		for i := 1; i < 2000 && writeErr == nil; i++ {
			writeErr = store.LogEvent(event(i))
		}
		_, checkpointErr = store.CheckpointWALIfLarge(context.Background(), 0, 200*time.Millisecond)
	})
	if writeErr == nil {
		t.Fatalf("2000 writes on a full volume all succeeded\n%s", out)
	}
	if !IsStoreFullError(writeErr) {
		t.Fatalf("write on a full volume failed with %v, not a full-store error", writeErr)
	}
	t.Logf("write: %v; checkpoint: %v", writeErr, checkpointErr)
	if n := strings.Count(out, "ALERT audit_store_full"); n != 1 {
		t.Fatalf("%d ALERT lines on a full volume, want 1:\n%s", n, out)
	}
	release()
	cleared := captureAuditStderr(t, func() {
		if err := store.LogEvent(event(9999)); err != nil {
			t.Errorf("store with room again: %v", err)
		}
	})
	if !strings.Contains(cleared, "audit_store_full cleared") {
		t.Fatalf("no cleared line once the volume had room again:\n%s", cleared)
	}
}

// substrate-1:GAP-0578 (c): the rate limit used to run on from the last ALERT
// line across a "cleared" line, so an outage that started less than a minute
// after the previous one's ALERT got no line at all when it ended inside that
// minute. A new outage after a cleared line now alerts at once; a third one
// inside the same minute (a flapping volume) is folded and named by one ALERT
// line a minute after the last, never lost.
func TestStoreFullAlertRestartsAfterACleared(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	storeFullAlertClock = func() time.Time { return now }
	t.Cleanup(func() { storeFullAlertClock = time.Now })
	store := &Store{dbPath: "/data/audit.db"}
	full := errors.New("database or disk is full (13)")
	step := func(d time.Duration) { now = now.Add(d) }
	out := captureAuditStderr(t, func() {
		store.NoteWriteError("hook_call_transaction", full) // T: outage 1
		step(20 * time.Second)
		store.noteWriteOK() // T+20: cleared
		step(20 * time.Second)
		store.NoteWriteError("hook_call_transaction", full) // T+40: outage 2, at once
		step(5 * time.Second)
		store.noteWriteOK() // T+45: cleared
		step(5 * time.Second)
		store.NoteWriteError("WAL checkpoint", full) // T+50: outage 3, folded
		store.NoteWriteError("WAL checkpoint", full)
		step(2 * time.Second)
		store.noteWriteOK() // T+52: no line yet
		step(48 * time.Second)
		store.noteWriteOK() // T+100: the folded outage's line
		store.noteWriteOK()
	})
	if n := strings.Count(out, "ALERT audit_store_full"); n != 3 {
		t.Fatalf("%d ALERT lines, want 3 (outage 1, outage 2 at once after its cleared line, the folded outage 3):\n%s", n, out)
	}
	if n := strings.Count(out, "audit_store_full cleared"); n != 2 {
		t.Fatalf("%d cleared lines, want 2 (one per alerted outage):\n%s", n, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 5 || !strings.Contains(lines[2], "ALERT audit_store_full") ||
		!strings.Contains(lines[4], "2 more writes were refused") || !strings.Contains(lines[4], "has room again") {
		t.Fatalf("lines out of order or the folded outage is not named:\n%s", out)
	}
}

// A volume that flaps every second for a minute logs a bounded number of
// lines: two ALERT lines and their cleared lines, then one folded ALERT line.
func TestStoreFullAlertFlappingVolumeIsBounded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	storeFullAlertClock = func() time.Time { return now }
	t.Cleanup(func() { storeFullAlertClock = time.Now })
	store := &Store{dbPath: "/data/audit.db"}
	full := errors.New("no space left on device")
	out := captureAuditStderr(t, func() {
		for range 59 {
			store.NoteWriteError("hook_call_transaction", full)
			now = now.Add(500 * time.Millisecond)
			store.noteWriteOK()
			now = now.Add(500 * time.Millisecond)
		}
		now = now.Add(2 * time.Second)
		store.noteWriteOK()
	})
	if n := strings.Count(out, "\n"); n != 5 {
		t.Fatalf("%d lines for a minute of flapping, want 5:\n%s", n, out)
	}
	if !strings.Contains(out, "57 more writes were refused") {
		t.Fatalf("the folded outages are not counted:\n%s", out)
	}
}
