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
