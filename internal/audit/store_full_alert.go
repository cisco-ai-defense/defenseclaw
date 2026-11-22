// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// storeFullAlertRepeat is the shortest time between two "ALERT
// audit_store_full" lines of one store: a full volume fails every write, and
// a store that takes a write in space it already had, then fails the next,
// must not flood the log.
const storeFullAlertRepeat = time.Minute

// storeFullAlertClock is the alert's clock (tests move it).
var storeFullAlertClock = time.Now

// storeFullTexts are the messages of a write refused for want of space where
// no errno or SQLite code survives in the error chain: SQLite's SQLITE_FULL,
// Linux and macOS ENOSPC and EDQUOT, and Windows ERROR_DISK_FULL.
var storeFullTexts = []string{
	"database or disk is full",
	"no space left on device",
	"disk quota exceeded",
	"not enough space on the disk",
}

// IsStoreFullError reports whether err is a write the audit store's volume
// had no room for: ENOSPC or EDQUOT in its chain, SQLite result code 13
// (SQLITE_FULL), or one of their messages in the text of an error of its
// chain. A checkpoint that cannot copy the WAL, an event-history insert, a
// correlation commit and a hook call's batch all fail this way when the
// volume is full.
func IsStoreFullError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) || sqlitePrimaryCode(err) == 13 {
		return true
	}
	// Every error of the chain: a wrapper with a fixed message (the
	// event-history insert's) hides its cause's text.
	pending := []error{err}
	for len(pending) > 0 && len(pending) < 64 {
		next := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		text := strings.ToLower(next.Error())
		for _, full := range storeFullTexts {
			if strings.Contains(text, full) {
				return true
			}
		}
		switch wrapped := next.(type) {
		case interface{ Unwrap() error }:
			if cause := wrapped.Unwrap(); cause != nil {
				pending = append(pending, cause)
			}
		case interface{ Unwrap() []error }:
			for _, cause := range wrapped.Unwrap() {
				if cause != nil {
					pending = append(pending, cause)
				}
			}
		}
	}
	return false
}

// storeFullAlert is the one operator signal of a store whose volume is full
// (substrate-1:GAP-0554): every write path reports here, so the signal does
// not depend on which write hit the full volume first.
type storeFullAlert struct {
	// full is set while the last reported write failed for want of space;
	// a successful write reads it without the lock.
	full atomic.Bool
	mu   sync.Mutex
	// alerted: an ALERT line was logged and its "cleared" line is owed.
	alerted   bool
	lastAlert time.Time
}

// NoteWriteError reports a failed write of the store, op naming it. A write
// that failed for want of space (IsStoreFullError) logs "ALERT
// audit_store_full" with its effect and repair, at most once a minute, and
// returns true; any other error is ignored.
func (s *Store) NoteWriteError(op string, err error) bool {
	if s == nil || !IsStoreFullError(err) {
		return false
	}
	alert := &s.fullAlert
	alert.full.Store(true)
	now := storeFullAlertClock()
	alert.mu.Lock()
	if !alert.lastAlert.IsZero() && now.Sub(alert.lastAlert) < storeFullAlertRepeat {
		alert.mu.Unlock()
		return true
	}
	alert.alerted, alert.lastAlert = true, now
	alert.mu.Unlock()
	cause := strings.Join(strings.Fields(err.Error()), " ")
	if len(cause) > 300 {
		cause = strings.ToValidUTF8(cause[:300], "") + "..."
	}
	fmt.Fprintf(os.Stderr, "[audit] ALERT audit_store_full: the audit store's volume has no space left (%s: %s), "+
		"so audit records are not written and hook calls that need one fail closed until it has room: "+
		"free space or enlarge the volume, and set observability.local.max_store_mb below its size (store %s)\n",
		op, cause, s.dbPath)
	return true
}

// noteWriteOK reports a committed write: once a store that was full takes a
// write again, the alert clears with one line.
func (s *Store) noteWriteOK() {
	if s == nil || !s.fullAlert.full.Load() {
		return
	}
	alert := &s.fullAlert
	alert.mu.Lock()
	if !alert.full.Swap(false) {
		alert.mu.Unlock()
		return
	}
	owed := alert.alerted
	alert.alerted = false
	alert.mu.Unlock()
	if owed {
		fmt.Fprintf(os.Stderr, "[audit] audit_store_full cleared: the audit store has room again and audit records are written (store %s)\n", s.dbPath)
	}
}

// noteGroupedTx reports the outcome of one shared transaction
// (runGroupedTx): its error, or each write's own.
func (s *Store) noteGroupedTx(op string, batch []*groupedWrite, err error) {
	if err != nil {
		s.NoteWriteError(op, err)
		return
	}
	committed := false
	for _, item := range batch {
		switch {
		case item.err != nil && !item.skipped:
			s.NoteWriteError(op, item.err)
		case item.ran:
			committed = true
		}
	}
	if committed {
		s.noteWriteOK()
	}
}
