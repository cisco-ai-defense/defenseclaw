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
// audit_store_full" lines of one outage, and between two lines that open a
// new outage soon after a "cleared" line: a full volume fails every write,
// and a store that takes a write in space it already had, then fails the
// next, must not flood the log.
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
//
// The rate limit (substrate-1:GAP-0578 c): within one outage an ALERT line
// repeats at most once a minute. A new outage after a "cleared" line alerts
// at once, even inside the minute; only a third outage inside a minute that
// already had two ALERT lines (a volume that flaps at its edge) is folded:
// its refused writes are counted and named by the next ALERT line, or, when
// the store has room again by then, by one ALERT line a minute after the
// last. No outage goes unlogged.
type storeFullAlert struct {
	// full is set while the last reported write failed for want of space;
	// a successful write reads it without the lock.
	full atomic.Bool
	// folded is set while refused writes wait for a line (see unreported);
	// a successful write reads it without the lock.
	folded atomic.Bool
	mu     sync.Mutex
	// alerted: an ALERT line covers the open outage and its "cleared" line
	// is owed.
	alerted bool
	// lastAlert is the last ALERT line, reAlert the last one that opened an
	// outage less than storeFullAlertRepeat after the line before it.
	lastAlert, reAlert time.Time
	// unreported counts the writes of folded outages since unreportedSince.
	unreported      int64
	unreportedSince time.Time
}

// NoteWriteError reports a failed write of the store, op naming it. A write
// that failed for want of space (IsStoreFullError) logs "ALERT
// audit_store_full" with its effect and repair under the rate limit of
// storeFullAlert and returns true; any other error is ignored.
func (s *Store) NoteWriteError(op string, err error) bool {
	if s == nil || !IsStoreFullError(err) {
		return false
	}
	alert := &s.fullAlert
	alert.full.Store(true)
	now := storeFullAlertClock()
	alert.mu.Lock()
	recent := !alert.lastAlert.IsZero() && now.Sub(alert.lastAlert) < storeFullAlertRepeat
	switch {
	case alert.alerted && recent:
		// The same outage, alerted less than a minute ago.
		alert.mu.Unlock()
		return true
	case !alert.alerted && recent && !alert.reAlert.IsZero() && now.Sub(alert.reAlert) < storeFullAlertRepeat:
		// A third outage inside a minute: fold it into the next line.
		if alert.unreported == 0 {
			alert.unreportedSince = now
		}
		alert.unreported++
		alert.folded.Store(true)
		alert.mu.Unlock()
		return true
	case !alert.alerted && recent:
		alert.reAlert = now
	}
	alert.alerted, alert.lastAlert = true, now
	folded := alert.takeUnreported()
	alert.mu.Unlock()
	cause := strings.Join(strings.Fields(err.Error()), " ")
	if len(cause) > 300 {
		cause = strings.ToValidUTF8(cause[:300], "") + "..."
	}
	fmt.Fprintf(os.Stderr, "[audit] ALERT audit_store_full: the audit store's volume has no space left (%s: %s)%s, "+
		"so audit records are not written and hook calls that need one fail closed until it has room: "+
		"free space or enlarge the volume, and set observability.local.max_store_mb below its size (store %s)\n",
		op, cause, folded, s.dbPath)
	return true
}

// takeUnreported returns the note on the folded writes and resets them; the
// caller holds mu.
func (alert *storeFullAlert) takeUnreported() string {
	if alert.unreported == 0 {
		return ""
	}
	note := fmt.Sprintf("; %d more writes were refused for want of space since %s in short outages",
		alert.unreported, alert.unreportedSince.UTC().Format(time.RFC3339))
	alert.unreported, alert.unreportedSince = 0, time.Time{}
	alert.folded.Store(false)
	return note
}

// noteWriteOK reports a committed write: once a store that was full takes a
// write again, the alert clears with one line, and folded outages that no
// line has named yet get their ALERT line once the rate limit allows it.
func (s *Store) noteWriteOK() {
	if s == nil {
		return
	}
	alert := &s.fullAlert
	if !alert.full.Load() && !alert.folded.Load() {
		return
	}
	now := storeFullAlertClock()
	alert.mu.Lock()
	owed := alert.full.Swap(false) && alert.alerted
	if owed {
		alert.alerted = false
	}
	folded := ""
	if !alert.alerted && alert.unreported > 0 && now.Sub(alert.lastAlert) >= storeFullAlertRepeat {
		folded = alert.takeUnreported()
		alert.lastAlert = now
	}
	alert.mu.Unlock()
	if owed {
		fmt.Fprintf(os.Stderr, "[audit] audit_store_full cleared: the audit store has room again and audit records are written (store %s)\n", s.dbPath)
	}
	if folded != "" {
		fmt.Fprintf(os.Stderr, "[audit] ALERT audit_store_full: the audit store's volume ran out of space%s; "+
			"it has room again and audit records are written, but hook calls that needed one failed closed meanwhile: "+
			"free space or enlarge the volume, and set observability.local.max_store_mb below its size (store %s)\n",
			strings.TrimPrefix(folded, ";"), s.dbPath)
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
