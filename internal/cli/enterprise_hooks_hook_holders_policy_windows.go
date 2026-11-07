//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0755. Any account may open the hook with no sharing, because every
// account must be able to run it, and while that handle is open Windows
// refuses every start of the hook for every account. A swap cannot end such
// a hold: renaming a new file over the hook name needs the old file to share
// deletion, and a handle that shares nothing does not (tested natively). The
// only thing that ends the hold is closing the handle. The standalone
// guardian runs as LocalSystem and may do that, inside these bounds (the
// lead's ruling of 2026-11-07):
//
//	(a) only when the same handle has been seen on two checks at least
//	    windowsHolderPersist apart, so a scanner's or a backup's brief
//	    exclusive read is never closed;
//	(b) only handles whose volume serial number and 128-bit file id equal the
//	    live hook's, with data or execute access, found by duplicating the
//	    handle into the guardian after its object type is known to be a
//	    file; never by name. Windows does not show a handle's share mode, so
//	    "denies delete sharing" is the fact about the whole file (an open for
//	    DELETE is refused) and the guardian closes one handle at a time and
//	    stops as soon as it is gone;
//	(c) never in a protected process, never in a process whose account is
//	    LocalSystem, LocalService, NetworkService or any other service
//	    identity, never in session 0; only in a process of a user account in
//	    an interactive session. The token is read from the process;
//	(d) every close writes a HIGH connector-hook-tampered audit row (image
//	    path, process id, account SID and name, session, granted access, hook
//	    path); a hold the guardian refuses to end writes one too, saying that
//	    nothing was closed;
//	(e) standalone only: windowsHolderStandalone is false for every other
//	    process, and nothing below runs;
//	(f) a holder that takes the handle again is closed again after the same
//	    backoff as the swap streak (10 s, doubling to 5 min), one audit row
//	    per holder per streak.

// windowsHolderStandalone reports whether this guardian serves the
// standalone profile. Tests replace it.
var windowsHolderStandalone = enterprisehooks.WindowsStandaloneProcess

// windowsHolderDataAccess are the access rights that make a handle a data or
// execute handle: FILE_READ_DATA, FILE_WRITE_DATA, FILE_APPEND_DATA and
// FILE_EXECUTE. A handle opened for attributes only takes no part in sharing.
const windowsHolderDataAccess = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_EXECUTE

// The cost of one scan is bounded: the processes are narrowed to those the
// system lists as using the file, a handle probe that does not answer is
// abandoned, and the whole pass ends at the budget.
var (
	windowsHolderMaxProbes    = 2048
	windowsHolderScanBudget   = 3 * time.Second
	windowsHolderProbeTimeout = 250 * time.Millisecond
	// windowsHolderMaxHung is how many abandoned probes may still be blocked
	// before the guardian stops probing until they return.
	windowsHolderMaxHung int32 = 24
)

// windowsHolderHung counts the probes abandoned and not yet returned.
var windowsHolderHung atomic.Int32

// windowsHookHolderIdentity is a file object: the volume and the file id.
type windowsHookHolderIdentity struct {
	volume uint64
	id     [16]byte
}

// windowsHolderProcess is what the rules need to know about a process.
type windowsHolderProcess struct {
	PID       uint32
	Started   uint64 // creation time, 100 ns ticks; tells a process from a later one with its id
	Image     string
	SID       string
	Session   uint32
	Protected bool
	Wow64     bool
	FactsErr  error // set when the token, session or protection could not be read
}

// windowsHolderHandle is one handle that names the hook.
type windowsHolderHandle struct {
	Process windowsHolderProcess
	Handle  uintptr
	Access  uint32
	// Attributes are the handle's flags from the handle table (OBJ_INHERIT,
	// OBJ_PROTECT_CLOSE, OBJ_AUDIT_OBJECT_CLOSE).
	Attributes uint32
	proc       windowsHolderProc
}

type windowsHolderKey struct {
	PID     uint32
	Started uint64
	Handle  uintptr
}

type windowsHolderProcKey struct {
	PID     uint32
	Started uint64
}

func (h windowsHolderHandle) key() windowsHolderKey {
	return windowsHolderKey{h.Process.PID, h.Process.Started, h.Handle}
}

func (h windowsHolderHandle) procKey() windowsHolderProcKey {
	return windowsHolderProcKey{h.Process.PID, h.Process.Started}
}

// windowsHolderProc is an open process that handles can be taken from.
type windowsHolderProc interface {
	Facts() windowsHolderProcess
	// Identify duplicates a handle into the guardian and names its file
	// object; disk is false for anything that is not a disk file.
	Identify(handle uintptr) (id windowsHookHolderIdentity, disk bool, err error)
	// CloseIf closes a handle in the process after checking, on a fresh
	// duplicate, that it still names want.
	CloseIf(handle uintptr, want windowsHookHolderIdentity) error
	Release()
}

// windowsHolderSnapshot is the system's answer for one scan.
type windowsHolderSnapshot struct {
	Identity  windowsHookHolderIdentity
	Entries   []windowsHandleEntryEx
	FileType  int // the object type index of files; -1 when not found
	PIDs      []uint32
	PIDsKnown bool
	Release   func()
}

type windowsHolderSystem interface {
	Snapshot(path string) (windowsHolderSnapshot, error)
	OpenProcess(pid uint32) (windowsHolderProc, error)
}

// windowsHolderSys is the system the scan reads; tests replace it.
var windowsHolderSys windowsHolderSystem = windowsNativeHolderSystem{}

// windowsHolderScan is what one pass found.
type windowsHolderScan struct {
	Identity windowsHookHolderIdentity
	Holders  []windowsHolderHandle
	Listed   bool     // the system listed the processes using the file
	Entries  int      // handles in the system table
	Probed   int      // handles duplicated and inspected
	Hung     int      // probes abandoned in this pass
	Unopened []uint32 // processes with a data handle that could not be opened (protected)
	Limited  string   // why the pass stopped early, or ""
	Elapsed  time.Duration
	procs    []windowsHolderProc
	release  func()
}

func (s *windowsHolderScan) close() {
	for _, proc := range s.procs {
		proc.Release()
	}
	if s.release != nil {
		s.release()
	}
}

// identifyWindowsHolderHandle runs one probe on a worker with a timeout. A
// probe that does not answer is abandoned, not waited for: a synchronous pipe
// handle whose owner is blocked in a call can stop a query on its duplicate,
// and the guardian holds windowsHookBinaryMu.
func identifyWindowsHolderHandle(proc windowsHolderProc, handle uintptr) (id windowsHookHolderIdentity, disk, hung bool, err error) {
	type answer struct {
		id   windowsHookHolderIdentity
		disk bool
		err  error
	}
	done := make(chan answer, 1)
	go func() {
		var a answer
		a.id, a.disk, a.err = proc.Identify(handle)
		done <- a
	}()
	timer := time.NewTimer(windowsHolderProbeTimeout)
	defer timer.Stop()
	select {
	case a := <-done:
		return a.id, a.disk, false, a.err
	case <-timer.C:
		windowsHolderHung.Add(1)
		go func() {
			<-done
			windowsHolderHung.Add(-1)
		}()
		return id, false, true, errors.New("the handle did not answer")
	}
}

// scanWindowsHolders finds the handles of other processes that name the
// hook's file object. It looks at file-type handles with data or execute
// access, in the processes the system lists as using the file when it
// answers, and stops at its limits.
func scanWindowsHolders(sys windowsHolderSystem, target string, self uint32) (*windowsHolderScan, error) {
	started := time.Now()
	snapshot, err := sys.Snapshot(target)
	if err != nil {
		return nil, err
	}
	scan := &windowsHolderScan{Identity: snapshot.Identity, Listed: snapshot.PIDsKnown, Entries: len(snapshot.Entries), release: snapshot.Release}
	defer func() { scan.Elapsed = time.Since(started) }()
	if snapshot.FileType < 0 {
		scan.close()
		return nil, errors.New("the file object type was not found in the handle table")
	}
	var listed map[uint32]bool
	if snapshot.PIDsKnown {
		listed = make(map[uint32]bool, len(snapshot.PIDs))
		for _, pid := range snapshot.PIDs {
			listed[pid] = true
		}
	}
	byPID := map[uint32][]windowsHandleEntryEx{}
	for _, entry := range snapshot.Entries {
		pid := uint32(entry.UniqueProcessID)
		if int(entry.ObjectTypeIndex) != snapshot.FileType || pid == self || pid <= 4 ||
			entry.GrantedAccess&windowsHolderDataAccess == 0 || (listed != nil && !listed[pid]) {
			continue
		}
		byPID[pid] = append(byPID[pid], entry)
	}
	pids := make([]uint32, 0, len(byPID))
	for pid := range byPID {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	deadline := started.Add(windowsHolderScanBudget)
	for _, pid := range pids {
		proc, err := sys.OpenProcess(pid)
		if err != nil {
			scan.Unopened = append(scan.Unopened, pid)
			continue
		}
		found, hungHere := false, false
		for _, entry := range byPID[pid] {
			switch {
			case scan.Probed >= windowsHolderMaxProbes:
				scan.Limited = fmt.Sprintf("more than %d handles to inspect", windowsHolderMaxProbes)
			case time.Now().After(deadline):
				scan.Limited = fmt.Sprintf("the scan took longer than %s", windowsHolderScanBudget)
			case windowsHolderHung.Load() >= windowsHolderMaxHung:
				scan.Limited = fmt.Sprintf("%d earlier handle probes are still blocked", windowsHolderHung.Load())
			}
			if scan.Limited != "" {
				break
			}
			scan.Probed++
			id, disk, hung, err := identifyWindowsHolderHandle(proc, entry.HandleValue)
			if hung {
				scan.Hung++
				hungHere = true
				continue
			}
			if err != nil || !disk || id != scan.Identity {
				continue
			}
			scan.Holders = append(scan.Holders, windowsHolderHandle{Process: proc.Facts(), Handle: entry.HandleValue, Access: entry.GrantedAccess, Attributes: entry.HandleAttributes, proc: proc})
			found = true
		}
		switch {
		case found:
			scan.procs = append(scan.procs, proc)
		case hungHere:
			// An abandoned probe may still use the process handle: it stays
			// open (a bounded leak, see windowsHolderMaxHung).
		default:
			proc.Release()
		}
		if scan.Limited != "" {
			break
		}
	}
	return scan, nil
}

// windowsHolderRefusal returns why the guardian may not close handles in a
// process (bound (c)), or "" when it may.
func windowsHolderRefusal(p windowsHolderProcess) string {
	if p.FactsErr == nil && !p.Protected {
		// A service identity is named before the session, which says less.
		if name := windowsServiceIdentityName(p.SID); name != "" {
			return "it runs as " + name
		}
	}
	switch {
	case p.FactsErr != nil:
		return fmt.Sprintf("its protection level, session or account could not be read (%v)", p.FactsErr)
	case p.Protected:
		return "it is a protected process"
	case p.Session == 0 || p.Session == 0xFFFFFFFF:
		return "it runs in session 0, which belongs to services, not to a user who is signed in"
	case !windowsUserAccountSID(p.SID):
		return "its account (" + p.SID + ") is not a local, domain or Entra user account"
	}
	return ""
}

// windowsObjProtectClose is OBJ_PROTECT_CLOSE in a handle's attributes: its
// owner asked that the handle never be closed.
const windowsObjProtectClose = 0x1

// windowsHolderHandleRefusal is windowsHolderRefusal for the process, then
// for the handle itself.
func windowsHolderHandleRefusal(h windowsHolderHandle) string {
	if reason := windowsHolderRefusal(h.Process); reason != "" {
		return reason
	}
	if h.Attributes&windowsObjProtectClose != 0 {
		return "its owner protected the handle from being closed"
	}
	return ""
}

// windowsServiceIdentityName names a service identity SID, or "".
func windowsServiceIdentityName(sid string) string {
	switch sid {
	case "S-1-5-18":
		return "LocalSystem"
	case "S-1-5-19":
		return "LocalService"
	case "S-1-5-20":
		return "NetworkService"
	case "S-1-5-7":
		return "the anonymous account"
	}
	for prefix, name := range map[string]string{
		"S-1-5-80-": "a service account (NT SERVICE)", "S-1-5-82-": "an IIS application pool identity",
		"S-1-5-83-": "a virtual machine identity", "S-1-5-90-": "a Window Manager account", "S-1-5-96-": "a Font Driver Host account",
	} {
		if strings.HasPrefix(sid, prefix) {
			return name
		}
	}
	return ""
}

// windowsUserAccountSID is true for the SIDs of user accounts: a local or
// domain account (S-1-5-21-) and an Entra ID account (S-1-12-1-).
func windowsUserAccountSID(sid string) bool {
	return strings.HasPrefix(sid, "S-1-5-21-") || strings.HasPrefix(sid, "S-1-12-1-")
}

// windowsHolderState is the guardian's memory of a hold, guarded by
// windowsHookBinaryMu. The persistence part ends at the first check that
// finds the hook free; the streak part ends after windowsHeldSwapStreakEnd
// without a hold.
type windowsHolderState struct {
	seenAt     time.Time
	firstSeen  map[windowsHolderKey]time.Time
	emptySince time.Time

	streakLast time.Time
	closes     int
	refusals   int
	nextClose  time.Time
	nextScan   time.Time
	lastErr    error
	rows       map[windowsHolderProcKey]bool
}

var windowsHolderGate windowsHolderState

// windowsHolderLog holds the lines the next report writes to the guardian
// log; windowsHolderAuditQueue the audit rows waiting for the gateway.
var (
	windowsHolderLog        []string
	windowsHolderAuditQueue []windowsHolderAuditRow
)

// windowsHolderPersist is how long a handle must have been seen, across
// checks, before it is closed: about two guardian ticks.
func windowsHolderPersist() time.Duration { return windowsHookBinaryCheckInterval * 4 / 5 }

// free forgets what was seen: the hook is not held, so the next hold starts
// its two checks again. The streak is not ended (a holder that lets go and
// takes the handle again is still in the same streak).
func (g *windowsHolderState) free() {
	g.firstSeen, g.seenAt, g.emptySince = nil, time.Time{}, time.Time{}
}

func (g *windowsHolderState) endStreak() {
	*g = windowsHolderState{firstSeen: g.firstSeen, seenAt: g.seenAt, emptySince: g.emptySince}
}

// observe records the holders of this check and returns the ones seen at
// least windowsHolderPersist ago, with no free check or gap of more than
// three ticks between.
func (g *windowsHolderState) observe(now time.Time, holders []windowsHolderHandle) []windowsHolderHandle {
	if !g.seenAt.IsZero() && now.Sub(g.seenAt) > 3*windowsHookBinaryCheckInterval {
		g.firstSeen = nil
	}
	next := make(map[windowsHolderKey]time.Time, len(holders))
	var persistent []windowsHolderHandle
	for _, holder := range holders {
		since, ok := g.firstSeen[holder.key()]
		if !ok {
			since = now
		}
		next[holder.key()] = since
		if now.Sub(since) >= windowsHolderPersist() {
			persistent = append(persistent, holder)
		}
	}
	g.firstSeen, g.seenAt = next, now
	sort.Slice(persistent, func(i, j int) bool {
		if persistent[i].Process.PID != persistent[j].Process.PID {
			return persistent[i].Process.PID < persistent[j].Process.PID
		}
		return persistent[i].Handle < persistent[j].Handle
	})
	return persistent
}

// refuse records a hold the guardian did not end and backs the next scan off
// like the swap streak: 10 s, doubling to 5 min.
func (g *windowsHolderState) refuse(now time.Time, err error) error {
	g.refusals++
	g.nextScan = now.Add(windowsHeldSwapDelay(g.refusals))
	g.lastErr = err
	return err
}

func (h windowsHolderHandle) describe() string {
	image := h.Process.Image
	if image == "" {
		image = "an unknown program"
	}
	return fmt.Sprintf("%s (process id %d, %s, session %d)", image, h.Process.PID, windowsHolderAccount(h.Process.SID), h.Process.Session)
}

// windowsHolderUserName looks an account name up; tests replace it.
var windowsHolderUserName = func(sid string) string {
	parsed, err := windows.StringToSid(sid)
	if err != nil {
		return ""
	}
	account, domain, _, err := parsed.LookupAccount("")
	if err != nil {
		return ""
	}
	if domain != "" {
		return domain + `\` + account
	}
	return account
}

// windowsHolderAccount is "NAME (SID)", or the SID alone. The lookup runs on
// a worker with a timeout: a domain account can take a long time to resolve.
func windowsHolderAccount(sid string) string {
	if sid == "" {
		return "an unknown account"
	}
	done := make(chan string, 1)
	go func() { done <- windowsHolderUserName(sid) }()
	select {
	case name := <-done:
		if name != "" {
			return name + " " + sid
		}
	case <-time.After(2 * time.Second):
	}
	return sid
}

// windowsHolderCloserEnabled is bound (e): only the standalone guardian.
func windowsHolderCloserEnabled() bool { return windowsHolderStandalone() }

// endWindowsExclusiveHold is called, with windowsHookBinaryMu held, when the
// hook refuses every start and an open for DELETE is refused: a handle that
// shares no deletion. It closes the handle that does it when the rules above
// allow, and returns how many handles it closed. A nil error with nothing
// closed means it is waiting (the second check, or the backoff).
func endWindowsExclusiveHold(target string) (int, error) {
	gate := &windowsHolderGate
	now := windowsHeldSwapNow()
	if !gate.streakLast.IsZero() && now.Sub(gate.streakLast) > windowsHeldSwapStreakEnd {
		gate.endStreak()
	}
	gate.streakLast = now
	if now.Before(gate.nextScan) {
		// The backoff skips the scan, not the hold: the handles seen so far
		// stay one continuous hold, so a refused holder is named again at the
		// next scan instead of waiting two checks once more.
		gate.seenAt = now
		return 0, gate.lastErr
	}
	scan, err := scanWindowsHolders(windowsHolderSys, target, uint32(os.Getpid()))
	if err != nil {
		return 0, gate.refuse(now, fmt.Errorf("the guardian could not list who holds the hook: %w", err))
	}
	defer scan.close()
	persistent := gate.observe(now, scan.Holders)
	if len(scan.Holders) == 0 {
		// A hold that ended between the start-style open and the scan is
		// not a finding; one that stays unseen across two checks is.
		if gate.emptySince.IsZero() {
			gate.emptySince = now
			return 0, nil
		}
		if now.Sub(gate.emptySince) < windowsHolderPersist() {
			return 0, nil
		}
		return 0, gate.refuse(now, fmt.Errorf("the guardian found no handle of a user process on it%s", scan.limits()))
	}
	gate.emptySince = time.Time{}
	if len(persistent) == 0 {
		return 0, nil
	}
	var refused *windowsHolderHandle
	refusedReason := ""
	for i, holder := range persistent {
		if reason := windowsHolderHandleRefusal(holder); reason != "" {
			gate.record(target, holder, false, reason, scan)
			if refused == nil {
				refused, refusedReason = &persistent[i], reason
			}
		}
	}
	if refused != nil {
		return 0, gate.refuse(now, fmt.Errorf("%s holds it with no sharing and the guardian does not close handles of that kind: %s", refused.describe(), refusedReason))
	}
	if scan.Listed && len(scan.Unopened) > 0 {
		return 0, gate.refuse(now, fmt.Errorf("process id %d also has files open that the guardian cannot inspect (a protected process), so it cannot tell whose handle refuses the start and closes none", scan.Unopened[0]))
	}
	if scan.Limited != "" {
		return 0, gate.refuse(now, fmt.Errorf("the guardian stopped looking for the holder: %s", scan.Limited))
	}
	if gate.closes > 0 && now.Before(gate.nextClose) {
		// The same hold again, before the backoff is over: never a tight loop.
		gate.nextScan = gate.nextClose.Add(-windowsHolderPersist())
		return 0, nil
	}
	closed := 0
	var firstErr error
	for _, holder := range persistent {
		if closed > 0 && !windowsHookBinaryDeleteBlocked(target) {
			// The hook is clear: the remaining handles block nothing and stay.
			break
		}
		if err := holder.proc.CloseIf(holder.Handle, scan.Identity); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("could not close the handle of %s: %w", holder.describe(), err)
			}
			continue
		}
		closed++
		gate.closes++
		gate.nextClose = now.Add(windowsHeldSwapDelay(gate.closes))
		gate.record(target, holder, true, "", scan)
	}
	if closed == 0 {
		return 0, gate.refuse(now, firstErr)
	}
	gate.refusals, gate.lastErr = 0, nil
	gate.nextScan = gate.nextClose.Add(-windowsHolderPersist())
	gate.firstSeen = nil
	return closed, nil
}

// limits says what kept the scan from seeing everything, in words that do not
// change from one scan to the next (the guardian logs an error once).
func (s *windowsHolderScan) limits() string {
	var parts []string
	if len(s.Unopened) > 0 {
		parts = append(parts, fmt.Sprintf("%d processes could not be opened", len(s.Unopened)))
	}
	if s.Limited != "" {
		parts = append(parts, "the scan stopped: "+s.Limited)
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

// summary is the cost of the scan, for the audit row and the log.
func (s *windowsHolderScan) summary() string {
	text := fmt.Sprintf("%d handles listed, %d inspected in %d ms", s.Entries, s.Probed, s.Elapsed.Milliseconds())
	if len(s.Unopened) > 0 {
		text += fmt.Sprintf(", %d processes could not be opened", len(s.Unopened))
	}
	if s.Hung > 0 {
		text += fmt.Sprintf(", %d probes did not answer", s.Hung)
	}
	if s.Limited != "" {
		text += ", stopped: " + s.Limited
	}
	return text
}

// record logs a close or a refusal and queues its audit row: the guardian
// log line for every close, the HIGH audit row once per holder per streak.
func (g *windowsHolderState) record(target string, holder windowsHolderHandle, closed bool, reason string, scan *windowsHolderScan) {
	if closed {
		windowsHolderLog = append(windowsHolderLog, fmt.Sprintf("[hook-guardian] tamper: closed the handle %s had on the hook binary %s (access 0x%08x), which allowed no deletion and refused every start of it; the file was not changed and the process was left running (close %d of this streak; if it takes the handle again it is closed again no sooner than %s; scan: %s)", holder.describe(), target, holder.Access, g.closes, g.nextClose.Format("15:04:05"), scan.summary()))
	}
	if g.rows == nil {
		g.rows = map[windowsHolderProcKey]bool{}
	}
	if g.rows[holder.procKey()] {
		return
	}
	g.rows[holder.procKey()] = true
	row := windowsHolderAuditRow{At: windowsHeldSwapNow().UTC(), Hook: target, Holder: holder.Process, Handle: holder.Handle, Access: holder.Access,
		Closed: closed, Reason: reason, Streak: g.closes, ScanMS: scan.Elapsed.Milliseconds(), Listed: scan.Entries, Probed: scan.Probed}
	row.Account = windowsHolderAccount(holder.Process.SID)
	if len(windowsHolderAuditQueue) >= 64 {
		windowsHolderAuditQueue = windowsHolderAuditQueue[1:]
	}
	windowsHolderAuditQueue = append(windowsHolderAuditQueue, row)
}

// windowsHolderAuditRow is one connector-hook-tampered row for the gateway.
type windowsHolderAuditRow struct {
	At      time.Time
	Hook    string
	Holder  windowsHolderProcess
	Account string // "NAME SID"
	Handle  uintptr
	Access  uint32
	Closed  bool
	Reason  string
	Streak  int
	ScanMS  int64
	Listed  int
	Probed  int
	tries   int
}

// event is the audit event of the row: the existing hook-tamper action, HIGH.
func (r windowsHolderAuditRow) event() audit.Event {
	clean := func(s string) string {
		return strings.Map(func(c rune) rune {
			if c < 0x20 || c == 0x7f {
				return ' '
			}
			return c
		}, s)
	}
	image := clean(r.Holder.Image)
	if image == "" {
		image = "an unknown program"
	}
	details := fmt.Sprintf("%s (process id %d, account %s, session %d) holds the hook binary %s open (access 0x%08x) in a way that allows no deletion, which refuses every start of it. ",
		image, r.Holder.PID, clean(r.Account), r.Holder.Session, r.Hook, r.Access)
	if r.Closed {
		details += "The hook guardian closed that handle; the file was not changed and the process was not ended."
	} else {
		details += "The hook guardian did not close it: " + clean(r.Reason) + "."
	}
	return audit.Event{
		Timestamp: r.At, Action: string(audit.ActionConnectorHookTampered), Target: r.Hook, Actor: "hook-guardian",
		Details: details, Severity: "HIGH",
		Structured: map[string]any{
			"hook_path": r.Hook, "holder_image": image, "holder_pid": r.Holder.PID, "holder_sid": r.Holder.SID,
			"holder_account": clean(r.Account), "holder_session": r.Holder.Session, "granted_access": fmt.Sprintf("0x%08x", r.Access),
			"handle_value": uint64(r.Handle), "wow64": r.Holder.Wow64, "closed": r.Closed, "not_closed_reason": clean(r.Reason),
			"streak_closes": r.Streak, "scan_ms": r.ScanMS, "handles_listed": r.Listed, "handles_inspected": r.Probed,
		},
	}
}

// windowsHolderAuditPost sends one row to the gateway; tests replace it.
var windowsHolderAuditPost = postWindowsHolderAudit

// postWindowsHolderAudit sends the row to the managed gateway's audit route
// with the administrator token, to the gateway service's own socket only.
func postWindowsHolderAudit(row windowsHolderAuditRow) error {
	base, token, managedHost, err := windowsManagedLaunchAuditEndpoint()
	if err != nil {
		return err
	}
	if !managedHost || token == "" {
		return errors.New("managed gateway audit endpoint is unavailable")
	}
	body, err := json.Marshal(row.event())
	if err != nil {
		return err
	}
	target, err := url.Parse(base)
	if err != nil || target.Scheme != "http" || target.User != nil || target.Path != "" {
		return errors.New("managed gateway audit endpoint is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/audit/event", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DefenseClaw-Client", "hook-guardian")
	client, err := managedGatewayClientFactory(3*time.Second, target.Host, managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway audit returned HTTP %d", response.StatusCode)
	}
	return nil
}

// windowsHolderAuditLastErr keeps a gateway that is down from filling the
// log; windowsHolderAuditMaxTries is how many checks a row waits for it.
var windowsHolderAuditLastErr string

const windowsHolderAuditMaxTries = 24

// reportWindowsHookHolders writes the queued log lines and sends the queued
// audit rows. The guardian calls it holding windowsHookBinaryMu after each
// check.
func reportWindowsHookHolders(stderr io.Writer) {
	for _, line := range windowsHolderLog {
		fmt.Fprintln(stderr, line)
	}
	windowsHolderLog = nil
	kept := windowsHolderAuditQueue[:0]
	for _, row := range windowsHolderAuditQueue {
		err := windowsHolderAuditPost(row)
		if err == nil {
			windowsHolderAuditLastErr = ""
			continue
		}
		if message := err.Error(); message != windowsHolderAuditLastErr {
			windowsHolderAuditLastErr = message
			fmt.Fprintf(stderr, "[hook-guardian] warn: could not record the hook-holder audit row (it is retried): %v\n", err)
		}
		if row.tries++; row.tries < windowsHolderAuditMaxTries {
			kept = append(kept, row)
		} else {
			fmt.Fprintf(stderr, "[hook-guardian] warn: dropped the hook-holder audit row for process id %d after %d tries; the line above is the only record\n", row.Holder.PID, row.tries)
		}
	}
	windowsHolderAuditQueue = kept
}
