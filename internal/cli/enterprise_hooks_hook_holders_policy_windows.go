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
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0755. A program may open the hook with no sharing (every account must
// be able to read and run it), and while that handle is open Windows refuses
// every start of the hook for every account. Whether a standard user's
// handle does that in Program Files is not shown yet (the lead's Codex lane
// tests it); an administrator's and SYSTEM's do. A swap cannot end such
// a hold: renaming a new file over the hook name needs the old file to share
// deletion, and a handle that shares nothing does not (tested natively). The
// only thing that ends the hold is closing the handle. The standalone
// guardian runs as LocalSystem and may do that, inside these bounds (the
// lead's ruling of 2026-11-07):
//
//	(a) only when the hook has stayed refused to a test open for deletion on
//	    two checks at least windowsHolderPersist apart, and the same program
//	    kept it so: a handle of the same process (process id and creation
//	    time) or of the same file object (the Object field of the handle
//	    table, which a duplicated handle keeps) on both checks. When only the
//	    same user (account SID and session) is there on both, a different
//	    process each time, it takes a third check. One brief hold, such as a
//	    scanner's or a backup's exclusive read, is gone by the second check
//	    and is not closed;
//	(b) only handles whose volume serial number and 128-bit file id equal the
//	    live hook's, with data or execute access, found by duplicating the
//	    handle into the guardian after its object type is known to be a
//	    file; never by name. Windows does not show a handle's share mode, so
//	    "denies delete sharing" is the fact about the whole file (an open for
//	    DELETE is refused). The candidates are grouped by the file object
//	    they refer to: with one file object among them, closing every handle
//	    of it is not collateral; with several, the guardian finishes one
//	    object at a time, the one with the fewest handles first, and stops as
//	    soon as the hook can be started. It works on one user at a time (the
//	    user whose hold began first); the handles of a second user are
//	    reached only if that user also kept a handle on the hook across the
//	    same checks and the hook is still refused after the first user's
//	    are closed;
//	(c) never in a protected process, never in a process whose account is
//	    LocalSystem, LocalService, NetworkService or any other service
//	    identity, never in session 0; only in a process of a user account in
//	    an interactive session. The token is read from the process. The
//	    handle table does not show whose handle refuses the start, but the
//	    sharing rules say which file objects can: a start asks for read and
//	    execute and shares read and delete, so an object can refuse it only if
//	    one of its handles can write or append, or if it is the only object on
//	    the hook. A holder of that kind on such an object may be the cause, so
//	    while one is there the guardian names it and closes no user's handle,
//	    except that after about 30 seconds, once per streak, it closes one
//	    user's handles, one object at a time, to rule that holder out. A
//	    holder on an object that cannot refuse the start (it only reads, beside
//	    another object) is named and the user's blockers are still closed. A
//	    user's handle that its owner protected from closing is named and
//	    skipped, and the others are still closed;
//	(d) every close writes a HIGH connector-hook-tampered audit row (image
//	    path, process id, account SID and name, session, granted access, hook
//	    path, how many candidate handles, processes and file objects there
//	    were); a hold the guardian refuses to end writes one too, saying that
//	    nothing was closed. The rows are kept, in memory and on disk, until
//	    the gateway has them. A close that finishes after the guardian has
//	    stopped waiting for it is audited when it finishes, from the worker,
//	    and does not wait for another pass;
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
// system lists as using the file, a call on a handle that does not answer is
// abandoned, and the whole pass ends at the budget.
var (
	windowsHolderMaxProbes    = 2048
	windowsHolderScanBudget   = 3 * time.Second
	windowsHolderProbeTimeout = 250 * time.Millisecond
	// windowsHolderMaxHung is how many abandoned calls may still be blocked
	// before the guardian stops probing until they return.
	windowsHolderMaxHung int32 = 24
	// windowsHolderSlowScan is the length of a scan after which the next
	// one waits, like a refused hold: a hold that makes every pass long is
	// not rescanned at every check.
	windowsHolderSlowScan = 500 * time.Millisecond
	// windowsHolderMaxCloses is how many handles one pass closes at most.
	windowsHolderMaxCloses = 64
	// windowsHolderRescans is how many times a pass looks again, at once,
	// when every handle it tried had been closed or replaced by its owner
	// since the scan (a holder that rotates its handle).
	windowsHolderRescans = 2
	// windowsHolderCommitWait is how much longer the guardian waits for a
	// close that has begun (the worker is past its last check, about to
	// close the handle) than for a probe: giving up on it would leave a
	// close the guardian cannot account for.
	windowsHolderCommitWait = 2 * time.Second
)

// windowsHolderHung counts the calls abandoned and not yet returned.
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
	FactsErr  error `json:"-"` // set when the token, session or protection could not be read
}

// windowsHolderHandle is one handle that names the hook.
type windowsHolderHandle struct {
	Process windowsHolderProcess
	Handle  uintptr
	// Object is the address of the file object the handle refers to, from
	// the handle table (0 when the system does not show it).
	Object uintptr
	Access uint32
	// Attributes are the handle's flags from the handle table (OBJ_INHERIT,
	// OBJ_PROTECT_CLOSE, OBJ_AUDIT_OBJECT_CLOSE).
	Attributes uint32
	proc       *windowsRefProc
}

// windowsHolderGroup is the user a hold belongs to: the account and the
// session of the process that has the handle.
type windowsHolderGroup struct {
	SID     string
	Session uint32
}

type windowsHolderProcKey struct {
	PID     uint32
	Started uint64
}

func (h windowsHolderHandle) group() windowsHolderGroup {
	return windowsHolderGroup{h.Process.SID, h.Process.Session}
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
	// duplicate, that it still names want. It runs on a worker with a
	// timeout. commit is called once, right before the close: it returns
	// false when the caller has given up (the close is then not made), and
	// otherwise tells the caller the close has begun, so that it waits a
	// little longer for the answer.
	CloseIf(handle uintptr, want windowsHookHolderIdentity, commit func() bool) error
	Release()
}

// windowsRefProc counts the users of an open process: the scan, and every
// worker still inside a call on one of its handles. The process is released
// when the last of them is done, even if that is a call the scan gave up on.
type windowsRefProc struct {
	windowsHolderProc
	refs atomic.Int32
}

func newWindowsRefProc(p windowsHolderProc) *windowsRefProc {
	r := &windowsRefProc{windowsHolderProc: p}
	r.refs.Store(1)
	return r
}

func (p *windowsRefProc) retain() { p.refs.Add(1) }

func (p *windowsRefProc) Release() {
	if p.refs.Add(-1) == 0 {
		p.windowsHolderProc.Release()
	}
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
	procs    []*windowsRefProc
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

// runWindowsHolderCall runs call on a worker with a timeout. A call that does
// not answer is abandoned, not waited for: a synchronous pipe handle whose
// owner is blocked in a call can stop any query on its duplicate (GetFileType
// included), and the guardian holds windowsHookBinaryMu. The worker holds its
// own reference to the process until it returns, however late. A call that
// answers after it was given up on is handed to late (under a lock, so that
// exactly one of the caller and late sees the answer). A call that does
// something irreversible calls commit first: commit is false once the caller
// has given up, and otherwise records that the call began, so that the caller
// waits up to windowsHolderCommitWait longer for the answer before it gives
// up; began tells it, when it does, that the thing may have been done.
func runWindowsHolderCall[T any](proc *windowsRefProc, call func(commit func() bool) T, late func(T)) (result T, answered, began bool) {
	proc.retain()
	var (
		mu        sync.Mutex
		gone      bool // guarded by mu
		committed bool // guarded by mu
		done      = make(chan T, 1)
	)
	go func() {
		defer proc.Release()
		r := call(func() bool {
			mu.Lock()
			defer mu.Unlock()
			if gone {
				return false
			}
			committed = true
			return true
		})
		mu.Lock()
		defer mu.Unlock()
		if gone {
			windowsHolderHung.Add(-1)
			if late != nil {
				late(r)
			}
			return
		}
		done <- r
	}()
	timer := time.NewTimer(windowsHolderProbeTimeout)
	defer timer.Stop()
	select {
	case r := <-done:
		return r, true, false
	case <-timer.C:
	}
	mu.Lock()
	select {
	case r := <-done:
		mu.Unlock()
		return r, true, true
	default:
	}
	if committed {
		// The worker is past its last check: give the close time to finish.
		mu.Unlock()
		extra := time.NewTimer(windowsHolderCommitWait)
		defer extra.Stop()
		select {
		case r := <-done:
			return r, true, true
		case <-extra.C:
		}
		mu.Lock()
		select {
		case r := <-done:
			mu.Unlock()
			return r, true, true
		default:
		}
	}
	windowsHolderHung.Add(1)
	gone = true
	began = committed
	mu.Unlock()
	return result, false, began
}

// identifyWindowsHolderHandle runs one probe through runWindowsHolderCall.
func identifyWindowsHolderHandle(proc *windowsRefProc, handle uintptr) (id windowsHookHolderIdentity, disk, hung bool, err error) {
	type answer struct {
		id   windowsHookHolderIdentity
		disk bool
		err  error
	}
	a, answered, _ := runWindowsHolderCall(proc, func(func() bool) answer {
		var a answer
		a.id, a.disk, a.err = proc.Identify(handle)
		return a
	}, nil)
	if !answered {
		return id, false, true, errors.New("the handle did not answer")
	}
	return a.id, a.disk, false, a.err
}

// errWindowsHolderTimedOut is a close that did not answer in time (or was
// given up on before it began): nothing was closed.
var errWindowsHolderTimedOut = errors.New("the handle did not answer in time, so it was not closed")

// errWindowsHolderMaybeClosed is a close that had begun when the guardian
// stopped waiting: the handle may have been closed. If it was, the worker
// audits it when it finishes; the next check shows whether the hook is free.
var errWindowsHolderMaybeClosed = errors.New("the handle did not answer in time, and may have been closed (the next check says)")

// closeWindowsHolderHandle closes one handle through runWindowsHolderCall,
// with the same worker and timeout as a probe: the fresh duplicate, its
// type, its identity and the check after the close all run on the worker. A
// close that finishes after the guardian gave up (a call is not cancellable
// once DuplicateHandle has begun) is audited by the worker as soon as it
// finishes: waiting for a later pass would lose it, because the pass only
// exists while the hook is still held.
func closeWindowsHolderHandle(target string, h windowsHolderHandle, want windowsHookHolderIdentity, counts windowsHolderCounts) error {
	err, answered, began := runWindowsHolderCall(h.proc, func(commit func() bool) error {
		return h.proc.CloseIf(h.Handle, want, commit)
	}, func(err error) {
		switch {
		case err == nil:
			auditWindowsHolderClose(target, h, "The close finished after the guardian had stopped waiting for it.", counts)
		case errors.Is(err, errWindowsHolderWrongObject):
			auditWindowsHolderWrongClose(target, h, counts)
		case errors.Is(err, errWindowsHolderCloseFailed):
			auditWindowsHolderFailedClose(target, h, counts)
		}
	})
	switch {
	case answered:
		return err
	case began:
		return errWindowsHolderMaybeClosed
	}
	return errWindowsHolderTimedOut
}

// auditWindowsHolderClose logs and queues the row of a close that happened
// outside a pass of the guardian's check (it finished late). It needs no
// guardian state: the row goes to the queue, and so to its file, at once, and
// the next check of the guardian delivers it. counts are the pass's own: how
// many candidates, processes and file objects it chose from.
func auditWindowsHolderClose(target string, h windowsHolderHandle, note string, counts windowsHolderCounts) {
	account := windowsHolderAccount(h.Process.SID)
	logWindowsHolder(fmt.Sprintf("[hook-guardian] tamper: closed the handle %s had on %s (access 0x%08x; one of %d candidate handle(s) in %d process(es) %s). %s", h.describe(), windowsHolderSubject(target), h.Access, counts.Handles, counts.Processes, counts.where(), note))
	queueWindowsHolderAudit(windowsHolderAuditRow{At: windowsHeldSwapNow().UTC(), Hook: target, Holder: h.Process, Handle: h.Handle, Access: h.Access,
		Closed: true, Note: note, Account: account, Counts: counts})
}

// auditWindowsHolderWrongClose is the same for a close that hit a handle that
// was not the hook's: the owner replaced the handle between the guardian's
// last check and the close.
func auditWindowsHolderWrongClose(target string, h windowsHolderHandle, counts windowsHolderCounts) {
	auditWindowsHolderDoubtfulClose(target, h, counts, "closed a handle in %s that, after the close, proved not to be on %s (access 0x%08x). %s",
		"After the close the handle proved not to be one on the hook: its owner had replaced it between the guardian's check and the close, so a handle that was not on the hook may have been closed.")
}

// auditWindowsHolderFailedClose is the same for a close whose last call failed.
// DuplicateHandle with DUPLICATE_CLOSE_SOURCE closes the source handle whatever
// it returns, so the handle may be gone.
func auditWindowsHolderFailedClose(target string, h windowsHolderHandle, counts windowsHolderCounts) {
	auditWindowsHolderDoubtfulClose(target, h, counts, "tried to close a handle in %s on %s (access 0x%08x), and the last call failed. %s",
		"The last call of the close failed, and Windows closes the source handle whatever that call returns, so the handle may have been closed.")
}

func auditWindowsHolderDoubtfulClose(target string, h windowsHolderHandle, counts windowsHolderCounts, warn, note string) {
	account := windowsHolderAccount(h.Process.SID)
	logWindowsHolder("[hook-guardian] warn: " + fmt.Sprintf(warn, h.describe(), windowsHolderSubject(target), h.Access, note))
	queueWindowsHolderAudit(windowsHolderAuditRow{At: windowsHeldSwapNow().UTC(), Hook: target, Holder: h.Process, Handle: h.Handle, Access: h.Access,
		Closed: true, Note: note, Account: account, Counts: counts})
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
		opened, err := sys.OpenProcess(pid)
		if err != nil {
			// A process that ended after the snapshot is gone, not protected:
			// OpenProcess says so with ERROR_INVALID_PARAMETER. Anything
			// else (access denied for a protected process) is a process the
			// guardian cannot inspect.
			if !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
				scan.Unopened = append(scan.Unopened, pid)
			}
			continue
		}
		proc := newWindowsRefProc(opened)
		found := false
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
				continue
			}
			if err != nil || !disk || id != scan.Identity {
				continue
			}
			scan.Holders = append(scan.Holders, windowsHolderHandle{Process: proc.Facts(), Handle: entry.HandleValue, Object: entry.Object, Access: entry.GrantedAccess, Attributes: entry.HandleAttributes, proc: proc})
			found = true
		}
		// A probe the scan gave up on keeps its own reference to the process,
		// so releasing the scan's reference here never closes the process
		// under it, and the last one to finish closes it.
		if found {
			scan.procs = append(scan.procs, proc)
		} else {
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
	seenAt time.Time
	// holds is what the guardian has seen of each user (account and session)
	// that had a candidate on the hook since it was last free.
	holds      map[windowsHolderGroup]*windowsHolderHold
	identity   windowsHookHolderIdentity
	emptySince time.Time

	streakLast time.Time
	closes     int
	refusals   int
	nextClose  time.Time
	nextScan   time.Time
	lastErr    error
	rows       map[windowsHolderProcKey]bool
	// overridden is set once the guardian has used its bounded override in
	// this streak (see windowsHolderOverrideAfter).
	overridden bool
}

var windowsHolderGate windowsHolderState

// windowsHolderHold is one user's hold on the hook, counted in ticks: checks
// at least windowsHolderPersist apart. A user is only a candidate for a
// close at the second tick when the same program kept it (see persistent),
// and at the third tick whatever program it is.
type windowsHolderHold struct {
	first    time.Time
	lastTick time.Time
	ticks    int
	// prev is what was seen at the tick before the current one; cur is what
	// has been seen at the current tick.
	prev, cur windowsHolderSeen
}

// windowsHolderSeen is what a user had on the hook at a tick: the processes
// and the file objects. A DuplicateHandle keeps the file object; a process
// keeps its id and creation time.
type windowsHolderSeen struct {
	procs   map[windowsHolderProcKey]bool
	objects map[uintptr]bool
}

func (s *windowsHolderSeen) add(holders []windowsHolderHandle) {
	if s.procs == nil {
		s.procs, s.objects = map[windowsHolderProcKey]bool{}, map[uintptr]bool{}
	}
	for _, h := range holders {
		s.procs[h.procKey()] = true
		if h.Object != 0 {
			s.objects[h.Object] = true
		}
	}
}

func (s windowsHolderSeen) has(h windowsHolderHandle) bool {
	return s.procs[h.procKey()] || (h.Object != 0 && s.objects[h.Object])
}

// persistent says whether a candidate of this user may be closed: on the
// third tick whatever it is (the same user kept the hook blocked across three
// checks), on the second only a handle of a process or of a file object that
// was there on the first (bound (a)).
func (h *windowsHolderHold) persistent(candidate windowsHolderHandle) bool {
	switch {
	case h.ticks >= 3:
		return true
	case h.ticks == 2:
		return h.prev.has(candidate)
	}
	return false
}

// windowsHolderOverrideAfter is how long a user's hold must have lasted,
// beside a holder the guardian will not touch that could be what refuses the
// start, before the guardian closes that user's handles once in the streak to
// rule the holder out: six checks, about 30 seconds.
func windowsHolderOverrideAfter() time.Duration { return 6 * windowsHookBinaryCheckInterval }

// windowsHolderPersist is how long a user must have had a candidate on the
// hook, across checks, before a handle is closed: about two guardian ticks.
func windowsHolderPersist() time.Duration { return windowsHookBinaryCheckInterval * 4 / 5 }

// free forgets what was seen: the hook is not held, so the next hold starts
// its checks again. The streak is not ended (a holder that lets go and
// takes the handle again is still in the same streak).
func (g *windowsHolderState) free() {
	g.holds, g.seenAt, g.emptySince = nil, time.Time{}, time.Time{}
}

func (g *windowsHolderState) endStreak() {
	*g = windowsHolderState{holds: g.holds, seenAt: g.seenAt, identity: g.identity, emptySince: g.emptySince}
	windowsHolderNames.Clear()
}

// observe records the users that have a candidate on the hook at this check
// and returns the candidates that may be closed (see persistent), the users
// whose hold began first first. A user that is not on the hook at this check,
// a gap of more than three ticks and another file all start over.
func (g *windowsHolderState) observe(now time.Time, identity windowsHookHolderIdentity, holders []windowsHolderHandle) []windowsHolderHandle {
	if !g.seenAt.IsZero() && (now.Sub(g.seenAt) > 3*windowsHookBinaryCheckInterval || g.identity != identity) {
		g.holds = nil
	}
	byUser := map[windowsHolderGroup][]windowsHolderHandle{}
	for _, holder := range holders {
		byUser[holder.group()] = append(byUser[holder.group()], holder)
	}
	next := make(map[windowsHolderGroup]*windowsHolderHold, len(byUser))
	var persistent []windowsHolderHandle
	for user, list := range byUser {
		hold := g.holds[user]
		switch {
		case hold == nil:
			hold = &windowsHolderHold{first: now, lastTick: now, ticks: 1}
			hold.cur.add(list)
		case now.Sub(hold.lastTick) >= windowsHolderPersist():
			hold.ticks++
			hold.lastTick = now
			hold.prev, hold.cur = hold.cur, windowsHolderSeen{}
			hold.cur.add(list)
		default:
			hold.cur.add(list)
		}
		next[user] = hold
		for _, holder := range list {
			if hold.persistent(holder) {
				persistent = append(persistent, holder)
			}
		}
	}
	g.holds, g.seenAt, g.identity = next, now, identity
	sort.Slice(persistent, func(i, j int) bool {
		a, b := persistent[i], persistent[j]
		if ha, hb := next[a.group()], next[b.group()]; ha != hb {
			if !ha.first.Equal(hb.first) {
				return ha.first.Before(hb.first)
			}
			if a.Process.SID != b.Process.SID {
				return a.Process.SID < b.Process.SID
			}
			return a.Process.Session < b.Process.Session
		}
		if a.Process.PID != b.Process.PID {
			return a.Process.PID < b.Process.PID
		}
		return a.Handle < b.Handle
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

// windowsHolderNames caches the account names looked up in this streak: a
// domain controller can take seconds to answer, and the guardian names the
// holder in every log line and refusal.
var windowsHolderNames sync.Map

// windowsHolderAccount is "NAME (SID)", or the SID alone. The lookup runs on
// a worker with a timeout, once per account per streak.
func windowsHolderAccount(sid string) string {
	if sid == "" {
		return "an unknown account"
	}
	if cached, ok := windowsHolderNames.Load(sid); ok {
		return cached.(string)
	}
	done := make(chan string, 1)
	go func() { done <- windowsHolderUserName(sid) }()
	text := sid
	select {
	case name := <-done:
		if name != "" {
			text = name + " " + sid
		}
	case <-time.After(2 * time.Second):
	}
	windowsHolderNames.Store(sid, text)
	return text
}

// windowsHolderCloserEnabled is bound (e): only the standalone guardian.
func windowsHolderCloserEnabled() bool { return windowsHolderStandalone() }

// windowsHolderCounts says how many candidates the guardian chose from, for
// the audit row and the log: handles, the processes that own them and the
// file objects they refer to. A close that was one of several candidates on
// more than one file object may have been a handle that was not the cause.
type windowsHolderCounts struct {
	Handles   int
	Processes int
	Objects   int
	// NoAddresses is true when a candidate's file object address is not shown
	// to the guardian (the service on Windows Server 2025): such a handle is
	// counted as a file object of its own, so Objects is then partly a count of
	// handles.
	NoAddresses bool
	Closed      int      // handles closed in the pass
	Left        []string // holders that were named and not closed
	// Note is a sentence the audit rows of a pass add (the bounded override).
	Note string
}

// where says, for a log line or an audit row, how many file objects the
// candidates are on, and when that number counts handles.
func (c windowsHolderCounts) where() string {
	if c.NoAddresses {
		return fmt.Sprintf("on %d file object(s), counting each handle whose file object address the system does not show to the guardian as a file object of its own", c.Objects)
	}
	return fmt.Sprintf("on %d file object(s)", c.Objects)
}

// windowsHolderObjectKey names a file object among the holders: the address
// the handle table shows, or the handle itself when the system shows none
// (such a handle is an object of its own).
type windowsHolderObjectKey struct {
	object uintptr
	pid    uint32
	handle uintptr
}

func (h windowsHolderHandle) objectKey() windowsHolderObjectKey {
	if h.Object != 0 {
		return windowsHolderObjectKey{object: h.Object}
	}
	return windowsHolderObjectKey{pid: h.Process.PID, handle: h.Handle}
}

// windowsHolderWriteAccess is the access that lets a handle refuse a start:
// a handle that can write or append is denied by the start's share mode.
const windowsHolderWriteAccess = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA

// windowsHolderStartBlockers says, for each file object among the data
// handles on the hook, whether it can be what refuses a start. A start asks
// for read and execute and shares read and delete. Windows allows a new open
// only if its access fits the share mode of every open handle and its share
// mode fits the access of every open handle, so with two or more objects every
// object without a write or append handle shares reading, and cannot be the
// cause. An object can refuse the start if it is the only object on the hook
// or one of its handles can write or append. A handle whose object address the
// system does not show (the guardian service gets no addresses on Windows
// Server 2025) counts as an object of its own: two handles on one file object
// then look like two objects, and the guardian may close a user's handle that
// frees nothing; that is bounded by the backoff and audited.
func windowsHolderStartBlockers(holders []windowsHolderHandle) map[windowsHolderObjectKey]bool {
	can := map[windowsHolderObjectKey]bool{}
	for _, h := range holders {
		key := h.objectKey()
		can[key] = can[key] || h.Access&windowsHolderWriteAccess != 0
	}
	if len(can) == 1 {
		for key := range can {
			can[key] = true
		}
	}
	return can
}

// overrideCandidates are the handles of the one user, the one whose hold began
// first, whose hold has lasted windowsHolderOverrideAfter, when the guardian
// has not used its override in this streak. eligible is in hold order.
func (g *windowsHolderState) overrideCandidates(now time.Time, eligible []windowsHolderHandle) []windowsHolderHandle {
	if g.overridden {
		return nil
	}
	var first windowsHolderGroup
	found := false
	var out []windowsHolderHandle
	for _, h := range eligible {
		hold := g.holds[h.group()]
		if hold == nil || now.Sub(hold.first) < windowsHolderOverrideAfter() {
			continue
		}
		if !found {
			first, found = h.group(), true
		}
		if h.group() == first {
			out = append(out, h)
		}
	}
	return out
}

// orderWindowsHolderCandidates puts the candidates in the order they are
// tried and counts them. The caller passes them with the user whose hold
// began first first; the guardian works on one user at a time. Within a user,
// handles that refer to the same file object stay together and a whole object
// is finished before the next one starts, so a handle of the blocking object
// is not left half closed while another object is closed; with one object
// among the candidates every handle of it is needed, and nothing is
// collateral. The objects are tried fewest handles first; among objects with
// as many handles, one with a handle that can write or append goes first (it
// is the kind that can refuse a start; on a host that shows no addresses every
// handle is an object of its own, so this is the order there), then by process
// id. A handle whose object address the system did not show is an object of
// its own.
func orderWindowsHolderCandidates(eligible []windowsHolderHandle) ([]windowsHolderHandle, windowsHolderCounts) {
	var users []windowsHolderGroup
	byUser := map[windowsHolderGroup][]windowsHolderHandle{}
	processes := map[windowsHolderProcKey]bool{}
	noAddresses := false
	for _, h := range eligible {
		noAddresses = noAddresses || h.Object == 0
		if _, seen := byUser[h.group()]; !seen {
			users = append(users, h.group())
		}
		byUser[h.group()] = append(byUser[h.group()], h)
		processes[h.procKey()] = true
	}
	ordered := make([]windowsHolderHandle, 0, len(eligible))
	objects := 0
	for _, user := range users {
		list, n := orderWindowsHolderUser(byUser[user])
		ordered, objects = append(ordered, list...), objects+n
	}
	return ordered, windowsHolderCounts{Handles: len(eligible), Processes: len(processes), Objects: objects, NoAddresses: noAddresses}
}

// orderWindowsHolderUser orders one user's candidates by file object and
// returns how many objects there are.
func orderWindowsHolderUser(eligible []windowsHolderHandle) ([]windowsHolderHandle, int) {
	groups := map[windowsHolderObjectKey][]windowsHolderHandle{}
	for _, h := range eligible {
		groups[h.objectKey()] = append(groups[h.objectKey()], h)
	}
	list := make([][]windowsHolderHandle, 0, len(groups))
	less := func(a, b windowsHolderHandle) bool {
		if a.Process.PID != b.Process.PID {
			return a.Process.PID < b.Process.PID
		}
		return a.Handle < b.Handle
	}
	canRefuse := func(group []windowsHolderHandle) bool {
		for _, h := range group {
			if h.Access&windowsHolderWriteAccess != 0 {
				return true
			}
		}
		return false
	}
	for _, group := range groups {
		sort.Slice(group, func(i, j int) bool { return less(group[i], group[j]) })
		list = append(list, group)
	}
	sort.Slice(list, func(i, j int) bool {
		if len(list[i]) != len(list[j]) {
			return len(list[i]) < len(list[j])
		}
		if a, b := canRefuse(list[i]), canRefuse(list[j]); a != b {
			return a
		}
		return less(list[i][0], list[j][0])
	})
	ordered := make([]windowsHolderHandle, 0, len(eligible))
	for _, group := range list {
		ordered = append(ordered, group...)
	}
	return ordered, len(list)
}

// windowsHolderProbes are the two facts the close loop asks of the file it
// works on before every close: whether an open for deletion is refused, and
// whether the open the hook makes of it (a start, for the binary; a read, for a
// runtime file) is refused.
type windowsHolderProbes struct {
	deleteBlocked func(path string) bool
	startRefused  func(path string) bool
}

// windowsHolderBinaryProbes are the hook binary's: the replaceable seams are
// read when called.
var windowsHolderBinaryProbes = windowsHolderProbes{
	deleteBlocked: func(path string) bool { return windowsHookBinaryDeleteBlocked(path) },
	startRefused:  func(path string) bool { return windowsHookBinaryHeldOpen(path) != "" },
}

// windowsHolderDataProbes are a hook runtime file's.
var windowsHolderDataProbes = windowsHolderProbes{
	deleteBlocked: func(path string) bool { return windowsHookDataDeleteBlocked(path) },
	startRefused:  func(path string) bool { return windowsHookDataReadRefused(path) },
}

// windowsHolderIsBinary tells the hook binary from the runtime files; the
// binary is the only watched file with this name.
func windowsHolderIsBinary(path string) bool {
	return strings.EqualFold(filepath.Base(path), "defenseclaw-hook.exe")
}

// windowsHolderSubject names the watched file in words.
func windowsHolderSubject(path string) string {
	if windowsHolderIsBinary(path) {
		return "the hook binary " + path
	}
	return "the hook runtime file " + path
}

// windowsHolderOpenSubject is windowsHolderSubject as the log line about a
// refused holder names it: "the hook" for the binary, whose lines have said so
// since the first round.
func windowsHolderOpenSubject(path string) string {
	if windowsHolderIsBinary(path) {
		return "the hook"
	}
	return windowsHolderSubject(path)
}

// windowsHolderRefuses says what a refused holder may be keeping the hook from.
func windowsHolderRefuses(path string) string {
	if windowsHolderIsBinary(path) {
		return "its starts"
	}
	return "the hook's reads (every guarded call fails closed)"
}

// windowsHolderRefusedWhat is the first half of the sentence an audit row and a
// log line say about the refusal.
func windowsHolderRefusedWhat(path string) string {
	if windowsHolderIsBinary(path) {
		return "A start of the hook was refused"
	}
	return "A read of the file by the hook was refused"
}

// The files besides the hook binary that a hook start reads, all of them
// administrator-written and readable by the standard users whose hooks read
// them, are the allow-list in enterprise_hooks_hook_runtime_watch.go. The
// guardian watches exactly those and no other file of the folder.

// windowsHolderDataHeldPerTick bounds the runtime files whose hold the guardian
// works on in one check, so that a standard user who holds many of them
// cannot take the check's time. The files left over are looked at first at the
// next check (windowsHolderDataCursor).
const windowsHolderDataHeldPerTick = 4

// windowsHookRuntimeDir is the hook runtime folder; tests replace it.
var windowsHookRuntimeDir = func() (string, error) {
	layout, err := windowsManagedLayout.standalone()
	return layout.HookRuntimeDir, err
}

// windowsHookDataReadRefused is the open the hook makes of a runtime file
// (ReadManagedHookRuntimeFile: read access, every sharing allowed) and whether
// it hits a sharing violation. windowsHookDataDeleteBlocked is the same test
// for deletion. Tests replace both.
var (
	windowsHookDataReadRefused = func(path string) bool {
		return windowsOpenRefused(path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	}
	windowsHookDataDeleteBlocked = func(path string) bool {
		return windowsOpenRefused(path, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	}
)

func windowsOpenRefused(path string, access, share uint32) bool {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return true
	}
	if err == nil {
		_ = windows.CloseHandle(handle)
	}
	return false
}

// windowsHolderDataGates and windowsHolderDataLast are the per-file gates and
// the last verdict logged for each watched runtime file, guarded by
// windowsHookBinaryMu.
var (
	windowsHolderDataGates = map[string]*windowsHolderState{}
	windowsHolderDataLast  = map[string]string{}
	// windowsHolderDataCursor is where the next check starts in the watch list,
	// after a check that stopped at windowsHolderDataHeldPerTick held files.
	windowsHolderDataCursor int
)

// keepWindowsHookRuntimeFiles is the guardian's check of the runtime files a
// hook start reads, called with windowsHookBinaryMu held and after the hook
// binary's own check. A file that refuses the hook's own read and an open for
// deletion is a hold; the guardian ends it by the same bounded close as the
// hook binary's (there is no swap for a data file), with its own persistence,
// backoff and streak per file. A check works on at most
// windowsHolderDataHeldPerTick held files; the rest wait for the next check,
// which starts where this one stopped. A file that is not on the watch list is
// never looked at.
func keepWindowsHookRuntimeFiles(stderr io.Writer) {
	if !windowsHolderCloserEnabled() {
		return
	}
	dir, err := windowsHookRuntimeDir()
	if err != nil {
		return
	}
	list := windowsHookRuntimeWatchList(dir)
	watched := map[string]bool{}
	for _, path := range list {
		watched[strings.ToLower(path)] = true
	}
	start := 0
	if len(list) > 0 {
		start = windowsHolderDataCursor % len(list)
	}
	windowsHolderDataCursor = 0
	held := 0
	for i := range list {
		path := list[(start+i)%len(list)]
		key := strings.ToLower(path)
		gate := windowsHolderDataGates[key]
		if gate == nil {
			gate = &windowsHolderState{}
			windowsHolderDataGates[key] = gate
		}
		if !windowsHookDataReadRefused(path) || !windowsHookDataDeleteBlocked(path) {
			gate.free()
			delete(windowsHolderDataLast, key)
			continue
		}
		if held >= windowsHolderDataHeldPerTick {
			windowsHolderDataCursor = (start + i) % len(list)
			break
		}
		held++
		closed, holdErr := endWindowsExclusiveHoldOn(gate, path, windowsHolderDataProbes)
		var message string
		switch {
		case holdErr == nil && closed == 0:
			continue
		case holdErr == nil && !windowsHookDataReadRefused(path):
			continue
		case holdErr != nil:
			message = fmt.Sprintf("the hook runtime file %s is held open by another program, so the hook cannot read it, and the guardian did not end the hold (%v)", path, holdErr)
		default:
			message = fmt.Sprintf("the hook runtime file %s is held open by another program, so the hook cannot read it, and the guardian did not end the hold (it closed %d handle(s), but a read is still refused)", path, closed)
		}
		if message != windowsHolderDataLast[key] {
			windowsHolderDataLast[key] = message
			fmt.Fprintf(stderr, "[hook-guardian] %s\n", message)
		}
	}
	for key := range windowsHolderDataGates {
		if !watched[key] {
			delete(windowsHolderDataGates, key)
			delete(windowsHolderDataLast, key)
		}
	}
}

// closeWindowsHolderCandidates closes the candidates in order, one at a
// time, asking before each whether the hook still refuses a start and still
// refuses an open for deletion, and stops as soon as either has cleared: a
// handle that only denies deletion is not closed once a start works. A close
// that does not answer in time stops the pass: nothing more is closed in that
// pass and the next check tries again (a close that had begun and finishes
// later is audited by its worker; began says one had).
func closeWindowsHolderCandidates(target string, probes windowsHolderProbes, identity windowsHookHolderIdentity, ordered []windowsHolderHandle, counts windowsHolderCounts) (closed []windowsHolderHandle, timedOut, began, onlyChanged bool, firstErr error) {
	changed, others := 0, 0
	defer func() { onlyChanged = changed > 0 && others == 0 && !timedOut }()
	for _, holder := range ordered {
		if len(closed) >= windowsHolderMaxCloses || !probes.deleteBlocked(target) || !probes.startRefused(target) {
			// Enough for one pass, or a start works or the hook is clear: the
			// remaining handles block nothing and stay.
			break
		}
		counts.Closed = len(closed) + 1
		err := closeWindowsHolderHandle(target, holder, identity, counts)
		switch {
		case errors.Is(err, errWindowsHolderTimedOut), errors.Is(err, errWindowsHolderMaybeClosed):
			timedOut = true
			suffix := "tries again at the next check"
			if errors.Is(err, errWindowsHolderMaybeClosed) {
				began, suffix = true, "looks again after the backoff of this streak"
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("the handle of %s %s; the guardian %s", holder.describe(), strings.TrimPrefix(err.Error(), "the handle "), suffix)
			}
		case err != nil:
			if errors.Is(err, errWindowsHolderChanged) {
				changed++
			} else {
				others++
			}
			if errors.Is(err, errWindowsHolderWrongObject) {
				auditWindowsHolderWrongClose(target, holder, counts)
			}
			if errors.Is(err, errWindowsHolderCloseFailed) {
				auditWindowsHolderFailedClose(target, holder, counts)
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("could not close the handle of %s: %w", holder.describe(), err)
			}
			continue
		default:
			closed = append(closed, holder)
			continue
		}
		break
	}
	return closed, timedOut, began, false, firstErr
}

// endWindowsExclusiveHold is called, with windowsHookBinaryMu held, when the
// hook refuses every start and an open for DELETE is refused: a handle that
// shares no deletion. It closes the handle that does it when the rules above
// allow, and returns how many handles it closed. A nil error with nothing
// closed means it is waiting (the second check, or the backoff).
func endWindowsExclusiveHold(target string) (int, error) {
	return endWindowsExclusiveHoldOn(&windowsHolderGate, target, windowsHolderBinaryProbes)
}

// endWindowsExclusiveHoldOn is endWindowsExclusiveHold for one file with its
// own gate: the persistence, the backoff and the streak are per file.
func endWindowsExclusiveHoldOn(gate *windowsHolderState, target string, probes windowsHolderProbes) (int, error) {
	now := windowsHeldSwapNow()
	if !gate.streakLast.IsZero() && now.Sub(gate.streakLast) > windowsHeldSwapStreakEnd {
		gate.endStreak()
	}
	gate.streakLast = now
	if now.Before(gate.nextScan) {
		// The backoff skips the scan, not the hold: the users seen so far
		// stay one continuous hold, so a refused holder is named again at the
		// next scan instead of waiting two checks once more.
		gate.seenAt = now
		return 0, gate.lastErr
	}
	for attempt := 0; ; attempt++ {
		closed, again, err := gate.pass(target, probes, now, attempt >= windowsHolderRescans)
		if !again {
			return closed, err
		}
	}
}

// pass is one look at who holds the hook, and the close. again is true when
// every handle it tried had been closed or replaced by its owner since the
// scan, which is what a holder that rotates its handle looks like: the
// caller looks again at once (a few times) instead of backing off. last is
// true on the final look, which then ends as any other failed close.
func (gate *windowsHolderState) pass(target string, probes windowsHolderProbes, now time.Time, last bool) (closed int, again bool, err error) {
	scan, err := scanWindowsHolders(windowsHolderSys, target, uint32(os.Getpid()))
	if err != nil {
		return 0, false, gate.refuse(now, fmt.Errorf("the guardian could not list who holds the hook: %w", err))
	}
	defer scan.close()
	persistent := gate.observe(now, scan.Identity, scan.Holders)
	if len(scan.Holders) == 0 {
		// A hold that ended between the start-style open and the scan is
		// not a finding; one that stays unseen across two checks is.
		if gate.emptySince.IsZero() {
			gate.emptySince = now
			return 0, false, nil
		}
		if now.Sub(gate.emptySince) < windowsHolderPersist() {
			return 0, false, nil
		}
		return 0, false, gate.refuse(now, fmt.Errorf("the guardian found no handle of a user process on it%s", scan.limits()))
	}
	gate.emptySince = time.Time{}
	if len(persistent) == 0 {
		if scan.Hung > 0 || scan.Elapsed > windowsHolderSlowScan {
			// A scan that is slow (hung probes, a huge table) is not repeated
			// at every check.
			gate.refusals++
			gate.nextScan = now.Add(windowsHeldSwapDelay(gate.refusals))
		}
		return 0, false, nil
	}
	// The handle table does not show whose handle refuses the start, but the
	// sharing rules say which file objects can (windowsHolderStartBlockers). A
	// holder the guardian will not touch (a service, a protected process,
	// session 0) on an object that can refuse the start may be the cause: while
	// one is there the guardian closes no user's handle, except once per
	// streak, after about 30 seconds, to rule it out. A refused holder on an
	// object that cannot refuse a start is named, and the user's blockers are
	// still closed. A user's handle its owner protected from closing is named
	// and skipped, and the others are still closed. A refused holder seen for
	// the first time is waited for.
	blockers := windowsHolderStartBlockers(scan.Holders)
	refusedObjects := map[windowsHolderObjectKey]bool{}
	for _, holder := range scan.Holders {
		if windowsHolderRefusal(holder.Process) != "" {
			refusedObjects[holder.objectKey()] = true
		}
	}
	var eligible, blocking, named []windowsHolderHandle
	var blockingReasons, namedReasons []string
	for _, holder := range persistent {
		reason := windowsHolderHandleRefusal(holder)
		switch {
		case reason == "" && refusedObjects[holder.objectKey()]:
			// The same file object as a handle the guardian will not touch:
			// closing this one frees nothing.
		case reason == "":
			eligible = append(eligible, holder)
		case windowsHolderRefusal(holder.Process) != "" && blockers[holder.objectKey()]:
			why := "it can write or append"
			if holder.Access&windowsHolderWriteAccess == 0 {
				why = "it is the only file object open on the hook"
			}
			blocking, blockingReasons = append(blocking, holder), append(blockingReasons, reason+" ("+why+")")
		default:
			named, namedReasons = append(named, holder), append(namedReasons, reason)
		}
	}
	ordered, counts := orderWindowsHolderCandidates(eligible)
	for i, holder := range blocking {
		counts.Left = append(counts.Left, holder.describe()+": "+blockingReasons[i])
		gate.record(target, holder, false, blockingReasons[i], scan, counts)
	}
	for i, holder := range named {
		if windowsHolderRefusal(holder.Process) != "" && !gate.rows[holder.procKey()] {
			logWindowsHolder(fmt.Sprintf("[hook-guardian] note: %s has %s open and the guardian will not touch it (%s), but it only reads and another file object is open too, so it cannot be what refuses a start; the guardian closes the user's blockers", holder.describe(), windowsHolderOpenSubject(target), namedReasons[i]))
		}
		counts.Left = append(counts.Left, holder.describe()+": "+namedReasons[i])
		gate.record(target, holder, false, namedReasons[i], scan, counts)
	}
	override := false
	if len(blocking) > 0 {
		candidates := gate.overrideCandidates(now, eligible)
		if len(candidates) == 0 {
			more := ""
			if len(blocking) > 1 {
				more = fmt.Sprintf(" (and %d more handle(s) of that kind)", len(blocking)-1)
			}
			kept := ""
			switch {
			case len(eligible) > 0 && gate.overridden:
				kept = fmt.Sprintf("; it closes none of the %d handle(s) of signed-in users that are open on the hook too: it already closed one user's handles once in this streak to rule that handle out", len(eligible))
			case len(eligible) > 0:
				kept = fmt.Sprintf("; it closes none of the %d handle(s) of signed-in users that are open on the hook too, because that handle could be what refuses the start; if it is still there after about %d seconds the guardian closes one user's handles once, to rule it out", len(eligible), int(windowsHolderOverrideAfter()/time.Second))
			}
			return 0, false, gate.refuse(now, fmt.Errorf("%s has %s open and may be what refuses %s; the guardian does not close handles of that kind: %s%s%s", blocking[0].describe(), windowsHolderOpenSubject(target), windowsHolderRefuses(target), blockingReasons[0], more, kept))
		}
		override = true
		left := counts.Left
		ordered, counts = orderWindowsHolderCandidates(candidates)
		counts.Left = left
		counts.Note = fmt.Sprintf("The guardian could not tell whether %s (%s) or this user's handle refused the start. This user's hold had lasted %d seconds, so the guardian closed this user's handles one at a time to rule the other holder out. It does this once per streak.",
			blocking[0].describe(), blockingReasons[0], int(now.Sub(gate.holds[candidates[0].group()].first)/time.Second))
	}
	if len(eligible) == 0 {
		if len(named) > 0 {
			more := ""
			if len(named) > 1 {
				more = fmt.Sprintf(" (and %d more handle(s) of that kind)", len(named)-1)
			}
			return 0, false, gate.refuse(now, fmt.Errorf("%s has %s open and may be what refuses %s; the guardian does not close handles of that kind: %s%s", named[0].describe(), windowsHolderOpenSubject(target), windowsHolderRefuses(target), namedReasons[0], more))
		}
		// What the guardian could close shares a file object with a holder
		// it has only just seen: wait for the next check.
		return 0, false, nil
	}
	if !override {
		for _, holder := range scan.Holders {
			if windowsHolderRefusal(holder.Process) != "" && blockers[holder.objectKey()] {
				// A holder the guardian will not touch, seen for the first
				// time: wait for the next check before closing anything.
				return 0, false, nil
			}
		}
	}
	if scan.Listed && len(scan.Unopened) > 0 {
		return 0, false, gate.refuse(now, fmt.Errorf("process id %d also has files open that the guardian cannot inspect (a protected process), so it cannot tell whose handle refuses the start and closes none", scan.Unopened[0]))
	}
	if scan.Limited != "" {
		return 0, false, gate.refuse(now, fmt.Errorf("the guardian stopped looking for the holder: %s", scan.Limited))
	}
	if gate.closes > 0 && now.Before(gate.nextClose) {
		// The same hold again, before the backoff is over: never a tight loop.
		gate.nextScan = gate.nextClose.Add(-windowsHolderPersist())
		return 0, false, nil
	}
	if override {
		gate.overridden = true
	}
	done, timedOut, began, onlyChanged, firstErr := closeWindowsHolderCandidates(target, probes, scan.Identity, ordered, counts)
	if len(done) == 0 {
		if timedOut {
			// Not a refusal: the next check tries again, unless a close had
			// begun (the handle may be gone and a late row is coming): that
			// counts in the streak like any close, with its backoff.
			gate.lastErr = nil
			if began {
				gate.closes++
				gate.nextClose = now.Add(windowsHeldSwapDelay(gate.closes))
				gate.nextScan = gate.nextClose.Add(-windowsHolderPersist())
			}
			return 0, false, firstErr
		}
		if firstErr == nil {
			// The hook was clear by the time the guardian came to close.
			return 0, false, nil
		}
		if onlyChanged && !last {
			return 0, true, nil
		}
		return 0, false, gate.refuse(now, firstErr)
	}
	gate.closes++
	gate.nextClose = now.Add(windowsHeldSwapDelay(gate.closes))
	counts.Closed = len(done)
	for _, holder := range done {
		gate.record(target, holder, true, "", scan, counts)
	}
	gate.refusals, gate.lastErr = 0, nil
	gate.nextScan = gate.nextClose.Add(-windowsHolderPersist())
	gate.holds = nil
	return len(done), false, nil
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
	if s == nil {
		return "the pass that began it ended before it finished"
	}
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
func (g *windowsHolderState) record(target string, holder windowsHolderHandle, closed bool, reason string, scan *windowsHolderScan, counts windowsHolderCounts) {
	if closed {
		line := fmt.Sprintf("[hook-guardian] tamper: closed the handle %s had on %s (access 0x%08x; one of %d candidate handle(s) in %d process(es) %s, %d closed in this pass). %s and so was a test open for deletion; the file was not changed and the process was left running (close %d of this streak; if it takes the handle again it is closed again no sooner than %s; scan: %s)",
			holder.describe(), windowsHolderSubject(target), holder.Access, counts.Handles, counts.Processes, counts.where(), counts.Closed, windowsHolderRefusedWhat(target), g.closes, g.nextClose.Format("15:04:05"), scan.summary())
		if len(counts.Left) > 0 {
			line += "; also open and not closed: " + strings.Join(counts.Left, "; ")
		}
		if counts.Note != "" {
			line += ". " + counts.Note
		}
		logWindowsHolder(line)
	}
	if g.rows == nil {
		g.rows = map[windowsHolderProcKey]bool{}
	}
	if g.rows[holder.procKey()] {
		return
	}
	g.rows[holder.procKey()] = true
	row := windowsHolderAuditRow{At: windowsHeldSwapNow().UTC(), Hook: target, Holder: holder.Process, Handle: holder.Handle, Access: holder.Access,
		Closed: closed, Reason: reason, Streak: g.closes, Counts: counts, Note: counts.Note}
	if scan != nil {
		row.ScanMS, row.Listed, row.Probed = scan.Elapsed.Milliseconds(), scan.Entries, scan.Probed
	}
	row.Account = windowsHolderAccount(holder.Process.SID)
	queueWindowsHolderAudit(row)
}

// windowsHolderAuditRow is one connector-hook-tampered row for the gateway.
type windowsHolderAuditRow struct {
	Seq     uint64
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
	Counts  windowsHolderCounts
	// Note is a sentence the row adds: a close that finished after the
	// guardian stopped waiting, or one that hit a handle that was not the hook's.
	Note string
	// Rejects is how many times the gateway refused the row for good (an
	// HTTP 4xx that a retry does not change).
	Rejects int
}

// event is the audit event of the row: the existing hook-tamper action, HIGH.
// The action is the same for a close and for a hold the guardian did not end;
// the closed field tells them apart. A row for a hold the guardian did not
// end stays HIGH: while that handle lives every hook start is refused, and
// the hooks guard no tool call, so the operator needs it as prominent as a
// close. The existing connector-hook-tampered events (the gateway's hook
// config guard) set no severity of their own, so there is no lower level for
// "seen, not acted on" to copy.
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
	who := fmt.Sprintf("%s (process id %d, account %s, session %d)", image, r.Holder.PID, clean(r.Account), r.Holder.Session)
	observed := windowsHolderRefusedWhat(r.Hook) + ", and so was a test open of it for deletion."
	var details string
	if r.Closed {
		details = fmt.Sprintf("%s had %s open (access 0x%08x). %s The hook guardian closed that handle (one of %d candidate handle(s) in %d process(es) %s); the file was not changed and the process was not ended.",
			who, windowsHolderSubject(r.Hook), r.Access, observed, r.Counts.Handles, r.Counts.Processes, r.Counts.where())
	} else {
		details = fmt.Sprintf("%s has %s open (access 0x%08x). %s This handle may be the cause. The hook guardian did not close it: %s.",
			who, windowsHolderSubject(r.Hook), r.Access, observed, clean(r.Reason))
	}
	if r.Note != "" {
		details += " " + clean(r.Note)
	}
	return audit.Event{
		Timestamp: r.At, Action: string(audit.ActionConnectorHookTampered), Target: r.Hook, Actor: "hook-guardian",
		Details: details, Severity: "HIGH",
		Structured: map[string]any{
			"hook_path": r.Hook, "holder_image": image, "holder_pid": r.Holder.PID, "holder_sid": r.Holder.SID,
			"holder_account": clean(r.Account), "holder_session": r.Holder.Session, "granted_access": fmt.Sprintf("0x%08x", r.Access),
			"handle_value": uint64(r.Handle), "wow64": r.Holder.Wow64, "closed": r.Closed, "not_closed_reason": clean(r.Reason),
			"streak_closes": r.Streak, "scan_ms": r.ScanMS, "handles_listed": r.Listed, "handles_inspected": r.Probed,
			"candidate_handles": r.Counts.Handles, "candidate_processes": r.Counts.Processes, "candidate_file_objects": r.Counts.Objects, "file_objects_counted_per_handle": r.Counts.NoAddresses,
			"handles_closed_in_pass": r.Counts.Closed, "note": clean(r.Note),
		},
	}
}

// windowsHolderAuditPost sends one row to the gateway; tests replace it.
var windowsHolderAuditPost = postWindowsHolderAudit

// windowsHolderAuditRefusal is the gateway answering a row with an HTTP
// status other than 200.
type windowsHolderAuditRefusal struct{ Status int }

func (e windowsHolderAuditRefusal) Error() string {
	return fmt.Sprintf("gateway audit returned HTTP %d", e.Status)
}

// permanent is true for a refusal that sending the same row again does not
// change: 400, 413, 415 and 422, the answers that describe a bad row (the
// gateway checks only the action, the JSON and the store). 401, 403, 404 and
// 405 are answers about the gateway, not the row (a token that does not match
// while it restarts, a route a gateway of another version lacks mid-upgrade):
// the row stays queued and a later try can deliver it.
func (e windowsHolderAuditRefusal) permanent() bool {
	switch e.Status {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity:
		return true
	}
	return false
}

// windowsHolderAuditMaxRejects is how many times the gateway may refuse a row
// for good before the guardian drops it, with a log line, so that one row it
// will never take does not hold up the rows behind it.
const windowsHolderAuditMaxRejects = 5

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
		return windowsHolderAuditRefusal{Status: response.StatusCode}
	}
	return nil
}

// The guardian's log lines and the audit rows waiting for the gateway. They
// are guarded by windowsHolderOutMu, not by windowsHookBinaryMu: the guardian
// delivers rows after it has released windowsHookBinaryMu, so a gateway that
// is down or slow never holds up a close. The rows are kept (in memory and, when
// the guardian knows its state folder, in a file there) until the gateway has
// taken them, and are delivered in order.
var (
	windowsHolderOutMu        sync.Mutex
	windowsHolderLog          []string
	windowsHolderAuditQueue   []windowsHolderAuditRow
	windowsHolderAuditSeq     uint64
	windowsHolderAuditPath    string
	windowsHolderAuditLoaded  bool
	windowsHolderAuditLastErr string
	windowsHolderAuditFails   int
	windowsHolderAuditNext    time.Time
	windowsHolderAuditSaveErr string
	windowsHolderFlushMu      sync.Mutex
)

// windowsHolderAuditMaxRows bounds the queue, in memory and on disk. Past it
// the oldest rows are dropped, with a log line.
const windowsHolderAuditMaxRows = 256

// windowsHolderAuditWrite writes the queue file; tests replace it.
var windowsHolderAuditWrite = writeWindowsBundleAdminFile

func logWindowsHolder(line string) {
	windowsHolderOutMu.Lock()
	defer windowsHolderOutMu.Unlock()
	windowsHolderLog = append(windowsHolderLog, line)
}

// setWindowsHolderAuditPath says where the queue is kept between guardian
// restarts.
func setWindowsHolderAuditPath(path string) {
	windowsHolderOutMu.Lock()
	defer windowsHolderOutMu.Unlock()
	if windowsHolderAuditPath != path {
		windowsHolderAuditPath, windowsHolderAuditLoaded = path, false
	}
}

// loadWindowsHolderAuditLocked reads the rows an earlier guardian process
// left in the queue file, once. The caller holds windowsHolderOutMu.
func loadWindowsHolderAuditLocked() {
	if windowsHolderAuditLoaded || windowsHolderAuditPath == "" {
		return
	}
	windowsHolderAuditLoaded = true
	removeWindowsHolderAuditTempFiles(windowsHolderAuditPath)
	info, err := os.Stat(windowsHolderAuditPath)
	if err != nil {
		return
	}
	var rows []windowsHolderAuditRow
	if info.Size() > 8<<20 {
		err = errors.New("the file is larger than 8 MiB")
	} else if data, readErr := os.ReadFile(windowsHolderAuditPath); readErr != nil {
		err = readErr
	} else {
		err = json.Unmarshal(data, &rows)
	}
	if err != nil {
		windowsHolderLog = append(windowsHolderLog, fmt.Sprintf("[hook-guardian] warn: ignored the saved hook-holder audit rows in %s: %v", windowsHolderAuditPath, err))
		return
	}
	for _, row := range rows {
		windowsHolderAuditSeq = max(windowsHolderAuditSeq, row.Seq)
	}
	windowsHolderAuditQueue = append(rows, windowsHolderAuditQueue...)
	trimWindowsHolderAuditLocked()
}

// removeWindowsHolderAuditTempFiles removes what a guardian that ended in the
// middle of a save left next to the queue file (<queue>.tmp-<process id>).
// Nothing writes the queue before the first load, so none is in use.
func removeWindowsHolderAuditTempFiles(path string) {
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return
	}
	prefix := strings.ToLower(filepath.Base(path)) + ".tmp-"
	for _, entry := range entries {
		if strings.HasPrefix(strings.ToLower(entry.Name()), prefix) && entry.Type().IsRegular() {
			_ = os.Remove(filepath.Join(filepath.Dir(path), entry.Name()))
		}
	}
}

func trimWindowsHolderAuditLocked() {
	if over := len(windowsHolderAuditQueue) - windowsHolderAuditMaxRows; over > 0 {
		windowsHolderLog = append(windowsHolderLog, fmt.Sprintf("[hook-guardian] warn: %d hook-holder audit rows are waiting for the gateway; dropped the %d oldest", len(windowsHolderAuditQueue), over))
		windowsHolderAuditQueue = windowsHolderAuditQueue[over:]
	}
}

// persistWindowsHolderAuditLocked writes the queue to its file (or removes
// the file when the queue is empty). A failure is logged once.
func persistWindowsHolderAuditLocked() {
	if windowsHolderAuditPath == "" {
		return
	}
	var err error
	if len(windowsHolderAuditQueue) == 0 {
		if err = os.Remove(windowsHolderAuditPath); errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	} else if data, marshalErr := json.Marshal(windowsHolderAuditQueue); marshalErr != nil {
		err = marshalErr
	} else {
		err = windowsHolderAuditWrite(windowsHolderAuditPath, data)
	}
	if err == nil {
		windowsHolderAuditSaveErr = ""
	} else if message := err.Error(); message != windowsHolderAuditSaveErr {
		windowsHolderAuditSaveErr = message
		windowsHolderLog = append(windowsHolderLog, fmt.Sprintf("[hook-guardian] warn: could not save the hook-holder audit rows waiting for the gateway (a guardian restart loses them): %v", err))
	}
}

// queueWindowsHolderAudit adds a row to the queue. It does no network call.
func queueWindowsHolderAudit(row windowsHolderAuditRow) {
	windowsHolderOutMu.Lock()
	defer windowsHolderOutMu.Unlock()
	loadWindowsHolderAuditLocked()
	windowsHolderAuditSeq++
	row.Seq = windowsHolderAuditSeq
	windowsHolderAuditQueue = append(windowsHolderAuditQueue, row)
	trimWindowsHolderAuditLocked()
	persistWindowsHolderAuditLocked()
}

// writeWindowsHolderLog writes the queued log lines. The guardian calls it
// after each check; it only writes to the log.
func writeWindowsHolderLog(stderr io.Writer) {
	windowsHolderOutMu.Lock()
	lines := windowsHolderLog
	windowsHolderLog = nil
	windowsHolderOutMu.Unlock()
	for _, line := range lines {
		fmt.Fprintln(stderr, line)
	}
}

// flushWindowsHolderAudit sends the queued rows to the gateway, oldest
// first, and stops at the first one it cannot send: the rest wait, in
// order, and the next try comes after a backoff (10 s, doubling to 5 min).
// The guardian calls it after it has released windowsHookBinaryMu. One flush
// runs at a time.
func flushWindowsHolderAudit(stderr io.Writer) {
	if !windowsHolderFlushMu.TryLock() {
		return
	}
	defer windowsHolderFlushMu.Unlock()
	windowsHolderOutMu.Lock()
	loadWindowsHolderAuditLocked()
	pending := append([]windowsHolderAuditRow(nil), windowsHolderAuditQueue...)
	wait := windowsHeldSwapNow().Before(windowsHolderAuditNext)
	windowsHolderOutMu.Unlock()
	if len(pending) == 0 || wait {
		return
	}
	var delivered, refusedSeq uint64
	var failure error
	var dropped []string
	for _, row := range pending {
		if failure = windowsHolderAuditPost(row); failure == nil {
			delivered = row.Seq
			continue
		}
		var refusal windowsHolderAuditRefusal
		if errors.As(failure, &refusal) && refusal.permanent() {
			if row.Rejects+1 >= windowsHolderAuditMaxRejects {
				// The gateway will not take this row: drop it, so that the
				// rows behind it are not held up for ever.
				dropped = append(dropped, fmt.Sprintf("[hook-guardian] warn: dropped the hook-holder audit row for %s (process id %d, %s): the gateway refused it %d times (%v)",
					row.Hook, row.Holder.PID, row.At.Format(time.RFC3339), row.Rejects+1, failure))
				delivered, failure = row.Seq, nil
				continue
			}
			refusedSeq = row.Seq
		}
		break
	}
	windowsHolderOutMu.Lock()
	windowsHolderLog = append(windowsHolderLog, dropped...)
	if refusedSeq > 0 {
		for i := range windowsHolderAuditQueue {
			if windowsHolderAuditQueue[i].Seq == refusedSeq {
				windowsHolderAuditQueue[i].Rejects++
			}
		}
		persistWindowsHolderAuditLocked()
	}
	if delivered > 0 {
		kept := windowsHolderAuditQueue[:0]
		for _, row := range windowsHolderAuditQueue {
			if row.Seq > delivered {
				kept = append(kept, row)
			}
		}
		windowsHolderAuditQueue = kept
		persistWindowsHolderAuditLocked()
	}
	var message string
	if failure == nil {
		windowsHolderAuditLastErr, windowsHolderAuditFails, windowsHolderAuditNext = "", 0, time.Time{}
	} else {
		windowsHolderAuditFails++
		windowsHolderAuditNext = windowsHeldSwapNow().Add(windowsHeldSwapDelay(windowsHolderAuditFails))
		if text := failure.Error(); text != windowsHolderAuditLastErr {
			windowsHolderAuditLastErr = text
			message = fmt.Sprintf("[hook-guardian] warn: could not record the hook-holder audit row (it is kept and retried): %v", failure)
		}
	}
	windowsHolderOutMu.Unlock()
	if message != "" {
		fmt.Fprintln(stderr, message)
	}
	// Lines the save or the load added.
	writeWindowsHolderLog(stderr)
}
