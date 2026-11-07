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
//	    two checks at least windowsHolderPersist apart, with a candidate of
//	    the same user (account SID and session) on both, whatever the handle
//	    value or process id (a user who hands the file to a new handle or
//	    process before each check is still the same hold). One brief hold,
//	    such as a scanner's or a backup's exclusive read, is gone by the
//	    second check and is not closed;
//	(b) only handles whose volume serial number and 128-bit file id equal the
//	    live hook's, with data or execute access, found by duplicating the
//	    handle into the guardian after its object type is known to be a
//	    file; never by name. Windows does not show a handle's share mode, so
//	    "denies delete sharing" is the fact about the whole file (an open for
//	    DELETE is refused). The candidates are grouped by the file object
//	    they refer to (the Object field of the handle table): with one file
//	    object among them, closing every handle of it is not collateral; with
//	    several, the guardian finishes one object at a time, the one with the
//	    fewest handles first, and stops as soon as the hook can be started;
//	(c) never in a protected process, never in a process whose account is
//	    LocalSystem, LocalService, NetworkService or any other service
//	    identity, never in session 0; only in a process of a user account in
//	    an interactive session. The token is read from the process. A holder
//	    it refuses is named and skipped; the other candidates are still
//	    closed;
//	(d) every close writes a HIGH connector-hook-tampered audit row (image
//	    path, process id, account SID and name, session, granted access, hook
//	    path, how many candidate handles, processes and file objects there
//	    were); a hold the guardian refuses to end writes one too, saying that
//	    nothing was closed. The rows are kept, in memory and on disk, until
//	    the gateway has them;
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
	// timeout; proceed turns false when the caller has given up, and the
	// close is then not made.
	CloseIf(handle uintptr, want windowsHookHolderIdentity, proceed func() bool) error
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
// exactly one of the caller and late sees the answer). live is false once the
// caller has given up; a call that does something irreversible checks it
// first.
func runWindowsHolderCall[T any](proc *windowsRefProc, call func(live func() bool) T, late func(T)) (result T, answered bool) {
	proc.retain()
	var (
		mu   sync.Mutex
		gone atomic.Bool
		done = make(chan T, 1)
	)
	go func() {
		defer proc.Release()
		r := call(func() bool { return !gone.Load() })
		mu.Lock()
		defer mu.Unlock()
		if gone.Load() {
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
		return r, true
	case <-timer.C:
		mu.Lock()
		defer mu.Unlock()
		select {
		case r := <-done:
			return r, true
		default:
		}
		windowsHolderHung.Add(1)
		gone.Store(true)
		return result, false
	}
}

// identifyWindowsHolderHandle runs one probe through runWindowsHolderCall.
func identifyWindowsHolderHandle(proc *windowsRefProc, handle uintptr) (id windowsHookHolderIdentity, disk, hung bool, err error) {
	type answer struct {
		id   windowsHookHolderIdentity
		disk bool
		err  error
	}
	a, answered := runWindowsHolderCall(proc, func(func() bool) answer {
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

// closeWindowsHolderHandle closes one handle through runWindowsHolderCall,
// with the same worker and timeout as a probe: the fresh duplicate, its
// type, its identity and the check after the close all run on the worker. A
// close that finishes after the guardian gave up is recorded for the next
// pass (a call is not cancellable once DuplicateHandle has begun).
func closeWindowsHolderHandle(h windowsHolderHandle, want windowsHookHolderIdentity) error {
	err, answered := runWindowsHolderCall(h.proc, func(live func() bool) error {
		return h.proc.CloseIf(h.Handle, want, live)
	}, func(err error) {
		if err == nil {
			windowsHolderLateClosed(h)
		}
	})
	if !answered {
		return errWindowsHolderTimedOut
	}
	return err
}

// windowsHolderLate are the closes that finished after the guardian gave up
// on them. The next pass audits them.
var (
	windowsHolderLateMu sync.Mutex
	windowsHolderLate   []windowsHolderHandle
)

func windowsHolderLateClosed(h windowsHolderHandle) {
	windowsHolderLateMu.Lock()
	defer windowsHolderLateMu.Unlock()
	windowsHolderLate = append(windowsHolderLate, h)
}

func takeWindowsHolderLateCloses() []windowsHolderHandle {
	windowsHolderLateMu.Lock()
	defer windowsHolderLateMu.Unlock()
	taken := windowsHolderLate
	windowsHolderLate = nil
	return taken
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
	// firstSeen is when a user (account and session) first had a candidate
	// on the hook in this hold. It is the user, not the handle or the
	// process, that persists: a holder that hands the open file to a new
	// handle or process before each check is still the same hold.
	firstSeen  map[windowsHolderGroup]time.Time
	identity   windowsHookHolderIdentity
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

// windowsHolderPersist is how long a user must have had a candidate on the
// hook, across checks, before a handle is closed: about two guardian ticks.
func windowsHolderPersist() time.Duration { return windowsHookBinaryCheckInterval * 4 / 5 }

// free forgets what was seen: the hook is not held, so the next hold starts
// its two checks again. The streak is not ended (a holder that lets go and
// takes the handle again is still in the same streak).
func (g *windowsHolderState) free() {
	g.firstSeen, g.seenAt, g.emptySince = nil, time.Time{}, time.Time{}
}

func (g *windowsHolderState) endStreak() {
	*g = windowsHolderState{firstSeen: g.firstSeen, seenAt: g.seenAt, identity: g.identity, emptySince: g.emptySince}
	windowsHolderNames.Clear()
}

// observe records the users that have a candidate on the hook at this check
// and returns the candidates of the users seen at least windowsHolderPersist
// ago, with no free check, no other file and no gap of more than three
// ticks between.
func (g *windowsHolderState) observe(now time.Time, identity windowsHookHolderIdentity, holders []windowsHolderHandle) []windowsHolderHandle {
	if !g.seenAt.IsZero() && (now.Sub(g.seenAt) > 3*windowsHookBinaryCheckInterval || g.identity != identity) {
		g.firstSeen = nil
	}
	next := make(map[windowsHolderGroup]time.Time, len(holders))
	for _, holder := range holders {
		if _, done := next[holder.group()]; done {
			continue
		}
		since, ok := g.firstSeen[holder.group()]
		if !ok {
			since = now
		}
		next[holder.group()] = since
	}
	var persistent []windowsHolderHandle
	for _, holder := range holders {
		if now.Sub(next[holder.group()]) >= windowsHolderPersist() {
			persistent = append(persistent, holder)
		}
	}
	g.firstSeen, g.seenAt, g.identity = next, now, identity
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
	Closed    int      // handles closed in the pass
	Left      []string // holders that were named and not closed
}

// orderWindowsHolderCandidates puts the candidates in the order they are
// tried and counts them. Handles that refer to the same file object stay
// together and a whole object is finished before the next one starts, so a
// handle of the blocking object is not left half closed while another
// object is closed; with one object among the candidates every handle of it
// is needed, and nothing is collateral. The objects are tried fewest
// handles first, then by process id. A handle whose object address the
// system did not show is an object of its own.
func orderWindowsHolderCandidates(eligible []windowsHolderHandle) ([]windowsHolderHandle, windowsHolderCounts) {
	type objectKey struct {
		object uintptr
		pid    uint32
		handle uintptr
	}
	groups := map[objectKey][]windowsHolderHandle{}
	processes := map[windowsHolderProcKey]bool{}
	for _, h := range eligible {
		key := objectKey{object: h.Object}
		if h.Object == 0 {
			key = objectKey{pid: h.Process.PID, handle: h.Handle}
		}
		groups[key] = append(groups[key], h)
		processes[h.procKey()] = true
	}
	list := make([][]windowsHolderHandle, 0, len(groups))
	less := func(a, b windowsHolderHandle) bool {
		if a.Process.PID != b.Process.PID {
			return a.Process.PID < b.Process.PID
		}
		return a.Handle < b.Handle
	}
	for _, group := range groups {
		sort.Slice(group, func(i, j int) bool { return less(group[i], group[j]) })
		list = append(list, group)
	}
	sort.Slice(list, func(i, j int) bool {
		if len(list[i]) != len(list[j]) {
			return len(list[i]) < len(list[j])
		}
		return less(list[i][0], list[j][0])
	})
	ordered := make([]windowsHolderHandle, 0, len(eligible))
	for _, group := range list {
		ordered = append(ordered, group...)
	}
	return ordered, windowsHolderCounts{Handles: len(eligible), Processes: len(processes), Objects: len(list)}
}

// closeWindowsHolderCandidates closes the candidates in order, one at a
// time, asking before each whether the hook can be started yet, and stops
// when it can. A close that does not answer in time stops the pass: nothing
// is closed in that process and the next check tries again.
func closeWindowsHolderCandidates(target string, identity windowsHookHolderIdentity, ordered []windowsHolderHandle) (closed []windowsHolderHandle, timedOut, onlyChanged bool, firstErr error) {
	changed, others := 0, 0
	defer func() { onlyChanged = changed > 0 && others == 0 && !timedOut }()
	for _, holder := range ordered {
		if len(closed) >= windowsHolderMaxCloses || !windowsHookBinaryDeleteBlocked(target) {
			// Enough for one pass, or the hook is clear: the remaining
			// handles block nothing and stay.
			break
		}
		err := closeWindowsHolderHandle(holder, identity)
		switch {
		case errors.Is(err, errWindowsHolderTimedOut):
			timedOut = true
			if firstErr == nil {
				firstErr = fmt.Errorf("the handle of %s %s; the guardian tries again at the next check", holder.describe(), strings.TrimPrefix(err.Error(), "the handle "))
			}
		case err != nil:
			if errors.Is(err, errWindowsHolderChanged) {
				changed++
			} else {
				others++
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
	return closed, timedOut, false, firstErr
}

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
	for _, late := range takeWindowsHolderLateCloses() {
		// A close the guardian gave up on finished after all.
		gate.record(target, late, true, "", nil, windowsHolderCounts{Handles: 1, Processes: 1, Objects: 1, Closed: 1})
	}
	if now.Before(gate.nextScan) {
		// The backoff skips the scan, not the hold: the users seen so far
		// stay one continuous hold, so a refused holder is named again at the
		// next scan instead of waiting two checks once more.
		gate.seenAt = now
		return 0, gate.lastErr
	}
	for attempt := 0; ; attempt++ {
		closed, again, err := gate.pass(target, now, attempt >= windowsHolderRescans)
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
func (gate *windowsHolderState) pass(target string, now time.Time, last bool) (closed int, again bool, err error) {
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
	// A holder the guardian will not touch is named and skipped; the other
	// candidates are still closed. It does not stop the close: a persistent
	// handle in a service that merely has the hook open must not keep a
	// user's blocking handle in place.
	var eligible, refused []windowsHolderHandle
	var refusedReasons []string
	for _, holder := range persistent {
		if reason := windowsHolderHandleRefusal(holder); reason != "" {
			refused, refusedReasons = append(refused, holder), append(refusedReasons, reason)
		} else {
			eligible = append(eligible, holder)
		}
	}
	ordered, counts := orderWindowsHolderCandidates(eligible)
	for i, holder := range refused {
		counts.Left = append(counts.Left, holder.describe()+": "+refusedReasons[i])
		gate.record(target, holder, false, refusedReasons[i], scan, counts)
	}
	if len(eligible) == 0 {
		more := ""
		if len(refused) > 1 {
			more = fmt.Sprintf(" (and %d more handle(s) of that kind)", len(refused)-1)
		}
		return 0, false, gate.refuse(now, fmt.Errorf("%s has the hook open and may be what refuses its starts; the guardian does not close handles of that kind: %s%s", refused[0].describe(), refusedReasons[0], more))
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
	done, timedOut, onlyChanged, firstErr := closeWindowsHolderCandidates(target, scan.Identity, ordered)
	if len(done) == 0 {
		if timedOut {
			// Not a refusal: no backoff, the next check tries again.
			gate.lastErr = nil
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
	gate.firstSeen = nil
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
		line := fmt.Sprintf("[hook-guardian] tamper: closed the handle %s had on the hook binary %s (access 0x%08x; one of %d candidate handle(s) in %d process(es) on %d file object(s), %d closed in this pass). A start of the hook was refused and so was a test open for deletion; the file was not changed and the process was left running (close %d of this streak; if it takes the handle again it is closed again no sooner than %s; scan: %s)",
			holder.describe(), target, holder.Access, counts.Handles, counts.Processes, counts.Objects, counts.Closed, g.closes, g.nextClose.Format("15:04:05"), scan.summary())
		if len(counts.Left) > 0 {
			line += "; also open and not closed: " + strings.Join(counts.Left, "; ")
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
		Closed: closed, Reason: reason, Streak: g.closes, Counts: counts}
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
}

// event is the audit event of the row: the existing hook-tamper action, HIGH.
// The action is the same for a close and for a hold the guardian did not end;
// the closed field tells them apart.
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
	observed := "A start of the hook was refused, and so was a test open of it for deletion."
	var details string
	if r.Closed {
		details = fmt.Sprintf("%s had the hook binary %s open (access 0x%08x). %s The hook guardian closed that handle (one of %d candidate handle(s) in %d process(es) on %d file object(s)); the file was not changed and the process was not ended.",
			who, r.Hook, r.Access, observed, r.Counts.Handles, r.Counts.Processes, r.Counts.Objects)
	} else {
		details = fmt.Sprintf("%s has the hook binary %s open (access 0x%08x). %s This handle may be the cause. The hook guardian did not close it: %s.",
			who, r.Hook, r.Access, observed, clean(r.Reason))
	}
	return audit.Event{
		Timestamp: r.At, Action: string(audit.ActionConnectorHookTampered), Target: r.Hook, Actor: "hook-guardian",
		Details: details, Severity: "HIGH",
		Structured: map[string]any{
			"hook_path": r.Hook, "holder_image": image, "holder_pid": r.Holder.PID, "holder_sid": r.Holder.SID,
			"holder_account": clean(r.Account), "holder_session": r.Holder.Session, "granted_access": fmt.Sprintf("0x%08x", r.Access),
			"handle_value": uint64(r.Handle), "wow64": r.Holder.Wow64, "closed": r.Closed, "not_closed_reason": clean(r.Reason),
			"streak_closes": r.Streak, "scan_ms": r.ScanMS, "handles_listed": r.Listed, "handles_inspected": r.Probed,
			"candidate_handles": r.Counts.Handles, "candidate_processes": r.Counts.Processes, "candidate_file_objects": r.Counts.Objects,
			"handles_closed_in_pass": r.Counts.Closed,
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
	var delivered uint64
	var failure error
	for _, row := range pending {
		if failure = windowsHolderAuditPost(row); failure != nil {
			break
		}
		delivered = row.Seq
	}
	windowsHolderOutMu.Lock()
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
