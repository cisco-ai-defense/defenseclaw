//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// GAP-0755: the bounds of the guardian's handle close, tested with an
// injected handle table and injected process facts. The syscall layer is
// tested natively (TestKeepWindowsManagedFileCopyEndsAnExclusiveHoldOf...).

const (
	fakeFileTypeIndex = 37
	fakeUserSID       = "S-1-5-21-1111-2222-3333-1001"
	fakeOtherUserSID  = "S-1-5-21-1111-2222-3333-1002"
)

type fakeHolderHandle struct {
	value      uintptr
	access     uint32
	id         windowsHookHolderIdentity
	disk       bool
	notFile    bool // its object type is not File: the scan must not touch it
	denyDelete bool // this is the handle that refuses every start
	// allowsStart: the handle denies deletion but a start of the hook works
	// (it shares reading); only with denyDelete.
	allowsStart bool
	// closeFails: the close is made and its last call reports a failure.
	closeFails bool
	block      chan struct{} // Identify does not answer until it is closed (a synchronous pipe)
	closeBlock chan struct{} // CloseIf does not answer until it is closed (the value became a blocked pipe)
	// commitFirst makes CloseIf tell the caller the close has begun before
	// it blocks on closeBlock: DuplicateHandle itself is slow, past the last
	// check, so the close happens even if the guardian gives up on it.
	commitFirst bool
	reuse       bool // the value names something else by the time of the close
	// wrongObject: the close is made and the handle turns out not to be the hook's.
	wrongObject bool
	closed      bool
	object      uintptr // the file object address the handle table shows
	// rotateTo is the handle the owner swaps this one for just before the
	// close: the old value is gone when the guardian tries it.
	rotateTo *fakeHolderHandle
}

type fakeHolderProcess struct {
	system   *fakeHolderSystem
	facts    windowsHolderProcess
	handles  []*fakeHolderHandle
	openErr  error
	closeLog []uintptr
	// attributes are the handle-table attributes of every handle it holds.
	attributes uint32
	released   atomic.Int32
}

func (p *fakeHolderProcess) Facts() windowsHolderProcess { return p.facts }

func (p *fakeHolderProcess) find(handle uintptr) *fakeHolderHandle {
	for _, h := range p.handles {
		if h.value == handle && !h.closed {
			return h
		}
	}
	return nil
}

func (p *fakeHolderProcess) Identify(handle uintptr) (windowsHookHolderIdentity, bool, error) {
	h := p.find(handle)
	if h == nil {
		return windowsHookHolderIdentity{}, false, errors.New("no such handle")
	}
	if h.notFile {
		p.system.t.Errorf("process %d: a handle whose object type is not File was probed", p.facts.PID)
	}
	if h.block != nil {
		<-h.block
	}
	return h.id, h.disk, nil
}

func (p *fakeHolderProcess) CloseIf(handle uintptr, want windowsHookHolderIdentity, commit func() bool) error {
	h := p.find(handle)
	if h != nil && h.closeBlock != nil && !h.commitFirst {
		<-h.closeBlock // the fresh check hangs: nothing has begun
	}
	if !commit() {
		return errWindowsHolderTimedOut
	}
	if h != nil && h.closeBlock != nil && h.commitFirst {
		<-h.closeBlock // DuplicateHandle hangs after the close began
	}
	if h != nil && h.wrongObject {
		h.closed = true
		return errWindowsHolderWrongObject
	}
	if h != nil && h.closeFails {
		h.closed = true
		return fmt.Errorf("%w (%v)", errWindowsHolderCloseFailed, errors.New("access denied"))
	}
	if h != nil && h.rotateTo != nil {
		h.closed = true
		p.handles = append(p.handles, h.rotateTo)
		return errWindowsHolderChanged
	}
	if h == nil || h.reuse || !h.disk || h.id != want {
		return errWindowsHolderChanged
	}
	h.closed = true
	p.closeLog = append(p.closeLog, handle)
	return nil
}

func (p *fakeHolderProcess) Release() { p.released.Add(1) }

type fakeHolderSystem struct {
	t         *testing.T
	hook      windowsHookHolderIdentity
	procs     map[uint32]*fakeHolderProcess
	unlisted  bool // the system does not list the processes using the file
	snapshots int
	snapErr   error
}

func (s *fakeHolderSystem) add(pid uint32, sid string, session uint32, handles ...*fakeHolderHandle) *fakeHolderProcess {
	p := &fakeHolderProcess{system: s, handles: handles, facts: windowsHolderProcess{
		PID: pid, Started: uint64(pid) * 1000, Image: fmt.Sprintf(`C:\Tools\holder%d.exe`, pid), SID: sid, Session: session}}
	s.procs[pid] = p
	return p
}

func (s *fakeHolderSystem) Snapshot(string) (windowsHolderSnapshot, error) {
	s.snapshots++
	if s.snapErr != nil {
		return windowsHolderSnapshot{}, s.snapErr
	}
	snapshot := windowsHolderSnapshot{Identity: s.hook, FileType: fakeFileTypeIndex, PIDsKnown: !s.unlisted, Release: func() {}}
	for pid, p := range s.procs {
		listed := false
		for _, h := range p.handles {
			if h.closed {
				continue
			}
			index := uint16(fakeFileTypeIndex)
			if h.notFile {
				index = 12
			}
			snapshot.Entries = append(snapshot.Entries, windowsHandleEntryEx{Object: h.object, UniqueProcessID: uintptr(pid), HandleValue: h.value, GrantedAccess: h.access, ObjectTypeIndex: index, HandleAttributes: p.attributes})
			listed = listed || h.id == s.hook
		}
		if listed || p.openErr != nil {
			snapshot.PIDs = append(snapshot.PIDs, pid)
		}
	}
	return snapshot, nil
}

func (s *fakeHolderSystem) OpenProcess(pid uint32) (windowsHolderProc, error) {
	p := s.procs[pid]
	if p == nil {
		return nil, errors.New("no such process")
	}
	if p.openErr != nil {
		return nil, p.openErr
	}
	return p, nil
}

// culprit is a read handle on the hook that allows no deletion.
func (s *fakeHolderSystem) culprit(value uintptr) *fakeHolderHandle {
	return &fakeHolderHandle{value: value, access: 0x120089, id: s.hook, disk: true, denyDelete: true}
}

// sharing is a read handle on the hook that shares deletion: it blocks nothing.
func (s *fakeHolderSystem) sharing(value uintptr) *fakeHolderHandle {
	return &fakeHolderHandle{value: value, access: 0x120089, id: s.hook, disk: true}
}

func (s *fakeHolderSystem) other(value uintptr) *fakeHolderHandle {
	return &fakeHolderHandle{value: value, access: 0x120089, id: windowsHookHolderIdentity{volume: 9, id: [16]byte{9}}, disk: true}
}

func (s *fakeHolderSystem) blocked() bool {
	for _, p := range s.procs {
		for _, h := range p.handles {
			if h.denyDelete && !h.closed {
				return true
			}
		}
	}
	return false
}

// startRefused is whether a start-style open of the hook is refused: a handle
// that denies deletion and does not allow reading to be shared.
func (s *fakeHolderSystem) startRefused() bool {
	for _, p := range s.procs {
		for _, h := range p.handles {
			if h.denyDelete && !h.allowsStart && !h.closed {
				return true
			}
		}
	}
	return false
}

// fakeWriteAccess is a read handle that can also write and append.
const fakeWriteAccess = 0x12008f

type holdRig struct {
	t       *testing.T
	sys     *fakeHolderSystem
	advance func(time.Duration)
	posted  []windowsHolderAuditRow
	target  string
	log     strings.Builder
}

func newHoldRig(t *testing.T) *holdRig {
	t.Helper()
	resetWindowsHeldSwapsForTest(t)
	rig := &holdRig{t: t, target: `C:\ProgramData\DefenseClaw\bin\defenseclaw-hook.exe`}
	rig.advance = fakeWindowsHeldSwapClock(t)
	rig.sys = &fakeHolderSystem{t: t, hook: windowsHookHolderIdentity{volume: 7, id: [16]byte{1, 2, 3}}, procs: map[uint32]*fakeHolderProcess{}}
	savedStandalone, savedSys, savedBlocked, savedPost, savedName := windowsHolderStandalone, windowsHolderSys, windowsHookBinaryDeleteBlocked, windowsHolderAuditPost, windowsHolderUserName
	savedOpenRefused, savedKeep := windowsHookBinaryOpenRefused, windowsHookBinaryKeep
	savedDataRead, savedDataDelete, savedDataDir := windowsHookDataReadRefused, windowsHookDataDeleteBlocked, windowsHookRuntimeDir
	savedTimeout, savedHung, savedProbes, savedWrite, savedCommit := windowsHolderProbeTimeout, windowsHolderMaxHung, windowsHolderMaxProbes, windowsHolderAuditWrite, windowsHolderCommitWait
	windowsHolderStandalone = func() bool { return true }
	windowsHolderSys = rig.sys
	windowsHookBinaryDeleteBlocked = func(string) bool { return rig.sys.blocked() }
	windowsHookBinaryOpenRefused = func(string) bool { return rig.sys.startRefused() }
	// The guardian's wrapper runs a hold pass of the test's own in place of
	// the check under the mutex; the wrapper itself is the real one.
	windowsHookBinaryKeep = func(stderr io.Writer, _ bool) { writeWindowsHolderLog(stderr) }
	windowsHolderAuditPost = func(row windowsHolderAuditRow) error { rig.posted = append(rig.posted, row); return nil }
	windowsHolderUserName = func(sid string) string { return `HOST\user-` + sid[len(sid)-4:] }
	resetWindowsHolderOutputForTest()
	t.Cleanup(func() {
		windowsHolderStandalone, windowsHolderSys, windowsHookBinaryDeleteBlocked, windowsHolderAuditPost, windowsHolderUserName = savedStandalone, savedSys, savedBlocked, savedPost, savedName
		windowsHookBinaryOpenRefused, windowsHookBinaryKeep = savedOpenRefused, savedKeep
		windowsHookDataReadRefused, windowsHookDataDeleteBlocked, windowsHookRuntimeDir = savedDataRead, savedDataDelete, savedDataDir
		windowsHolderProbeTimeout, windowsHolderMaxHung, windowsHolderMaxProbes, windowsHolderAuditWrite, windowsHolderCommitWait = savedTimeout, savedHung, savedProbes, savedWrite, savedCommit
		resetWindowsHolderOutputForTest()
	})
	return rig
}

// resetWindowsHolderOutputForTest forgets the hold, the log lines and the
// audit queue (and the file they are kept in).
func resetWindowsHolderOutputForTest() {
	windowsHolderOutMu.Lock()
	defer windowsHolderOutMu.Unlock()
	windowsHolderGate, windowsHolderLog, windowsHolderAuditQueue = windowsHolderState{}, nil, nil
	windowsHolderAuditSeq, windowsHolderAuditPath, windowsHolderAuditLoaded = 0, "", false
	windowsHolderAuditLastErr, windowsHolderAuditFails, windowsHolderAuditNext, windowsHolderAuditSaveErr = "", 0, time.Time{}, ""
	windowsHolderNames.Clear()
	windowsHolderDataGates, windowsHolderDataLast, windowsHolderDataCursor = map[string]*windowsHolderState{}, map[string]string{}, 0
}

// reportWindowsHookHolders is what the guardian does after a check: the log
// lines under the guardian's mutex, the audit rows after it.
func reportWindowsHookHolders(stderr io.Writer) {
	writeWindowsHolderLog(stderr)
	flushWindowsHolderAudit(stderr)
}

// check is one guardian check of a held hook, followed by the guardian's report.
func (r *holdRig) check() (int, error) {
	r.t.Helper()
	closed, err := endWindowsExclusiveHold(r.target)
	keepWindowsStandaloneHookBinary(&r.log, false)
	return closed, err
}

// tick moves one guardian interval on and checks.
func (r *holdRig) tick() (int, error) {
	r.advance(windowsHookBinaryCheckInterval)
	return r.check()
}

func TestWindowsHolderOneTickIsNotClosed(t *testing.T) {
	rig := newHoldRig(t)
	holder := rig.sys.culprit(0x44)
	proc := rig.sys.add(4100, fakeUserSID, 2, holder)
	if closed, err := rig.check(); closed != 0 || err != nil {
		t.Fatalf("first sight: closed %d, %v", closed, err)
	}
	// More checks inside the same tick (the guardian also checks before each
	// reconcile) do not make a second tick.
	rig.advance(500 * time.Millisecond)
	if closed, err := rig.check(); closed != 0 || err != nil {
		t.Fatalf("0.5 s later: closed %d, %v", closed, err)
	}
	if len(proc.closeLog) != 0 || holder.closed || len(rig.posted) != 0 {
		t.Fatalf("a hold seen once was acted on: closes %v, rows %d", proc.closeLog, len(rig.posted))
	}
}

func TestWindowsHolderTwoTickHoldIsClosedAndAudited(t *testing.T) {
	rig := newHoldRig(t)
	holder := rig.sys.culprit(0x44)
	proc := rig.sys.add(4100, fakeUserSID, 2, holder, rig.sys.other(0x48))
	if closed, err := rig.check(); closed != 0 || err != nil {
		t.Fatalf("tick 1: closed %d, %v", closed, err)
	}
	closed, err := rig.tick()
	if closed != 1 || err != nil || !holder.closed || len(proc.closeLog) != 1 {
		t.Fatalf("tick 2: closed %d, %v, closes %v", closed, err, proc.closeLog)
	}
	if proc.handles[1].closed {
		t.Fatal("a handle on a different file in the same process was closed")
	}
	if len(rig.posted) != 1 {
		t.Fatalf("audit rows %d, want 1", len(rig.posted))
	}
	event := rig.posted[0].event()
	if event.Action != string(audit.ActionConnectorHookTampered) || event.Severity != "HIGH" || event.Target != rig.target {
		t.Fatalf("event %+v", event)
	}
	for key, want := range map[string]any{
		"holder_image": `C:\Tools\holder4100.exe`, "holder_pid": uint32(4100), "holder_sid": fakeUserSID, "holder_session": uint32(2),
		"granted_access": "0x00120089", "hook_path": rig.target, "closed": true, "holder_account": `HOST\user-1001 ` + fakeUserSID,
	} {
		if event.Structured[key] != want {
			t.Errorf("structured %s = %v, want %v", key, event.Structured[key], want)
		}
	}
	for _, want := range []string{`C:\Tools\holder4100.exe`, "process id 4100", "account HOST", "session 2", "closed that handle", "was not changed"} {
		if !strings.Contains(event.Details, want) {
			t.Errorf("details %q miss %q", event.Details, want)
		}
	}
	if !strings.Contains(rig.log.String(), "tamper: closed the handle") || strings.Count(rig.log.String(), "[hook-guardian]") != 1 {
		t.Fatalf("guardian log %q", rig.log.String())
	}
}

// A brief exclusive read (a scanner, a backup) is gone at the second check,
// or is another handle: neither is closed.
func TestWindowsHolderTransientHoldsAreNotClosed(t *testing.T) {
	rig := newHoldRig(t)
	first := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, first)
	if _, err := rig.check(); err != nil {
		t.Fatal(err)
	}
	// The check in between found the hook free.
	windowsHolderGate.free()
	if closed, err := rig.tick(); closed != 0 || err != nil || first.closed {
		t.Fatalf("hold that returned after a free check: closed %d, %v", closed, err)
	}
	// A holder of another user at the next tick: not the same hold.
	first.closed = true
	second := rig.sys.culprit(0x50)
	rig.sys.add(4200, fakeOtherUserSID, 2, second)
	if closed, err := rig.tick(); closed != 0 || err != nil || second.closed {
		t.Fatalf("another user's holder at the second tick: closed %d, %v", closed, err)
	}
	// The same user in another session is another hold as well.
	second.closed = true
	third := rig.sys.culprit(0x58)
	rig.sys.add(4300, fakeOtherUserSID, 3, third)
	if closed, err := rig.tick(); closed != 0 || err != nil || third.closed {
		t.Fatalf("the same user in another session: closed %d, %v", closed, err)
	}
	if len(rig.posted) != 0 {
		t.Fatalf("rows for holds that were never closed: %d", len(rig.posted))
	}
}

// S1. Bound (a): at the second check only the same program counts (the same
// process, or the same file object); a different process of the same user
// needs a third check. A user who hands the open file to a new process
// before each check does not escape, and a brief hold is still never closed.
func TestWindowsHolderAnotherProcessOfTheSameUserIsClosedAtTheThirdCheck(t *testing.T) {
	rig := newHoldRig(t)
	first := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, first)
	if closed, err := rig.check(); closed != 0 || err != nil {
		t.Fatalf("first sight: %d, %v", closed, err)
	}
	// The file is handed to another process (a new id, a new handle value, a
	// new file object) and the old handle is closed, so the hook is never free.
	first.closed = true
	second := rig.sys.culprit(0x78)
	second.object = 0x2000
	rig.sys.add(4200, fakeUserSID, 2, second)
	if closed, err := rig.tick(); closed != 0 || err != nil || second.closed {
		t.Fatalf("a different process of the same user was closed at the second check: %d, %v", closed, err)
	}
	if closed, err := rig.tick(); closed != 1 || err != nil || !second.closed {
		t.Fatalf("the third check: %d, %v", closed, err)
	}
	if len(rig.posted) != 1 || rig.posted[0].Holder.PID != 4200 {
		t.Fatalf("rows %+v, want one row for the process that held it when it was closed", rig.posted)
	}
}

// The same process with another handle (a DuplicateHandle, a new open) is the
// same program: closed at the second check.
func TestWindowsHolderTheSameProcessWithAnotherHandleIsClosedAtTheSecondCheck(t *testing.T) {
	rig := newHoldRig(t)
	first := rig.sys.culprit(0x44)
	proc := rig.sys.add(4100, fakeUserSID, 2, first)
	_, _ = rig.check()
	first.closed = true
	second := rig.sys.culprit(0x78)
	proc.handles = append(proc.handles, second)
	if closed, err := rig.tick(); closed != 1 || err != nil || !second.closed {
		t.Fatalf("the second check: %d, %v", closed, err)
	}
}

// The same file object in another process (an inherited or duplicated handle)
// is the same hold too.
func TestWindowsHolderTheSameFileObjectInAnotherProcessIsClosedAtTheSecondCheck(t *testing.T) {
	rig := newHoldRig(t)
	first := rig.sys.culprit(0x44)
	first.object = 0xfffff800a0
	rig.sys.add(4100, fakeUserSID, 2, first)
	_, _ = rig.check()
	first.closed = true
	second := rig.sys.culprit(0x78)
	second.object = 0xfffff800a0
	rig.sys.add(4200, fakeUserSID, 2, second)
	if closed, err := rig.tick(); closed != 1 || err != nil || !second.closed {
		t.Fatalf("the second check: %d, %v", closed, err)
	}
}

// A process that ended and a new one that got its id and its handle value, for
// the same user, is a different program (the creation time says so): it takes
// a third check, and the audit row has the new process's creation time.
func TestWindowsHolderReusedProcessIdOfTheSameUserIsClosedAtTheThirdCheck(t *testing.T) {
	rig := newHoldRig(t)
	rig.sys.add(4100, fakeUserSID, 2, rig.sys.culprit(0x44))
	if _, err := rig.check(); err != nil {
		t.Fatal(err)
	}
	replacement := rig.sys.add(4100, fakeUserSID, 2, rig.sys.culprit(0x44))
	replacement.facts.Started += 777
	if closed, err := rig.tick(); closed != 0 || err != nil {
		t.Fatalf("the replacement process at the second check: %d, %v", closed, err)
	}
	if closed, err := rig.tick(); closed != 1 || err != nil {
		t.Fatalf("the replacement process at the third check: %d, %v", closed, err)
	}
	if len(rig.posted) != 1 || rig.posted[0].Holder.Started != replacement.facts.Started {
		t.Fatalf("rows %+v", rig.posted)
	}
}

// Another file at the second check (the hook was replaced) starts over.
func TestWindowsHolderAnotherFileObjectStartsTheTwoChecksAgain(t *testing.T) {
	rig := newHoldRig(t)
	holder := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, holder)
	if _, err := rig.check(); err != nil {
		t.Fatal(err)
	}
	rig.sys.hook = windowsHookHolderIdentity{volume: 7, id: [16]byte{9, 9, 9}}
	holder.id = rig.sys.hook
	if closed, err := rig.tick(); closed != 0 || err != nil || holder.closed {
		t.Fatalf("the hook was another file at the second check: %d, %v", closed, err)
	}
	if closed, err := rig.tick(); closed != 1 || err != nil {
		t.Fatalf("third check: %d, %v", closed, err)
	}
}

// Bound (c): the account, the session and the protection of the holder.
func TestWindowsHolderNeverClosesServicesProtectedOrSession0Processes(t *testing.T) {
	cases := []struct {
		name      string
		sid       string
		session   uint32
		protected bool
		factsErr  error
		want      string
	}{
		{"LocalSystem service", "S-1-5-18", 0, false, nil, "LocalSystem"},
		{"LocalSystem in a user session", "S-1-5-18", 2, false, nil, "LocalSystem"},
		{"LocalService", "S-1-5-19", 0, false, nil, "LocalService"},
		{"NetworkService in a user session", "S-1-5-20", 3, false, nil, "NetworkService"},
		{"virtual service account", "S-1-5-80-1-2-3-4-5", 2, false, nil, "service account"},
		{"user in session 0", fakeUserSID, 0, false, nil, "session 0"},
		{"protected process", fakeUserSID, 2, true, nil, "protected process"},
		{"token unreadable", fakeUserSID, 2, false, errors.New("token: access denied"), "could not be read"},
		{"built-in group SID", "S-1-5-32-544", 2, false, nil, "not a local, domain or Entra user"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newHoldRig(t)
			holder := rig.sys.culprit(0x44)
			proc := rig.sys.add(4100, tc.sid, tc.session, holder)
			proc.facts.Protected, proc.facts.FactsErr = tc.protected, tc.factsErr
			if _, err := rig.check(); err != nil {
				t.Fatal(err)
			}
			closed, err := rig.tick()
			if closed != 0 || err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "process id 4100") {
				t.Fatalf("closed %d, err %v", closed, err)
			}
			for i := 0; i < 12; i++ {
				if _, again := rig.tick(); again == nil || again.Error() != err.Error() {
					t.Fatalf("tick %d: %v, want the same named verdict", i, again)
				}
			}
			if len(proc.closeLog) != 0 || holder.closed {
				t.Fatalf("a handle was closed: %v", proc.closeLog)
			}
			if len(rig.posted) != 1 || rig.posted[0].Closed || !strings.Contains(rig.posted[0].event().Details, "did not close it") {
				t.Fatalf("rows %+v, want one row that says nothing was closed", rig.posted)
			}
			if rig.sys.snapshots > 6 {
				t.Fatalf("%d scans in 65 s of a hold that cannot be ended: no backoff", rig.sys.snapshots)
			}
		})
	}
}

func TestWindowsHolderLeavesAHandleItsOwnerProtectedFromClosing(t *testing.T) {
	rig := newHoldRig(t)
	holder := rig.sys.culprit(0x44)
	proc := rig.sys.add(4100, fakeUserSID, 2, holder)
	proc.attributes = windowsObjProtectClose
	_, _ = rig.check()
	closed, err := rig.tick()
	if closed != 0 || err == nil || !strings.Contains(err.Error(), "protected the handle from being closed") || holder.closed {
		t.Fatalf("closed %d, %v", closed, err)
	}
}

// While a service (a refused holder) that could be what refuses
// the start has the hook open, the guardian closes no user's handle at first:
// it names the service, once, and backs off. After about 30 seconds of the
// user's hold it closes that user's handles once in the streak, to rule the
// service out, and says so in the row. It does not do it again in the streak.
func TestWindowsHolderARefusedHolderThatCouldRefuseTheStartKeepsTheGuardianOffUntilTheBoundedOverride(t *testing.T) {
	rig := newHoldRig(t)
	user := rig.sys.sharing(0x44)
	userProc := rig.sys.add(4100, fakeUserSID, 2, user)
	service := rig.sys.culprit(0x90)
	service.access = fakeWriteAccess
	rig.sys.add(700, "S-1-5-18", 0, service)
	if _, err := rig.check(); err != nil {
		t.Fatal(err)
	}
	closed, err := rig.tick()
	if closed != 0 || err == nil || !strings.Contains(err.Error(), "has the hook open and may be what refuses its starts") ||
		!strings.Contains(err.Error(), "closes none of the 1 handle(s) of signed-in users") || !strings.Contains(err.Error(), "after about 30 seconds") {
		t.Fatalf("closed %d, %v", closed, err)
	}
	for i := 0; i < 5; i++ {
		if closed, _ := rig.tick(); closed != 0 {
			t.Fatalf("tick %d closed %d handle(s) while the service has the hook open", i, closed)
		}
	}
	if user.closed || len(userProc.closeLog) != 0 || len(rig.posted) != 1 || rig.posted[0].Closed || rig.posted[0].Holder.PID != 700 || !strings.Contains(rig.posted[0].Reason, "LocalSystem") {
		t.Fatalf("before the override: closes %v, rows %+v, want one row that names the service and says nothing was closed", userProc.closeLog, rig.posted)
	}
	// 35 s into the hold: the bounded override.
	closed, err = rig.tick()
	if closed != 1 || err != nil || !user.closed || service.closed {
		t.Fatalf("override: closed %d, %v (user %v, service %v)", closed, err, user.closed, service.closed)
	}
	if len(rig.posted) != 2 || !rig.posted[1].Closed || rig.posted[1].Holder.PID != 4100 || !strings.Contains(rig.posted[1].Note, "once per streak") ||
		!strings.Contains(rig.posted[1].event().Details, "rule the other holder out") || !strings.Contains(rig.log.String(), "rule the other holder out") {
		t.Fatalf("override rows %+v, log %q", rig.posted, rig.log.String())
	}
	// Once per streak: another user handle is not closed while the service stays.
	again := rig.sys.sharing(0x50)
	rig.sys.add(4300, fakeUserSID, 2, again)
	for i := 0; i < 8; i++ {
		rig.advance(windowsHeldSwapBackoffBase)
		if closed, _ := rig.tick(); closed != 0 {
			t.Fatalf("second override in the streak (tick %d)", i)
		}
	}
	if _, err := rig.check(); again.closed || err == nil || !strings.Contains(err.Error(), "already closed one user's handles once in this streak") {
		t.Fatalf("second handle %v, %v", again.closed, err)
	}
	// Once the service has let go the user's handle is the one that refuses.
	service.closed = true
	again.denyDelete = true
	rig.advance(6 * time.Minute) // past every backoff
	for i := 0; i < 6 && !again.closed; i++ {
		if _, err := rig.tick(); err != nil {
			t.Fatalf("after the service let go: %v", err)
		}
	}
	if !again.closed {
		t.Fatal("the user's handle was not closed after the service let go")
	}
}

// The sharper rule. A start needs read and execute and shares
// read and delete, so a holder that only reads, beside another file object,
// cannot be what refuses it: it is named and the user's blocker is closed.
func TestWindowsHolderAReadOnlyRefusedHolderBesideAnotherObjectDoesNotKeepAUsersBlockerOpen(t *testing.T) {
	rig := newHoldRig(t)
	service := rig.sys.culprit(0x90)
	service.object, service.allowsStart = 100, true // read only, denies deletion, a start works
	rig.sys.add(700, "S-1-5-18", 0, service)
	user := rig.sys.culprit(0x44)
	user.object, user.access = 200, fakeWriteAccess // an admin process that reads and writes
	userProc := rig.sys.add(4100, fakeUserSID, 2, user)
	if _, err := rig.check(); err != nil {
		t.Fatal(err)
	}
	closed, err := rig.tick()
	if closed != 1 || err != nil || !user.closed || service.closed || len(userProc.closeLog) != 1 {
		t.Fatalf("closed %d, %v (user %v, service %v)", closed, err, user.closed, service.closed)
	}
	if len(rig.posted) != 2 {
		t.Fatalf("rows %+v, want one for the service and one for the closed handle", rig.posted)
	}
	byPID := map[uint32]windowsHolderAuditRow{}
	for _, row := range rig.posted {
		byPID[row.Holder.PID] = row
	}
	if row := byPID[4100]; !row.Closed || row.Counts.Closed != 1 {
		t.Fatalf("the closed handle's row %+v", row)
	}
	if row := byPID[700]; row.Closed || !strings.Contains(row.Reason, "LocalSystem") {
		t.Fatalf("the service's row %+v, want closed=false", row)
	}
	if !strings.Contains(rig.log.String(), "cannot be what refuses a start") {
		t.Fatalf("log %q", rig.log.String())
	}
}

// The same service, able to write, can refuse the start: it keeps the guardian
// off. So does a read-only service that is the only file object on the hook,
// and a handle on a file object the system did not show (it may be anything).
func TestWindowsHolderARefusedHolderThatCanRefuseTheStartStillBlocksTheClose(t *testing.T) {
	cases := []struct {
		name       string
		serviceObj uintptr
		serviceAcc uint32
		userObj    uintptr
	}{
		{"it can write", 100, fakeWriteAccess, 200},
		{"the only object", 100, 0x120089, 100},
		{"objects the system did not show, and it can write", 0, fakeWriteAccess, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newHoldRig(t)
			service := rig.sys.culprit(0x90)
			service.object, service.access = tc.serviceObj, tc.serviceAcc
			rig.sys.add(700, "S-1-5-18", 0, service)
			user := rig.sys.sharing(0x44)
			user.object = tc.userObj
			rig.sys.add(4100, fakeUserSID, 2, user)
			_, _ = rig.check()
			for i := 0; i < 4; i++ {
				if closed, _ := rig.tick(); closed != 0 || user.closed {
					t.Fatalf("tick %d: closed %d", i, closed)
				}
			}
			if len(rig.posted) != 1 || rig.posted[0].Closed {
				t.Fatalf("rows %+v", rig.posted)
			}
		})
	}
}

// The guardian service gets no file object addresses on Windows Server 2025:
// every handle then counts as an object of its own, so a read-only service
// handle beside a user's blocker is exonerated and the blocker is closed.
func TestWindowsHolderHandlesWithoutAnObjectAddressAreObjectsOfTheirOwn(t *testing.T) {
	rig := newHoldRig(t)
	service := rig.sys.culprit(0x90)
	service.allowsStart = true // object 0, read only
	rig.sys.add(700, "S-1-5-18", 0, service)
	user := rig.sys.culprit(0x44)
	user.access = fakeWriteAccess // object 0
	rig.sys.add(4100, fakeUserSID, 2, user)
	_, _ = rig.check()
	if closed, err := rig.tick(); closed != 1 || err != nil || !user.closed || service.closed {
		t.Fatalf("closed %d, %v (user %v)", closed, err, user.closed)
	}
}

// Regression: a user's own handle that its owner protected
// from closing is skipped and named; the others are still closed.
func TestWindowsHolderAUsersProtectedHandleIsSkippedAndTheOthersAreStillClosed(t *testing.T) {
	rig := newHoldRig(t)
	decoy := rig.sys.sharing(0x44)
	decoyProc := rig.sys.add(4100, fakeUserSID, 2, decoy)
	decoyProc.attributes = windowsObjProtectClose
	culprit := rig.sys.culprit(0x50)
	culpritProc := rig.sys.add(4200, fakeUserSID, 2, culprit)
	_, _ = rig.check()
	closed, err := rig.tick()
	if closed != 1 || err != nil || !culprit.closed || decoy.closed || len(decoyProc.closeLog) != 0 || len(culpritProc.closeLog) != 1 {
		t.Fatalf("closed %d, %v (culprit %v, decoy %v)", closed, err, culprit.closed, decoy.closed)
	}
	if len(rig.posted) != 2 {
		t.Fatalf("rows %+v", rig.posted)
	}
	for _, row := range rig.posted {
		if row.Holder.PID == 4100 && (row.Closed || !strings.Contains(row.Reason, "protected the handle from being closed")) {
			t.Fatalf("the protected handle's row %+v", row)
		}
	}
}

// A handle that only denies deletion is not closed
// once a start works.
func TestWindowsHolderStopsClosingOnceAStartWorks(t *testing.T) {
	rig := newHoldRig(t)
	refuses := rig.sys.culprit(0x44)
	deletionOnly := rig.sys.culprit(0x48)
	deletionOnly.allowsStart = true
	rig.sys.add(4100, fakeUserSID, 2, refuses, deletionOnly)
	_, _ = rig.check()
	closed, err := rig.tick()
	if closed != 1 || err != nil || !refuses.closed || deletionOnly.closed {
		t.Fatalf("closed %d, %v (refuses %v, deletion only %v)", closed, err, refuses.closed, deletionOnly.closed)
	}
}

// A service's handle seen for the first time is waited for, not acted on and
// not audited: the user's handle is closed at the next check if it has gone.
func TestWindowsHolderAServiceHandleSeenOnceIsWaitedFor(t *testing.T) {
	rig := newHoldRig(t)
	user := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, user)
	_, _ = rig.check()
	service := rig.sys.sharing(0x90)
	service.access = fakeWriteAccess
	rig.sys.add(700, "S-1-5-18", 0, service)
	if closed, err := rig.tick(); closed != 0 || err != nil || user.closed || len(rig.posted) != 0 {
		t.Fatalf("a service's first sight: closed %d, %v, rows %d", closed, err, len(rig.posted))
	}
	service.closed = true
	if closed, err := rig.tick(); closed != 1 || err != nil || !user.closed {
		t.Fatalf("after the service had gone: closed %d, %v", closed, err)
	}
}

// One user at a time: the user whose hold began first. A second user's handle
// is closed only if the first user's did not free the hook.
func TestWindowsHolderClosesOneUsersHandlesBeforeAnothers(t *testing.T) {
	t.Run("the first user's handle is the blocker", func(t *testing.T) {
		rig := newHoldRig(t)
		a, b := rig.sys.culprit(0x44), rig.sys.sharing(0x50)
		rig.sys.add(4100, fakeUserSID, 2, a)
		rig.sys.add(4200, fakeOtherUserSID, 2, b)
		_, _ = rig.check()
		if closed, err := rig.tick(); closed != 1 || err != nil || !a.closed || b.closed {
			t.Fatalf("closed %d, %v: a %v, b %v", closed, err, a.closed, b.closed)
		}
	})
	t.Run("the second user's handle is the blocker", func(t *testing.T) {
		rig := newHoldRig(t)
		a, b := rig.sys.sharing(0x44), rig.sys.culprit(0x50)
		rig.sys.add(4100, fakeUserSID, 2, a)
		rig.sys.add(4200, fakeOtherUserSID, 2, b)
		_, _ = rig.check()
		if closed, err := rig.tick(); closed != 2 || err != nil || !a.closed || !b.closed {
			t.Fatalf("closed %d, %v: a %v, b %v", closed, err, a.closed, b.closed)
		}
	})
}

// With only refused holders nothing is closed, and the verdict says what was
// seen, not how the handle was opened.
func TestWindowsHolderOnlyRefusedHoldersCloseNothingAndTheWordsSayWhatWasSeen(t *testing.T) {
	rig := newHoldRig(t)
	rig.sys.add(700, "S-1-5-18", 0, rig.sys.sharing(0x90))
	rig.sys.add(800, "S-1-5-19", 0, rig.sys.culprit(0x94))
	_, _ = rig.check()
	closed, err := rig.tick()
	if closed != 0 || err == nil || !strings.Contains(err.Error(), "has the hook open and may be what refuses its starts") || !strings.Contains(err.Error(), "and 1 more") {
		t.Fatalf("closed %d, %v", closed, err)
	}
	for _, text := range []string{err.Error(), rig.posted[0].event().Details} {
		if strings.Contains(text, "no sharing") || strings.Contains(text, "allows no deletion") {
			t.Fatalf("%q claims a sharing mode the guardian cannot read", text)
		}
	}
	if details := rig.posted[0].event().Details; !strings.Contains(details, "A start of the hook was refused, and so was a test open of it for deletion.") {
		t.Fatalf("details %q", details)
	}
}

func TestWindowsHolderNamesAProtectedProcessItCannotInspect(t *testing.T) {
	rig := newHoldRig(t)
	user := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, user)
	protected := rig.sys.add(4200, "S-1-5-18", 0, rig.sys.other(0x10))
	protected.openErr = windows.ERROR_ACCESS_DENIED
	if _, err := rig.check(); err != nil {
		t.Fatal(err)
	}
	closed, err := rig.tick()
	if closed != 0 || err == nil || !strings.Contains(err.Error(), "process id 4200") || !strings.Contains(err.Error(), "cannot inspect") || user.closed {
		t.Fatalf("closed %d, %v", closed, err)
	}
	// Without the system's list of the processes that use the file nothing
	// says the protected process matters.
	rig2 := newHoldRig(t)
	rig2.sys.unlisted = true
	user2 := rig2.sys.culprit(0x44)
	rig2.sys.add(4100, fakeUserSID, 2, user2)
	rig2.sys.add(4200, "S-1-5-18", 0, rig2.sys.other(0x10)).openErr = windows.ERROR_ACCESS_DENIED
	if _, err := rig2.check(); err != nil {
		t.Fatal(err)
	}
	if closed, err := rig2.tick(); closed != 1 || err != nil || !user2.closed {
		t.Fatalf("unlisted: closed %d, %v", closed, err)
	}
	// S7. A process that ended between the snapshot and the open is gone, not
	// protected: it does not stop the close.
	rig3 := newHoldRig(t)
	user3 := rig3.sys.culprit(0x44)
	rig3.sys.add(4100, fakeUserSID, 2, user3)
	rig3.sys.add(4200, fakeUserSID, 2, rig3.sys.other(0x10)).openErr = fmt.Errorf("the process had ended: %w", windows.ERROR_INVALID_PARAMETER)
	if _, err := rig3.check(); err != nil {
		t.Fatal(err)
	}
	if closed, err := rig3.tick(); closed != 1 || err != nil || !user3.closed {
		t.Fatalf("a process that ended after the snapshot: closed %d, %v", closed, err)
	}
}

func TestWindowsHolderIdentityMismatchIsNotClosed(t *testing.T) {
	t.Run("a handle on another file", func(t *testing.T) {
		rig := newHoldRig(t)
		proc := rig.sys.add(4100, fakeUserSID, 2, rig.sys.other(0x44))
		proc.handles[0].denyDelete = true
		if _, err := rig.check(); err != nil {
			t.Fatal(err)
		}
		closed, err := rig.tick()
		if closed != 0 || err == nil || !strings.Contains(err.Error(), "found no handle of a user process") || len(proc.closeLog) != 0 {
			t.Fatalf("closed %d, %v", closed, err)
		}
	})
	t.Run("not a disk file", func(t *testing.T) {
		rig := newHoldRig(t)
		pipe := rig.sys.culprit(0x44)
		pipe.disk = false
		rig.sys.add(4100, fakeUserSID, 2, pipe)
		_, _ = rig.check()
		if closed, err := rig.tick(); closed != 0 || err == nil || pipe.closed {
			t.Fatalf("closed %d, %v", closed, err)
		}
	})
	t.Run("the handle value was reused before the close", func(t *testing.T) {
		rig := newHoldRig(t)
		holder := rig.sys.culprit(0x44)
		holder.reuse = true
		proc := rig.sys.add(4100, fakeUserSID, 2, holder)
		_, _ = rig.check()
		closed, err := rig.tick()
		if closed != 0 || err == nil || !strings.Contains(err.Error(), "no longer names the hook") || len(proc.closeLog) != 0 || len(rig.posted) != 0 {
			t.Fatalf("closed %d, %v, rows %d", closed, err, len(rig.posted))
		}
	})
}

// Bound (f): a holder that takes the handle again is closed again after the
// backoff, one row per holder per streak, never a tight loop.
func TestWindowsHolderBacksOffWhenTheHolderTakesTheHandleAgain(t *testing.T) {
	rig := newHoldRig(t)
	next := uintptr(0x44)
	proc := rig.sys.add(4100, fakeUserSID, 2, rig.sys.culprit(next))
	var closes []time.Duration
	elapsed := time.Duration(0)
	for elapsed < 130*time.Second {
		rig.advance(time.Second)
		elapsed += time.Second
		closed, err := rig.check()
		if err != nil {
			t.Fatalf("at %s: %v", elapsed, err)
		}
		if closed > 0 {
			closes = append(closes, elapsed)
			next += 4
			proc.handles = append(proc.handles, rig.sys.culprit(next)) // the same process opens it again at once
		}
	}
	if len(closes) != 4 {
		t.Fatalf("closes at %v, want 4 in 130 s", closes)
	}
	for i := 1; i < len(closes); i++ {
		if gap := closes[i] - closes[i-1]; gap < windowsHeldSwapDelay(i) {
			t.Fatalf("close %d came %s after the one before, backoff is %s", i+1, gap, windowsHeldSwapDelay(i))
		}
	}
	if len(rig.posted) != 1 {
		t.Fatalf("%d audit rows for one holder in one streak, want 1", len(rig.posted))
	}
	if rig.sys.snapshots > 30 {
		t.Fatalf("%d scans in 130 s of 1 s checks", rig.sys.snapshots)
	}
	if !strings.Contains(rig.log.String(), "closed again no sooner than") {
		t.Fatalf("no backoff notice in %q", rig.log.String())
	}
	// A different process in the same streak is a second finding.
	other := rig.sys.culprit(0x90)
	rig.sys.add(4300, fakeUserSID, 2, other)
	for i := 0; i < 90 && !other.closed; i++ {
		rig.advance(time.Second)
		if _, err := rig.check(); err != nil {
			t.Fatal(err)
		}
	}
	if !other.closed || len(rig.posted) != 2 || rig.posted[1].Holder.PID != 4300 {
		t.Fatalf("second holder closed %v, rows %d", other.closed, len(rig.posted))
	}
	// Ten quiet minutes end the streak; the same process then gets a new row.
	for _, p := range rig.sys.procs {
		for _, h := range p.handles {
			h.closed = true
		}
	}
	windowsHolderGate.free()
	rig.advance(11 * time.Minute)
	again := rig.sys.culprit(0xA0)
	proc.handles = append(proc.handles, again)
	_, _ = rig.check()
	if closed, err := rig.tick(); closed != 1 || err != nil || len(rig.posted) != 3 || rig.posted[2].Holder.PID != 4100 {
		t.Fatalf("new streak: closed %d, %v, rows %d", closed, err, len(rig.posted))
	}
}

// The handle table does not show a handle's share mode, so the guardian
// closes one handle, asks again, and stops when the hook is clear.
func TestWindowsHolderStopsAtTheHandleThatBlocks(t *testing.T) {
	t.Run("the blocking handle comes first", func(t *testing.T) {
		rig := newHoldRig(t)
		a, b, c := rig.sys.culprit(0x40), rig.sys.sharing(0x44), rig.sys.sharing(0x48)
		rig.sys.add(4100, fakeUserSID, 2, a, b, c)
		_, _ = rig.check()
		if closed, err := rig.tick(); closed != 1 || err != nil || !a.closed || b.closed || c.closed {
			t.Fatalf("closed %d, %v: a %v b %v c %v", closed, err, a.closed, b.closed, c.closed)
		}
	})
	t.Run("a handle that shares deletion comes first", func(t *testing.T) {
		rig := newHoldRig(t)
		a, b, c := rig.sys.sharing(0x40), rig.sys.culprit(0x44), rig.sys.sharing(0x48)
		rig.sys.add(4100, fakeUserSID, 2, a, b, c)
		_, _ = rig.check()
		closed, err := rig.tick()
		// The share mode of one handle cannot be read, so the first handle is
		// closed before the guardian learns it blocked nothing. The third is
		// not touched.
		if closed != 2 || err != nil || !a.closed || !b.closed || c.closed {
			t.Fatalf("closed %d, %v: a %v b %v c %v", closed, err, a.closed, b.closed, c.closed)
		}
	})
}

func TestWindowsHolderOnlyFileTypeHandlesAreProbed(t *testing.T) {
	rig := newHoldRig(t)
	notFile := &fakeHolderHandle{value: 0x30, access: 0x12019f, notFile: true}
	culprit := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, notFile, culprit)
	_, _ = rig.check()
	if closed, err := rig.tick(); closed != 1 || err != nil || !culprit.closed {
		t.Fatalf("closed %d, %v", closed, err)
	}
}

// A handle whose owner is blocked in a call on it can stop a query on its
// duplicate. The pass abandons the probe and goes on.
func TestWindowsHolderAProbeThatDoesNotAnswerCannotWedgeThePass(t *testing.T) {
	rig := newHoldRig(t)
	windowsHolderProbeTimeout = 20 * time.Millisecond
	pipe := &fakeHolderHandle{value: 0x10, access: 0x120089, block: make(chan struct{})}
	culprit := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, pipe, culprit)
	started := time.Now()
	_, _ = rig.check()
	// A scan with a probe that did not answer is not repeated at the next
	// check: the second scan comes after the first backoff step.
	if _, err := rig.tick(); err != nil || rig.sys.snapshots != 1 {
		t.Fatalf("a scan with a hung probe was repeated at once: %d scans, %v", rig.sys.snapshots, err)
	}
	closed, err := rig.tick()
	if closed != 1 || err != nil || !culprit.closed {
		t.Fatalf("closed %d, %v", closed, err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("two scans took %s", elapsed)
	}
	if windowsHolderHung.Load() != 2 {
		t.Fatalf("abandoned probes %d, want 2", windowsHolderHung.Load())
	}
	close(pipe.block)
	waitFor(t, 2*time.Second, func() bool { return windowsHolderHung.Load() == 0 })
}

func TestWindowsHolderStopsProbingWhileEarlierProbesAreStillBlocked(t *testing.T) {
	rig := newHoldRig(t)
	windowsHolderProbeTimeout, windowsHolderMaxHung = 20*time.Millisecond, 1
	pipe := &fakeHolderHandle{value: 0x10, access: 0x120089, block: make(chan struct{})}
	culprit := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, pipe, culprit)
	_, _ = rig.check()
	closed, err := rig.tick()
	if closed != 0 || err == nil || !strings.Contains(err.Error(), "earlier handle probes are still blocked") || culprit.closed {
		t.Fatalf("closed %d, %v", closed, err)
	}
	close(pipe.block)
	waitFor(t, 2*time.Second, func() bool { return windowsHolderHung.Load() == 0 })
}

func TestWindowsHolderStopsAtTheProbeLimit(t *testing.T) {
	rig := newHoldRig(t)
	windowsHolderMaxProbes = 5
	var handles []*fakeHolderHandle
	for i := 0; i < 20; i++ {
		handles = append(handles, rig.sys.other(uintptr(0x10+4*i)))
	}
	culprit := rig.sys.culprit(0x400)
	rig.sys.add(4100, fakeUserSID, 2, append(handles, culprit)...)
	_, _ = rig.check()
	closed, err := rig.tick()
	if closed != 0 || err == nil || !strings.Contains(err.Error(), "more than 5 handles to inspect") || culprit.closed {
		t.Fatalf("closed %d, %v", closed, err)
	}
}

// A 32-bit process on a 64-bit system has the same handle values and the same
// duplicate and close calls; the audit row says so.
func TestWindowsHolderClosesTheHandleOfAWow64Process(t *testing.T) {
	rig := newHoldRig(t)
	culprit := rig.sys.culprit(0x1c4)
	proc := rig.sys.add(4100, fakeUserSID, 2, culprit)
	proc.facts.Wow64, proc.facts.Image = true, `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`
	_, _ = rig.check()
	if closed, err := rig.tick(); closed != 1 || err != nil || !culprit.closed {
		t.Fatalf("closed %d, %v", closed, err)
	}
	if len(rig.posted) != 1 || rig.posted[0].event().Structured["wow64"] != true {
		t.Fatalf("rows %+v", rig.posted)
	}
}

// S3. A gateway that is down never stops the close; the row is kept, not
// dropped after a number of checks, and goes out in order when the gateway
// is back.
func TestWindowsHolderAuditRowsWaitForTheGatewayAndGoOutInOrder(t *testing.T) {
	rig := newHoldRig(t)
	down := true
	attempts := 0
	windowsHolderAuditPost = func(row windowsHolderAuditRow) error {
		attempts++
		if down {
			return errors.New("connection refused")
		}
		rig.posted = append(rig.posted, row)
		return nil
	}
	first := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, first)
	_, _ = rig.check()
	if closed, err := rig.tick(); closed != 1 || err != nil || !first.closed {
		t.Fatalf("the gateway is down: closed %d, %v", closed, err)
	}
	// A second holder, much later, in the same streak: its row queues behind.
	second := rig.sys.culprit(0x50)
	rig.sys.add(4200, fakeUserSID, 3, second)
	_, _ = rig.check()
	for i := 0; i < 40 && !second.closed; i++ {
		_, _ = rig.tick()
	}
	if !second.closed {
		t.Fatal("the second holder was not closed while the gateway was down")
	}
	// Two hours with the gateway down: far past 24 checks.
	for i := 0; i < 1440; i++ {
		rig.advance(windowsHookBinaryCheckInterval)
		reportWindowsHookHolders(&rig.log)
	}
	if len(rig.posted) != 0 || len(windowsHolderAuditQueue) != 2 {
		t.Fatalf("posted %d, queued %d after two hours", len(rig.posted), len(windowsHolderAuditQueue))
	}
	if attempts > 60 {
		t.Fatalf("%d post attempts in two hours of 5 s checks: no backoff", attempts)
	}
	if strings.Count(rig.log.String(), "could not record the hook-holder audit row") != 1 || strings.Contains(rig.log.String(), "dropped") {
		t.Fatalf("log %q", rig.log.String())
	}
	down = false
	rig.advance(10 * time.Minute)
	reportWindowsHookHolders(&rig.log)
	if len(rig.posted) != 2 || len(windowsHolderAuditQueue) != 0 || rig.posted[0].Holder.PID != 4100 || rig.posted[1].Holder.PID != 4200 {
		t.Fatalf("posted %+v, queued %d", rig.posted, len(windowsHolderAuditQueue))
	}
}

// A row stays queued when a later one is refused, and the flush stops at the
// first failure instead of paying a timeout for every row.
func TestWindowsHolderAuditFlushStopsAtTheFirstFailure(t *testing.T) {
	rig := newHoldRig(t)
	attempts := 0
	windowsHolderAuditPost = func(windowsHolderAuditRow) error { attempts++; return errors.New("timed out") }
	for i := 0; i < 5; i++ {
		queueWindowsHolderAudit(windowsHolderAuditRow{Hook: rig.target})
	}
	reportWindowsHookHolders(&rig.log)
	if attempts != 1 || len(windowsHolderAuditQueue) != 5 {
		t.Fatalf("attempts %d, queued %d", attempts, len(windowsHolderAuditQueue))
	}
}

// The post runs outside every lock the guardian's check needs: a gateway
// that accepts and stalls does not hold up the queueing of the next row (the
// close path) for as long as the post lasts.
func TestWindowsHolderAuditPostDoesNotBlockQueueingOrTheGuardianMutex(t *testing.T) {
	rig := newHoldRig(t)
	release := make(chan struct{})
	inPost := make(chan struct{}, 1)
	windowsHolderAuditPost = func(row windowsHolderAuditRow) error {
		inPost <- struct{}{}
		<-release
		rig.posted = append(rig.posted, row)
		return nil
	}
	queueWindowsHolderAudit(windowsHolderAuditRow{Hook: rig.target})
	done := make(chan struct{})
	go func() { flushWindowsHolderAudit(&rig.log); close(done) }()
	<-inPost
	if !windowsHookBinaryMu.TryLock() { // the guardian's mutex is free while the post is stuck
		t.Fatal("the guardian's mutex was held while a post was in flight")
	}
	windowsHookBinaryMu.Unlock()
	queued := make(chan struct{})
	go func() { queueWindowsHolderAudit(windowsHolderAuditRow{Hook: rig.target}); close(queued) }()
	select {
	case <-queued:
	case <-time.After(2 * time.Second):
		t.Fatal("queueing a row waited for a post that was in flight")
	}
	close(release)
	<-done
	if len(rig.posted) != 1 || len(windowsHolderAuditQueue) != 1 {
		t.Fatalf("posted %d, queued %d", len(rig.posted), len(windowsHolderAuditQueue))
	}
}

// The queue is a file too: a guardian restart with the gateway still down
// loses nothing, and the rows go out in order afterwards.
func TestWindowsHolderAuditRowsSurviveAGuardianRestart(t *testing.T) {
	rig := newHoldRig(t)
	file := filepath.Join(t.TempDir(), "hook-guardian", "holder-audit-queue.json")
	windowsHolderAuditWrite = writeWindowsBundleFile
	windowsHolderAuditPost = func(windowsHolderAuditRow) error { return errors.New("connection refused") }
	setWindowsHolderAuditPath(file)
	for i := 0; i < 3; i++ {
		queueWindowsHolderAudit(windowsHolderAuditRow{Hook: rig.target, Holder: windowsHolderProcess{PID: uint32(100 + i)}})
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("the queue file was not written: %v", err)
	}
	// The guardian process restarts: nothing in memory, the file stays.
	windowsHolderOutMu.Lock()
	windowsHolderAuditQueue, windowsHolderAuditSeq, windowsHolderAuditLoaded = nil, 0, false
	windowsHolderOutMu.Unlock()
	windowsHolderAuditPost = func(row windowsHolderAuditRow) error { rig.posted = append(rig.posted, row); return nil }
	reportWindowsHookHolders(&rig.log)
	if len(rig.posted) != 3 || rig.posted[0].Holder.PID != 100 || rig.posted[2].Holder.PID != 102 {
		t.Fatalf("posted %+v", rig.posted)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the queue file stays after delivery: %v", err)
	}
	queueWindowsHolderAudit(windowsHolderAuditRow{Hook: rig.target})
	if windowsHolderAuditQueue[0].Seq != 4 {
		t.Fatalf("sequence %d after a reload, want 4", windowsHolderAuditQueue[0].Seq)
	}
}

func TestWindowsHolderAuditQueueIsBounded(t *testing.T) {
	rig := newHoldRig(t)
	windowsHolderAuditPost = func(windowsHolderAuditRow) error { return errors.New("connection refused") }
	for i := 0; i < windowsHolderAuditMaxRows+40; i++ {
		queueWindowsHolderAudit(windowsHolderAuditRow{Hook: rig.target})
	}
	if len(windowsHolderAuditQueue) != windowsHolderAuditMaxRows || windowsHolderAuditQueue[0].Seq != 41 {
		t.Fatalf("queued %d, first sequence %d", len(windowsHolderAuditQueue), windowsHolderAuditQueue[0].Seq)
	}
	reportWindowsHookHolders(&rig.log)
	if !strings.Contains(rig.log.String(), "dropped the") {
		t.Fatalf("log %q", rig.log.String())
	}
}

func TestWindowsHolderSnapshotFailureBacksOff(t *testing.T) {
	rig := newHoldRig(t)
	rig.sys.snapErr = errors.New("the handle table is larger than 192 MiB")
	for i := 0; i < 12; i++ {
		if _, err := rig.tick(); err == nil || !strings.Contains(err.Error(), "could not list who holds the hook") {
			t.Fatalf("tick %d: %v", i, err)
		}
	}
	if rig.sys.snapshots > 5 {
		t.Fatalf("%d snapshots in 60 s of failures", rig.sys.snapshots)
	}
}

// Bound (e): the closer runs only in the standalone guardian. On any other
// profile a held and delete-blocked hook takes the swap path of the
// previous release and the handle table is never read.
func TestKeepWindowsManagedFileCopyDoesNotCloseHandlesOutsideTheStandaloneProfile(t *testing.T) {
	requireAdministratorTestToken(t, "the product restore writes the hook binary with the install file descriptor (an Administrators owner)")
	for _, standalone := range []bool{false, true} {
		t.Run(fmt.Sprintf("standalone=%v", standalone), func(t *testing.T) {
			rig := newHoldRig(t)
			windowsHolderStandalone = func() bool { return standalone }
			root := t.TempDir()
			target := filepath.Join(root, "bin", "defenseclaw-hook.exe")
			copyPath := filepath.Join(root, "hook-guardian", "payload", "defenseclaw-hook.exe")
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				t.Fatal(err)
			}
			writeWindowsSystemProgram(t, "HOSTNAME.EXE", target, nil)
			want, err := windowsFileSHA256Hex(target)
			if err != nil {
				t.Fatal(err)
			}
			if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, true); err != nil || damage != "" {
				t.Fatalf("keep copy: restored %q, %v", damage, err)
			}
			t.Cleanup(func() { removeWindowsReplacementCopies(filepath.Dir(target)) })
			rig.sys.add(4100, fakeUserSID, 2, rig.sys.culprit(0x44))
			savedRefused := windowsHookBinaryOpenRefused
			windowsHookBinaryOpenRefused = func(string) bool { return rig.sys.blocked() }
			t.Cleanup(func() { windowsHookBinaryOpenRefused = savedRefused })
			damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false)
			if standalone {
				if damage != "" || err != nil || rig.sys.snapshots != 1 {
					t.Fatalf("standalone: restored %q, %v, scans %d (a swap is not tried; the first sight waits)", damage, err, rig.sys.snapshots)
				}
				return
			}
			if rig.sys.snapshots != 0 || len(rig.posted) != 0 || len(windowsHolderLog) != 0 {
				t.Fatalf("outside the standalone profile the handle table was read (%d scans) or a row written", rig.sys.snapshots)
			}
			if err != nil || !strings.Contains(damage, "held open by another program") {
				t.Fatalf("outside the standalone profile: restored %q, %v, want the swap of the previous release", damage, err)
			}
		})
	}
}

// Any check that does not find the hook held starts the two checks again.
func TestKeepWindowsManagedFileCopyForgetsAHoldWhenTheHookIsFree(t *testing.T) {
	rig := newHoldRig(t)
	root := t.TempDir()
	target := filepath.Join(root, "bin", "defenseclaw-hook.exe")
	copyPath := filepath.Join(root, "hook-guardian", "payload", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	writeWindowsSystemProgram(t, "HOSTNAME.EXE", target, nil)
	want, err := windowsFileSHA256Hex(target)
	if err != nil {
		t.Fatal(err)
	}
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, true); err != nil || damage != "" {
		t.Fatalf("keep copy: restored %q, %v", damage, err)
	}
	holder := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, holder)
	savedRefused := windowsHookBinaryOpenRefused
	windowsHookBinaryOpenRefused = func(string) bool { return rig.sys.blocked() }
	t.Cleanup(func() { windowsHookBinaryOpenRefused = savedRefused })
	step := func(wantClosed bool) {
		t.Helper()
		rig.advance(windowsHookBinaryCheckInterval)
		if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false); damage != "" || err != nil {
			t.Fatalf("restored %q, %v", damage, err)
		}
		if holder.closed != wantClosed {
			t.Fatalf("handle closed %v, want %v", holder.closed, wantClosed)
		}
	}
	step(false)
	holder.denyDelete = false // the hook is free at the next check
	step(false)
	holder.denyDelete = true
	step(false) // first sight again
	step(true)
}

// M1. CloseIf runs on the same worker and timeout as a probe: the owner of a
// handle can close its value, get it back as a synchronous pipe with a read
// pending, and GetFileType on a duplicate of it then blocks. Under the
// guardian's mutex that would stop the hook restore and the reconcile for good.
func TestWindowsHolderACloseThatDoesNotAnswerCannotWedgeTheGuardian(t *testing.T) {
	rig := newHoldRig(t)
	windowsHolderProbeTimeout = 20 * time.Millisecond
	culprit := rig.sys.culprit(0x44)
	culprit.closeBlock = make(chan struct{})
	proc := rig.sys.add(4100, fakeUserSID, 2, culprit)
	_, _ = rig.check()
	started := time.Now()
	closed, err := rig.tick()
	if closed != 0 || err == nil || !strings.Contains(err.Error(), "did not answer in time, so it was not closed") || !strings.Contains(err.Error(), "tries again at the next check") {
		t.Fatalf("closed %d, %v", closed, err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("the pass took %s", elapsed)
	}
	if culprit.closed || len(proc.closeLog) != 0 || len(rig.posted) != 0 {
		t.Fatalf("a close that did not answer was counted: closed %v, rows %d", culprit.closed, len(rig.posted))
	}
	if windowsHolderHung.Load() != 1 {
		t.Fatalf("abandoned calls %d, want 1", windowsHolderHung.Load())
	}
	// Not a refusal: no backoff, the next check tries again.
	before := rig.sys.snapshots
	if _, err := rig.tick(); err == nil || rig.sys.snapshots != before+1 {
		t.Fatalf("the next check did not try again: %d scans after %d, %v", rig.sys.snapshots, before, err)
	}
	// The blocked call returns after the guardian gave up: it must not close.
	close(culprit.closeBlock)
	waitFor(t, 2*time.Second, func() bool { return windowsHolderHung.Load() == 0 })
	if culprit.closed {
		t.Fatal("a close the guardian had given up on was made when the call returned")
	}
	if queued := queuedWindowsHolderRows(); queued != 0 {
		t.Fatalf("%d audit rows for a close that never happened", queued)
	}
	// With the pipe gone the next check closes it.
	culprit.closeBlock = nil
	if closed, err := rig.tick(); closed != 1 || err != nil || !culprit.closed {
		t.Fatalf("next check: closed %d, %v", closed, err)
	}
}

// queuedWindowsHolderRows is how many audit rows wait for the gateway.
func queuedWindowsHolderRows() int {
	windowsHolderOutMu.Lock()
	defer windowsHolderOutMu.Unlock()
	return len(windowsHolderAuditQueue)
}

// A close that had begun when the guardian gave up finishes
// afterwards and frees the hook. No further pass exists (the hook is free), so
// the row cannot wait for one: it is written to the queue and to its file the
// moment the close finishes, and the guardian's next check delivers it, once.
func TestWindowsHolderACloseThatFinishesLateIsAuditedWithoutAnotherHoldPass(t *testing.T) {
	rig := newHoldRig(t)
	windowsHolderProbeTimeout, windowsHolderCommitWait = 20*time.Millisecond, 40*time.Millisecond
	file := filepath.Join(t.TempDir(), "hook-guardian", "holder-audit-queue.json")
	windowsHolderAuditWrite = writeWindowsBundleFile
	setWindowsHolderAuditPath(file)
	culprit := rig.sys.culprit(0x44)
	culprit.closeBlock, culprit.commitFirst = make(chan struct{}), true
	rig.sys.add(4100, fakeUserSID, 2, culprit, rig.sys.sharing(0x48))
	_, _ = rig.check()
	closed, err := rig.tick()
	if closed != 0 || err == nil || !strings.Contains(err.Error(), "may have been closed") || strings.Contains(err.Error(), "so it was not closed") {
		t.Fatalf("closed %d, %v: the verdict must not say the handle was not closed", closed, err)
	}
	// L1: a close that had begun counts in the streak, with its backoff.
	if windowsHolderGate.closes != 1 || windowsHolderGate.nextClose.IsZero() {
		t.Fatalf("a begun close was not counted in the streak: closes %d, next %v", windowsHolderGate.closes, windowsHolderGate.nextClose)
	}
	close(culprit.closeBlock)
	waitFor(t, 2*time.Second, func() bool { return queuedWindowsHolderRows() == 1 })
	if !culprit.closed || windowsHolderHung.Load() != 0 {
		t.Fatalf("the late close did not happen (closed %v, hung %d)", culprit.closed, windowsHolderHung.Load())
	}
	// Written to disk at once, before any pass or flush.
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("the late close was not saved: %v", err)
	}
	var saved []windowsHolderAuditRow
	if err := json.Unmarshal(data, &saved); err != nil || len(saved) != 1 || !saved[0].Closed || saved[0].Holder.PID != 4100 {
		t.Fatalf("saved rows %+v, %v", saved, err)
	}
	// S3: the row carries the pass's own counts (2 handles on 2 file objects
	// in 1 process), not a made-up 1/1/1.
	if c := saved[0].Counts; c.Handles != 2 || c.Processes != 1 || c.Objects != 2 {
		t.Fatalf("late row counts %+v, want 2 handles, 1 process, 2 objects", c)
	}
	// The hook is free now: the guardian runs no hold pass, only the real
	// wrapper's flush.
	keepWindowsStandaloneHookBinary(&rig.log, false)
	keepWindowsStandaloneHookBinary(&rig.log, false)
	if len(rig.posted) != 1 || !rig.posted[0].Closed || rig.posted[0].Holder.PID != 4100 || !strings.Contains(rig.posted[0].Note, "stopped waiting") {
		t.Fatalf("rows %+v, want exactly one late-close row", rig.posted)
	}
	if event := rig.posted[0].event(); event.Severity != "HIGH" || !strings.Contains(event.Details, "closed that handle") || !strings.Contains(event.Details, "stopped waiting") {
		t.Fatalf("event %+v", event)
	}
	if !strings.Contains(rig.log.String(), "closed the handle") || !strings.Contains(rig.log.String(), "stopped waiting") {
		t.Fatalf("guardian log %q", rig.log.String())
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the queue file stays after delivery: %v", err)
	}
}

// A close that has begun is waited for a little longer than a probe: when it
// finishes inside that time the pass sees the answer, as any close, and there
// is no late row.
func TestWindowsHolderACloseThatHasBegunIsWaitedForABoundedExtraTime(t *testing.T) {
	rig := newHoldRig(t)
	windowsHolderProbeTimeout, windowsHolderCommitWait = 20*time.Millisecond, 2*time.Second
	culprit := rig.sys.culprit(0x44)
	culprit.closeBlock, culprit.commitFirst = make(chan struct{}), true
	rig.sys.add(4100, fakeUserSID, 2, culprit)
	_, _ = rig.check()
	go func() {
		time.Sleep(150 * time.Millisecond)
		close(culprit.closeBlock)
	}()
	closed, err := rig.tick()
	if closed != 1 || err != nil || !culprit.closed {
		t.Fatalf("closed %d, %v", closed, err)
	}
	if windowsHolderHung.Load() != 0 || len(rig.posted) != 1 || rig.posted[0].Note != "" || queuedWindowsHolderRows() != 0 {
		t.Fatalf("hung %d, rows %+v, queued %d: want one ordinary row", windowsHolderHung.Load(), rig.posted, queuedWindowsHolderRows())
	}
}

// A close that hit a handle that was not the hook's is audited
// too: it closed something of the user's.
func TestWindowsHolderACloseOfTheWrongObjectIsAudited(t *testing.T) {
	rig := newHoldRig(t)
	culprit := rig.sys.culprit(0x44)
	culprit.wrongObject = true
	rig.sys.add(4100, fakeUserSID, 2, culprit)
	_, _ = rig.check()
	if closed, err := rig.tick(); closed != 0 || err == nil {
		t.Fatalf("closed %d, %v", closed, err)
	}
	if len(rig.posted) != 1 || !strings.Contains(rig.posted[0].Note, "proved not to be one on the hook") || !strings.Contains(rig.log.String(), "proved not to be on the hook binary") {
		t.Fatalf("rows %+v, log %q", rig.posted, rig.log.String())
	}
}

// DuplicateHandle with DUPLICATE_CLOSE_SOURCE closes the
// source handle even when it fails: the guardian audits that as a close that
// may have happened.
func TestWindowsHolderACloseWhoseLastCallFailedIsAudited(t *testing.T) {
	rig := newHoldRig(t)
	culprit := rig.sys.culprit(0x44)
	culprit.closeFails = true
	rig.sys.add(4100, fakeUserSID, 2, culprit)
	_, _ = rig.check()
	if closed, err := rig.tick(); closed != 0 || err == nil {
		t.Fatalf("closed %d, %v", closed, err)
	}
	if len(rig.posted) != 1 || !strings.Contains(rig.posted[0].Note, "closes the source handle whatever that call returns") || !strings.Contains(rig.log.String(), "the last call failed") {
		t.Fatalf("rows %+v, log %q", rig.posted, rig.log.String())
	}
}

// Only 400, 413, 415 and 422 describe a bad row.
func TestWindowsHolderAuditRefusalPermanentStatuses(t *testing.T) {
	for status, want := range map[int]bool{400: true, 413: true, 415: true, 422: true, 401: false, 403: false, 404: false, 405: false, 408: false, 409: false, 429: false, 500: false, 503: false} {
		if got := (windowsHolderAuditRefusal{Status: status}).permanent(); got != want {
			t.Errorf("HTTP %d: permanent = %v, want %v", status, got, want)
		}
	}
}

// S2. A probe the scan gave up on keeps its own reference to the process, so
// the process handle is closed when the probe returns, even late, not never.
func TestWindowsHolderAProcessHandleIsReleasedWhenAnAbandonedProbeReturns(t *testing.T) {
	rig := newHoldRig(t)
	windowsHolderProbeTimeout = 20 * time.Millisecond
	rig.sys.unlisted = true // every process with a file handle is looked at
	pipe := &fakeHolderHandle{value: 0x10, access: 0x120089, block: make(chan struct{})}
	proc := rig.sys.add(4100, fakeUserSID, 2, pipe, rig.sys.other(0x20))
	_, _ = rig.check()
	if proc.released.Load() != 0 {
		t.Fatalf("the process was released (%d) while an abandoned probe could still use it", proc.released.Load())
	}
	close(pipe.block)
	waitFor(t, 2*time.Second, func() bool { return proc.released.Load() == 1 })
	// A scan that found a handle releases it once, at the end of the pass.
	// The scan's reference is not the last one: each probe's worker holds its
	// own and drops it in a deferred call that runs after the worker has sent
	// its answer, so the pass can return first (the hosted Windows runner
	// read the count in that window: 1 of 2). The process is closed when the
	// last reference goes, so the count is awaited, as in the half above.
	rig2 := newHoldRig(t)
	found := rig2.sys.add(4100, fakeUserSID, 2, rig2.sys.culprit(0x44))
	_, _ = rig2.check()
	_, _ = rig2.tick()
	for end := time.Now().Add(2 * time.Second); found.released.Load() < 2 && time.Now().Before(end); {
		time.Sleep(10 * time.Millisecond)
	}
	if found.released.Load() != 2 {
		t.Fatalf("released %d times in two passes, want once per pass", found.released.Load())
	}
}

// The candidates are grouped by the file object they refer to (caveat (b)).
func TestWindowsHolderGroupsCandidatesByFileObject(t *testing.T) {
	t.Run("one file object: every handle of it is needed, none is collateral", func(t *testing.T) {
		rig := newHoldRig(t)
		a, b := rig.sys.culprit(0x40), rig.sys.culprit(0x44)
		a.object, b.object = 0xfffff800a0, 0xfffff800a0
		pa := rig.sys.add(4100, fakeUserSID, 2, a)
		pb := rig.sys.add(4200, fakeUserSID, 2, b) // inherited by a child
		_, _ = rig.check()
		closed, err := rig.tick()
		if closed != 2 || err != nil || !a.closed || !b.closed || len(pa.closeLog) != 1 || len(pb.closeLog) != 1 {
			t.Fatalf("closed %d, %v: a %v b %v", closed, err, a.closed, b.closed)
		}
		event := rig.posted[0].event()
		for key, want := range map[string]any{"candidate_handles": 2, "candidate_processes": 2, "candidate_file_objects": 1, "handles_closed_in_pass": 2} {
			if event.Structured[key] != want {
				t.Errorf("structured %s = %v, want %v", key, event.Structured[key], want)
			}
		}
		if !strings.Contains(rig.log.String(), "one of 2 candidate handle(s) in 2 process(es) on 1 file object(s)") {
			t.Fatalf("log %q", rig.log.String())
		}
	})
	t.Run("several objects: one at a time, whole objects, stops when the hook starts", func(t *testing.T) {
		rig := newHoldRig(t)
		// Object 200 has two handles and is the blocker; object 100 and 300
		// have one each and share deletion.
		x := rig.sys.sharing(0x40)
		x.object = 100
		y1, y2 := rig.sys.culprit(0x44), rig.sys.culprit(0x48)
		y1.object, y2.object = 200, 200
		z1, z2, z3 := rig.sys.sharing(0x4c), rig.sys.sharing(0x50), rig.sys.sharing(0x54)
		z1.object, z2.object, z3.object = 300, 300, 300
		rig.sys.add(4100, fakeUserSID, 2, x, y1, y2, z1, z2, z3)
		_, _ = rig.check()
		closed, err := rig.tick()
		// Fewest handles first: object 100, then 200 (both handles; the hook
		// starts after the second), and object 300 is not touched.
		if closed != 3 || err != nil || !x.closed || !y1.closed || !y2.closed || z1.closed || z2.closed || z3.closed {
			t.Fatalf("closed %d, %v: x %v y1 %v y2 %v z %v", closed, err, x.closed, y1.closed, y2.closed, z1.closed)
		}
		if got := rig.posted[0].event().Structured["candidate_file_objects"]; got != 3 {
			t.Fatalf("candidate_file_objects %v, want 3", got)
		}
	})
	t.Run("the closes of one pass are bounded", func(t *testing.T) {
		rig := newHoldRig(t)
		windowsHolderMaxCloses = 3
		t.Cleanup(func() { windowsHolderMaxCloses = 64 })
		var handles []*fakeHolderHandle
		for i := 0; i < 6; i++ {
			h := rig.sys.culprit(uintptr(0x40 + 4*i))
			h.object = 77
			handles = append(handles, h)
		}
		rig.sys.add(4100, fakeUserSID, 2, handles...)
		_, _ = rig.check()
		if closed, err := rig.tick(); closed != 3 || err != nil {
			t.Fatalf("closed %d, %v", closed, err)
		}
	})
}

// S1. The holder rotates its handle and its process before every check. It
// is the same user, so it is closed at the third check, and the guardian
// then backs off.
func TestWindowsHolderARotatingHolderIsClosedAtTheThirdCheckAndBacksOff(t *testing.T) {
	rig := newHoldRig(t)
	pid, value := uint32(4100), uintptr(0x44)
	rotate := func() *fakeHolderHandle {
		for _, p := range rig.sys.procs {
			for _, h := range p.handles {
				h.closed = true
			}
		}
		pid++
		value += 8
		h := rig.sys.culprit(value)
		rig.sys.add(pid, fakeUserSID, 2, h)
		return h
	}
	current := rotate()
	if _, err := rig.check(); err != nil || current.closed {
		t.Fatalf("first check: %v", err)
	}
	current = rotate()
	if closed, err := rig.tick(); closed != 0 || err != nil || current.closed {
		t.Fatalf("second check: closed %d, %v", closed, err)
	}
	current = rotate()
	closed, err := rig.tick()
	if closed != 1 || err != nil || !current.closed {
		t.Fatalf("third check: closed %d, %v", closed, err)
	}
	// It takes the file again with a new handle each tick: closed again no
	// sooner than the backoff, scans bounded, one row per process.
	var closes []time.Duration
	elapsed := time.Duration(0)
	for elapsed < 130*time.Second {
		rotate()
		rig.advance(windowsHookBinaryCheckInterval)
		elapsed += windowsHookBinaryCheckInterval
		n, err := rig.check()
		if err != nil {
			t.Fatalf("at %s: %v", elapsed, err)
		}
		if n > 0 {
			closes = append(closes, elapsed)
		}
	}
	if len(closes) < 2 || len(closes) > 4 {
		t.Fatalf("closes at %v in 130 s", closes)
	}
	for i := 1; i < len(closes); i++ {
		if closes[i]-closes[i-1] < windowsHeldSwapDelay(i+1)-windowsHookBinaryCheckInterval {
			t.Fatalf("closes at %v: no backoff", closes)
		}
	}
	// Three scans per close, none while the backoff lasts.
	if rig.sys.snapshots > 14 {
		t.Fatalf("%d scans in 130 s of a rotating hold", rig.sys.snapshots)
	}
}

// A holder that swaps its handle for another between the scan and the close
// is looked at again at once, a few times, instead of costing a backoff.
func TestWindowsHolderLooksAgainWhenTheHandleWasReplacedBetweenScanAndClose(t *testing.T) {
	rig := newHoldRig(t)
	third := rig.sys.culprit(0x60)
	second := rig.sys.culprit(0x50)
	second.rotateTo = third
	first := rig.sys.culprit(0x44)
	first.rotateTo = second
	rig.sys.add(4100, fakeUserSID, 2, first)
	_, _ = rig.check()
	closed, err := rig.tick()
	if closed != 1 || err != nil || !third.closed || rig.sys.snapshots != 4 {
		t.Fatalf("closed %d, %v, third closed %v, scans %d (one at the first check, three at the second)", closed, err, third.closed, rig.sys.snapshots)
	}
	// A holder that replaces its handle every time is given up on after the
	// rescans and backs off like a refusal.
	rig2 := newHoldRig(t)
	chain := rig2.sys.culprit(0x44)
	head := chain
	for i := 0; i < 6; i++ {
		next := rig2.sys.culprit(uintptr(0x50 + 8*i))
		head.rotateTo = next
		head = next
	}
	rig2.sys.add(4100, fakeUserSID, 2, chain)
	_, _ = rig2.check()
	closed, err = rig2.tick()
	if closed != 0 || err == nil || !strings.Contains(err.Error(), "no longer names the hook") || rig2.sys.snapshots != 1+1+windowsHolderRescans {
		t.Fatalf("closed %d, %v, scans %d", closed, err, rig2.sys.snapshots)
	}
	before := rig2.sys.snapshots
	if _, err := rig2.tick(); err == nil || rig2.sys.snapshots != before {
		t.Fatalf("no backoff after the rescans: %v, scans %d after %d", err, rig2.sys.snapshots, before)
	}
}

// A repeated hold that is skipped by the backoff still counts as one hold:
// after the backoff the next scan closes at once.
func TestWindowsHolderRescansBackOffWhileAHoldPersists(t *testing.T) {
	rig := newHoldRig(t)
	service := rig.sys.culprit(0x44)
	rig.sys.add(700, "S-1-5-18", 0, service)
	for i := 0; i < 24; i++ { // two minutes of 5 s checks
		_, _ = rig.tick()
	}
	if rig.sys.snapshots > 7 {
		t.Fatalf("%d scans in two minutes of a hold the guardian cannot end", rig.sys.snapshots)
	}
}

// S4. The queue file is readable and writable only by SYSTEM and the
// Administrators, as the real writer leaves it.
func TestWindowsHolderAuditQueueFileIsForSystemAndAdministratorsOnly(t *testing.T) {
	requireAdministratorTestToken(t, "the queue file is owned by Administrators")
	newHoldRig(t)
	file := filepath.Join(t.TempDir(), "hook-guardian", "holder-audit-queue.json")
	setWindowsHolderAuditPath(file)
	queueWindowsHolderAudit(windowsHolderAuditRow{Hook: "hook"})
	expected, err := windows.SecurityDescriptorFromString(windowsBundleAdminFileSDDL())
	if err != nil {
		t.Fatal(err)
	}
	actual, err := windows.GetNamedSecurityInfo(file, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := actual.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("the queue file inherits access: %s", actual.String())
	}
	if matches, err := windowsEnterpriseExactDescriptorMatch(actual, expected); err != nil || !matches {
		t.Fatalf("the queue file's descriptor is %s, want %s (%v)", actual.String(), expected.String(), err)
	}
	for _, other := range []string{";;;BU)", ";;;WD)", ";;;AU)", ";;;IU)"} {
		if strings.Contains(actual.String(), other) {
			t.Fatalf("the queue file grants access to %s: %s", other, actual.String())
		}
	}
}

// S4. A save that ended in the middle leaves <queue>.tmp-<pid>; the guardian
// removes it when it starts, and nothing else.
func TestWindowsHolderStartRemovesTempFilesAnEarlierSaveLeft(t *testing.T) {
	newHoldRig(t)
	dir := filepath.Join(t.TempDir(), "hook-guardian")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "holder-audit-queue.json")
	stale, unrelated := file+".tmp-4242", filepath.Join(dir, "targets.yaml.tmp-4242")
	for _, path := range []string{stale, unrelated} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	windowsHolderAuditWrite = writeWindowsBundleFile
	setWindowsHolderAuditPath(file)
	queueWindowsHolderAudit(windowsHolderAuditRow{})
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the leftover temp file of the queue stays: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("a file that is not the queue's was removed: %v", err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("the queue file: %v", err)
	}
}

// S4. A row the gateway refuses for good (a 4xx a retry does not change) is
// dropped, with a log line, after a few tries, so that it does not hold up the
// rows behind it. A refusal that may pass (5xx, 408, 429) never drops a row.
func TestWindowsHolderAuditRowTheGatewayRefusesForGoodIsDroppedAndDoesNotBlockTheQueue(t *testing.T) {
	rig := newHoldRig(t)
	status := 400
	windowsHolderAuditPost = func(row windowsHolderAuditRow) error {
		if row.Holder.PID == 100 {
			return windowsHolderAuditRefusal{Status: status}
		}
		rig.posted = append(rig.posted, row)
		return nil
	}
	for _, pid := range []uint32{100, 101} {
		queueWindowsHolderAudit(windowsHolderAuditRow{Hook: rig.target, Holder: windowsHolderProcess{PID: pid}})
	}
	for _, retry := range []int{503, 408, 429, 401, 403, 404, 405} {
		status = retry
		for i := 0; i < windowsHolderAuditMaxRejects+3; i++ {
			rig.advance(10 * time.Minute)
			reportWindowsHookHolders(&rig.log)
		}
		if len(rig.posted) != 0 || queuedWindowsHolderRows() != 2 {
			t.Fatalf("HTTP %d: posted %d, queued %d: a row that may still pass was dropped", retry, len(rig.posted), queuedWindowsHolderRows())
		}
	}
	status = 400
	for i := 1; i < windowsHolderAuditMaxRejects; i++ {
		rig.advance(10 * time.Minute)
		reportWindowsHookHolders(&rig.log)
		if len(rig.posted) != 0 || queuedWindowsHolderRows() != 2 {
			t.Fatalf("after %d refusals: posted %d, queued %d", i, len(rig.posted), queuedWindowsHolderRows())
		}
	}
	rig.advance(10 * time.Minute)
	reportWindowsHookHolders(&rig.log)
	if len(rig.posted) != 1 || rig.posted[0].Holder.PID != 101 || queuedWindowsHolderRows() != 0 {
		t.Fatalf("posted %+v, queued %d: the row behind the refused one was held up", rig.posted, queuedWindowsHolderRows())
	}
	if !strings.Contains(rig.log.String(), "dropped the hook-holder audit row") || !strings.Contains(rig.log.String(), "process id 100") {
		t.Fatalf("log %q", rig.log.String())
	}
}

// dataRig is a rig whose watched folder holds every allow-listed runtime file
// (machine-policy.json, the closure marker, and an enrollment and a selector
// in each connector folder); only the paths in held are held.
func dataRig(t *testing.T, held ...string) (rig *holdRig, dir string) {
	t.Helper()
	rig = newHoldRig(t)
	dir = filepath.Join(t.TempDir(), "DefenseClaw-HookRuntime")
	names := []string{"machine-policy.json", ".defenseclaw-hot-config-undo-closed"}
	for _, connector := range windowsHookRuntimeConnectors {
		names = append(names, filepath.Join(connector, "enrollment.json"), filepath.Join(connector, ".defenseclaw-managed-runtime-selector.state"))
	}
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	isHeld := func(path string) bool {
		for _, h := range held {
			if !filepath.IsAbs(h) {
				h = filepath.Join(dir, h)
			}
			if strings.EqualFold(h, path) {
				return true
			}
		}
		return false
	}
	windowsHookRuntimeDir = func() (string, error) { return dir, nil }
	windowsHookDataReadRefused = func(path string) bool { return isHeld(path) && rig.sys.startRefused() }
	windowsHookDataDeleteBlocked = func(path string) bool { return isHeld(path) && rig.sys.blocked() }
	return rig, dir
}

// keepData is one guardian check of the runtime files, then its report.
func keepData(rig *holdRig) {
	keepWindowsHookRuntimeFiles(&rig.log)
	writeWindowsHolderLog(&rig.log)
	flushWindowsHolderAudit(&rig.log)
}

// The guardian's check works on at most windowsHolderDataHeldPerTick held
// files, and the next check starts where it stopped, so that a user who holds
// many runtime files does not take the whole check and every file is reached.
func TestWindowsHolderTheRuntimeFilePassIsBoundedPerCheck(t *testing.T) {
	rig, dir := dataRig(t)
	files := windowsHookRuntimeWatchList(dir)
	if len(files) != 2+2*len(windowsHookRuntimeConnectors) {
		t.Fatalf("%d files on the watch list", len(files))
	}
	windowsHookDataReadRefused = func(string) bool { return true }
	windowsHookDataDeleteBlocked = func(string) bool { return true }
	keepData(rig)
	if rig.sys.snapshots != windowsHolderDataHeldPerTick {
		t.Fatalf("%d scans in the first check, want the bound %d", rig.sys.snapshots, windowsHolderDataHeldPerTick)
	}
	rig.advance(windowsHookBinaryCheckInterval)
	keepData(rig)
	if rig.sys.snapshots != 2*windowsHolderDataHeldPerTick {
		t.Fatalf("%d scans after two checks, want %d: the second check must reach the files the first left", rig.sys.snapshots, 2*windowsHolderDataHeldPerTick)
	}
	for check := 2; check < (len(files)+windowsHolderDataHeldPerTick-1)/windowsHolderDataHeldPerTick; check++ {
		rig.advance(windowsHookBinaryCheckInterval)
		keepData(rig)
	}
	scanned := 0
	for _, gate := range windowsHolderDataGates {
		if !gate.streakLast.IsZero() {
			scanned++
		}
	}
	if scanned != len(files) {
		t.Fatalf("%d of %d files were reached in %d checks", scanned, len(files), (len(files)+windowsHolderDataHeldPerTick-1)/windowsHolderDataHeldPerTick)
	}
}

// DefenseClaw's own lock files are held with no sharing for a whole
// transaction by Setup and by the command line, and the hook never opens them.
// A real share-0 hold of each of them, and of a temp file, is never scanned,
// closed or reported, while a share-0 hold of machine-policy.json beside them
// is closed at the second check with one row: the rig does act on a file the
// hook reads.
func TestWindowsHolderTheLockFilesDefenseClawHoldsAreNeverActedOn(t *testing.T) {
	rig := newHoldRig(t)
	dir := filepath.Join(t.TempDir(), "DefenseClaw-HookRuntime")
	locks := []string{
		filepath.Join(dir, "copilot", ".defenseclaw-enrollment.lock"),
		filepath.Join(dir, "copilot", ".defenseclaw-managed-runtime-selector.lock"),
		filepath.Join(dir, "hermes", ".defenseclaw-enrollment.lock"),
		filepath.Join(dir, "hermes", ".defenseclaw-managed-runtime-selector.lock"),
		filepath.Join(dir, "copilot", ".defenseclaw-policy-1234.tmp"),
	}
	policy := filepath.Join(dir, "machine-policy.json")
	for _, path := range append([]string{policy}, locks...) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	hold := func(path string) {
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := windows.CreateFile(name, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			t.Fatalf("hold %s: %v", path, err)
		}
		t.Cleanup(func() { _ = windows.CloseHandle(handle) })
	}
	for _, path := range locks {
		hold(path)
		if !windowsOpenRefused(path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE) {
			t.Fatalf("%s is not held: the test proves nothing", path)
		}
	}
	windowsHookRuntimeDir = func() (string, error) { return dir, nil }
	holder := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, holder)
	for i := 0; i < 6; i++ {
		keepData(rig)
		rig.advance(windowsHookBinaryCheckInterval)
	}
	if rig.sys.snapshots != 0 || holder.closed || len(rig.posted) != 0 {
		t.Fatalf("a lock file was acted on: scans %d, closed %v, rows %+v", rig.sys.snapshots, holder.closed, rig.posted)
	}
	if strings.Contains(rig.log.String(), ".lock") {
		t.Fatalf("log names a lock file: %q", rig.log.String())
	}
	// The control: the same rig closes the hold of the machine policy.
	hold(policy)
	windowsHookDataDeleteBlocked = func(path string) bool { return strings.EqualFold(path, policy) && rig.sys.blocked() }
	windowsHookDataReadRefused = func(path string) bool { return strings.EqualFold(path, policy) && rig.sys.startRefused() }
	for i := 0; i < 3; i++ {
		keepData(rig)
		rig.advance(windowsHookBinaryCheckInterval)
	}
	if !holder.closed || len(rig.posted) != 1 || rig.posted[0].Hook != policy {
		t.Fatalf("control: closed %v, rows %+v", holder.closed, rig.posted)
	}
}

// Within one user the handle that can write or append is tried first (it is
// the kind that can refuse a start), also where the system shows no file
// object addresses and every handle is an object of its own; the counts then
// say they count handles.
func TestWindowsHolderTriesTheWriteHandleFirstWhereNoAddressesAreShown(t *testing.T) {
	user := windowsHolderProcess{PID: 4100, Started: 1, SID: fakeUserSID, Session: 2}
	read1 := windowsHolderHandle{Process: user, Handle: 0x40, Access: 0x120089}
	read2 := windowsHolderHandle{Process: user, Handle: 0x44, Access: 0x120089}
	write := windowsHolderHandle{Process: user, Handle: 0x48, Access: fakeWriteAccess}
	ordered, counts := orderWindowsHolderCandidates([]windowsHolderHandle{read1, read2, write})
	if ordered[0].Handle != 0x48 || ordered[1].Handle != 0x40 || ordered[2].Handle != 0x44 {
		t.Fatalf("order %#x %#x %#x, want the write handle first, then by handle value", ordered[0].Handle, ordered[1].Handle, ordered[2].Handle)
	}
	if !counts.NoAddresses || counts.Objects != 3 || !strings.Contains(counts.where(), "counting each handle whose file object address the system does not show") {
		t.Fatalf("counts %+v: %s", counts, counts.where())
	}
	// With addresses shown the counts are file objects.
	read1.Object, read2.Object, write.Object = 0xa0, 0xa0, 0xb0
	_, counts = orderWindowsHolderCandidates([]windowsHolderHandle{read1, read2, write})
	if counts.NoAddresses || counts.where() != "on 2 file object(s)" {
		t.Fatalf("counts %+v: %s", counts, counts.where())
	}
}

// A hold of machine-policy.json (every guarded call fails closed while the
// hook cannot read it) is closed at the second check by the same bounded
// close, with one HIGH row that names the file.
func TestWindowsHolderAHeldMachinePolicyIsClosedAfterTwoChecksWithOneRow(t *testing.T) {
	rig, dir := dataRig(t, "machine-policy.json")
	policy := filepath.Join(dir, "machine-policy.json")
	holder := rig.sys.culprit(0x44)
	proc := rig.sys.add(4100, fakeUserSID, 2, holder)
	keepData(rig)
	if holder.closed {
		t.Fatal("closed at first sight")
	}
	rig.advance(windowsHookBinaryCheckInterval)
	keepData(rig)
	if !holder.closed || len(proc.closeLog) != 1 {
		t.Fatalf("not closed at the second check: %v", proc.closeLog)
	}
	if len(rig.posted) != 1 || !rig.posted[0].Closed || rig.posted[0].Hook != policy {
		t.Fatalf("rows %+v, want one closed=true row for %s", rig.posted, policy)
	}
	event := rig.posted[0].event()
	if event.Target != policy || event.Severity != "HIGH" || !strings.Contains(event.Details, "the hook runtime file "+policy) ||
		!strings.Contains(event.Details, "A read of the file by the hook was refused") || strings.Contains(event.Details, "hook binary") {
		t.Fatalf("event %+v", event)
	}
	if !strings.Contains(rig.log.String(), "closed the handle") || !strings.Contains(rig.log.String(), "the hook runtime file") {
		t.Fatalf("log %q", rig.log.String())
	}
	// The hold is gone: the next check is quiet.
	rig.advance(windowsHookBinaryCheckInterval)
	keepData(rig)
	if len(rig.posted) != 1 {
		t.Fatalf("rows after the hold ended: %d", len(rig.posted))
	}
}

// A file that is held but is not on the watch list is never looked at: no
// scan, no close, no row. A held watched file does not draw the guardian to
// its neighbour, and each file has its own gate.
func TestWindowsHolderAHeldFileThatIsNotWatchedIsIgnored(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig, _ := dataRig(t, outside)
	holder := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, holder)
	for i := 0; i < 6; i++ {
		keepData(rig)
		rig.advance(windowsHookBinaryCheckInterval)
	}
	if rig.sys.snapshots != 0 || holder.closed || len(rig.posted) != 0 {
		t.Fatalf("a file outside the runtime folder was acted on: scans %d, closed %v, rows %d", rig.sys.snapshots, holder.closed, len(rig.posted))
	}
	// Two watched files, one held: the gates are separate.
	rig2, dir2 := dataRig(t, "machine-policy.json")
	a, b := filepath.Join(dir2, "machine-policy.json"), filepath.Join(dir2, "copilot", "enrollment.json")
	h2 := rig2.sys.culprit(0x44)
	rig2.sys.add(4100, fakeUserSID, 2, h2)
	keepData(rig2)
	rig2.advance(windowsHookBinaryCheckInterval)
	keepData(rig2)
	if !h2.closed || len(windowsHolderDataGates) != len(windowsHookRuntimeWatchList(dir2)) || windowsHolderDataGates[strings.ToLower(a)].closes != 1 || windowsHolderDataGates[strings.ToLower(b)].closes != 0 {
		t.Fatalf("closed %v, gates %d", h2.closed, len(windowsHolderDataGates))
	}
}

// Outside the standalone profile the guardian reads no handle table for a
// runtime file.
func TestWindowsHolderDataFilesAreLeftAloneOutsideTheStandaloneProfile(t *testing.T) {
	rig, _ := dataRig(t, "machine-policy.json")
	windowsHolderStandalone = func() bool { return false }
	holder := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, holder)
	for i := 0; i < 4; i++ {
		keepData(rig)
		rig.advance(windowsHookBinaryCheckInterval)
	}
	if rig.sys.snapshots != 0 || holder.closed || len(rig.posted) != 0 {
		t.Fatalf("outside the standalone profile: scans %d, closed %v, rows %d", rig.sys.snapshots, holder.closed, len(rig.posted))
	}
}

// A service's hold of the file is named and not closed, like the hook binary's.
func TestWindowsHolderAServiceHoldOfARuntimeFileIsNamedAndNotClosed(t *testing.T) {
	rig, dir := dataRig(t, "machine-policy.json")
	policy := filepath.Join(dir, "machine-policy.json")
	service := rig.sys.culprit(0x90)
	service.access = fakeWriteAccess
	rig.sys.add(700, "S-1-5-18", 0, service)
	user := rig.sys.sharing(0x44)
	rig.sys.add(4100, fakeUserSID, 2, user)
	for i := 0; i < 4; i++ {
		keepData(rig)
		rig.advance(windowsHookBinaryCheckInterval)
	}
	if service.closed || user.closed {
		t.Fatal("a handle was closed while a service holds the file")
	}
	if len(rig.posted) != 1 || rig.posted[0].Closed || rig.posted[0].Hook != policy || !strings.Contains(rig.posted[0].Reason, "LocalSystem") {
		t.Fatalf("rows %+v", rig.posted)
	}
	if !strings.Contains(rig.log.String(), "the hook runtime file "+policy+" is held open") {
		t.Fatalf("log %q", rig.log.String())
	}
}

func waitFor(t *testing.T, limit time.Duration, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
