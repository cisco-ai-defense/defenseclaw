//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
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

// GAP-0755 round 4: the bounds of the guardian's handle close, tested with an
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
	notFile    bool          // its object type is not File: the scan must not touch it
	denyDelete bool          // this is the handle that refuses every start
	block      chan struct{} // Identify does not answer until it is closed (a synchronous pipe)
	closeBlock chan struct{} // CloseIf does not answer until it is closed (the value became a blocked pipe)
	// ignoreGiveUp makes CloseIf close even after the guardian gave up on it:
	// the narrow race between the live check and DuplicateHandle.
	ignoreGiveUp bool
	reuse        bool // the value names something else by the time of the close
	closed       bool
	object       uintptr // the file object address the handle table shows
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

func (p *fakeHolderProcess) CloseIf(handle uintptr, want windowsHookHolderIdentity, proceed func() bool) error {
	h := p.find(handle)
	if h != nil && h.closeBlock != nil {
		<-h.closeBlock
		if !h.ignoreGiveUp && !proceed() {
			return errWindowsHolderTimedOut
		}
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
	savedTimeout, savedHung, savedProbes, savedWrite := windowsHolderProbeTimeout, windowsHolderMaxHung, windowsHolderMaxProbes, windowsHolderAuditWrite
	windowsHolderStandalone = func() bool { return true }
	windowsHolderSys = rig.sys
	windowsHookBinaryDeleteBlocked = func(string) bool { return rig.sys.blocked() }
	windowsHolderAuditPost = func(row windowsHolderAuditRow) error { rig.posted = append(rig.posted, row); return nil }
	windowsHolderUserName = func(sid string) string { return `HOST\user-` + sid[len(sid)-4:] }
	resetWindowsHolderOutputForTest()
	t.Cleanup(func() {
		windowsHolderStandalone, windowsHolderSys, windowsHookBinaryDeleteBlocked, windowsHolderAuditPost, windowsHolderUserName = savedStandalone, savedSys, savedBlocked, savedPost, savedName
		windowsHolderProbeTimeout, windowsHolderMaxHung, windowsHolderMaxProbes, windowsHolderAuditWrite = savedTimeout, savedHung, savedProbes, savedWrite
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
	windowsHolderLateMu.Lock()
	windowsHolderLate = nil
	windowsHolderLateMu.Unlock()
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
	reportWindowsHookHolders(&r.log)
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

// S1: the hold is the hook staying blocked with a candidate of the same user
// (account and session), whatever the handle value or the process. A user who
// hands the open file to a new handle or process before each check does not
// escape, and a brief hold is still never closed.
func TestWindowsHolderTheSameUserWithAnotherHandleOrProcessIsTheSameHold(t *testing.T) {
	rig := newHoldRig(t)
	first := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, first)
	if closed, err := rig.check(); closed != 0 || err != nil {
		t.Fatalf("first sight: %d, %v", closed, err)
	}
	// The file object is handed to another process (a new id, a new handle
	// value) and the old handle is closed, so the hook is never free.
	first.closed = true
	second := rig.sys.culprit(0x78)
	rig.sys.add(4200, fakeUserSID, 2, second)
	if closed, err := rig.tick(); closed != 1 || err != nil || !second.closed {
		t.Fatalf("the handed-on handle was not closed at the second check: %d, %v", closed, err)
	}
	if len(rig.posted) != 1 || rig.posted[0].Holder.PID != 4200 {
		t.Fatalf("rows %+v, want one row for the process that held it when it was closed", rig.posted)
	}
}

// A process that ended and a new one that got its id and its handle value, for
// the same user, is the same hold as well; the creation time still tells them
// apart in the audit row.
func TestWindowsHolderReusedProcessIdOfTheSameUserIsClosedAtTheSecondCheck(t *testing.T) {
	rig := newHoldRig(t)
	rig.sys.add(4100, fakeUserSID, 2, rig.sys.culprit(0x44))
	if _, err := rig.check(); err != nil {
		t.Fatal(err)
	}
	replacement := rig.sys.add(4100, fakeUserSID, 2, rig.sys.culprit(0x44))
	replacement.facts.Started += 777
	if closed, err := rig.tick(); closed != 1 || err != nil {
		t.Fatalf("the replacement process: %d, %v", closed, err)
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

// S4. A handle in a service that merely has the hook open (a scanner, a
// backup) is named and skipped; it does not keep a user's handle in place.
func TestWindowsHolderASecondNameHeldByAServiceIsNamedAndSkipped(t *testing.T) {
	rig := newHoldRig(t)
	user := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, user)
	service := rig.sys.sharing(0x90)
	rig.sys.add(700, "S-1-5-18", 0, service)
	if _, err := rig.check(); err != nil {
		t.Fatal(err)
	}
	closed, err := rig.tick()
	if closed != 1 || err != nil || !user.closed || service.closed {
		t.Fatalf("closed %d, %v (user closed %v, service closed %v)", closed, err, user.closed, service.closed)
	}
	if len(rig.posted) != 2 {
		t.Fatalf("rows %d, want one for the close and one for the service", len(rig.posted))
	}
	var named bool
	for _, row := range rig.posted {
		if row.Holder.PID == 700 && !row.Closed && strings.Contains(row.Reason, "LocalSystem") {
			named = true
		}
	}
	if !named || !strings.Contains(rig.log.String(), "also open and not closed") || !strings.Contains(rig.log.String(), "LocalSystem") {
		t.Fatalf("the service was not named: rows %+v, log %q", rig.posted, rig.log.String())
	}
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
	// Two hours with the gateway down: far past the 24 checks of round 4.
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
	windowsHookBinaryMu.Lock() // the guardian's mutex is free while the post is stuck
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
	if closed != 0 || err == nil || !strings.Contains(err.Error(), "did not answer in time") || !strings.Contains(err.Error(), "tries again at the next check") {
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
	if late := takeWindowsHolderLateCloses(); len(late) != 0 {
		t.Fatalf("late closes %v", late)
	}
	// With the pipe gone the next check closes it.
	culprit.closeBlock = nil
	if closed, err := rig.tick(); closed != 1 || err != nil || !culprit.closed {
		t.Fatalf("next check: closed %d, %v", closed, err)
	}
}

// A close that was already past its last check when the guardian gave up is
// still audited, at the next pass.
func TestWindowsHolderACloseThatFinishesLateIsAuditedAtTheNextPass(t *testing.T) {
	rig := newHoldRig(t)
	windowsHolderProbeTimeout = 20 * time.Millisecond
	culprit := rig.sys.culprit(0x44)
	culprit.closeBlock, culprit.ignoreGiveUp = make(chan struct{}), true
	rig.sys.add(4100, fakeUserSID, 2, culprit)
	_, _ = rig.check()
	if closed, err := rig.tick(); closed != 0 || err == nil {
		t.Fatalf("closed %d, %v", closed, err)
	}
	close(culprit.closeBlock)
	waitFor(t, 2*time.Second, func() bool { return windowsHolderHung.Load() == 0 })
	if !culprit.closed {
		t.Fatal("the fixture's late close did not happen")
	}
	if _, err := rig.tick(); err != nil && !strings.Contains(err.Error(), "found no handle") {
		t.Fatal(err)
	}
	if len(rig.posted) != 1 || !rig.posted[0].Closed || rig.posted[0].Holder.PID != 4100 {
		t.Fatalf("rows %+v, want the late close audited", rig.posted)
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
	rig2 := newHoldRig(t)
	found := rig2.sys.add(4100, fakeUserSID, 2, rig2.sys.culprit(0x44))
	_, _ = rig2.check()
	_, _ = rig2.tick()
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

// S1. The holder rotates its handle (and its process) before every check. It
// is closed at the second check, and the guardian then backs off.
func TestWindowsHolderARotatingHolderIsClosedAtTheSecondCheckAndBacksOff(t *testing.T) {
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
	closed, err := rig.tick()
	if closed != 1 || err != nil || !current.closed {
		t.Fatalf("second check: closed %d, %v", closed, err)
	}
	// It takes the file again with a new handle each tick: closed again no
	// sooner than the backoff, scans bounded, one row per process.
	var closes []time.Duration
	elapsed := time.Duration(0)
	for elapsed < 130*time.Second {
		current = rotate()
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
	// One scan per check at most while it is not closing, and not one per
	// check once it is: the scans are bounded by the backoff.
	if rig.sys.snapshots > 12 {
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
