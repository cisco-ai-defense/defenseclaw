//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	reuse      bool          // the value names something else by the time of the close
	closed     bool
}

type fakeHolderProcess struct {
	system   *fakeHolderSystem
	facts    windowsHolderProcess
	handles  []*fakeHolderHandle
	openErr  error
	closeLog []uintptr
	// attributes are the handle-table attributes of every handle it holds.
	attributes uint32
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

func (p *fakeHolderProcess) CloseIf(handle uintptr, want windowsHookHolderIdentity) error {
	h := p.find(handle)
	if h == nil || h.reuse || !h.disk || h.id != want {
		return errWindowsHolderChanged
	}
	h.closed = true
	p.closeLog = append(p.closeLog, handle)
	return nil
}

func (p *fakeHolderProcess) Release() {}

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
			snapshot.Entries = append(snapshot.Entries, windowsHandleEntryEx{UniqueProcessID: uintptr(pid), HandleValue: h.value, GrantedAccess: h.access, ObjectTypeIndex: index, HandleAttributes: p.attributes})
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
	savedTimeout, savedHung, savedProbes := windowsHolderProbeTimeout, windowsHolderMaxHung, windowsHolderMaxProbes
	windowsHolderStandalone = func() bool { return true }
	windowsHolderSys = rig.sys
	windowsHookBinaryDeleteBlocked = func(string) bool { return rig.sys.blocked() }
	windowsHolderAuditPost = func(row windowsHolderAuditRow) error { rig.posted = append(rig.posted, row); return nil }
	windowsHolderUserName = func(sid string) string { return `HOST\user-` + sid[len(sid)-4:] }
	windowsHolderGate, windowsHolderLog, windowsHolderAuditQueue = windowsHolderState{}, nil, nil
	t.Cleanup(func() {
		windowsHolderStandalone, windowsHolderSys, windowsHookBinaryDeleteBlocked, windowsHolderAuditPost, windowsHolderUserName = savedStandalone, savedSys, savedBlocked, savedPost, savedName
		windowsHolderProbeTimeout, windowsHolderMaxHung, windowsHolderMaxProbes = savedTimeout, savedHung, savedProbes
		windowsHolderGate, windowsHolderLog, windowsHolderAuditQueue = windowsHolderState{}, nil, nil
	})
	return rig
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
	// A different process holds it at the next tick: not the same hold.
	first.closed = true
	second := rig.sys.culprit(0x50)
	rig.sys.add(4200, fakeUserSID, 2, second)
	if closed, err := rig.tick(); closed != 0 || err != nil || second.closed {
		t.Fatalf("another holder at the second tick: closed %d, %v", closed, err)
	}
	if len(rig.posted) != 0 {
		t.Fatalf("rows for holds that were never closed: %d", len(rig.posted))
	}
}

func TestWindowsHolderReusedProcessIdIsNotTheSameHolder(t *testing.T) {
	rig := newHoldRig(t)
	rig.sys.add(4100, fakeUserSID, 2, rig.sys.culprit(0x44))
	if _, err := rig.check(); err != nil {
		t.Fatal(err)
	}
	// The process ended and a new one got its id and its handle value.
	replacement := rig.sys.add(4100, fakeUserSID, 2, rig.sys.culprit(0x44))
	replacement.facts.Started += 777
	if closed, err := rig.tick(); closed != 0 || err != nil {
		t.Fatalf("the replacement process was closed at its first sight: %d, %v", closed, err)
	}
	if closed, err := rig.tick(); closed != 1 || err != nil {
		t.Fatalf("the replacement at its second sight: %d, %v", closed, err)
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

// Another name for the same file id, held by a service, is judged by the
// process that holds it, like every other handle on the file object.
func TestWindowsHolderASecondNameHeldByAServiceStopsTheClose(t *testing.T) {
	rig := newHoldRig(t)
	user := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, user)
	service := rig.sys.sharing(0x90)
	rig.sys.add(700, "S-1-5-18", 0, service)
	if _, err := rig.check(); err != nil {
		t.Fatal(err)
	}
	closed, err := rig.tick()
	if closed != 0 || err == nil || !strings.Contains(err.Error(), "LocalSystem") || user.closed || service.closed {
		t.Fatalf("closed %d, %v (user closed %v)", closed, err, user.closed)
	}
}

func TestWindowsHolderNamesAProtectedProcessItCannotInspect(t *testing.T) {
	rig := newHoldRig(t)
	user := rig.sys.culprit(0x44)
	rig.sys.add(4100, fakeUserSID, 2, user)
	protected := rig.sys.add(4200, "S-1-5-18", 0, rig.sys.other(0x10))
	protected.openErr = errors.New("Access is denied.")
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
	rig2.sys.add(4200, "S-1-5-18", 0, rig2.sys.other(0x10)).openErr = errors.New("Access is denied.")
	if _, err := rig2.check(); err != nil {
		t.Fatal(err)
	}
	if closed, err := rig2.tick(); closed != 1 || err != nil || !user2.closed {
		t.Fatalf("unlisted: closed %d, %v", closed, err)
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
	closed, err := rig.tick()
	if closed != 1 || err != nil || !culprit.closed {
		t.Fatalf("closed %d, %v", closed, err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("two passes took %s", elapsed)
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

func TestWindowsHolderAuditRowIsRetriedUntilTheGatewayTakesIt(t *testing.T) {
	rig := newHoldRig(t)
	failures := 2
	windowsHolderAuditPost = func(row windowsHolderAuditRow) error {
		if failures > 0 {
			failures--
			return errors.New("connection refused")
		}
		rig.posted = append(rig.posted, row)
		return nil
	}
	rig.sys.add(4100, fakeUserSID, 2, rig.sys.culprit(0x44))
	_, _ = rig.check()
	if closed, err := rig.tick(); closed != 1 || err != nil {
		t.Fatalf("closed %d, %v", closed, err)
	}
	if len(rig.posted) != 0 || len(windowsHolderAuditQueue) != 1 {
		t.Fatalf("posted %d, queued %d after a refused post", len(rig.posted), len(windowsHolderAuditQueue))
	}
	reportWindowsHookHolders(&rig.log)
	reportWindowsHookHolders(&rig.log)
	if len(rig.posted) != 1 || len(windowsHolderAuditQueue) != 0 || strings.Count(rig.log.String(), "could not record the hook-holder audit row") != 1 {
		t.Fatalf("posted %d, queued %d, log %q", len(rig.posted), len(windowsHolderAuditQueue), rig.log.String())
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
