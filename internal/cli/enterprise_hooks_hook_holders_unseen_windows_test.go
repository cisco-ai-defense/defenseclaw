//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// rel-1-0-10 GAP-0068 review: a check whose scan finds nobody while the hook
// stays refused keeps the users seen before (a holder that rotated its
// handle), but only for three checks after they were last seen. The backoff
// refreshed their last sighting at every check, so a hold the scan cannot see
// (a protected process) kept them for as long as it lasted, and the first
// sighting of the user after it was closed at once as its second check.
func TestWindowsHolderAHoldTheScanCannotSeeDoesNotKeepAUser(t *testing.T) {
	rig := newHoldRig(t)
	first := rig.sys.culprit(0x44)
	user := rig.sys.add(4100, fakeUserSID, 2, first)
	if closed, err := rig.check(); closed != 0 || err != nil {
		t.Fatalf("first sight: closed %d, %v", closed, err)
	}
	// The user lets go and a protected process takes the hook: it stays
	// refused, and no scan sees who holds it.
	first.closed = true
	rig.sys.add(4200, fakeOtherUserSID, 2, rig.sys.culprit(0x60)).openErr = windows.ERROR_ACCESS_DENIED
	for i := 0; i < 24; i++ { // two minutes of 5 s checks, through the backoff
		if closed, _ := rig.tick(); closed != 0 {
			t.Fatalf("check %d: closed %d while nobody the scan sees holds the hook", i+2, closed)
		}
	}
	// The protected process lets go and the user takes the hook again.
	delete(rig.sys.procs, 4200)
	again := rig.sys.culprit(0x48)
	user.handles = append(user.handles, again)
	scans := rig.sys.snapshots
	for i := 0; rig.sys.snapshots == scans; i++ {
		if i > 80 {
			t.Fatalf("no scan in %d checks after the protected process let go", i)
		}
		if closed, _ := rig.tick(); closed != 0 || again.closed {
			t.Fatalf("the user's first sighting in two minutes was closed at once (closed %d): it was its first check, not its second", closed)
		}
	}
	closed, err := rig.tick()
	if closed != 1 || err != nil || !again.closed || len(user.closeLog) != 1 {
		t.Fatalf("next check: closed %d, %v, closes %v (seen at two checks in a row, the hook refused)", closed, err, user.closeLog)
	}
}

// deniedProbeSystem is the fake handle table with processes whose handles
// cannot be duplicated for a reason other than a closed handle (access denied).
type deniedProbeSystem struct {
	*fakeHolderSystem
	deny map[uint32]bool
}

func (s deniedProbeSystem) OpenProcess(pid uint32) (windowsHolderProc, error) {
	proc, err := s.fakeHolderSystem.OpenProcess(pid)
	if err != nil || !s.deny[pid] {
		return proc, err
	}
	return deniedProbeProc{proc}, nil
}

type deniedProbeProc struct{ windowsHolderProc }

func (deniedProbeProc) Identify(uintptr) (windowsHookHolderIdentity, bool, error) {
	return windowsHookHolderIdentity{}, false, windows.ERROR_ACCESS_DENIED
}

// rel-1-0-10 GAP-0068 review: only a listed handle that is no longer a handle
// (ERROR_INVALID_HANDLE) is one a holder rotated away; a probe that failed
// otherwise does not make the check scan the handle table again.
func TestWindowsHolderOnlyAClosedHandleMakesAnEmptyCheckLookAgain(t *testing.T) {
	rig := newHoldRig(t)
	rig.sys.add(4200, fakeOtherUserSID, 2, rig.sys.culprit(0x60)).openErr = windows.ERROR_ACCESS_DENIED
	rig.sys.add(4300, fakeUserSID, 2, rig.sys.sharing(0x70))
	windowsHolderSys = deniedProbeSystem{fakeHolderSystem: rig.sys, deny: map[uint32]bool{4300: true}}
	if closed, err := rig.check(); closed != 0 || err != nil || rig.sys.snapshots != 1 {
		t.Fatalf("closed %d, %v, %d scans; want one scan (a denied probe is not a rotated handle)", closed, err, rig.sys.snapshots)
	}
}

// The rig's fake processes are seen whatever their ids. The scan skips the
// guardian's own process id, and a fake id equal to the test process's own
// (Windows ids are multiples of 4, as the fake ones are) made that fake
// process invisible: tests that need it failed only on the runs where the
// test process got that id.
func TestWindowsHolderRigSeesAFakeProcessWithTheTestsOwnID(t *testing.T) {
	rig := newHoldRig(t)
	holder := rig.sys.culprit(0x44)
	proc := rig.sys.add(uint32(os.Getpid()), fakeUserSID, 2, holder)
	if closed, err := rig.check(); closed != 0 || err != nil {
		t.Fatalf("first check: closed %d, %v", closed, err)
	}
	if closed, err := rig.tick(); closed != 1 || err != nil || !holder.closed || len(proc.closeLog) != 1 {
		t.Fatalf("second check: closed %d, %v (a fake process with the test's own id was not seen)", closed, err)
	}
}
