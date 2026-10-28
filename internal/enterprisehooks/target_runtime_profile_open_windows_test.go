//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// shortenWindowsManagedRuntimeProfileRetry swaps in an n-attempt schedule with
// no real sleeping and a fresh budget, and counts CreateFile calls.
func shortenWindowsManagedRuntimeProfileRetry(t *testing.T, attempts int, onSleep func(call int)) *int {
	t.Helper()
	schedule := make([]time.Duration, attempts)
	for index := 1; index < attempts; index++ {
		schedule[index] = time.Millisecond
	}
	previousSchedule := windowsManagedRuntimeProfileRetrySchedule
	previousSleep := windowsManagedRuntimeProfileSleep
	previousCreate := windowsManagedRuntimeProfileCreateFile
	previousBudget := windowsManagedRuntimeProfileRetryBudget
	windowsManagedRuntimeProfileRetrySchedule = schedule
	windowsManagedRuntimeProfileRetryBudget = time.Hour
	resetWindowsManagedRuntimeProfileRetrySpent()
	sleeps := 0
	windowsManagedRuntimeProfileSleep = func(time.Duration) {
		sleeps++
		if onSleep != nil {
			onSleep(sleeps)
		}
	}
	calls := 0
	windowsManagedRuntimeProfileCreateFile = func(
		name *uint16, access, share uint32, sa *windows.SecurityAttributes, disposition, flags uint32, template windows.Handle,
	) (windows.Handle, error) {
		calls++
		return previousCreate(name, access, share, sa, disposition, flags, template)
	}
	t.Cleanup(func() {
		windowsManagedRuntimeProfileRetrySchedule = previousSchedule
		windowsManagedRuntimeProfileSleep = previousSleep
		windowsManagedRuntimeProfileCreateFile = previousCreate
		windowsManagedRuntimeProfileRetryBudget = previousBudget
		resetWindowsManagedRuntimeProfileRetrySpent()
	})
	return &calls
}

func resetWindowsManagedRuntimeProfileRetrySpent() {
	windowsManagedRuntimeProfileRetrySpent.Lock()
	windowsManagedRuntimeProfileRetrySpent.total = 0
	windowsManagedRuntimeProfileRetrySpent.Unlock()
}

// holdWindowsTestDirectory opens dir the way a third-party holder would and
// returns a release func that is safe to call more than once.
func holdWindowsTestDirectory(t *testing.T, dir string, access, share uint32) func() {
	t.Helper()
	extended, err := winpath.Extended(dir)
	if err != nil {
		t.Fatal(err)
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(ptr, access, share, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatalf("hold %s: %v", dir, err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			_ = windows.CloseHandle(handle)
		}
	}
	t.Cleanup(release)
	return release
}

func newWindowsManagedRuntimeProfileTarget(t *testing.T) windowsManagedRuntimeTarget {
	t.Helper()
	sid := currentWindowsTestSID(t)
	home := newWindowsManagedRuntimeBAOwnedProfile(t, sid)
	target, err := resolveWindowsManagedRuntimeTarget(home, sid.String(), filepath.Join(home, ".defenseclaw"))
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func openWindowsManagedRuntimeProfileUnderPrivilege(target windowsManagedRuntimeTarget, access windowsManagedRuntimeProfileAccess) error {
	return windowsManagedRuntimeSetupPrivilege(func() error {
		handle, err := openWindowsManagedRuntimeProfile(target, access)
		if err == nil {
			_ = windows.CloseHandle(handle)
		}
		return err
	})
}

// The field failure: a holder that reads the home folder but does not share
// writing made planning fail with ERROR_SHARING_VIOLATION, because planning
// asked for FILE_APPEND_DATA it never used.
func TestWindowsManagedRuntimePlanSucceedsWhileHomeIsHeldForReading(t *testing.T) {
	sid := currentWindowsTestSID(t)
	home := newWindowsManagedRuntimeBAOwnedProfile(t, sid)
	calls := shortenWindowsManagedRuntimeProfileRetry(t, 3, nil)
	holdWindowsTestDirectory(t, home, windows.GENERIC_READ, windows.FILE_SHARE_READ)

	plan, err := PlanWindowsManagedRuntimeRoots(
		windowsManagedRuntimeTestManifest(home, sid),
		`C:\ProgramData\DefenseClaw\etc\targets.yaml`,
		strings.Repeat("a", 64),
	)
	if err != nil {
		t.Fatalf("plan with a read-only holder on the home folder: %v", err)
	}
	if len(plan.Roots) != 1 {
		t.Fatalf("plan roots = %+v, want one", plan.Roots)
	}
	if *calls != 1 {
		t.Fatalf("read-mode open took %d attempts, want 1 (no collision)", *calls)
	}
}

func TestWindowsManagedRuntimeMutateOpenRetriesUntilHolderReleases(t *testing.T) {
	target := newWindowsManagedRuntimeProfileTarget(t)
	var release func()
	calls := shortenWindowsManagedRuntimeProfileRetry(t, 5, func(sleep int) {
		if sleep == 2 {
			release()
		}
	})
	release = holdWindowsTestDirectory(t, target.home, windows.GENERIC_READ, windows.FILE_SHARE_READ)

	if err := openWindowsManagedRuntimeProfileUnderPrivilege(target, windowsManagedRuntimeProfileMutate); err != nil {
		t.Fatalf("mutate open after the holder released: %v", err)
	}
	if *calls != 3 {
		t.Fatalf("mutate open took %d attempts, want 3 (two collisions, then success)", *calls)
	}
}

func TestWindowsManagedRuntimeProfileOpenNamesUserWhenRetriesRunOut(t *testing.T) {
	target := newWindowsManagedRuntimeProfileTarget(t)
	const attempts = 4
	calls := shortenWindowsManagedRuntimeProfileRetry(t, attempts, nil)
	// A holder with delete access collides with both modes: neither shares
	// delete, by design.
	holdWindowsTestDirectory(t, target.home, windows.GENERIC_READ|windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)

	for _, access := range []windowsManagedRuntimeProfileAccess{windowsManagedRuntimeProfileRead, windowsManagedRuntimeProfileMutate} {
		*calls = 0
		resetWindowsManagedRuntimeProfileRetrySpent()
		err := openWindowsManagedRuntimeProfileUnderPrivilege(target, access)
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			t.Fatalf("mode %d error = %v, want a sharing violation", access, err)
		}
		for _, want := range []string{target.sid.String(), target.home, "another process has the folder open", "sharing violation after 4 attempts"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("mode %d error %q does not contain %q", access, err, want)
			}
		}
		if *calls != attempts {
			t.Fatalf("mode %d made %d attempts, want the whole schedule (%d)", access, *calls, attempts)
		}
	}
}

func TestWindowsManagedRuntimeProfileOpenStopsAtProcessRetryBudget(t *testing.T) {
	target := newWindowsManagedRuntimeProfileTarget(t)
	calls := shortenWindowsManagedRuntimeProfileRetry(t, 10, nil)
	windowsManagedRuntimeProfileRetryBudget = 3 * time.Millisecond
	holdWindowsTestDirectory(t, target.home, windows.GENERIC_READ|windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)

	if err := openWindowsManagedRuntimeProfileUnderPrivilege(target, windowsManagedRuntimeProfileRead); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("error = %v, want a sharing violation", err)
	}
	if *calls != 4 {
		t.Fatalf("made %d attempts, want 4 (first try plus the 3 ms budget)", *calls)
	}
	// The budget is per process: a later open gets no retries at all.
	*calls = 0
	if err := openWindowsManagedRuntimeProfileUnderPrivilege(target, windowsManagedRuntimeProfileRead); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("second open error = %v, want a sharing violation", err)
	}
	if *calls != 1 {
		t.Fatalf("second open made %d attempts after the budget was spent, want 1", *calls)
	}
}

func TestWindowsManagedRuntimeProfileOpenDoesNotRetryOtherErrors(t *testing.T) {
	target := newWindowsManagedRuntimeProfileTarget(t)
	for _, injected := range []error{windows.ERROR_ACCESS_DENIED, windows.ERROR_FILE_NOT_FOUND} {
		calls := shortenWindowsManagedRuntimeProfileRetry(t, 5, nil)
		windowsManagedRuntimeProfileCreateFile = func(*uint16, uint32, uint32, *windows.SecurityAttributes, uint32, uint32, windows.Handle) (windows.Handle, error) {
			*calls++
			return windows.InvalidHandle, injected
		}
		err := openWindowsManagedRuntimeProfileUnderPrivilege(target, windowsManagedRuntimeProfileMutate)
		if !errors.Is(err, injected) {
			t.Fatalf("error = %v, want %v", err, injected)
		}
		if *calls != 1 {
			t.Fatalf("%v was retried: %d attempts, want 1", injected, *calls)
		}
		if !strings.Contains(err.Error(), "for "+target.sid.String()+" at "+target.home) {
			t.Fatalf("error %q does not name the user and folder", err)
		}
	}
}

func TestWindowsManagedRuntimeProfileReadModeAsksForNoWriteAccess(t *testing.T) {
	const writeAccess = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
		windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE
	read, readShare, readFlags := windowsManagedRuntimeProfileOpenParameters(windowsManagedRuntimeProfileRead)
	if read&writeAccess != 0 {
		t.Fatalf("read mode access 0x%x includes write-class rights 0x%x", read, read&writeAccess)
	}
	if read&windows.READ_CONTROL == 0 {
		t.Fatal("read mode dropped READ_CONTROL; the guardian ACL check needs it")
	}
	if readFlags&windows.FILE_FLAG_WRITE_THROUGH != 0 {
		t.Fatal("read mode still asks for WRITE_THROUGH")
	}
	mutate, mutateShare, mutateFlags := windowsManagedRuntimeProfileOpenParameters(windowsManagedRuntimeProfileMutate)
	if mutate&windows.FILE_APPEND_DATA == 0 || mutateFlags&windows.FILE_FLAG_WRITE_THROUGH == 0 {
		t.Fatalf("mutate mode access 0x%x flags 0x%x changed from before", mutate, mutateFlags)
	}
	for name, share := range map[string]uint32{"read": readShare, "mutate": mutateShare} {
		if share&windows.FILE_SHARE_DELETE != 0 {
			t.Fatalf("%s mode shares delete; the handle must pin the folder", name)
		}
		if share != windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE {
			t.Fatalf("%s mode share 0x%x changed from before", name, share)
		}
	}

	// And through the real call path.
	target := newWindowsManagedRuntimeProfileTarget(t)
	shortenWindowsManagedRuntimeProfileRetry(t, 1, nil)
	var requested uint32
	previous := windowsManagedRuntimeProfileCreateFile
	windowsManagedRuntimeProfileCreateFile = func(name *uint16, access, share uint32, sa *windows.SecurityAttributes, disposition, flags uint32, template windows.Handle) (windows.Handle, error) {
		requested = access
		return previous(name, access, share, sa, disposition, flags, template)
	}
	if err := openWindowsManagedRuntimeProfileUnderPrivilege(target, windowsManagedRuntimeProfileRead); err != nil {
		t.Fatalf("read-mode open: %v", err)
	}
	if requested != read {
		t.Fatalf("read-mode open requested 0x%x, want 0x%x", requested, read)
	}
}

func TestWindowsManagedRuntimePlanSkipsProfileStillBusyAfterRetries(t *testing.T) {
	sid := currentWindowsTestSID(t)
	home := newWindowsManagedRuntimeBAOwnedProfile(t, sid)
	shortenWindowsManagedRuntimeProfileRetry(t, 3, nil)
	holdWindowsTestDirectory(t, home, windows.GENERIC_READ|windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	manifest := windowsManagedRuntimeTestManifest(home, sid)
	manifestPath := `C:\ProgramData\DefenseClaw\etc\targets.yaml`

	// Without the skip, a busy profile still fails the whole plan.
	if _, err := PlanWindowsManagedRuntimeRoots(manifest, manifestPath, strings.Repeat("a", 64)); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("plan without skipping: error = %v, want a sharing violation", err)
	}

	resetWindowsManagedRuntimeProfileRetrySpent()
	var published *Manifest
	plan, err := PlanWindowsManagedRuntimeRootsSkippingBusyProfiles(
		manifest, manifestPath, strings.Repeat("a", 64),
		func(reduced Manifest) (string, error) {
			published = &reduced
			return strings.Repeat("b", 64), nil
		},
	)
	if err != nil {
		t.Fatalf("plan skipping busy profiles: %v", err)
	}
	if published == nil || len(published.Targets) != 0 {
		t.Fatalf("published manifest = %+v, want every row of the busy user removed", published)
	}
	if plan.ManifestSHA256 != strings.Repeat("b", 64) || plan.TargetCount != 0 || len(plan.Roots) != 0 {
		t.Fatalf("plan = %+v, want it bound to the reduced manifest with no roots", plan)
	}
	if len(plan.SkippedProfiles) != 1 {
		t.Fatalf("skipped profiles = %+v, want one", plan.SkippedProfiles)
	}
	skipped := plan.SkippedProfiles[0]
	if skipped.SID != sid.String() || skipped.UserHome != home ||
		!strings.Contains(skipped.Reason, "another process has the folder open") {
		t.Fatalf("skipped profile = %+v, want the user, folder and cause", skipped)
	}
}

func TestWindowsManagedRuntimePlanSkipKeepsOtherErrorsFatal(t *testing.T) {
	sid := currentWindowsTestSID(t)
	home := newWindowsManagedRuntimeBAOwnedProfile(t, sid)
	shortenWindowsManagedRuntimeProfileRetry(t, 3, nil)
	windowsManagedRuntimeProfileCreateFile = func(*uint16, uint32, uint32, *windows.SecurityAttributes, uint32, uint32, windows.Handle) (windows.Handle, error) {
		return windows.InvalidHandle, windows.ERROR_ACCESS_DENIED
	}
	published := false
	_, err := PlanWindowsManagedRuntimeRootsSkippingBusyProfiles(
		windowsManagedRuntimeTestManifest(home, sid),
		`C:\ProgramData\DefenseClaw\etc\targets.yaml`,
		strings.Repeat("a", 64),
		func(Manifest) (string, error) { published = true; return strings.Repeat("b", 64), nil },
	)
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("error = %v, want access denied to stay fatal", err)
	}
	if published {
		t.Fatal("the manifest was rewritten for a non-busy failure")
	}
}

func TestWindowsManagedRuntimeSkippedProfilesValidation(t *testing.T) {
	sid := currentWindowsTestSID(t)
	other := "S-1-5-21-111-222-333-1009"
	manifest := windowsManagedRuntimeTestManifest(`C:\Users\carol`, sid)
	ok := WindowsManagedRuntimeSkippedProfile{SID: other, UserHome: `C:\Users\dave`, Reason: "sharing violation"}
	if err := validateWindowsManagedRuntimeSkippedProfiles([]WindowsManagedRuntimeSkippedProfile{ok}, manifest); err != nil {
		t.Fatalf("valid skipped profile rejected: %v", err)
	}
	for name, bad := range map[string][]WindowsManagedRuntimeSkippedProfile{
		"still enrolled": {{SID: sid.String(), UserHome: `C:\Users\carol`, Reason: "busy"}},
		"duplicate":      {ok, ok},
		"empty reason":   {{SID: other, UserHome: `C:\Users\dave`, Reason: " "}},
		"relative home":  {{SID: other, UserHome: `Users\dave`, Reason: "busy"}},
		"invalid SID":    {{SID: "not-a-sid", UserHome: `C:\Users\dave`, Reason: "busy"}},
		"long reason":    {{SID: other, UserHome: `C:\Users\dave`, Reason: strings.Repeat("x", windowsManagedRuntimeSkipReasonMax+1)}},
	} {
		if err := validateWindowsManagedRuntimeSkippedProfiles(bad, manifest); err == nil {
			t.Fatalf("%s: invalid skipped profile accepted", name)
		}
	}
	if got := boundWindowsManagedRuntimeSkipReason("a\r\nb\x00c"); got != "a  b c" {
		t.Fatalf("bounded reason = %q, want control characters folded", got)
	}
}
