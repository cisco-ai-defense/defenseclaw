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

	// Upgrade and Repair skip the busy user too, but keep their rows: the
	// plan stays bound to the unchanged manifest and simply has no root.
	validation, err := PlanWindowsManagedRuntimeRoots(manifest, manifestPath, strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("plan without publishing: %v", err)
	}
	if validation.ManifestSHA256 != strings.Repeat("a", 64) || validation.TargetCount != 1 ||
		len(validation.Roots) != 0 || len(validation.SkippedProfiles) != 1 ||
		validation.SkippedProfiles[0].SID != sid.String() {
		t.Fatalf("validation plan = %+v, want the busy user skipped without a manifest change", validation)
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

// One profile the installer cannot open skips that user; it never fails the
// plan for everyone. A failure that is not about one profile still does.
func TestWindowsManagedRuntimePlanSkipsInaccessibleProfileButHostErrorsStayFatal(t *testing.T) {
	sid := currentWindowsTestSID(t)
	home := newWindowsManagedRuntimeBAOwnedProfile(t, sid)
	shortenWindowsManagedRuntimeProfileRetry(t, 3, nil)
	previousCreate := windowsManagedRuntimeProfileCreateFile
	windowsManagedRuntimeProfileCreateFile = func(*uint16, uint32, uint32, *windows.SecurityAttributes, uint32, uint32, windows.Handle) (windows.Handle, error) {
		return windows.InvalidHandle, windows.ERROR_ACCESS_DENIED
	}
	published := false
	plan, err := PlanWindowsManagedRuntimeRootsSkippingBusyProfiles(
		windowsManagedRuntimeTestManifest(home, sid),
		`C:\ProgramData\DefenseClaw\etc\targets.yaml`,
		strings.Repeat("a", 64),
		func(Manifest) (string, error) { published = true; return strings.Repeat("b", 64), nil },
	)
	if err != nil {
		t.Fatalf("plan with an inaccessible profile: %v", err)
	}
	if !published || len(plan.SkippedProfiles) != 1 || len(plan.Roots) != 0 {
		t.Fatalf("plan = %+v, want the inaccessible user skipped and removed", plan)
	}

	windowsManagedRuntimeProfileCreateFile = previousCreate
	resetWindowsManagedRuntimeProfileRetrySpent()
	previousEntropy := windowsManagedRuntimeEntropy
	windowsManagedRuntimeEntropy = strings.NewReader("")
	t.Cleanup(func() { windowsManagedRuntimeEntropy = previousEntropy })
	if _, err := PlanWindowsManagedRuntimeRoots(
		windowsManagedRuntimeTestManifest(home, sid),
		`C:\ProgramData\DefenseClaw\etc\targets.yaml`,
		strings.Repeat("a", 64),
	); !errors.Is(err, errWindowsManagedRuntimePlanHost) {
		t.Fatalf("error = %v, want a host planning failure to stay fatal", err)
	}
}

func TestWindowsManagedRuntimeSkippedProfilesValidation(t *testing.T) {
	sid := currentWindowsTestSID(t)
	other := "S-1-5-21-111-222-333-1009"
	manifest := windowsManagedRuntimeTestManifest(`C:\Users\carol`, sid)
	// Upgrade and Repair skip a user without revoking their rows.
	stillEnrolled := WindowsManagedRuntimeSkippedProfile{SID: sid.String(), UserHome: `C:\Users\carol`, Reason: "busy"}
	if err := validateWindowsManagedRuntimeSkippedProfiles([]WindowsManagedRuntimeSkippedProfile{stillEnrolled}, manifest); err != nil {
		t.Fatalf("skipped user still enrolled rejected: %v", err)
	}
	ok := WindowsManagedRuntimeSkippedProfile{SID: other, UserHome: `C:\Users\dave`, Reason: "sharing violation"}
	if err := validateWindowsManagedRuntimeSkippedProfiles([]WindowsManagedRuntimeSkippedProfile{ok}, manifest); err != nil {
		t.Fatalf("valid skipped profile rejected: %v", err)
	}
	for name, bad := range map[string][]WindowsManagedRuntimeSkippedProfile{
		"duplicate":     {ok, ok},
		"empty reason":  {{SID: other, UserHome: `C:\Users\dave`, Reason: " "}},
		"relative home": {{SID: other, UserHome: `Users\dave`, Reason: "busy"}},
		"invalid SID":   {{SID: "not-a-sid", UserHome: `C:\Users\dave`, Reason: "busy"}},
		"long reason":   {{SID: other, UserHome: `C:\Users\dave`, Reason: strings.Repeat("x", windowsManagedRuntimeSkipReasonMax+1)}},
	} {
		if err := validateWindowsManagedRuntimeSkippedProfiles(bad, manifest); err == nil {
			t.Fatalf("%s: invalid skipped profile accepted", name)
		}
	}
	if got := boundWindowsManagedRuntimeSkipReason("a\r\nb\x00c"); got != "a  b c" {
		t.Fatalf("bounded reason = %q, want control characters folded", got)
	}
}

// A holder that reads the folder without sharing writes does not stop
// planning, but staging's and finalize's write opens would collide with it
// after planning, failing the install for everyone. A fresh Install probes
// that open while planning and skips the user instead.
func TestWindowsManagedRuntimeFreshInstallPlanSkipsUserBlockedForWriters(t *testing.T) {
	sid := currentWindowsTestSID(t)
	home := newWindowsManagedRuntimeBAOwnedProfile(t, sid)
	shortenWindowsManagedRuntimeProfileRetry(t, 3, nil)
	holdWindowsTestDirectory(t, home, windows.GENERIC_READ, windows.FILE_SHARE_READ)

	plan, err := PlanWindowsManagedRuntimeRootsSkippingBusyProfiles(
		windowsManagedRuntimeTestManifest(home, sid),
		`C:\ProgramData\DefenseClaw\etc\targets.yaml`,
		strings.Repeat("a", 64),
		func(Manifest) (string, error) { return strings.Repeat("b", 64), nil },
	)
	if err != nil {
		t.Fatalf("fresh-install plan with a writer-blocking holder: %v", err)
	}
	if len(plan.Roots) != 0 || len(plan.SkippedProfiles) != 1 || plan.SkippedProfiles[0].SID != sid.String() {
		t.Fatalf("plan = %+v, want the user skipped because staging could not open the folder", plan)
	}
}

// A retained .defenseclaw whose DACL drifted (here: every canonical entry
// replaced by one full-control grant) fails every fresh Install for every user
// unless it is repaired. Every planning mode re-stamps the canonical
// descriptor, records the repair, and plans the root as a canonical baseline.
func TestWindowsManagedRuntimeFreshInstallPlanRepairsDriftedRetainedRoot(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	dataDir := filepath.Join(home, ".defenseclaw")
	if _, err := ensureWindowsTargetOwnedDirectoryTree(home, filepath.Join(dataDir, "hooks"), target); err != nil {
		t.Fatal(err)
	}
	drifted, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		windowsManagedRuntimeTestAccess(target, 0x001f01ff),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		dataDir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, drifted, nil,
	); err != nil {
		t.Fatal(err)
	}
	manifest := windowsManagedRuntimeTestManifest(home, target)
	manifestPath := `C:\ProgramData\DefenseClaw\etc\targets.yaml`

	validation, err := PlanWindowsManagedRuntimeRoots(manifest, manifestPath, strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("Upgrade/Repair plan with a drifted retained root: %v", err)
	}
	if len(validation.RepairedProfiles) != 1 || len(validation.SkippedProfiles) != 0 || len(validation.Roots) != 1 {
		t.Fatalf("Upgrade/Repair plan = %+v, want the drifted root repaired", validation)
	}
	if err := windows.SetNamedSecurityInfo(
		dataDir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, drifted, nil,
	); err != nil {
		t.Fatal(err)
	}

	published := false
	plan, err := PlanWindowsManagedRuntimeRootsSkippingBusyProfiles(
		manifest, manifestPath, strings.Repeat("a", 64),
		func(Manifest) (string, error) { published = true; return strings.Repeat("b", 64), nil },
	)
	if err != nil {
		t.Fatalf("fresh-install plan with a drifted retained root: %v", err)
	}
	if published || len(plan.SkippedProfiles) != 0 {
		t.Fatalf("plan skipped the user instead of repairing: %+v", plan)
	}
	if len(plan.Roots) != 1 || plan.Roots[0].Baseline != windowsManagedRuntimeBaselineCanonical {
		t.Fatalf("plan roots = %+v, want the repaired root as a canonical baseline", plan.Roots)
	}
	if len(plan.RepairedProfiles) != 1 || plan.RepairedProfiles[0].SID != target.String() ||
		strings.TrimSpace(plan.RepairedProfiles[0].Reason) == "" {
		t.Fatalf("repaired profiles = %+v, want the user with the drift reason", plan.RepairedProfiles)
	}
	assertWindowsTargetOwnedCanonicalDirectory(t, dataDir, target)
}

// A row whose profile no longer exists (deleted or renamed after the last
// enumeration) skips that user. The other user is still planned, and
// Upgrade/Repair keep the stale rows rather than revoke them.
func TestWindowsManagedRuntimePlanSkipsRowWhoseProfileIsGone(t *testing.T) {
	sid := currentWindowsTestSID(t)
	home := newWindowsManagedRuntimeBAOwnedProfile(t, sid)
	shortenWindowsManagedRuntimeProfileRetry(t, 3, nil)
	gone, err := windows.StringToSid("S-1-5-21-1947302811-2864019257-3719054423-1077")
	if err != nil {
		t.Fatal(err)
	}
	goneHome := filepath.Join(t.TempDir(), "renamed-away")
	manifest := windowsManagedRuntimeTestManifest(home, sid)
	manifest.Targets = append(manifest.Targets, windowsManagedRuntimeTestManifest(goneHome, gone).Targets...)

	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("plan with a vanished profile: %v", err)
	}
	if len(plan.Roots) != 1 || !strings.EqualFold(plan.Roots[0].SID, sid.String()) {
		t.Fatalf("plan roots = %+v, want only the live user", plan.Roots)
	}
	if len(plan.SkippedProfiles) != 1 || plan.SkippedProfiles[0].SID != gone.String() ||
		!strings.HasPrefix(plan.SkippedProfiles[0].Reason, "profile_invalid: ") {
		t.Fatalf("skipped = %+v, want the vanished user", plan.SkippedProfiles)
	}
	if plan.TargetCount != len(manifest.Targets) {
		t.Fatalf("target count = %d, want the unchanged manifest's %d", plan.TargetCount, len(manifest.Targets))
	}
	if err := validateWindowsManagedRuntimePlan(plan, manifest); err != nil {
		t.Fatalf("plan with a skipped enrolled user does not validate: %v", err)
	}
}
