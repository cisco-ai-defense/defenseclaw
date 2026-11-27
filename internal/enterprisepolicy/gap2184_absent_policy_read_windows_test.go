//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// GAP-2184: a policy file that is not installed (managed-settings.json on
// most machines) is an answer, not a replacement in flight. Its read waited
// out the whole transient-name budget, 31 timer-rounded sleeps (about 230 ms
// on Windows), on every guardian pass. It now gets one confirming look.
func TestGAP2184ReadPolicyFileOfAnAbsentFileWaitsOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	waits := 0
	t.Cleanup(safefile.SetTransientRetrySleepForTest(func(time.Duration) { waits++ }))
	data, exists, err := readPolicyFileWith(Options{GOOS: "windows", SkipTrustChecks: true}, path, nil)
	if err != nil || exists || data != nil {
		t.Fatalf("data=%q exists=%v err=%v, want an absent file", data, exists, err)
	}
	if waits != 1 {
		t.Fatalf("an absent policy file waited %d times for a replacement, want one confirming look", waits)
	}
}

// GAP-2184: a policy file seen by the read and then missing is a replacement
// in flight; it keeps the whole budget and is never reported as absent.
func TestGAP2184ReadPolicyFileSeenThenMissingIsNotAbsence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	writeFile(t, path, "{}\n")
	removed := false
	validate := func(Options, string) error {
		if !removed {
			removed = true
			return os.Remove(path)
		}
		return nil
	}
	waits := 0
	t.Cleanup(safefile.SetTransientRetrySleepForTest(func(time.Duration) { waits++ }))
	data, exists, err := readPolicyFileWith(Options{GOOS: "windows"}, path, validate)
	if err == nil || exists || data != nil || !removed {
		t.Fatalf("data=%q exists=%v err=%v removed=%v, want an uncertain read error", data, exists, err, removed)
	}
	if waits < 31 {
		t.Fatalf("a policy file that vanished after it was seen waited %d times, want the whole budget", waits)
	}
}

// GAP-2201, GAP-2252: a version floor pass whose snapshot goes stale at every
// lock reads every source under the Claude Code policy lock (the fallback of
// reconcileClaudeVersionFloorFor). That read of the absent
// managed-settings.json waited out the transient-name budget under the lock,
// about 230 ms against the 200 ms smoke bar on a loaded host. Count the waits
// under the lock, not the time.
func TestGAP2201FloorFallbackUnderTheLockDoesNotWaitOutAnAbsentSource(t *testing.T) {
	requireGAP1833Elevated(t)
	opts, _ := windowsFloorOptions(t)
	if _, err := PublishWindowsClaudeVersionFloor(opts, []string{"claudecode"}); err != nil {
		t.Fatal(err)
	}
	base := joinFor(opts, claudeDir(t, opts), "managed-settings.json")
	if _, err := os.Lstat(base); !os.IsNotExist(err) {
		t.Fatalf("managed-settings.json must be absent for this row: %v", err)
	}
	dropDir := dirFor(opts, claudeFloorFile(t, opts))
	admins := wellKnownSID(t, windows.WinBuiltinAdministratorsSid)
	inLock, waits, locks := false, 0, 0
	t.Cleanup(safefile.SetTransientRetrySleepForTest(func(time.Duration) {
		if inLock {
			waits++
		}
	}))
	stub := windowsClaudeFloorTransaction
	windowsClaudeFloorTransaction = func(fn func(string) error) error {
		locks++
		// An administrator drop-in lands at every lock: the snapshot is
		// never unchanged, so the last attempt reads under the lock.
		path := filepath.Join(dropDir, fmt.Sprintf("50-company-%d.json", locks))
		writeFile(t, path, "{}\n")
		ownAs(t, path, admins)
		inLock = true
		defer func() { inLock = false }()
		return stub(fn)
	}
	t.Cleanup(func() { windowsClaudeFloorTransaction = stub })
	if _, err := PublishWindowsClaudeVersionFloor(opts, []string{"claudecode"}); err != nil {
		t.Fatal(err)
	}
	t.Logf("GAP2201 version floor fallback pass: %d locks, %d transient waits under the lock", locks, waits)
	if locks != claudeFloorSnapshotAttempts {
		t.Fatalf("the pass took the lock %d times, want %d (the last one reads under the lock)", locks, claudeFloorSnapshotAttempts)
	}
	if waits > 1 {
		t.Errorf("the under-lock read waited %d times for a replacement of an absent source, want at most one confirming look", waits)
	}
}
