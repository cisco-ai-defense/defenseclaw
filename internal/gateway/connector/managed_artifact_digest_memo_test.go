// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// useManagedArtifactDigestSeams replaces the per-OS memo seams and the memo
// clock for one test, and empties the memo before and after it. ends counts
// the change epochs the digest ended (one per full read of a guarded file).
func useManagedArtifactDigestSeams(
	t *testing.T,
	stamp func(*os.File) (managedArtifactStamp, bool),
	exclusive func(string) (*os.File, error),
	end func(*os.File) error,
) (clock *time.Time, ends *int) {
	t.Helper()
	savedEligible, savedCopyEligible, savedStamp, savedAttributes, savedOpen, savedEnd, savedNow := managedArtifactDigestMemoEligible,
		managedProtectedHookCopyEligible,
		managedArtifactStampOf, managedArtifactAttributeStampOf, openManagedArtifactExclusive, endManagedArtifactChangeEpoch, managedArtifactDigests.now
	savedNotice, savedNotices := managedArtifactDigestDegradedNotice, managedArtifactDigestDegradedNotices
	now := time.Unix(1_800_000_000, 0)
	count := 0
	managedArtifactStampOf, openManagedArtifactExclusive = stamp, exclusive
	managedArtifactAttributeStampOf = func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{}, false }
	managedArtifactDigestDegradedNotice = func(string) {}
	managedArtifactDigestDegradedNotices = &sync.Map{}
	endManagedArtifactChangeEpoch = func(file *os.File) error {
		count++
		return end(file)
	}
	managedArtifactDigests.Lock()
	managedArtifactDigests.entries = nil
	managedArtifactDigests.now = func() time.Time { return now }
	managedArtifactDigests.Unlock()
	t.Cleanup(func() {
		managedArtifactDigestMemoEligible, managedProtectedHookCopyEligible = savedEligible, savedCopyEligible
		managedArtifactStampOf = savedStamp
		managedArtifactAttributeStampOf = savedAttributes
		openManagedArtifactExclusive, endManagedArtifactChangeEpoch = savedOpen, savedEnd
		managedArtifactDigestDegradedNotice, managedArtifactDigestDegradedNotices = savedNotice, savedNotices
		managedArtifactDigests.Lock()
		managedArtifactDigests.entries = nil
		managedArtifactDigests.now = savedNow
		managedArtifactDigests.Unlock()
	})
	return &now, &count
}

func useManagedArtifactAttributeStampSeam(stamp func(*os.File) (managedArtifactStamp, bool)) {
	managedArtifactAttributeStampOf = stamp
}

func countManagedArtifactDataReads(t *testing.T) *atomic.Int64 {
	t.Helper()
	saved := managedArtifactDigestRead
	reads := &atomic.Int64{}
	managedArtifactDigestRead = func(dst io.Writer, file *os.File, maxBytes int64) (int64, error) {
		reads.Add(1)
		return saved(dst, file, maxBytes)
	}
	t.Cleanup(func() { managedArtifactDigestRead = saved })
	return reads
}

func endManagedArtifactChangeEpochFake(*os.File) error { return nil }

func writeManagedArtifactFixture(t *testing.T, path string, fill byte) string {
	t.Helper()
	body := bytes.Repeat([]byte{fill}, 2<<20)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func managedArtifactDigestOf(t *testing.T, path string, memoize bool) string {
	t.Helper()
	got, exists, err := stableManagedArtifactDigestWith(path, "managed hook runtime artifact", 4<<20, "", memoize)
	if err != nil || !exists {
		t.Fatalf("digest %s: %v, exists %v", path, err, exists)
	}
	return got
}

func managedArtifactDigestRemembered(path string) bool {
	managedArtifactDigests.Lock()
	defer managedArtifactDigests.Unlock()
	_, ok := managedArtifactDigests.entries[managedArtifactDigestKey(path)]
	return ok
}

func managedArtifactDigestEntries() int {
	managedArtifactDigests.Lock()
	defer managedArtifactDigests.Unlock()
	return len(managedArtifactDigests.entries)
}

// GAP-0438: the guardian's interval reconcile digests the enterprise hook
// binary for every Claude Code, Codex and Cursor target. The binary is read
// again only when the version stamp of the opened file changes or its last
// full read is 10 minutes old. Each full read first ends the change epoch of
// the file; a memo hit never does.
func TestManagedArtifactDigestReadsTheHookBinaryOnlyWhenItsVersionChanges(t *testing.T) {
	version := managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, USN: 10}
	clock, ends := useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) { return version, true },
		os.Open,
		endManagedArtifactChangeEpochFake,
	)
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	first := writeManagedArtifactFixture(t, path, 1)
	if got := managedArtifactDigestOf(t, path, true); got != first {
		t.Fatalf("first digest %s, want %s", got, first)
	}
	if *ends != 1 {
		t.Fatalf("the full read ended %d change epochs, want 1", *ends)
	}
	// The fake stamp does not follow this write, so the old digest proves
	// the unchanged version was not read again.
	second := writeManagedArtifactFixture(t, path, 2)
	if got := managedArtifactDigestOf(t, path, true); got != first {
		t.Fatalf("an unchanged version was read again: %s, want %s", got, first)
	}
	if *ends != 1 {
		t.Fatalf("a memo hit ended the change epoch (%d ends)", *ends)
	}
	version.USN = 11
	if got := managedArtifactDigestOf(t, path, true); got != second {
		t.Fatalf("a new version kept the old digest: %s, want %s", got, second)
	}
	if *ends != 2 {
		t.Fatalf("the full read of a new version ended %d change epochs in all, want 2", *ends)
	}
	// The bound is the literal 10 minutes of the guardian's own hook binary
	// check, not the constant under test.
	third := writeManagedArtifactFixture(t, path, 3)
	*clock = clock.Add(10*time.Minute - time.Second)
	if got := managedArtifactDigestOf(t, path, true); got != second {
		t.Fatalf("the memo ended before 10 minutes: %s, want %s", got, second)
	}
	*clock = clock.Add(time.Second)
	if got := managedArtifactDigestOf(t, path, true); got != third {
		t.Fatalf("the memo outlived 10 minutes: %s, want %s", got, third)
	}
}

func TestManagedArtifactDigestMemoizesNothingWithoutAGuardedStableStamp(t *testing.T) {
	cases := []struct {
		name      string
		memoize   bool
		stamp     func(*os.File) (managedArtifactStamp, bool)
		exclusive func(string) (*os.File, error)
		end       func(*os.File) error
		wantEnds  int
		wantReads int64
		changed   bool
		degraded  bool
	}{
		{
			name:      "not an eligible artifact",
			memoize:   false,
			stamp:     func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{ID: 1, USN: 1}, true },
			exclusive: os.Open,
			end:       endManagedArtifactChangeEpochFake,
			wantEnds:  0,
			wantReads: 6,
		},
		{
			name:    "a writer holds the file",
			memoize: true,
			stamp:   func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{ID: 1, USN: 1}, true },
			exclusive: func(string) (*os.File, error) {
				return nil, os.ErrPermission
			},
			end:       endManagedArtifactChangeEpochFake,
			wantEnds:  0,
			wantReads: 6,
		},
		{
			name:      "no change journal",
			memoize:   true,
			stamp:     func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{}, false },
			exclusive: os.Open,
			end:       endManagedArtifactChangeEpochFake,
			wantEnds:  3,
			wantReads: 3,
			degraded:  true,
		},
		{
			name:      "the change epoch cannot be ended",
			memoize:   true,
			stamp:     func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{ID: 1, USN: 1}, true },
			exclusive: os.Open,
			end:       func(*os.File) error { return errors.ErrUnsupported },
			wantEnds:  3,
			wantReads: 3,
			degraded:  true,
		},
		{
			name:    "the stamp moved during the read",
			memoize: true,
			stamp: func() func(*os.File) (managedArtifactStamp, bool) {
				usn := int64(0)
				return func(*os.File) (managedArtifactStamp, bool) {
					usn++
					return managedArtifactStamp{ID: 1, USN: usn}, true
				}
			}(),
			exclusive: os.Open,
			end:       endManagedArtifactChangeEpochFake,
			wantEnds:  3,
			wantReads: 3,
			changed:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ends := useManagedArtifactDigestSeams(t, tc.stamp, tc.exclusive, tc.end)
			reads := countManagedArtifactDataReads(t)
			path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
			version := int64(0)
			if tc.degraded {
				useManagedArtifactAttributeStampSeam(func(*os.File) (managedArtifactStamp, bool) {
					return managedArtifactStamp{ID: 1, Size: 2 << 20, Links: 1, Written: version}, true
				})
			}
			for fill := byte(1); fill <= 3; fill++ {
				version = int64(fill)
				want := writeManagedArtifactFixture(t, path, fill)
				got, exists, err := stableManagedArtifactDigestWith(path, "managed hook runtime artifact", 4<<20, "", tc.memoize)
				if tc.changed {
					if err == nil || !exists {
						t.Fatalf("version %d: a moving stamp returned %q, exists %v, err %v", fill, got, exists, err)
					}
				} else if err != nil || !exists || got != want {
					t.Fatalf("version %d: digest %s, exists %v, err %v; want %s", fill, got, exists, err, want)
				}
			}
			wantEntries := 0
			if tc.degraded {
				wantEntries = 1
			}
			if left := managedArtifactDigestEntries(); left != wantEntries {
				t.Fatalf("%d memo entries kept, want %d", left, wantEntries)
			}
			if *ends != tc.wantEnds {
				t.Fatalf("%d change epochs ended, want %d", *ends, tc.wantEnds)
			}
			if got := reads.Load(); got != tc.wantReads {
				t.Fatalf("%d data reads, want %d", got, tc.wantReads)
			}
		})
	}
}

// A full read of a new version replaces the earlier digest. A moving full
// stamp remembers nothing; an unusable epoch remembers an attribute stamp.
func TestManagedArtifactDigestFullReadReplacesTheRememberedDigest(t *testing.T) {
	cases := []struct {
		name    string
		moving  bool // the stamp moves on every call: the read is not remembered
		failEnd bool // a new version whose change epoch cannot be ended
	}{
		{name: "the stamp moved during the read", moving: true},
		{name: "the change epoch cannot be ended", failEnd: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			version := managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, USN: 10}
			moving, failEnd := false, false
			useManagedArtifactDigestSeams(t,
				func(*os.File) (managedArtifactStamp, bool) {
					if moving {
						version.USN++
					}
					return version, true
				},
				os.Open,
				func(*os.File) error {
					if failEnd {
						return errors.ErrUnsupported
					}
					return nil
				},
			)
			useManagedArtifactAttributeStampSeam(func(*os.File) (managedArtifactStamp, bool) {
				return managedArtifactStamp{ID: version.ID, Size: version.Size, Links: 1, Written: version.USN}, true
			})
			path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
			writeManagedArtifactFixture(t, path, 1)
			managedArtifactDigestOf(t, path, true)
			if !managedArtifactDigestRemembered(path) {
				t.Fatal("the first full read was not remembered")
			}
			moving = tc.moving
			if tc.failEnd {
				version.USN++
				failEnd = true
			}
			want := writeManagedArtifactFixture(t, path, 2)
			got, exists, err := stableManagedArtifactDigestWith(path, "managed hook runtime artifact", 4<<20, "", true)
			if tc.moving {
				if err == nil || !exists {
					t.Fatalf("a moving stamp returned digest %q, exists %v, err %v", got, exists, err)
				}
			} else if err != nil || !exists || got != want {
				t.Fatalf("digest %s, exists %v, err %v; want the full read %s", got, exists, err, want)
			}
			if remembered := managedArtifactDigestRemembered(path); remembered != tc.failEnd {
				t.Fatalf("remembered new version = %v, want %v", remembered, tc.failEnd)
			}
		})
	}
}

// A memo hit also needs the path to still name the opened file: a rename
// after the open turns the call into a full read, which reports the change
// and drops the remembered digest.
func TestManagedArtifactDigestMemoMissesWhenThePathIsReplacedAfterTheOpen(t *testing.T) {
	// os.Open on Windows shares no delete access, so the open file can be
	// renamed there only through the deny-write open of the product.
	open := os.Open
	if runtime.GOOS == "windows" {
		open = openManagedArtifactExclusive
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "defenseclaw-hook.exe")
	replacement := filepath.Join(dir, "defenseclaw-hook.exe.new")
	version := managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, USN: 10}
	replace := false
	useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) {
			// The first stamp of a call comes after the open and its
			// identity checks, right before the memo lookup.
			if replace {
				replace = false
				if err := os.Rename(path, path+".old"); err != nil {
					t.Errorf("move the opened file away: %v", err)
				}
				if err := os.Rename(replacement, path); err != nil {
					t.Errorf("rename the replacement in: %v", err)
				}
			}
			return version, true
		},
		open,
		endManagedArtifactChangeEpochFake,
	)
	first := writeManagedArtifactFixture(t, path, 1)
	if got := managedArtifactDigestOf(t, path, true); got != first {
		t.Fatalf("first digest %s, want %s", got, first)
	}
	writeManagedArtifactFixture(t, replacement, 2)
	replace = true
	got, exists, err := stableManagedArtifactDigestWith(path, "managed hook runtime artifact", 4<<20, "", true)
	if replace {
		t.Fatal("the call took no stamp")
	}
	if err == nil || got == first || !exists {
		t.Fatalf("a path replaced after the open: digest %q, exists %v, err %v; want the change reported", got, exists, err)
	}
	if managedArtifactDigestRemembered(path) {
		t.Fatal("the remembered digest outlived a replacement of the path")
	}
}

// memoArtifactConnector lists fixed hook runtime artifacts.
type memoArtifactConnector struct {
	stubConnector
	artifacts []string
}

func (c *memoArtifactConnector) HookRuntimeArtifacts(SetupOpts) []string { return c.artifacts }

// GAP-0438 at the production call site: managedHookScriptDigests memoizes an
// eligible hook binary outside the connector data dir and reads a file of the
// data dir in full on every call, eligible or not.
func TestManagedHookScriptDigestsMemoizesOnlyTheHookBinaryOutsideTheDataDir(t *testing.T) {
	version := managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, USN: 10}
	_, ends := useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) { return version, true },
		os.Open,
		endManagedArtifactChangeEpochFake,
	)
	managedArtifactDigestMemoEligible = func(string) bool { return true }
	dataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	script := filepath.Join(dataDir, "hooks", "inspect-tool.sh")
	conn := &memoArtifactConnector{stubConnector: stubConnector{name: "memo-artifacts"}, artifacts: []string{binary, script}}
	opts := SetupOpts{DataDir: dataDir}

	binaryFirst := writeManagedArtifactFixture(t, binary, 1)
	scriptFirst := writeManagedArtifactFixture(t, script, 2)
	got, err := managedHookScriptDigests(opts, conn)
	if err != nil {
		t.Fatal(err)
	}
	if got[filepath.Base(binary)] != binaryFirst || got[filepath.Base(script)] != scriptFirst {
		t.Fatalf("first digests %v, want %s and %s", got, binaryFirst, scriptFirst)
	}
	// The fake stamp does not follow these writes: the hook binary keeps
	// its first digest (one full read across both calls) and the data-dir
	// script gets its new one (a full read on every call).
	writeManagedArtifactFixture(t, binary, 3)
	scriptSecond := writeManagedArtifactFixture(t, script, 4)
	got, err = managedHookScriptDigests(opts, conn)
	if err != nil {
		t.Fatal(err)
	}
	if got[filepath.Base(binary)] != binaryFirst {
		t.Fatalf("the hook binary outside the data dir was read again: %s, want %s", got[filepath.Base(binary)], binaryFirst)
	}
	if got[filepath.Base(script)] != scriptSecond {
		t.Fatalf("a data-dir file was memoized: %s, want %s", got[filepath.Base(script)], scriptSecond)
	}
	if *ends != 1 {
		t.Fatalf("%d full memo reads across two calls, want 1", *ends)
	}
	if managedArtifactDigestRemembered(script) {
		t.Fatal("a data-dir file has a memo entry")
	}
}

// VerifyManagedSharedHookScriptDigests, and every other caller of
// stableManagedArtifactDigestForOwner, reads the file in full on every call.
func TestStableManagedArtifactDigestForOwnerNeverMemoizes(t *testing.T) {
	_, ends := useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{ID: 1, USN: 1}, true },
		os.Open,
		endManagedArtifactChangeEpochFake,
	)
	managedArtifactDigestMemoEligible = func(string) bool { return true }
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	for fill := byte(1); fill <= 3; fill++ {
		want := writeManagedArtifactFixture(t, path, fill)
		got, exists, err := stableManagedArtifactDigestForOwner(path, "managed shared hook script", 4<<20, "")
		if err != nil || !exists || got != want {
			t.Fatalf("version %d: digest %s, exists %v, err %v; want %s", fill, got, exists, err, want)
		}
	}
	if left := managedArtifactDigestEntries(); left != 0 || *ends != 0 {
		t.Fatalf("stableManagedArtifactDigestForOwner memoized: %d entries, %d change epochs ended", left, *ends)
	}
}

// Only the enterprise hook binary outside the connector data dir may be
// memoized: a hook script or token sidecar in the per-user data dir is read
// in full on every call.
func TestManagedArtifactDigestMemoSkipsTheConnectorDataDir(t *testing.T) {
	saved := managedArtifactDigestMemoEligible
	t.Cleanup(func() { managedArtifactDigestMemoEligible = saved })
	dataDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "bin", "defenseclaw-hook.exe")
	inside := filepath.Join(dataDir, "hooks", "defenseclaw-hook.exe")

	managedArtifactDigestMemoEligible = func(string) bool { return true }
	if !managedArtifactDigestMemoWanted(dataDir, outside) {
		t.Fatal("the eligible hook binary outside the data dir is not memoized")
	}
	if managedArtifactDigestMemoWanted(dataDir, inside) {
		t.Fatal("a file in the connector data dir is memoized")
	}
	managedArtifactDigestMemoEligible = func(string) bool { return false }
	if managedArtifactDigestMemoWanted(dataDir, outside) {
		t.Fatal("an artifact that is not the enterprise hook binary is memoized")
	}
}

// Eleven managed targets and the five-second guardian check must share the
// post-epoch stamp. The epoch-end seam moves the USN as NTFS does.
func TestManagedHookBinarySharesOneDataReadAcrossTargetsAndGuardian(t *testing.T) {
	version := managedArtifactStamp{Volume: 7, ID: 42, Size: 2 << 20, Links: 1, Written: 100, USN: 500}
	clock, ends := useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) { return version, true },
		os.Open,
		func(*os.File) error { version.USN++; return nil },
	)
	reads := countManagedArtifactDataReads(t)
	managedArtifactDigestMemoEligible = func(string) bool { return true }
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	want := writeManagedArtifactFixture(t, path, 1)
	conn := &memoArtifactConnector{stubConnector: stubConnector{name: "memo-artifacts"}, artifacts: []string{path}}
	for cycle := range 2 {
		for target := range 11 {
			got, err := managedHookScriptDigests(SetupOpts{DataDir: t.TempDir()}, conn)
			if err != nil || got[filepath.Base(path)] != want {
				t.Fatalf("cycle %d target %d: digest %v, err %v", cycle, target, got, err)
			}
		}
		guardian, err := ManagedEnterpriseHookBinarySHA256Hex(path)
		if err != nil || "sha256:"+guardian != want {
			t.Fatalf("cycle %d guardian digest %q, err %v", cycle, guardian, err)
		}
		if got := reads.Load(); got != 1 {
			t.Fatalf("cycle %d used %d data reads, want one in all", cycle, got)
		}
		*clock = clock.Add(time.Minute)
	}
	if *ends != 1 || version.USN != 501 {
		t.Fatalf("epoch ends %d, final USN %d; want 1 and 501", *ends, version.USN)
	}
}

// The protected copy is prewarmed before the 30-minute idle observation. It
// has no periodic clock; the target's single ten-minute clock drives all
// full reads while the 5-second checks and minute reconciles continue.
func TestManagedHookBinaryIdleThirtyMinutesHasOneSharedBackstop(t *testing.T) {
	stamps := map[string]managedArtifactStamp{}
	clock, _ := useManagedArtifactDigestSeams(t,
		func(file *os.File) (managedArtifactStamp, bool) { return stamps[file.Name()], true },
		os.Open,
		func(file *os.File) error {
			stamp := stamps[file.Name()]
			stamp.USN++
			stamps[file.Name()] = stamp
			return nil
		},
	)
	reads := countManagedArtifactDataReads(t)
	managedArtifactDigestMemoEligible = func(string) bool { return true }
	managedProtectedHookCopyEligible = func(string) bool { return true }
	target := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	copyPath := filepath.Join(t.TempDir(), "hook-guardian", "payload", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(copyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	want := writeManagedArtifactFixture(t, target, 1)
	writeManagedArtifactFixture(t, copyPath, 1)
	stamps[target] = managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, USN: 10}
	stamps[copyPath] = managedArtifactStamp{Volume: 7, ID: 2, Size: 2 << 20, USN: 20}
	if _, err := ManagedProtectedHookCopySHA256Hex(copyPath); err != nil {
		t.Fatal(err)
	}
	reads.Store(0)
	start := *clock
	conn := &memoArtifactConnector{stubConnector: stubConnector{name: "memo-artifacts"}, artifacts: []string{target}}
	for tick := range 30 * 12 {
		*clock = start.Add(time.Duration(tick) * 5 * time.Second)
		before := reads.Load()
		if tick%12 == 0 {
			got, err := managedHookScriptDigests(SetupOpts{DataDir: t.TempDir()}, conn)
			if err != nil || got[filepath.Base(target)] != want {
				t.Fatalf("minute %d: digest %v, err %v", tick/12, got, err)
			}
			if _, err := ManagedProtectedHookCopySHA256Hex(copyPath); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := ManagedEnterpriseHookBinarySHA256Hex(target); err != nil || "sha256:"+got != want {
			t.Fatalf("tick %d: guardian digest %q, err %v", tick, got, err)
		}
		wantDelta := int64(0)
		if tick%120 == 0 {
			wantDelta = 1
		}
		if delta := reads.Load() - before; delta != wantDelta {
			t.Fatalf("tick %d: %d data reads, want %d", tick, delta, wantDelta)
		}
	}
	if got := reads.Load(); got != 3 {
		t.Fatalf("30-minute idle observation read %d times, want 3", got)
	}
}

func TestManagedHookBinaryEachIdentityFieldForcesOneRead(t *testing.T) {
	version := managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, Links: 1, Written: 100, Changed: 100, USN: 10}
	useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) { return version, true },
		os.Open,
		endManagedArtifactChangeEpochFake,
	)
	reads := countManagedArtifactDataReads(t)
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	want := writeManagedArtifactFixture(t, path, 1)
	for index, change := range []func(){
		func() {},
		func() { version.Size++ },
		func() { version.Written++ },
		func() { version.ID++ },
		func() { version.USN++ },
	} {
		change()
		if got := managedArtifactDigestOf(t, path, true); got != want {
			t.Fatalf("identity change %d: digest %s, want %s", index, got, want)
		}
		if got := reads.Load(); got != int64(index+1) {
			t.Fatalf("identity change %d: %d data reads, want %d", index, got, index+1)
		}
	}
	// An in-place edit with the write time put back still moves the USN.
	other := writeManagedArtifactFixture(t, path, 2)
	version.USN++
	if got := managedArtifactDigestOf(t, path, true); got != other || reads.Load() != 6 {
		t.Fatalf("tamper digest %s after %d reads, want %s after 6", got, reads.Load(), other)
	}
}

func TestManagedProtectedHookCopyReadsOnlyWhenItsIdentityChanges(t *testing.T) {
	version := managedArtifactStamp{Volume: 7, ID: 2, Size: 2 << 20, USN: 20}
	clock, _ := useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) { return version, true },
		os.Open,
		endManagedArtifactChangeEpochFake,
	)
	reads := countManagedArtifactDataReads(t)
	managedProtectedHookCopyEligible = func(string) bool { return true }
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	first := writeManagedArtifactFixture(t, path, 1)
	if got, err := ManagedProtectedHookCopySHA256Hex(path); err != nil || "sha256:"+got != first {
		t.Fatalf("first copy digest %q, err %v", got, err)
	}
	*clock = clock.Add(30 * time.Minute)
	if got, err := ManagedProtectedHookCopySHA256Hex(path); err != nil || "sha256:"+got != first || reads.Load() != 1 {
		t.Fatalf("unchanged copy after 30 minutes: digest %q, reads %d, err %v", got, reads.Load(), err)
	}
	second := writeManagedArtifactFixture(t, path, 2)
	version.USN++
	if got, err := ManagedProtectedHookCopySHA256Hex(path); err != nil || "sha256:"+got != second || reads.Load() != 2 {
		t.Fatalf("changed copy: digest %q, reads %d, err %v", got, reads.Load(), err)
	}
}

func TestManagedHookBinaryConcurrentMissesShareOneDataRead(t *testing.T) {
	version := managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, USN: 10}
	_, ends := useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) { return version, true },
		os.Open,
		endManagedArtifactChangeEpochFake,
	)
	reads := countManagedArtifactDataReads(t)
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	want := writeManagedArtifactFixture(t, path, 1)
	start := make(chan struct{})
	results := make(chan string, 11)
	var workers sync.WaitGroup
	for range 11 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			got, exists, err := stableManagedArtifactDigestWith(path, "managed hook runtime artifact", 4<<20, "", true)
			if err != nil || !exists || got != want {
				results <- got
			}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	for got := range results {
		t.Errorf("concurrent caller got %q, want %q", got, want)
	}
	if got := reads.Load(); got != 1 || *ends != 1 {
		t.Fatalf("concurrent misses used %d data reads and %d epoch ends, want one each", got, *ends)
	}
}

func TestManagedHookBinaryWriterHeldFallsBackToFreshTwoPassRead(t *testing.T) {
	_, ends := useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{ID: 1, USN: 10}, true },
		func(string) (*os.File, error) { return nil, os.ErrPermission },
		endManagedArtifactChangeEpochFake,
	)
	reads := countManagedArtifactDataReads(t)
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	first := writeManagedArtifactFixture(t, path, 1)
	if got := managedArtifactDigestOf(t, path, true); got != first {
		t.Fatal("first read did not verify the file")
	}
	second := writeManagedArtifactFixture(t, path, 2)
	if got := managedArtifactDigestOf(t, path, true); got != second {
		t.Fatal("the writer-held file kept its old digest")
	}
	if reads.Load() != 4 || *ends != 0 || managedArtifactDigestRemembered(path) {
		t.Fatalf("writer-held file: reads %d, epoch ends %d, memo %v", reads.Load(), *ends, managedArtifactDigestRemembered(path))
	}
}

// The five-second guardian and ten-minute reconcile share one attribute-only
// memo when no journal exists or its close record cannot be written. The copy
// uses the same backstop in this mode, even though its journaled memo does not
// expire.
func TestManagedArtifactDigestDegradedThirtyMinuteBackstop(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fullOK bool
	}{
		{name: "no change journal"},
		{name: "journal epoch cannot end", fullOK: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stamps := map[string]managedArtifactStamp{}
			clock, ends := useManagedArtifactDigestSeams(t,
				func(file *os.File) (managedArtifactStamp, bool) {
					stamp := stamps[file.Name()]
					stamp.USN = 42
					return stamp, tc.fullOK
				},
				os.Open,
				func(*os.File) error { return errors.ErrUnsupported },
			)
			useManagedArtifactAttributeStampSeam(func(file *os.File) (managedArtifactStamp, bool) {
				return stamps[file.Name()], true
			})
			reads := countManagedArtifactDataReads(t)
			managedArtifactDigestMemoEligible = func(string) bool { return true }
			managedProtectedHookCopyEligible = func(string) bool { return true }
			notices := map[string]int{}
			managedArtifactDigestDegradedNotice = func(path string) { notices[path]++ }
			target := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
			copyPath := filepath.Join(t.TempDir(), "hook-guardian", "payload", "defenseclaw-hook.exe")
			if err := os.MkdirAll(filepath.Dir(copyPath), 0o700); err != nil {
				t.Fatal(err)
			}
			want := writeManagedArtifactFixture(t, target, 1)
			copyWant := writeManagedArtifactFixture(t, copyPath, 1)
			stamps[target] = managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, Links: 1, Written: 100, Changed: 100}
			stamps[copyPath] = managedArtifactStamp{Volume: 7, ID: 2, Size: 2 << 20, Links: 1, Written: 100, Changed: 100}
			start := *clock
			for tick := range 30 * 12 {
				*clock = start.Add(time.Duration(tick) * 5 * time.Second)
				before := reads.Load()
				if got, err := ManagedEnterpriseHookBinarySHA256Hex(target); err != nil || "sha256:"+got != want {
					t.Fatalf("tick %d target digest %q, err %v", tick, got, err)
				}
				wantTargetReads := int64(0)
				if tick%120 == 0 {
					wantTargetReads = 1
				}
				if delta := reads.Load() - before; delta != wantTargetReads {
					t.Fatalf("tick %d target used %d data passes, want %d", tick, delta, wantTargetReads)
				}
				if tick%120 == 0 {
					before = reads.Load()
					if got, err := ManagedProtectedHookCopySHA256Hex(copyPath); err != nil || "sha256:"+got != copyWant {
						t.Fatalf("tick %d copy digest %q, err %v", tick, got, err)
					}
					if delta := reads.Load() - before; delta != 1 {
						t.Fatalf("tick %d copy used %d data passes, want one", tick, delta)
					}
				}
			}
			if got := reads.Load(); got != 6 || *ends != 6 {
				t.Fatalf("30 minutes used %d data passes and %d epoch ends, want six each", got, *ends)
			}
			if notices[target] != 1 || notices[copyPath] != 1 {
				t.Fatalf("degraded notices: target %d, copy %d; want one each", notices[target], notices[copyPath])
			}
		})
	}
}

func TestManagedArtifactDigestDegradedStampFieldsForceOneRead(t *testing.T) {
	stamp := managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, Links: 1, Written: 100, Changed: 100, Attributes: 32}
	useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{}, false },
		os.Open,
		func(*os.File) error { return errors.ErrUnsupported },
	)
	useManagedArtifactAttributeStampSeam(func(*os.File) (managedArtifactStamp, bool) { return stamp, true })
	reads := countManagedArtifactDataReads(t)
	managedArtifactDigestMemoEligible = func(string) bool { return true }
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	want := writeManagedArtifactFixture(t, path, 1)
	for index, change := range []func(){
		func() {},
		func() { stamp.Size++ },
		func() { stamp.ID++ },
		func() { stamp.Volume++ },
		func() { stamp.Written++ },
		func() { stamp.Changed++ },
		func() { stamp.Attributes++ },
	} {
		change()
		if got, err := ManagedEnterpriseHookBinarySHA256Hex(path); err != nil || "sha256:"+got != want {
			t.Fatalf("field %d digest %q, err %v", index, got, err)
		}
		if got := reads.Load(); got != int64(index+1) {
			t.Fatalf("field %d used %d reads, want %d", index, got, index+1)
		}
	}
	link := path + ".link"
	if err := os.Link(path, link); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if _, err := ManagedEnterpriseHookBinarySHA256Hex(path); err == nil {
		t.Fatal("a linked target was answered from the degraded memo")
	}
	if got := reads.Load(); got != 7 {
		t.Fatalf("a linked target read %d times, want no new read after seven", got)
	}
}

func TestManagedArtifactDigestDegradedAndJournaledEntriesDoNotCross(t *testing.T) {
	fullOK := false
	stamp := managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, Links: 1, Written: 100, Changed: 100}
	useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) {
			full := stamp
			full.USN = 42
			return full, fullOK
		},
		os.Open,
		func(*os.File) error {
			if !fullOK {
				return errors.ErrUnsupported
			}
			return nil
		},
	)
	useManagedArtifactAttributeStampSeam(func(*os.File) (managedArtifactStamp, bool) { return stamp, true })
	reads := countManagedArtifactDataReads(t)
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	want := writeManagedArtifactFixture(t, path, 1)
	for index, mode := range []bool{false, true, false} {
		fullOK = mode
		if got := managedArtifactDigestOf(t, path, true); got != want {
			t.Fatalf("mode %d digest %q, want %q", index, got, want)
		}
		if got := reads.Load(); got != int64(index+1) {
			t.Fatalf("mode %d used %d reads, want %d", index, got, index+1)
		}
	}
}

func TestManagedArtifactDigestDegradedRejectsStampMovingDuringRead(t *testing.T) {
	useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{}, false },
		os.Open,
		func(*os.File) error { return errors.ErrUnsupported },
	)
	reads := countManagedArtifactDataReads(t)
	version := int64(0)
	useManagedArtifactAttributeStampSeam(func(*os.File) (managedArtifactStamp, bool) {
		version++
		return managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, Links: 1, Written: version}, true
	})
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	writeManagedArtifactFixture(t, path, 1)
	got, exists, err := stableManagedArtifactDigestWith(path, "managed hook runtime artifact", 4<<20, "", true)
	if err == nil || !strings.Contains(err.Error(), "changed during bounded digest") || got != "" || !exists {
		t.Fatalf("moving attribute stamp: digest %q, exists %v, err %v", got, exists, err)
	}
	if reads.Load() != 1 || managedArtifactDigestRemembered(path) {
		t.Fatalf("moving attribute stamp used %d reads, remembered %v; want one read and no memo", reads.Load(), managedArtifactDigestRemembered(path))
	}
}

func TestManagedArtifactDigestDegradedConcurrentMissesShareOneDataRead(t *testing.T) {
	stamp := managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, Links: 1, Written: 100}
	_, ends := useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{}, false },
		os.Open,
		func(*os.File) error { return errors.ErrUnsupported },
	)
	useManagedArtifactAttributeStampSeam(func(*os.File) (managedArtifactStamp, bool) { return stamp, true })
	reads := countManagedArtifactDataReads(t)
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	want := writeManagedArtifactFixture(t, path, 1)
	start := make(chan struct{})
	results := make(chan string, 11)
	var workers sync.WaitGroup
	for range 11 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			got, exists, err := stableManagedArtifactDigestWith(path, "managed hook runtime artifact", 4<<20, "", true)
			if err != nil || !exists || got != want {
				results <- got
			}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	for got := range results {
		t.Errorf("concurrent caller got %q, want %q", got, want)
	}
	if got := reads.Load(); got != 1 || *ends != 1 {
		t.Fatalf("concurrent degraded misses used %d data reads and %d epoch attempts, want one each", got, *ends)
	}
}
