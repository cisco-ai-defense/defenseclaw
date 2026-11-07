// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// windowsCodexStateCommittedPathForTest is the writer copy of the state
// (GAP-0650), where every transaction starts.
func windowsCodexStateCommittedPathForTest(opts WindowsCodexMachineRequirementsOptions) string {
	return filepath.Join(filepath.Dir(opts.ManagedStatePath), windowsCodexManagedStateCommittedFile)
}

// windowsCodexStateFilesForTest is every physical file of the state: the
// fixed name, the writer copy and each hook copy on disk.
func windowsCodexStateFilesForTest(t *testing.T, opts WindowsCodexMachineRequirementsOptions) []string {
	t.Helper()
	files := []string{opts.ManagedStatePath, windowsCodexStateCommittedPathForTest(opts)}
	generations, err := windowsCodexManagedStateGenerations(filepath.Dir(opts.ManagedStatePath))
	if err != nil {
		t.Fatal(err)
	}
	return append(files, generations...)
}

// windowsCodexStatePresentForTest reports whether the hook would read state:
// the hook copy the current counter names exists.
func windowsCodexStatePresentForTest(t *testing.T, opts WindowsCodexMachineRequirementsOptions) bool {
	t.Helper()
	dir := filepath.Dir(opts.ManagedStatePath)
	counter, err := readWindowsCodexTransactionCounter(filepath.Join(dir, WindowsCodexManagedWriterLockFile))
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Lstat(windowsCodexStableStateFile(dir, counter))
	return err == nil
}

func removeWindowsCodexStateForTest(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
	t.Helper()
	for _, path := range windowsCodexStateFilesForTest(t, opts) {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
}

// holdWindowsCodexFileForTest opens path for reading the way a standard
// user can: share is the sharing it grants (0 refuses all, FILE_SHARE_READ
// refuses delete and write).
func holdWindowsCodexFileForTest(t *testing.T, path string, share uint32) windows.Handle {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := windows.UTF16PtrFromString(extended)
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, share, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatalf("hold %s: %v", path, err)
	}
	return handle
}

type windowsCodexStateTxFixture struct {
	dir, requirements, state, lock string
}

func newWindowsCodexStateTxFixture(t *testing.T) windowsCodexStateTxFixture {
	t.Helper()
	requireWindowsCodexWriterForTest(t)
	stubWindowsCodexTrustForTest(t, "")
	dir := t.TempDir()
	return windowsCodexStateTxFixture{
		dir:          dir,
		requirements: filepath.Join(dir, "requirements.toml"),
		state:        filepath.Join(dir, windowsCodexManagedStateFile),
		lock:         filepath.Join(dir, WindowsCodexManagedWriterLockFile),
	}
}

func (f windowsCodexStateTxFixture) run(t *testing.T, fn func() error) uint64 {
	t.Helper()
	if err := withWindowsCodexMachinePolicyLock(f.requirements, fn); err != nil {
		t.Fatalf("transaction: %v", err)
	}
	counter, err := readWindowsCodexTransactionCounter(f.lock)
	if err != nil {
		t.Fatal(err)
	}
	if counter%2 != 0 {
		t.Fatalf("the transaction left the counter odd: %d", counter)
	}
	return counter
}

func (f windowsCodexStateTxFixture) write(data string) func() error {
	return func() error { return writeWindowsCodexManagedState(f.state, []byte(data)) }
}

// requireStateCopy checks the hook copy the counter names holds want, and the
// writer copy too.
func (f windowsCodexStateTxFixture) requireStateCopy(t *testing.T, counter uint64, want string) {
	t.Helper()
	copyPath := windowsCodexStableStateFile(f.dir, counter)
	if data, err := os.ReadFile(copyPath); err != nil || string(data) != want {
		t.Fatalf("hook copy %s = %q, %v; want %q", copyPath, data, err, want)
	}
	if data, err := os.ReadFile(filepath.Join(f.dir, windowsCodexManagedStateCommittedFile)); err != nil || string(data) != want {
		t.Fatalf("writer copy = %q, %v; want %q", data, err, want)
	}
	descriptor, err := windows.GetNamedSecurityInfo(copyPath, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if mask, found := windowsCodexUsersMaskForTest(t, copyPath); !found || mask&^uint32(windows.FILE_GENERIC_READ) != 0 {
		t.Fatalf("hook copy %s: BUILTIN\\Users mask 0x%x (found %v), want read only (%s)", copyPath, mask, found, descriptor)
	}
	if mask, found := windowsCodexUsersMaskForTest(t, filepath.Join(f.dir, windowsCodexManagedStateCommittedFile)); found {
		t.Fatalf("the writer copy grants BUILTIN\\Users 0x%x; want no entry, so no standard user can hold it", mask)
	}
}

// The state is written under a new name in each transaction, so a reader
// that holds an older copy open, with no sharing or without delete sharing,
// blocks no write (GAP-0650, g582 review 7 M2). The hook then reads the new
// copy, and a later transaction removes the old one once it is released.
func TestWindowsCodexStateHeldOldCopyDoesNotBlockTheNextWrite(t *testing.T) {
	for _, hold := range []struct {
		name  string
		share uint32
	}{
		{name: "no sharing", share: 0},
		{name: "no delete sharing", share: windows.FILE_SHARE_READ},
	} {
		t.Run(hold.name, func(t *testing.T) {
			f := newWindowsCodexStateTxFixture(t)
			first := f.run(t, f.write("first"))
			f.requireStateCopy(t, first, "first")
			old := windowsCodexStableStateFile(f.dir, first)
			held := holdWindowsCodexFileForTest(t, old, hold.share)
			closed := false
			defer func() {
				if !closed {
					_ = windows.CloseHandle(held)
				}
			}()

			second := f.run(t, f.write("second"))
			f.requireStateCopy(t, second, "second")
			if _, err := os.Lstat(old); err != nil {
				t.Fatalf("the held old copy should stay while it is held: %v", err)
			}
			registry, err := resolveWindowsCodexManagedRuntimeRegistryStable(f.lock, func(stateFile string) (WindowsCodexManagedRuntimeRegistry, error) {
				data, err := os.ReadFile(stateFile)
				return WindowsCodexManagedRuntimeRegistry{Active: true, GatewayAddr: string(data)}, err
			})
			if err != nil || registry.GatewayAddr != "second" {
				t.Fatalf("the hook read %+v, %v; want the new copy", registry, err)
			}

			_ = windows.CloseHandle(held)
			closed = true
			third := f.run(t, func() error { return nil })
			f.requireStateCopy(t, third, "second")
			generations, err := windowsCodexManagedStateGenerations(f.dir)
			if err != nil || len(generations) != 1 {
				t.Fatalf("hook copies after the release = %q, %v; want only the current one", generations, err)
			}
		})
	}
}

// A transaction that changes neither the state nor requirements.toml (Verify,
// status, a guardian pass with nothing to do) leaves the hook copy alone and
// the counter where it was (g582 round 9 L1); one that writes the requirements
// carries the state forward under its own end value; one that removes the
// state leaves no copy at all.
func TestWindowsCodexStateCarriesForwardAndIsRemovedWithoutCopies(t *testing.T) {
	f := newWindowsCodexStateTxFixture(t)
	first := f.run(t, f.write("kept"))
	firstCopy := windowsCodexStableStateFile(f.dir, first)
	firstInfo, err := os.Stat(firstCopy)
	if err != nil {
		t.Fatal(err)
	}
	var seen windowsCodexStableFile
	second := f.run(t, func() error {
		var err error
		seen, err = readWindowsCodexManagedState(f.state, false)
		return err
	})
	if !seen.existed || string(seen.data) != "kept" || second != first {
		t.Fatalf("the read-only transaction read %+v and ended at counter %d after %d; want the same counter", seen, second, first)
	}
	f.requireStateCopy(t, second, "kept")
	if secondInfo, err := os.Stat(firstCopy); err != nil || !os.SameFile(firstInfo, secondInfo) || !secondInfo.ModTime().Equal(firstInfo.ModTime()) {
		t.Fatalf("the read-only transaction rewrote the hook copy: %v", err)
	}

	third := f.run(t, func() error {
		windowsCodexActiveManagedState.requirementsTouched = true
		return nil
	})
	if third == second {
		t.Fatalf("a transaction that wrote requirements.toml kept counter %d; the hook must see the pair change", third)
	}
	f.requireStateCopy(t, third, "kept")
	if _, err := os.Lstat(windowsCodexStableStateFile(f.dir, first)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the earlier copy stayed: %v", err)
	}

	f.run(t, func() error { return deleteWindowsCodexManagedState(f.state) })
	for _, name := range []string{windowsCodexManagedStateFile, windowsCodexManagedStateCommittedFile} {
		if _, err := os.Lstat(filepath.Join(f.dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s stayed after the state was removed: %v", name, err)
		}
	}
	if generations, _ := windowsCodexManagedStateGenerations(f.dir); len(generations) != 0 {
		t.Fatalf("hook copies stayed after the state was removed: %q", generations)
	}
	var after windowsCodexStableFile
	f.run(t, func() error {
		var err error
		after, err = readWindowsCodexManagedState(f.state, true)
		return err
	})
	if after.existed {
		t.Fatalf("removed state came back: %q", after.data)
	}
}

// A writer that stopped mid-transaction leaves the counter odd. The hook
// fails closed meanwhile, never inactive, and the next transaction starts
// from the writer copy and writes the copy for its own end value.
func TestWindowsCodexStateRecoversFromAStoppedWriter(t *testing.T) {
	f := newWindowsCodexStateTxFixture(t)
	f.run(t, f.write("committed"))
	// The stopped writer had moved the counter to 3 and created the copy its
	// end value 4 names, with state it never committed.
	writeWindowsCodexLockFileForTest(t, f.lock, 3, windowsCodexWriterLockSDDL)
	if err := os.WriteFile(windowsCodexManagedStateGenerationPath(f.dir, 4), []byte("uncommitted"), 0o600); err != nil {
		t.Fatal(err)
	}
	windowsCodexReaderWait = 150 * time.Millisecond
	if registry, err := resolveWindowsCodexManagedRuntimeRegistryStable(f.lock, func(string) (WindowsCodexManagedRuntimeRegistry, error) {
		return WindowsCodexManagedRuntimeRegistry{}, nil
	}); err == nil || registry.Active || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("an odd counter = %+v, %v; want a fail-closed timeout", registry, err)
	}
	next := f.run(t, func() error { return nil })
	if next != 6 {
		t.Fatalf("counter after recovery = %d, want 6", next)
	}
	f.requireStateCopy(t, next, "committed")
	if generations, _ := windowsCodexManagedStateGenerations(f.dir); len(generations) != 1 {
		t.Fatalf("hook copies after recovery = %q; want only the current one", generations)
	}
}

// After the counter wraps, an end value whose copy is still held open from
// before is skipped, so a commit always creates its copy new and the hook
// never reads the old one under the new counter.
func TestWindowsCodexStateCounterSkipsAHeldCopyAfterTheWrap(t *testing.T) {
	f := newWindowsCodexStateTxFixture(t)
	// The last even value before the wrap: the next start (wrap+1) wraps to 1.
	writeWindowsCodexLockFileForTest(t, f.lock, windowsCodexTransactionCounterWrap, windowsCodexWriterLockSDDL)
	if err := os.WriteFile(filepath.Join(f.dir, windowsCodexManagedStateCommittedFile), []byte("current"), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := windowsCodexManagedStateGenerationPath(f.dir, 2)
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	held := holdWindowsCodexFileForTest(t, stale, 0)
	defer windows.CloseHandle(held)
	counter := f.run(t, func() error { return nil })
	if counter != 4 {
		t.Fatalf("counter after the wrap = %d, want 4 (2 is taken by a held copy)", counter)
	}
	f.requireStateCopy(t, counter, "current")
}

// A host that 1.0.8 set up keeps the state in the fixed name. The first
// transaction of this release writes it into the writer copy and the hook
// copy and removes the fixed name; while a reader holds the fixed name open
// it stays, and an empty writer copy keeps a later transaction from taking it
// for the state.
func TestWindowsCodexStateMigratesTheFixedNameOf108(t *testing.T) {
	f := newWindowsCodexStateTxFixture(t)
	if got := windowsCodexStableStateFile(f.dir, 0); got != f.state {
		t.Fatalf("an unused writer lock reads %s, want the fixed name", got)
	}
	if err := os.WriteFile(f.state, []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	held := holdWindowsCodexFileForTest(t, f.state, windows.FILE_SHARE_READ)
	closed := false
	defer func() {
		if !closed {
			_ = windows.CloseHandle(held)
		}
	}()
	first := f.run(t, func() error { return nil })
	f.requireStateCopy(t, first, "legacy")
	if _, err := os.Lstat(f.state); err != nil {
		t.Fatalf("the held fixed name should stay while it is held: %v", err)
	}

	f.run(t, func() error { return deleteWindowsCodexManagedState(f.state) })
	committed := filepath.Join(f.dir, windowsCodexManagedStateCommittedFile)
	if data, err := os.ReadFile(committed); err != nil || len(data) != 0 {
		t.Fatalf("writer copy while the fixed name is held = %q, %v; want an empty copy", data, err)
	}
	var seen windowsCodexStableFile
	f.run(t, func() error {
		var err error
		seen, err = readWindowsCodexManagedState(f.state, true)
		return err
	})
	if seen.existed {
		t.Fatalf("the held fixed name was taken for the state: %q", seen.data)
	}

	_ = windows.CloseHandle(held)
	closed = true
	f.run(t, func() error { return nil })
	for _, path := range []string{f.state, committed} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s stayed once nothing held the fixed name: %v", path, err)
		}
	}
}

// The state is read and written only inside a transaction, and only at the
// logical path of its folder.
func TestWindowsCodexStateRefusesAccessOutsideItsTransaction(t *testing.T) {
	f := newWindowsCodexStateTxFixture(t)
	if _, err := readWindowsCodexManagedState(f.state, true); err == nil {
		t.Fatal("a read outside a transaction was allowed")
	}
	if err := withWindowsCodexMachinePolicyLock(f.requirements, func() error {
		return writeWindowsCodexManagedState(filepath.Join(f.dir, "other.state"), []byte("x"))
	}); err == nil || !strings.Contains(err.Error(), "noncanonical") {
		t.Fatalf("a write at another path = %v; want refused", err)
	}
	for _, name := range []string{".defenseclaw-managed-hooks.state.012", ".defenseclaw-managed-hooks.state.x1", ".defenseclaw-managed-hooks.state."} {
		if _, ok := windowsCodexManagedStateGenerationOf(name); ok {
			t.Fatalf("%s was taken for a hook copy", name)
		}
	}
	if counter, ok := windowsCodexManagedStateGenerationOf(".DefenseClaw-Managed-Hooks.State.42"); !ok || counter != 42 {
		t.Fatalf("hook copy name parse = %d, %v", counter, ok)
	}
}

// A requirements.toml a process holds open without delete sharing is named
// with that process, and the update is written as soon as it is released
// (GAP-0650, documented Windows limit); while it stays held the enforced
// policy and state stay as they were.
func TestWindowsCodexHeldRequirementsNamesTheHolderAndRetriesOnRelease(t *testing.T) {
	row := windowsCodexRemovalRowsForTest[0]
	for _, released := range []bool{true, false} {
		t.Run(map[bool]string{true: "released", false: "still held"}[released], func(t *testing.T) {
			opts := installWindowsCodexGuardForRemovalTest(t, row)
			before, err := os.ReadFile(opts.RequirementsPath)
			if err != nil {
				t.Fatal(err)
			}
			held := holdWindowsCodexFileForTest(t, opts.RequirementsPath, windows.FILE_SHARE_READ)
			closed := false
			closeHeld := func() {
				if !closed {
					closed = true
					_ = windows.CloseHandle(held)
				}
			}
			defer closeHeld()
			if !windowsCodexFileHeldAgainstDelete(opts.RequirementsPath) {
				t.Fatal("the held requirements.toml was not seen as held")
			}
			holders := windowsCodexRequirementsHolders(opts.RequirementsPath)
			self := fmt.Sprintf("(PID %d)", os.Getpid())
			if !strings.Contains(strings.Join(holders, ", "), self) {
				t.Fatalf("Restart Manager holders = %q; want this process %s", holders, self)
			}

			previousWait, previousSleep, previousNow := windowsCodexHeldRetryWait, windowsCodexHeldRetrySleep, windowsCodexHeldRetryNow
			t.Cleanup(func() {
				windowsCodexHeldRetryWait, windowsCodexHeldRetrySleep, windowsCodexHeldRetryNow = previousWait, previousSleep, previousNow
			})
			now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
			windowsCodexHeldRetryNow = func() time.Time { return now }
			windowsCodexHeldRetryWait = 10 * time.Second
			polls := 0
			windowsCodexHeldRetrySleep = func(d time.Duration) {
				polls++
				now = now.Add(d)
				if released && polls == 2 {
					closeHeld()
				}
			}

			report, err := RemoveWindowsCodexMachineRequirements(opts)
			if released {
				requireWindowsCodexGuardRemovedForTest(t, opts, report, err, row.keys...)
				if polls != 2 {
					t.Fatalf("the removal polled %d times, want it to retry right after the release", polls)
				}
				return
			}
			var heldErr *WindowsCodexRequirementsHeldError
			if !errors.As(err, &heldErr) || report.OK {
				t.Fatalf("still held: %+v, %v; want the named hold", report, err)
			}
			for _, want := range []string{opts.RequirementsPath, "held open by", self, "enforced Codex policy stays in place", windowsCodexHeldRetryPromise} {
				if !strings.Contains(err.Error(), want) || (want == self && !strings.Contains(report.RequirementsHeldBy, self)) {
					t.Fatalf("held error %q / held_by %q does not name %q", err, report.RequirementsHeldBy, want)
				}
			}
			if after, readErr := os.ReadFile(opts.RequirementsPath); readErr != nil || !bytes.Equal(after, before) {
				t.Fatalf("the held requirements changed: %v", readErr)
			}
			if !windowsCodexStatePresentForTest(t, opts) {
				t.Fatal("the state the hook reads went while the requirements stayed")
			}
		})
	}
}

// g582 round 9 S1: the first transaction of 1.0.9 on a host 1.0.8 set up reads
// the fixed state file, which 1.0.8 made user-readable. A user who holds it
// open with no sharing at all stops the read. The holder is named and the
// transaction waits for the release a bounded time, like it does for
// requirements.toml; after a failed begin nothing was written, so the counter
// goes back to the value it had and the hook copy it names stays the pair the
// hook reads, never a half-begun transaction.
func TestWindowsCodexMigrationOfAFixedNameHeldWithNoSharing(t *testing.T) {
	for _, released := range []bool{true, false} {
		t.Run(map[bool]string{true: "released", false: "still held"}[released], func(t *testing.T) {
			f := newWindowsCodexStateTxFixture(t)
			live := f.run(t, f.write("live"))
			// The writer copy of this release is gone, so the next
			// transaction reads the fixed name of 1.0.8.
			if err := os.Remove(filepath.Join(f.dir, windowsCodexManagedStateCommittedFile)); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.state, []byte("legacy"), 0o600); err != nil {
				t.Fatal(err)
			}
			held := holdWindowsCodexFileForTest(t, f.state, 0)
			closed := false
			closeHeld := func() {
				if !closed {
					closed = true
					_ = windows.CloseHandle(held)
				}
			}
			defer closeHeld()

			previousWait, previousSleep, previousNow := windowsCodexHeldRetryWait, windowsCodexHeldRetrySleep, windowsCodexHeldRetryNow
			t.Cleanup(func() {
				windowsCodexHeldRetryWait, windowsCodexHeldRetrySleep, windowsCodexHeldRetryNow = previousWait, previousSleep, previousNow
			})
			now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
			windowsCodexHeldRetryNow = func() time.Time { return now }
			windowsCodexHeldRetryWait = 10 * time.Second
			polls := 0
			windowsCodexHeldRetrySleep = func(d time.Duration) {
				polls++
				now = now.Add(d)
				if released && polls == 1 {
					closeHeld()
				}
			}

			ran := 0
			err := withWindowsCodexRequirementsReleaseRetry(func() error {
				return withWindowsCodexMachinePolicyLock(f.requirements, func() error {
					ran++
					return nil
				})
			})
			counter, counterErr := readWindowsCodexTransactionCounter(f.lock)
			if counterErr != nil {
				t.Fatal(counterErr)
			}
			if released {
				if err != nil || ran != 1 {
					t.Fatalf("after the release: err = %v, ran %d times; want one run of the transaction", err, ran)
				}
				if counter%2 != 0 || counter == live {
					t.Fatalf("counter = %d after the migration, was %d", counter, live)
				}
				f.requireStateCopy(t, counter, "legacy")
				if _, err := os.Lstat(f.state); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("the fixed name stayed once it was released: %v", err)
				}
				return
			}
			var heldErr *WindowsCodexRequirementsHeldError
			self := fmt.Sprintf("(PID %d)", os.Getpid())
			if !errors.As(err, &heldErr) || !heldErr.Reading || ran != 0 {
				t.Fatalf("held fixed name: err = %v, ran %d; want the named read hold and no run", err, ran)
			}
			for _, want := range []string{f.state, "held open by", self, "cannot read it", windowsCodexHeldRetryPromise} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("held error %q does not name %q", err, want)
				}
			}
			if counter != live {
				t.Fatalf("counter = %d after the failed begin, want %d: the hook copy it names is still the pair", counter, live)
			}
			registry, err := resolveWindowsCodexManagedRuntimeRegistryStable(f.lock, func(stateFile string) (WindowsCodexManagedRuntimeRegistry, error) {
				data, err := os.ReadFile(stateFile)
				return WindowsCodexManagedRuntimeRegistry{Active: true, GatewayAddr: string(data)}, err
			})
			if err != nil || registry.GatewayAddr != "live" {
				t.Fatalf("the hook read %+v, %v after the failed begin; want the state it had", registry, err)
			}
		})
	}
}

// windowsCodexStateDirSnapshotForTest records the identity and modification
// time of every file in dir, so a later snapshot shows what a pass rewrote.
func windowsCodexStateDirSnapshotForTest(t *testing.T, dir string) map[string]os.FileInfo {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := map[string]os.FileInfo{}
	for _, entry := range entries {
		info, err := os.Stat(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		snapshot[entry.Name()] = info
	}
	return snapshot
}

// requireSameDirForTest fails when a file appeared, vanished or was replaced
// or rewritten between two snapshots. The writer lock changes size with the
// counter, so it is compared by its size (the counter) and left out of the
// modification-time check.
func requireSameDirForTest(t *testing.T, when string, before, after map[string]os.FileInfo) {
	t.Helper()
	for name, old := range before {
		now, ok := after[name]
		if !ok {
			t.Fatalf("%s: %s vanished", when, name)
		}
		if !os.SameFile(old, now) || old.Size() != now.Size() {
			t.Fatalf("%s: %s was replaced or resized (size %d to %d)", when, name, old.Size(), now.Size())
		}
		if !strings.EqualFold(name, WindowsCodexManagedWriterLockFile) && !old.ModTime().Equal(now.ModTime()) {
			t.Fatalf("%s: %s was rewritten (%s to %s)", when, name, old.ModTime(), now.ModTime())
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			t.Fatalf("%s: %s appeared", when, name)
		}
	}
}

// One no-change rule serves every caller (g582 round 11, GAP-0764): a pass
// that sets the state to the bytes it already holds, or publishes the
// requirements.toml it already has, changes nothing the hook reads, so it
// keeps the hook copy and the counter and writes nothing, whether a standard
// account held an older copy meanwhile or not.
func TestWindowsCodexStateUnchangedPassesAfterAReleasedHoldWriteNothing(t *testing.T) {
	f := newWindowsCodexStateTxFixture(t)
	first := f.run(t, f.write("state-one"))
	// A standard account holds the current copy, refusing every sharing.
	held := holdWindowsCodexFileForTest(t, windowsCodexStableStateFile(f.dir, first), 0)
	closed := false
	defer func() {
		if !closed {
			_ = windows.CloseHandle(held)
		}
	}()
	second := f.run(t, f.write("state-two"))
	if second == first {
		t.Fatalf("a changed state kept counter %d", second)
	}
	f.requireStateCopy(t, second, "state-two")

	// Passes that set the same bytes, read, or publish an identical
	// requirements.toml, while the older copy is held and after it is
	// released.
	passes := []func() error{
		f.write("state-two"),
		func() error {
			_, err := readWindowsCodexManagedState(f.state, false)
			return err
		},
		func() error {
			windowsCodexActiveManagedState.requirementsTouched = windowsCodexRequirementsPublishChanges(
				safefile.SharedFile{Exists: true, Data: []byte("same")}, []byte("same"), false, false)
			return nil
		},
		func() error { return nil },
	}
	runAll := func(when string) {
		t.Helper()
		before := windowsCodexStateDirSnapshotForTest(t, f.dir)
		for index, pass := range passes {
			if counter := f.run(t, pass); counter != second {
				t.Fatalf("%s: pass %d moved the counter from %d to %d", when, index, second, counter)
			}
		}
		after := windowsCodexStateDirSnapshotForTest(t, f.dir)
		if when == "after the release" {
			// The first pass after the release removes the older copy that
			// was held; nothing else changes.
			delete(before, filepath.Base(windowsCodexStableStateFile(f.dir, first)))
		}
		requireSameDirForTest(t, when, before, after)
		f.requireStateCopy(t, second, "state-two")
	}
	runAll("while the older copy is held")
	if _, err := os.Lstat(windowsCodexStableStateFile(f.dir, first)); err != nil {
		t.Fatalf("the held older copy should stay while it is held: %v", err)
	}
	_ = windows.CloseHandle(held)
	closed = true
	runAll("after the release")
	runAll("a second round after the release")
	if _, err := os.Lstat(windowsCodexStableStateFile(f.dir, first)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the older copy stayed after its release: %v", err)
	}

	// A real change still advances the counter and writes the new copy.
	if third := f.run(t, f.write("state-three")); third == second {
		t.Fatalf("a changed state kept counter %d", third)
	}
}

// windowsCodexRequirementsPublishChanges is the rule behind the requirements
// side of the no-change rule.
func TestWindowsCodexRequirementsPublishChangesOnlyWhenTheFileChanges(t *testing.T) {
	existing := safefile.SharedFile{Exists: true, Data: []byte("a")}
	for _, row := range []struct {
		name       string
		base       safefile.SharedFile
		candidate  []byte
		remove     bool
		unreadable bool
		want       bool
	}{
		{"same bytes", existing, []byte("a"), false, false, false},
		{"same bytes, users cannot read the file", existing, []byte("a"), false, true, true},
		{"other bytes", existing, []byte("b"), false, false, true},
		{"new file", safefile.SharedFile{}, []byte("a"), false, false, true},
		{"remove an existing file", existing, nil, true, false, true},
		{"remove an absent file", safefile.SharedFile{}, nil, true, false, false},
	} {
		if got := windowsCodexRequirementsPublishChanges(row.base, row.candidate, row.remove, row.unreadable); got != row.want {
			t.Errorf("%s: changes = %v, want %v", row.name, got, row.want)
		}
	}
}

// The whole guardian pass: the target publication, the reconcile and the
// verification, over a state a standard account held open meanwhile. Once
// the policy and the targets are as they should be, further passes leave the
// current copy, the writer copy, requirements.toml and the counter alone.
func TestWindowsCodexGuardianPassesThatChangeNothingKeepTheStateCopy(t *testing.T) {
	row := windowsCodexRemovalRowsForTest[0]
	opts := newWindowsCodexMachineGuardFixtureForTest(t, row.requirements)
	dir := filepath.Dir(opts.RequirementsPath)
	lock := filepath.Join(dir, WindowsCodexManagedWriterLockFile)
	alice := WindowsCodexManagedRuntimeTarget{SID: "S-1-5-21-111-222-333-1001", DataDir: `C:\Users\alice\.defenseclaw`}
	bob := WindowsCodexManagedRuntimeTarget{SID: "S-1-5-21-111-222-333-1002", DataDir: `C:\Users\bob\.defenseclaw`}
	if report, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
		t.Fatalf("reconcile: %+v, %v", report, err)
	}
	if err := PublishWindowsCodexManagedRuntimeTargets(opts, []WindowsCodexManagedRuntimeTarget{alice}); err != nil {
		t.Fatal(err)
	}
	current := func() (uint64, string) {
		t.Helper()
		counter, err := readWindowsCodexTransactionCounter(lock)
		if err != nil {
			t.Fatal(err)
		}
		return counter, windowsCodexStableStateFile(dir, counter)
	}
	counter, copyPath := current()
	held := holdWindowsCodexFileForTest(t, copyPath, 0)
	closed := false
	defer func() {
		if !closed {
			_ = windows.CloseHandle(held)
		}
	}()
	// The reconcile that follows a real change makes a newer copy.
	if err := PublishWindowsCodexManagedRuntimeTargets(opts, []WindowsCodexManagedRuntimeTarget{alice, bob}); err != nil {
		t.Fatal(err)
	}
	changed, _ := current()
	if changed == counter {
		t.Fatalf("a changed target set kept counter %d", counter)
	}
	pass := func() {
		t.Helper()
		if err := PublishWindowsCodexManagedRuntimeTargets(opts, []WindowsCodexManagedRuntimeTarget{alice, bob}); err != nil {
			t.Fatal(err)
		}
		if report, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
			t.Fatalf("reconcile: %+v, %v", report, err)
		}
		if report, err := VerifyWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
			t.Fatalf("verify: %+v, %v", report, err)
		}
	}
	// The first pass settles any normalisation of the target set.
	pass()
	settled, settledCopy := current()
	before := windowsCodexStateDirSnapshotForTest(t, dir)
	for i := 0; i < 3; i++ {
		pass()
	}
	if after, afterCopy := current(); after != settled || afterCopy != settledCopy {
		t.Fatalf("unchanged passes moved the current copy from %s (%d) to %s (%d)", settledCopy, settled, afterCopy, after)
	}
	requireSameDirForTest(t, "unchanged passes while an older copy is held", before, windowsCodexStateDirSnapshotForTest(t, dir))

	_ = windows.CloseHandle(held)
	closed = true
	pass() // removes the older copy that was held
	before = windowsCodexStateDirSnapshotForTest(t, dir)
	for i := 0; i < 3; i++ {
		pass()
	}
	if after, _ := current(); after != settled {
		t.Fatalf("unchanged passes after the release moved the counter from %d to %d", settled, after)
	}
	requireSameDirForTest(t, "unchanged passes after the release", before, windowsCodexStateDirSnapshotForTest(t, dir))
}

// GAP-0765. The first Codex transaction of this release on a host upgraded
// from 1.0.8 reads the state at its fixed name. A user who holds that file
// open and refuses read sharing (no sharing at all, or write and delete
// sharing only) makes the read fail with a sharing violation. It is never
// taken for an absent state: the transaction retries for its bounded time,
// then fails with the named, retryable read hold; the file, the writer copy
// and the counter are as they were (nothing written, no success), and once
// the holder lets go the next attempt migrates the state.
func TestWindowsCodexUpgradeFromAFixedNameReadHoldFailsRetryablyAndLeavesTheStateIntact(t *testing.T) {
	for _, hold := range []struct {
		name  string
		share uint32
	}{
		{name: "no sharing", share: 0},
		{name: "write and delete sharing only", share: windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE},
	} {
		t.Run(hold.name, func(t *testing.T) {
			f := newWindowsCodexStateTxFixture(t)
			if err := os.WriteFile(f.state, []byte("state of 1.0.8"), 0o600); err != nil {
				t.Fatal(err)
			}
			held := holdWindowsCodexFileForTest(t, f.state, hold.share)
			closed := false
			closeHeld := func() {
				if !closed {
					closed = true
					_ = windows.CloseHandle(held)
				}
			}
			defer closeHeld()

			previousWait, previousSleep, previousNow := windowsCodexHeldRetryWait, windowsCodexHeldRetrySleep, windowsCodexHeldRetryNow
			previousHolders := windowsCodexRequirementsHolders
			t.Cleanup(func() {
				windowsCodexHeldRetryWait, windowsCodexHeldRetrySleep, windowsCodexHeldRetryNow = previousWait, previousSleep, previousNow
				windowsCodexRequirementsHolders = previousHolders
			})
			now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
			windowsCodexHeldRetryNow = func() time.Time { return now }
			windowsCodexHeldRetryWait = 30 * time.Second
			slept := time.Duration(0)
			windowsCodexHeldRetrySleep = func(d time.Duration) { slept += d; now = now.Add(d) }
			windowsCodexRequirementsHolders = func(string) []string { return []string{"holder.exe (PID 4242)"} }

			ran := 0
			attempt := func() error {
				return withWindowsCodexRequirementsReleaseRetry(func() error {
					return withWindowsCodexMachinePolicyLock(f.requirements, func() error {
						ran++
						return nil
					})
				})
			}
			before := windowsCodexStateDirSnapshotForTest(t, f.dir)
			err := attempt()
			var heldErr *WindowsCodexRequirementsHeldError
			if err == nil || !errors.As(err, &heldErr) || !heldErr.Reading || ran != 0 {
				t.Fatalf("a held fixed name: err = %v, ran %d times; want the named read hold and no run, never a success", err, ran)
			}
			for _, want := range []string{f.state, "holder.exe (PID 4242)", "cannot read it", windowsCodexHeldRetryPromise} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("held error %q does not name %q", err, want)
				}
			}
			if slept < windowsCodexHeldRetryWait-windowsCodexHeldRetryPoll {
				t.Fatalf("the transaction waited %s for the release; want about %s", slept, windowsCodexHeldRetryWait)
			}
			// Nothing but the writer lock was created, still at counter 0, so
			// the hook keeps reading the state of 1.0.8.
			after := windowsCodexStateDirSnapshotForTest(t, f.dir)
			for name := range after {
				if _, ok := before[name]; !ok && !strings.EqualFold(name, WindowsCodexManagedWriterLockFile) {
					t.Fatalf("the failed attempt created %s", name)
				}
			}
			if counter, err := readWindowsCodexTransactionCounter(f.lock); err != nil || counter != 0 {
				t.Fatalf("counter after the failed attempt = %d, %v; want 0", counter, err)
			}
			if data, err := os.ReadFile(f.state); err != nil && hold.share != 0 {
				t.Fatalf("the state of 1.0.8 cannot be read back: %v", err)
			} else if err == nil && string(data) != "state of 1.0.8" {
				t.Fatalf("the state of 1.0.8 was changed to %q", data)
			}
			if _, err := os.Lstat(f.state); err != nil {
				t.Fatalf("the state of 1.0.8 is gone: %v", err)
			}

			// The holder lets go: the next attempt migrates the state.
			closeHeld()
			if err := attempt(); err != nil || ran != 1 {
				t.Fatalf("after the release: err = %v, ran %d times; want one run", err, ran)
			}
			counter, err := readWindowsCodexTransactionCounter(f.lock)
			if err != nil || counter == 0 || counter%2 != 0 {
				t.Fatalf("counter after the migration = %d, %v", counter, err)
			}
			f.requireStateCopy(t, counter, "state of 1.0.8")
			if _, err := os.Lstat(f.state); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the fixed name stayed once it was released: %v", err)
			}
		})
	}
}

// stampWindowsCodexSDDLForTest replaces the owner and the protected access
// list of the existing file at path.
func stampWindowsCodexSDDLForTest(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, _ := descriptor.Owner()
	dacl, _, _ := descriptor.DACL()
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		t.Fatalf("stamp %s: %v", path, err)
	}
}

// g582 round 11c, S1. The no-change rule (GAP-0764) keeps the hook copy only
// while that copy is what a pass would write: a copy that was truncated,
// changed or given another access list since it was written is published
// again under a new name, so the hook never reads a damaged or exposed copy
// for longer than one guardian pass. A copy a user holds open without
// sharing cannot be read; it counts as intact, and its access list, which is
// read without opening the data, is still judged.
func TestWindowsCodexUnchangedPassRepublishesADamagedOrExposedHookCopy(t *testing.T) {
	canonicalPlusUsersWrite := "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFW;;;BU)"
	noHolder := ^uint32(0)
	for _, row := range []struct {
		name string
		// damage changes the hook copy at path.
		damage func(t *testing.T, path string)
		// hold is the share mode of a user who holds the copy, or noHolder.
		hold uint32
		// republished: the pass writes a new copy.
		republished bool
	}{
		{"bytes changed", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("tampered-state"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, noHolder, true},
		{"truncated", func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, noHolder, true},
		{"access list gives Users write", func(t *testing.T, path string) {
			stampWindowsCodexSDDLForTest(t, path, canonicalPlusUsersWrite)
		}, noHolder, true},
		{"access list gives Users write while a user holds the copy with no sharing", func(t *testing.T, path string) {
			stampWindowsCodexSDDLForTest(t, path, canonicalPlusUsersWrite)
		}, 0, true},
		{"intact copy held with no sharing", func(t *testing.T, path string) {}, 0, false},
		{"intact copy held with write and delete sharing only", func(t *testing.T, path string) {},
			windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newWindowsCodexStateTxFixture(t)
			first := f.run(t, f.write("state-one"))
			current := windowsCodexStableStateFile(f.dir, first)
			if row.hold != noHolder {
				held := holdWindowsCodexFileForTest(t, current, row.hold)
				defer func() { _ = windows.CloseHandle(held) }()
			}
			row.damage(t, current)
			before := windowsCodexStateDirSnapshotForTest(t, f.dir)
			second := f.run(t, func() error { return nil })
			if !row.republished {
				if second != first {
					t.Fatalf("an intact copy moved the counter from %d to %d", first, second)
				}
				requireSameDirForTest(t, row.name, before, windowsCodexStateDirSnapshotForTest(t, f.dir))
				return
			}
			if second == first {
				t.Fatalf("a %s hook copy kept counter %d", row.name, first)
			}
			f.requireStateCopy(t, second, "state-one")
			if row.hold != noHolder {
				if _, err := os.Lstat(current); err != nil {
					t.Fatalf("the held old copy should stay while it is held: %v", err)
				}
			} else if _, err := os.Lstat(current); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the replaced copy stayed: %v", err)
			}
			// The pass after that finds nothing to do.
			if third := f.run(t, func() error { return nil }); third != second {
				t.Fatalf("the republished copy moved the counter from %d to %d", second, third)
			}
		})
	}
}

// g582 round 11c, L1 (round 11b). publishWindowsCodexRequirements marks the
// transaction as having touched requirements.toml only when the publication
// writes it, through the real call: an identical readable file leaves the
// flag alone; a file ordinary users cannot read is published again with the
// read and counts.
func TestWindowsCodexPublishRequirementsMarksTheTransactionOnlyWhenItWrites(t *testing.T) {
	f := newWindowsCodexStateTxFixture(t)
	body := []byte("[features]\nhooks = true\n")
	for _, row := range []struct {
		name string
		sddl string
		want bool
	}{
		{"identical file users can read", "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)", false},
		{"identical file users cannot read", "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			if err := os.WriteFile(f.requirements, body, 0o600); err != nil {
				t.Fatal(err)
			}
			stampWindowsCodexSDDLForTest(t, f.requirements, row.sddl)
			var touched bool
			f.run(t, func() error {
				base, err := readWindowsCodexSharedRequirements(f.requirements)
				if err != nil {
					return err
				}
				if err := publishWindowsCodexRequirements(base, body, false); err != nil {
					return err
				}
				touched = windowsCodexActiveManagedState.requirementsTouched
				return nil
			})
			if touched != row.want {
				t.Fatalf("requirementsTouched = %v, want %v", touched, row.want)
			}
		})
	}
}

// g582 round 11c, the r11 residual. A program that opens requirements.toml
// without read sharing but sharing delete was never found by the delete
// probe, because that open asked for no data access and Windows does not
// check such an open against the share mode of the other handle. The failed
// read came back unnamed, was never waited for, and the guardian could not
// recover.
func TestWindowsCodexRequirementsHeldProbeSeesAHolderThatDeniesReadSharing(t *testing.T) {
	f := newWindowsCodexStateTxFixture(t)
	if err := os.WriteFile(f.requirements, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if windowsCodexFileHeldAgainstDelete(f.requirements) {
		t.Fatal("a file nobody holds reads as held")
	}
	for _, share := range []struct {
		name  string
		share uint32
		held  bool
	}{
		{"no sharing", 0, true},
		{"write and delete sharing only", windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE, true},
		{"read sharing only", windows.FILE_SHARE_READ, true},
		{"everything shared", windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE, false},
	} {
		handle := holdWindowsCodexFileForTest(t, f.requirements, share.share)
		got := windowsCodexFileHeldAgainstDelete(f.requirements)
		_ = windows.CloseHandle(handle)
		if got != share.held {
			t.Errorf("%s: held = %v, want %v", share.name, got, share.held)
		}
	}
}
