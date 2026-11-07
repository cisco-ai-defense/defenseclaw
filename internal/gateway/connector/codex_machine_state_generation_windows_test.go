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
