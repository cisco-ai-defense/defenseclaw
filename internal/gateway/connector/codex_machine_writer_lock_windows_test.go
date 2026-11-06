// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// holdWindowsCodexLockForTest takes path exclusively the way a writer of 1.0.8
// and earlier did.
func holdWindowsCodexLockForTest(path string) (windows.Handle, *windows.Overlapped, error) {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, nil, err
	}
	handle, err := windows.CreateFile(ptr, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS, 0, 0)
	if err != nil {
		return 0, nil, err
	}
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(handle,
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, nil, err
	}
	return handle, overlapped, nil
}

// stubWindowsCodexTrustForTest stands a temporary folder in for the protected
// Codex policy folder.
func stubWindowsCodexTrustForTest(t *testing.T, programData string) {
	t.Helper()
	originalProgramData := windowsCodexMachineProgramData
	originalDir := windowsCodexMachineTrustedDirCheck
	originalFile := windowsCodexMachineTrustedFileCheck
	originalWait := windowsCodexReaderWait
	originalCounter := windowsCodexTransactionCounterRead
	t.Cleanup(func() {
		windowsCodexMachineProgramData = originalProgramData
		windowsCodexMachineTrustedDirCheck = originalDir
		windowsCodexMachineTrustedFileCheck = originalFile
		windowsCodexReaderWait = originalWait
		windowsCodexTransactionCounterRead = originalCounter
	})
	if programData != "" {
		windowsCodexMachineProgramData = func() (string, error) { return programData, nil }
	}
	windowsCodexMachineTrustedDirCheck = func(string, string) error { return nil }
	windowsCodexMachineTrustedFileCheck = func(string, string) error { return nil }
}

func requireWindowsCodexWriterForTest(t *testing.T) {
	t.Helper()
	if err := requireWindowsCodexMachineAdministrator(); err != nil {
		t.Skipf("needs an elevated Administrator or LocalSystem token to stamp an Administrators owner: %v", err)
	}
}

// writeWindowsCodexLockFileForTest writes a lock file of size bytes with sddl.
func writeWindowsCodexLockFileForTest(t *testing.T, path string, size int, sddl string) {
	t.Helper()
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	if sddl == "" {
		return
	}
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

func windowsCodexUsersMaskForTest(t *testing.T, path string) (uint32, bool) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("lock DACL: %v", err)
	}
	var mask uint32
	found := false
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			t.Fatal(err)
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).IsWellKnown(windows.WinBuiltinUsersSid) {
			mask |= uint32(ace.Mask)
			found = true
		}
	}
	return mask, found
}

// The writer lock gives BUILTIN\Users read attributes, read control and
// synchronize only: no data access, so no standard user can share-lock,
// byte-range-lock or hold it against a writer (GAP-0650). Every transaction
// keeps the counter odd while it runs and leaves it even and advanced.
func TestWindowsCodexWriterLockGrantsUsersOnlyAttributesAndCountsTransactions(t *testing.T) {
	requireWindowsCodexWriterForTest(t)
	dir := t.TempDir()
	stubWindowsCodexTrustForTest(t, "")
	requirements := filepath.Join(dir, "requirements.toml")
	lockPath := filepath.Join(dir, WindowsCodexManagedWriterLockFile)

	var during uint64
	if err := withWindowsCodexMachinePolicyLock(requirements, func() error {
		var err error
		during, err = readWindowsCodexTransactionCounter(lockPath)
		return err
	}); err != nil {
		t.Fatalf("transaction: %v", err)
	}
	after, err := readWindowsCodexTransactionCounter(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if during%2 != 1 || after != during+1 {
		t.Fatalf("counter during=%d after=%d, want odd then the next even value", during, after)
	}
	descriptor, err := windows.GetNamedSecurityInfo(lockPath, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if drift := windowsCodexWriterLockDescriptorDrift(descriptor); drift != "" {
		t.Fatalf("writer lock descriptor %s: %s", descriptor.String(), drift)
	}
	mask, found := windowsCodexUsersMaskForTest(t, lockPath)
	const allowed = windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL | windows.SYNCHRONIZE
	if !found || mask&^allowed != 0 {
		t.Fatalf("BUILTIN\\Users mask 0x%x (found %v), want only read attributes, read control and synchronize (0x%x)", mask, found, allowed)
	}

	if err := withWindowsCodexMachinePolicyLock(requirements, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	second, err := readWindowsCodexTransactionCounter(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if second <= after || second%2 != 0 {
		t.Fatalf("second transaction left counter %d after %d", second, after)
	}
}

// A writer lock carrying the user-readable descriptor of the old lock, or any
// other drift under an administrator owner, is put back by the next
// transaction; the lock of 1.0.8 and earlier is removed.
func TestWindowsCodexWriterLockRestampsDriftAndRemovesTheOldLock(t *testing.T) {
	requireWindowsCodexWriterForTest(t)
	dir := t.TempDir()
	stubWindowsCodexTrustForTest(t, "")
	lockPath := filepath.Join(dir, WindowsCodexManagedWriterLockFile)
	legacy := filepath.Join(dir, windowsCodexManagedLegacyLockFile)
	writeWindowsCodexLockFileForTest(t, lockPath, 4, "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)")
	writeWindowsCodexLockFileForTest(t, legacy, 0, "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)")

	if err := withWindowsCodexMachinePolicyLock(filepath.Join(dir, "requirements.toml"), func() error { return nil }); err != nil {
		t.Fatalf("transaction: %v", err)
	}
	mask, _ := windowsCodexUsersMaskForTest(t, lockPath)
	if mask != windowsCodexWriterLockUsersAccess {
		t.Fatalf("BUILTIN\\Users mask after the transaction = 0x%x, want 0x%x", mask, windowsCodexWriterLockUsersAccess)
	}
	if counter, err := readWindowsCodexTransactionCounter(lockPath); err != nil || counter != 6 {
		t.Fatalf("counter = %d, %v; want 6 after a lock that held 4", counter, err)
	}
	if _, err := os.Lstat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the lock of an earlier release was kept: %v", err)
	}
}

// A writer that stopped mid-transaction leaves the counter odd; the next one
// still moves it to a new odd value and ends even.
func TestWindowsCodexWriterLockRecoversAnOddCounter(t *testing.T) {
	requireWindowsCodexWriterForTest(t)
	dir := t.TempDir()
	stubWindowsCodexTrustForTest(t, "")
	lockPath := filepath.Join(dir, WindowsCodexManagedWriterLockFile)
	writeWindowsCodexLockFileForTest(t, lockPath, 7, windowsCodexWriterLockSDDL)
	var during uint64
	if err := withWindowsCodexMachinePolicyLock(filepath.Join(dir, "requirements.toml"), func() error {
		var err error
		during, err = readWindowsCodexTransactionCounter(lockPath)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	after, _ := readWindowsCodexTransactionCounter(lockPath)
	if during != 9 || after != 10 {
		t.Fatalf("counter during=%d after=%d, want 9 then 10", during, after)
	}
}

func scriptedWindowsCodexCounterForTest(t *testing.T, values ...uint64) *int {
	t.Helper()
	calls := 0
	windowsCodexTransactionCounterRead = func(string) (uint64, error) {
		value := values[len(values)-1]
		if calls < len(values) {
			value = values[calls]
		}
		calls++
		return value, nil
	}
	return &calls
}

// The hook-side reader keeps a result only when the counter was even and the
// same before and after the read; an odd or changed counter reads again, and a
// counter that stays odd fails closed instead of reporting the connector
// inactive.
func TestWindowsCodexStableReaderAcceptsOnlyAnUnchangedEvenCounter(t *testing.T) {
	cases := []struct {
		name     string
		counters []uint64
		resolves int
		want     string
		timeout  bool
	}{
		{name: "stable even", counters: []uint64{4, 4}, resolves: 1, want: "first"},
		{name: "odd then even", counters: []uint64{5, 6, 6}, resolves: 1, want: "first"},
		{name: "changed during the read", counters: []uint64{4, 6, 6, 6}, resolves: 2, want: "second"},
		{name: "even then odd during the read", counters: []uint64{4, 5, 6, 6}, resolves: 2, want: "second"},
		{name: "persistently odd", counters: []uint64{7}, resolves: 0, timeout: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubWindowsCodexTrustForTest(t, "")
			windowsCodexReaderWait = 150 * time.Millisecond
			scriptedWindowsCodexCounterForTest(t, tc.counters...)
			resolves := 0
			result, err := resolveWindowsCodexManagedRuntimeRegistryStable(`C:\x\lock`, func(string) (WindowsCodexManagedRuntimeRegistry, error) {
				resolves++
				label := "first"
				if resolves > 1 {
					label = "second"
				}
				return WindowsCodexManagedRuntimeRegistry{Active: true, GatewayAddr: label}, nil
			})
			if resolves != tc.resolves {
				t.Fatalf("resolve ran %d times, want %d", resolves, tc.resolves)
			}
			if tc.timeout {
				if err == nil || !strings.Contains(err.Error(), "timed out") || result.Active {
					t.Fatalf("persistently odd counter = %+v, %v; want a fail-closed timeout", result, err)
				}
				return
			}
			if err != nil || !result.Active || result.GatewayAddr != tc.want {
				t.Fatalf("result = %+v, %v; want the %s read", result, err, tc.want)
			}
		})
	}
}

func newWindowsCodexReaderFixture(t *testing.T) (programData, policyDir, hook string) {
	t.Helper()
	programData = t.TempDir()
	policyDir = filepath.Join(programData, "OpenAI", "Codex")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stubWindowsCodexTrustForTest(t, programData)
	windowsCodexReaderWait = 150 * time.Millisecond
	return programData, policyDir, filepath.Join(programData, "DefenseClaw", "bin", "defenseclaw-hook.exe")
}

func windowsCodexLockSizeForTest(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The reader never reports the connector inactive while DefenseClaw's state
// is there or a transaction is running, through the real counter.
func TestWindowsCodexReaderIsNeverInactiveWhileStateExistsOrATransactionRuns(t *testing.T) {
	t.Run("state without requirements, no transaction", func(t *testing.T) {
		_, policyDir, hook := newWindowsCodexReaderFixture(t)
		windowsCodexLockSizeForTest(t, filepath.Join(policyDir, WindowsCodexManagedWriterLockFile), 2)
		// The hook copy the counter names (GAP-0650).
		if err := os.WriteFile(windowsCodexManagedStateGenerationPath(policyDir, 2), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		registry, err := ResolveWindowsCodexManagedRuntimeRegistry(hook)
		if err == nil || registry.Active {
			t.Fatalf("state without requirements = %+v, %v; want an error", registry, err)
		}
	})
	t.Run("nothing published yet, transaction running", func(t *testing.T) {
		_, policyDir, hook := newWindowsCodexReaderFixture(t)
		windowsCodexLockSizeForTest(t, filepath.Join(policyDir, WindowsCodexManagedWriterLockFile), 3)
		registry, err := ResolveWindowsCodexManagedRuntimeRegistry(hook)
		if err == nil || !strings.Contains(err.Error(), "timed out") || registry.Active {
			t.Fatalf("a running transaction = %+v, %v; want a fail-closed timeout, never inactive", registry, err)
		}
	})
	t.Run("nothing published, no transaction", func(t *testing.T) {
		_, policyDir, hook := newWindowsCodexReaderFixture(t)
		windowsCodexLockSizeForTest(t, filepath.Join(policyDir, WindowsCodexManagedWriterLockFile), 2)
		registry, err := ResolveWindowsCodexManagedRuntimeRegistry(hook)
		if err != nil || registry.Active {
			t.Fatalf("clean committed absence = %+v, %v; want inactive", registry, err)
		}
	})
	t.Run("state appears during the read", func(t *testing.T) {
		_, policyDir, hook := newWindowsCodexReaderFixture(t)
		lock := filepath.Join(policyDir, WindowsCodexManagedWriterLockFile)
		windowsCodexLockSizeForTest(t, lock, 2)
		reads := 0
		windowsCodexTransactionCounterRead = func(path string) (uint64, error) {
			reads++
			if reads == 2 {
				// A writer ran between the two counter reads of the reader and
				// published the hook copy of the state its end value names.
				if err := os.WriteFile(windowsCodexManagedStateGenerationPath(policyDir, 4), []byte("{}\n"), 0o600); err != nil {
					return 0, err
				}
				windowsCodexLockSizeForTest(t, lock, 4)
				return 4, nil
			}
			return readWindowsCodexTransactionCounter(path)
		}
		registry, err := ResolveWindowsCodexManagedRuntimeRegistry(hook)
		if err == nil || registry.Active || reads < 4 {
			t.Fatalf("read across a transaction = %+v, %v (%d counter reads); want it read again and refused", registry, err, reads)
		}
	})
}

// A writer of this release that starts during an upgrade-fallback read
// creates its lock first; the reader then reads again against the counter.
func TestWindowsCodexLegacyFallbackReadsAgainWhenAWriterStarts(t *testing.T) {
	_, policyDir, hook := newWindowsCodexReaderFixture(t)
	legacy := filepath.Join(policyDir, windowsCodexManagedLegacyLockFile)
	writer := filepath.Join(policyDir, WindowsCodexManagedWriterLockFile)
	windowsCodexLockSizeForTest(t, legacy, 0)
	windowsCodexMachineTrustedFileCheck = func(path, _ string) error {
		if strings.EqualFold(path, legacy) {
			if _, err := os.Lstat(writer); errors.Is(err, os.ErrNotExist) {
				// The writer is mid-transaction: lock created, counter odd.
				windowsCodexLockSizeForTest(t, writer, 1)
			}
		}
		return nil
	}
	registry, err := ResolveWindowsCodexManagedRuntimeRegistry(hook)
	if err == nil || !strings.Contains(err.Error(), "timed out") || registry.Active {
		t.Fatalf("fallback read across a new writer = %+v, %v; want it re-read against the counter", registry, err)
	}
}

// readWindowsCodexTransactionCounter asks for the attributes only: its handle
// takes no part in sharing, so a writer opens the lock for data while it is
// open.
func TestWindowsCodexCounterReadDoesNotBlockAWriterOpen(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, WindowsCodexManagedWriterLockFile)
	windowsCodexLockSizeForTest(t, lockPath, 2)
	extended, err := winpath.Extended(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	ptr, _ := windows.UTF16PtrFromString(extended)
	held, err := windows.CreateFile(ptr, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, 0, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(held)
	writer, err := windows.CreateFile(ptr, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatalf("an attribute-only handle with no sharing blocked the writer's open: %v", err)
	}
	_ = windows.CloseHandle(writer)
}
