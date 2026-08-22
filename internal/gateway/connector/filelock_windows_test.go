//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestManagedWindowsFileLockContentionIsBoundedAndProgressContinues(t *testing.T) {
	originalTimeout := windowsManagedFileLockTimeout
	originalRetry := windowsManagedFileLockRetry
	windowsManagedFileLockTimeout = 150 * time.Millisecond
	windowsManagedFileLockRetry = 10 * time.Millisecond
	t.Cleanup(func() {
		windowsManagedFileLockTimeout = originalTimeout
		windowsManagedFileLockRetry = originalRetry
	})

	dir := t.TempDir()
	blockedPath := filepath.Join(dir, "first", "config.toml")
	if err := os.MkdirAll(filepath.Dir(blockedPath), 0o700); err != nil {
		t.Fatal(err)
	}
	hostile, hostileParent, err := openWindowsManagedFileLock(blockedPath + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer hostileParent.Close()
	hostileHandle := windows.Handle(hostile.Fd())
	hostileOverlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(
		hostileHandle,
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		hostileOverlapped,
	); err != nil {
		hostile.Close()
		t.Fatalf("hold hostile lock: %v", err)
	}
	held := true
	release := func() {
		if !held {
			return
		}
		_ = windows.UnlockFileEx(hostileHandle, 0, 1, 0, hostileOverlapped)
		_ = hostile.Close()
		held = false
	}
	t.Cleanup(release)

	callbackCalled := false
	started := time.Now()
	err = withFileLockMode(blockedPath, true, func() error {
		callbackCalled = true
		return nil
	})
	elapsed := time.Since(started)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("managed contended lock error = %v, want bounded timeout", err)
	}
	if callbackCalled {
		t.Fatal("managed callback ran without acquiring the hostile lock")
	}
	if elapsed > time.Second {
		t.Fatalf("managed contention returned after %s, want under one second", elapsed)
	}

	// A failed first target must not strand the guardian: the next target can
	// acquire its independent lock while the hostile first lock remains held.
	secondProgress := false
	secondPath := filepath.Join(dir, "second", "config.toml")
	if err := os.MkdirAll(filepath.Dir(secondPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := withFileLockMode(secondPath, true, func() error {
		secondProgress = true
		return nil
	}); err != nil {
		t.Fatalf("subsequent target lock: %v", err)
	}
	if !secondProgress {
		t.Fatal("subsequent target did not progress after first-target contention")
	}

	// Once the hostile process releases its handle, the next periodic tick can
	// repair the original target using the same bounded acquisition path.
	release()
	tickProgress := false
	if err := withFileLockMode(blockedPath, true, func() error {
		tickProgress = true
		return nil
	}); err != nil {
		t.Fatalf("next-tick original target lock: %v", err)
	}
	if !tickProgress {
		t.Fatal("next tick did not progress after hostile lock release")
	}
}

func TestManagedWindowsRuntimeLocksPinEffectiveOwnerForEveryConnector(t *testing.T) {
	for _, connectorName := range []string{"claudecode", "codex", "cursor"} {
		t.Run(connectorName, func(t *testing.T) {
			dataDir := t.TempDir()
			if err := ReconcileManagedNativeHookRuntime(
				dataDir,
				"127.0.0.1:18970",
				connectorName,
				"scoped-test-token",
			); err != nil {
				t.Fatalf("reconcile managed runtime: %v", err)
			}
			entry := HookContractLockEntry{
				Connector:    connectorName,
				ContractID:   connectorName + "-hooks-v1",
				HookFailMode: "closed",
			}
			if err := SaveRecoveredHookContractLockEntryForMode(
				dataDir,
				entry,
				"2026-08-22T12:00:01Z",
				"2026-08-22T12:00:00Z",
			); err != nil {
				t.Fatalf("save managed contract: %v", err)
			}
			for _, lockPath := range []string{
				filepath.Join(dataDir, "hooks", ".hookcfg.lock"),
				filepath.Join(dataDir, "hook_contract_lock.json.lock"),
			} {
				assertWindowsManagedLockHasEffectiveOwner(t, lockPath)
			}
		})
	}
}

func TestManagedWindowsFileLockDescriptorNamesEffectiveUserNotTokenDefaultOwner(t *testing.T) {
	target, err := windows.StringToSid("S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatal(err)
	}
	if target.Equals(windowsProcessUserSIDForTest(t)) {
		t.Skip("fixture SID collides with process user")
	}
	pinWindowsEffectiveUserSIDForTest(t, target)
	descriptor, err := windowsManagedFileLockSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if owner == nil || !owner.Equals(target) {
		t.Fatalf("managed lock descriptor owner=%v, want effective target %s", owner, target)
	}
}

func TestManagedWindowsFileLockRejectsExistingForeignOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hook_contract_lock.json.lock")
	file, parent, err := openWindowsManagedFileLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}

	foreign, err := windows.StringToSid("S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatal(err)
	}
	if foreign.Equals(windowsProcessUserSIDForTest(t)) {
		t.Skip("fixture SID collides with process user")
	}
	pinWindowsEffectiveUserSIDForTest(t, foreign)
	file, parent, err = openWindowsManagedFileLock(path)
	if file != nil {
		_ = file.Close()
	}
	if parent != nil {
		_ = parent.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "owner does not match") {
		t.Fatalf("foreign-owner managed lock error=%v, want owner rejection", err)
	}
}

func TestManagedWindowsFileLockDeniesRenameWhileHeld(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".hookcfg.lock")
	file, parent, err := openWindowsManagedFileLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	defer parent.Close()
	if err := os.Rename(path, path+".moved"); err == nil {
		t.Fatal("managed lock name was replaceable while its handle was held")
	} else if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) &&
		!errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("rename held managed lock error=%v, want sharing refusal", err)
	}
}

func TestManagedWindowsFileLockRejectsNoncanonicalDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".hookcfg.lock")
	target := windowsProcessUserSIDForTest(t)
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"O:%sD:P(A;;FA;;;%s)(A;;FR;;;WD)",
		target,
		target,
	))
	if err != nil {
		t.Fatal(err)
	}
	security := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		&security,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}

	file, parent, err := openWindowsManagedFileLock(path)
	if file != nil {
		_ = file.Close()
	}
	if parent != nil {
		_ = parent.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "DACL") {
		t.Fatalf("noncanonical managed lock error=%v, want DACL rejection", err)
	}
}

func TestManagedWindowsFileLockRejectsHardLink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hook_contract_lock.json.lock")
	file, parent, err := openWindowsManagedFileLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "second-name.lock")
	if err := os.Link(path, alias); err != nil {
		if errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
			errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
			t.Skipf("test volume does not support hard links: %v", err)
		}
		t.Fatal(err)
	}
	file, parent, err = openWindowsManagedFileLock(path)
	if file != nil {
		_ = file.Close()
	}
	if parent != nil {
		_ = parent.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("hard-linked managed lock error=%v, want link-count rejection", err)
	}
}

func TestManagedWindowsFileLockRejectsNonemptyPersistentFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".hookcfg.lock")
	file, parent, err := openWindowsManagedFileLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("unexpected")); err != nil {
		_ = file.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	file, parent, err = openWindowsManagedFileLock(path)
	if file != nil {
		_ = file.Close()
	}
	if parent != nil {
		_ = parent.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("nonempty managed lock error=%v, want empty-file rejection", err)
	}
}

func assertWindowsManagedLockHasEffectiveOwner(t *testing.T, path string) {
	t.Helper()
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	if err := validateWindowsManagedFileLockHandle(handle); err != nil {
		t.Fatalf("validate %s: %v", path, err)
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	want := windowsProcessUserSIDForTest(t)
	if owner == nil || !owner.Equals(want) {
		t.Fatalf("managed lock owner=%v, want exact process user %s", owner, want)
	}
}

func TestOrdinaryWindowsFileLockRetainsBlockingSemantics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	hostile, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	handle := windows.Handle(hostile.Fd())
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(
		handle,
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		overlapped,
	); err != nil {
		hostile.Close()
		t.Fatalf("hold ordinary contention fixture: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- withFileLock(path, func() error { return nil })
	}()
	select {
	case err := <-done:
		_ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped)
		_ = hostile.Close()
		t.Fatalf("ordinary lock returned before contention released: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	if err := windows.UnlockFileEx(handle, 0, 1, 0, overlapped); err != nil {
		hostile.Close()
		t.Fatal(err)
	}
	if err := hostile.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ordinary lock after release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ordinary blocking lock did not progress after contention release")
	}
}
