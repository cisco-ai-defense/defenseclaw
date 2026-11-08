//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func TestManagedWindowsOpenCodePortRecordIsSystemOnly(t *testing.T) {
	if err := requireWindowsEnterpriseLocalSystem(); err != nil {
		t.Skip("the SYSTEM-only record requires a LocalSystem test token")
	}
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := WindowsOpenCodeServicePortsPath(filepath.Join(dir, "targets.yaml"))
	if ports, err := LoadWindowsOpenCodeServicePorts(path); err != nil || len(ports) != 0 {
		t.Fatalf("missing record = %v, %v", ports, err)
	}
	want := map[string]int{testLocalUserSID: 25001, testEntraUserSID: 25002}
	if err := WriteWindowsOpenCodeServicePorts(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadWindowsOpenCodeServicePorts(path)
	if err != nil || len(got) != len(want) || got[testLocalUserSID] != 25001 || got[testEntraUserSID] != 25002 {
		t.Fatalf("record = %v, %v", got, err)
	}
	if err := validateWindowsOpenCodeServicePortsFile(path); err != nil {
		t.Fatalf("record ACL: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteWindowsOpenCodeServicePorts(path, want); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("unchanged record was rewritten")
	}
	if err := WriteWindowsOpenCodeServicePorts(path, map[string]int{testLocalUserSID: 25001, testEntraUserSID: 25001}); err == nil {
		t.Fatal("record writer accepted one port for two accounts")
	}
	stampWindowsTargetsManifestTestSDDL(t, path, windowsTargetsManifestAdminFileSDDL)
	if _, err := LoadWindowsOpenCodeServicePorts(path); err == nil {
		t.Fatal("administrators-readable record was accepted")
	}
	if err := WriteWindowsOpenCodeServicePorts(path, want); err == nil {
		t.Fatal("writer adopted an ACL-drifted record")
	}
}

func TestManagedWindowsOpenCodeRecordClosesImportWindow(t *testing.T) {
	if err := requireWindowsEnterpriseLocalSystem(); err != nil {
		t.Skip("the SYSTEM-only record requires a LocalSystem test token")
	}
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := WindowsOpenCodeServicePortsPath(filepath.Join(dir, "targets.yaml"))
	state := WindowsOpenCodeServicePortsState{Ports: map[string]int{testLocalUserSID: 25001}, ImportDone: true}
	if err := WriteWindowsOpenCodeServicePortsFull(path, state); err != nil {
		t.Fatal(err)
	}
	data, err := readWindowsOpenCodePortRecord(path)
	if err != nil || !strings.Contains(string(data), `"import_done": true`) {
		t.Fatalf("committed import flag: %s, %v", data, err)
	}
	loaded, err := LoadWindowsOpenCodeServicePortsFull(path)
	if err != nil || !loaded.ImportDone || loaded.Ports[testLocalUserSID] != 25001 {
		t.Fatalf("committed record: %+v, %v", loaded, err)
	}
	state.ImportDone = false // a record an earlier build wrote is also done
	if err := WriteWindowsOpenCodeServicePortsFull(path, state); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadWindowsOpenCodeServicePortsFull(path)
	if err != nil || !loaded.ImportDone {
		t.Fatalf("older record reopened the import window: %+v, %v", loaded, err)
	}
}

func TestManagedWindowsOpenCodeContestedMarkIsSystemOnly(t *testing.T) {
	if err := requireWindowsEnterpriseLocalSystem(); err != nil {
		t.Skip("the SYSTEM-only record requires a LocalSystem test token")
	}
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := WindowsOpenCodeServicePortsPath(filepath.Join(dir, "targets.yaml"))
	state := WindowsOpenCodeServicePortsState{
		Ports:     map[string]int{testLocalUserSID: 25001},
		Contested: []WindowsOpenCodeContestedPort{{Port: 25002, SIDs: []string{testLocalUserSID, testEntraUserSID}}},
	}
	if err := WriteWindowsOpenCodeServicePortsFull(path, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadWindowsOpenCodeServicePortsFull(path)
	if err != nil || !loaded.Exists || len(loaded.Contested) != 1 || loaded.Contested[0].Port != 25002 {
		t.Fatalf("contested mark was not kept: %+v, %v", loaded, err)
	}
	if err := WriteWindowsOpenCodeServicePortsFull(path, WindowsOpenCodeServicePortsState{Ports: state.Ports, Contested: []WindowsOpenCodeContestedPort{{Port: 25001, SIDs: state.Contested[0].SIDs}}}); err == nil {
		t.Fatal("writer accepted a contested mark on a bound port")
	}
	claimants, err := ClearWindowsOpenCodeContestedPort(path, 25002, "administrator", time.Now())
	if err != nil || len(claimants) != 2 {
		t.Fatalf("clear: %v, %v", claimants, err)
	}
	loaded, err = LoadWindowsOpenCodeServicePortsFull(path)
	if err != nil || len(loaded.Contested) != 0 || len(loaded.Cleared) != 1 || loaded.Ports[testLocalUserSID] != 25001 {
		t.Fatalf("clear changed a binding or lost its audit: %+v, %v", loaded, err)
	}
	if _, err := ClearWindowsOpenCodeContestedPort(path, 25002, "administrator", time.Now()); err == nil {
		t.Fatal("unmarked port was cleared twice")
	}
}

func TestManagedWindowsOpenCodeContestedMarkCanBeClearedByElevatedAdministrator(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() || !errors.Is(windowsEnterpriseMutationIdentityCheck(), errWindowsEnterpriseNotLocalSystem) {
		t.Skip("requires an elevated administrator token")
	}
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := WindowsOpenCodeServicePortsPath(filepath.Join(dir, "targets.yaml"))
	state := WindowsOpenCodeServicePortsState{
		Ports:     map[string]int{testLocalUserSID: 25001},
		Contested: []WindowsOpenCodeContestedPort{{Port: 25002, SIDs: []string{testEntraUserSID}}},
	}
	if err := RunWithWindowsOwnerRestorePrivilege(func() error {
		return WriteWindowsOpenCodeServicePortsFull(path, state)
	}); err != nil {
		t.Fatal(err)
	}
	// An elevated session can hold SeBackupPrivilege enabled (an SSH or
	// scheduled-task launch does), and Go opens every file with backup
	// semantics, so the denial below was not observable there. Disable the
	// backup and restore privileges in the process token for the rest of the
	// test, as the GitHub runner token has them: the clear must then enable
	// its own scoped privilege, and the record must still deny a plain read.
	disableWindowsProcessPrivilegesForTest(t, "SeBackupPrivilege", "SeRestorePrivilege")
	if _, err := os.ReadFile(path); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("administrator read of SYSTEM-only record = %v", err)
	}
	claimants, err := ClearWindowsOpenCodeContestedPort(path, 25002, "administrator", time.Now())
	if err != nil || len(claimants) != 1 || claimants[0] != testEntraUserSID {
		t.Fatalf("clear = %v, %v", claimants, err)
	}
	if err := RunWithWindowsOwnerRestorePrivilege(func() error {
		got, loadErr := LoadWindowsOpenCodeServicePortsFull(path)
		if loadErr != nil {
			return loadErr
		}
		if len(got.Contested) != 0 || len(got.Cleared) != 1 || got.Ports[testLocalUserSID] != 25001 {
			t.Errorf("clear changed a binding or lost its audit: %+v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := RunWithWindowsOwnerRestorePrivilege(func() error {
		return validateWindowsOpenCodeServicePortsFile(path)
	}); err != nil {
		t.Fatalf("clear changed the SYSTEM-only ACL: %v", err)
	}
}

func TestManagedWindowsOpenCodeClearWaitsForReconcileLock(t *testing.T) {
	if err := requireWindowsEnterpriseLocalSystem(); err != nil {
		t.Skip("the SYSTEM-only record requires a LocalSystem test token")
	}
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := WindowsOpenCodeServicePortsPath(filepath.Join(dir, "targets.yaml"))
	state := WindowsOpenCodeServicePortsState{
		Ports: map[string]int{testLocalUserSID: 25001}, ImportDone: true,
		Contested: []WindowsOpenCodeContestedPort{{Port: 25002, SIDs: []string{testEntraUserSID}}},
	}
	if err := WriteWindowsOpenCodeServicePortsFull(path, state); err != nil {
		t.Fatal(err)
	}
	unlock, err := LockWindowsOpenCodeServicePorts(path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		_, clearErr := ClearWindowsOpenCodeContestedPort(path, 25002, "administrator", time.Now())
		done <- clearErr
	}()
	<-started
	select {
	case err := <-done:
		unlock()
		t.Fatalf("clear ran while the guardian lock was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("clear did not run after the guardian lock was released")
	}
	loaded, err := LoadWindowsOpenCodeServicePortsFull(path)
	if err != nil || len(loaded.Contested) != 0 || len(loaded.Cleared) != 1 || loaded.Ports[testLocalUserSID] != 25001 {
		t.Fatalf("clear lost its audit or binding: %+v, %v", loaded, err)
	}
}

// The reconcile lock must not depend on a name any account can create first.
// An ordinary account that squats the old predictable global mutex name
// changes nothing: the guardian pass and the administrator clear take
// the lock inside the protected record folder.
func TestManagedWindowsOpenCodeLockIgnoresPredictableGlobalNames(t *testing.T) {
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := WindowsOpenCodeServicePortsPath(filepath.Join(dir, "targets.yaml"))
	const squatted = `Global\Cisco.DefenseClaw.EnterpriseHooks.OpenCodePorts`
	name, err := windows.UTF16PtrFromString(squatted)
	if err != nil {
		t.Fatal(err)
	}
	mutex, err := windows.CreateMutex(nil, true, name)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		t.Skipf("global mutex unavailable: %v", err)
	}
	defer windows.CloseHandle(mutex) //nolint:errcheck
	done := make(chan error, 1)
	go func() {
		unlock, lockErr := LockWindowsOpenCodeServicePorts(path)
		if lockErr == nil {
			unlock()
		}
		done <- lockErr
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a squatted global name blocked the reconcile lock: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a squatted global name stalled the reconcile lock")
	}
}

// A standard account (Administrators and the current user disabled in its
// token, Users and Everyone left on) can neither create the lock file nor
// open or hold an existing one.
func TestManagedWindowsOpenCodeLockStandardUserCannotCreateOrHold(t *testing.T) {
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := WindowsOpenCodeServicePortsPath(filepath.Join(dir, "targets.yaml"))
	lockPath := filepath.Join(dir, WindowsOpenCodeReconcileLockFileName)
	token, err := createWindowsStandardAccountToken()
	if err != nil {
		if errors.Is(err, windows.ERROR_PROC_NOT_FOUND) || errors.Is(err, windows.ERROR_CALL_NOT_IMPLEMENTED) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
			t.Skipf("CreateRestrictedToken unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer token.Close() //nolint:errcheck
	asStandard := func() error {
		file, openErr := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
		if openErr == nil {
			_ = file.Close()
			return errors.New("a standard account created or opened the reconcile lock file")
		}
		if !errors.Is(openErr, os.ErrPermission) {
			return openErr
		}
		return nil
	}
	if err := runWindowsManagedRuntimeRestrictedToken(token, asStandard); err != nil {
		t.Fatalf("before the lock file exists: %v", err)
	}
	unlock, err := LockWindowsOpenCodeServicePorts(path)
	if err != nil {
		t.Fatalf("reconciliation could not create the lock beside a hostile account: %v", err)
	}
	if err := runWindowsManagedRuntimeRestrictedToken(token, asStandard); err != nil {
		unlock()
		t.Fatalf("while the lock is held: %v", err)
	}
	unlock()
	if err := runWindowsManagedRuntimeRestrictedToken(token, asStandard); err != nil {
		t.Fatalf("after the lock file exists: %v", err)
	}
	unlock, err = LockWindowsOpenCodeServicePorts(path)
	if err != nil {
		t.Fatalf("reconciliation could not reuse the lock file: %v", err)
	}
	unlock()
}

// A lock file that is not administrator-only (planted or drifted) is refused
// rather than trusted.
func TestManagedWindowsOpenCodeLockRefusesWidenedLockFile(t *testing.T) {
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := WindowsOpenCodeServicePortsPath(filepath.Join(dir, "targets.yaml"))
	lockPath := filepath.Join(dir, WindowsOpenCodeReconcileLockFileName)
	unlock, err := LockWindowsOpenCodeServicePorts(path)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(lockPath, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if unlock, err := LockWindowsOpenCodeServicePorts(path); err == nil {
		unlock()
		t.Fatal("a lock file readable by ordinary accounts was accepted")
	}
}

// lockFileOwnerForTest returns the owner SID of the lock file.
func lockFileOwnerForTest(t *testing.T, lockPath string) *windows.SID {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(lockPath, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		t.Fatalf("lock file owner: %v", err)
	}
	return owner
}

// A new lock file is owned by Administrators, never by the creating token's
// default owner: an object owner holds implicit WRITE_DAC, so only a fixed
// administrator owner keeps the protected DACL out of an ordinary account's
// reach. The benign twin: the file is reused on the next pass.
func TestManagedWindowsOpenCodeLockFileIsAdministratorOwned(t *testing.T) {
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := WindowsOpenCodeServicePortsPath(filepath.Join(dir, "targets.yaml"))
	lockPath := filepath.Join(dir, WindowsOpenCodeReconcileLockFileName)
	unlock, err := LockWindowsOpenCodeServicePorts(path)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	if owner := lockFileOwnerForTest(t, lockPath); !owner.Equals(administrators) {
		t.Fatalf("lock file owner = %s, want Administrators", owner)
	}
	unlock, err = LockWindowsOpenCodeServicePorts(path)
	if err != nil {
		t.Fatalf("an Administrators-owned lock file was refused: %v", err)
	}
	unlock()
}

// A lock file planted by another account keeps a trusted-looking protected
// SYSTEM/Administrators DACL but is owned by that account, which could still
// rewrite the DACL and hold the lock. It is refused, for the guardian pass,
// for the administrator clear (same function), and on every retry.
func TestManagedWindowsOpenCodeLockRefusesLockFileOwnedByAnotherAccount(t *testing.T) {
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := WindowsOpenCodeServicePortsPath(filepath.Join(dir, "targets.yaml"))
	lockPath := filepath.Join(dir, WindowsOpenCodeReconcileLockFileName)
	unlock, err := LockWindowsOpenCodeServicePorts(path)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	other, err := windows.CreateWellKnownSid(windows.WinLocalServiceSid)
	if err != nil {
		t.Fatal(err)
	}
	extended, err := winpath.Extended(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	// Another account as owner needs SeRestorePrivilege (skipped when the
	// token lacks it). The DACL stays the accepted SYSTEM/Administrators one.
	assignNativeOTLPFixtureOwnerOrSkip(t, extended, other)
	if owner := lockFileOwnerForTest(t, lockPath); !owner.Equals(other) {
		t.Fatalf("fixture owner = %s, want %s", owner, other)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if unlock, err := LockWindowsOpenCodeServicePorts(path); err == nil {
			unlock()
			t.Fatal("a lock file owned by another account was accepted")
		}
	}
	// Handing the file back to Administrators makes it trusted again.
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	assignNativeOTLPFixtureOwnerOrSkip(t, extended, administrators)
	unlock, err = LockWindowsOpenCodeServicePorts(path)
	if err != nil {
		t.Fatalf("an Administrators-owned lock file was refused: %v", err)
	}
	unlock()
}

func createWindowsStandardAccountToken() (windows.Token, error) {
	var process windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &process); err != nil {
		return 0, err
	}
	defer process.Close() //nolint:errcheck
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return 0, err
	}
	user, err := process.GetTokenUser()
	if err != nil {
		return 0, err
	}
	disabled := [2]windows.SIDAndAttributes{{Sid: administrators}, {Sid: user.User.Sid}}
	procedure := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	if err := procedure.Find(); err != nil {
		return 0, err
	}
	const disableMaxPrivilege = 0x1
	var primary windows.Token
	result, _, callErr := procedure.Call(
		uintptr(process), disableMaxPrivilege, uintptr(len(disabled)), uintptr(unsafe.Pointer(&disabled[0])),
		0, 0, 0, 0, uintptr(unsafe.Pointer(&primary)),
	)
	runtime.KeepAlive(disabled)
	if result == 0 {
		if callErr != windows.ERROR_SUCCESS {
			return 0, callErr
		}
		return 0, windows.ERROR_GEN_FAILURE
	}
	defer primary.Close() //nolint:errcheck
	var impersonation windows.Token
	if err := windows.DuplicateTokenEx(primary, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation); err != nil {
		return 0, err
	}
	return impersonation, nil
}
