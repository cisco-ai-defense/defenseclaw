//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func TestEnsureWindowsTargetOwnedDirectoryTreePinsOwnerAndProtectedDACL(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	var creation windowsTargetOwnedDirectoryCreation
	if err := runWindowsTestThreadImpersonatedAsSelf(func() error {
		var err error
		creation, err = ensureWindowsTargetOwnedDirectoryTree(home, hookDir, target)
		return err
	}); err != nil {
		t.Fatalf("create target-owned directory tree: %v", err)
	}
	if !creation.createdDataDir || !creation.createdHookDir {
		t.Fatalf("fresh managed directory creation = %+v, want exact data and hook ownership", creation)
	}
	for _, path := range []string{filepath.Dir(hookDir), hookDir} {
		assertWindowsTargetOwnedCanonicalDirectory(t, path, target)
	}
	if err := runWindowsTestThreadImpersonatedAsSelf(func() error {
		var err error
		creation, err = ensureWindowsTargetOwnedDirectoryTree(home, hookDir, target)
		return err
	}); err != nil {
		t.Fatalf("reopen canonical target-owned directory tree: %v", err)
	}
	if creation.createdDataDir || creation.createdHookDir {
		t.Fatalf("reopened managed directory tree claimed creation ownership: %+v", creation)
	}
}

func TestEnsureWindowsTargetOwnedDirectoryTreeRejectsPreexistingNoncanonicalDirectory(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	dataDir := filepath.Join(home, ".defenseclaw")
	// A normal directory create inherits the parent ACL and, for an elevated
	// administrator token, may also select BUILTIN\Administrators as owner.
	// Neither shape is an acceptable managed-runtime preimage.
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	before := windowsTestSecurityDescriptorString(t, dataDir)
	var creation windowsTargetOwnedDirectoryCreation
	err := runWindowsTestThreadImpersonatedAsSelf(func() error {
		var err error
		creation, err = ensureWindowsTargetOwnedDirectoryTree(
			home,
			filepath.Join(dataDir, "hooks"),
			target,
		)
		return err
	})
	if err == nil {
		t.Fatal("noncanonical pre-existing directory was adopted")
	}
	after := windowsTestSecurityDescriptorString(t, dataDir)
	if after != before {
		t.Fatalf("rejected directory security descriptor changed:\nbefore=%s\nafter=%s", before, after)
	}
	if creation.createdDataDir || creation.createdHookDir {
		t.Fatalf("rejected pre-existing directory claimed creation ownership: %+v", creation)
	}
	if _, statErr := os.Lstat(filepath.Join(dataDir, "hooks")); !os.IsNotExist(statErr) {
		t.Fatalf("rejected directory gained a managed child: %v", statErr)
	}
}

// GAP-1180: the guardian records the protected executable selection of an
// account that never ran DefenseClaw. It creates %USERPROFILE%\.defenseclaw for
// the receipt and its lock as that account (exact owner, protected DACL), and
// a junction planted in the folder's place is refused, never followed.
func TestWindowsManagedSetupSelectionCreatesMissingDataDir(t *testing.T) {
	target := currentWindowsTestSID(t)
	executable := filepath.Join(t.TempDir(), "hermes.exe")
	if err := os.WriteFile(executable, []byte("guardian-selected Hermes image"), 0o700); err != nil {
		t.Fatal(err)
	}
	row := func(home string) windowsGenericManagedTarget {
		return windowsGenericManagedTarget{
			home:    home,
			dataDir: filepath.Join(home, ".defenseclaw"),
			sid:     target,
			conn:    connector.NewHermesConnector(),
			setup:   connector.SetupOpts{AgentExecutable: executable, AgentVersion: "0.20.0"},
		}
	}
	record := func(selection windowsGenericManagedTarget) (created bool, err error) {
		err = runWindowsTestThreadImpersonatedAsSelf(func() error {
			var err error
			if created, err = ensureWindowsManagedSetupSelectionDataDir(selection); err != nil {
				return err
			}
			return recordWindowsManagedSetupSelection(selection)
		})
		return created, err
	}

	fresh := row(newWindowsTargetOwnedTestHome(t, target))
	if created, err := record(fresh); err != nil || !created {
		t.Fatalf("selection for an account without a data dir: created=%v err=%v", created, err)
	}
	assertWindowsTargetOwnedCanonicalDirectory(t, fresh.dataDir, target)
	if _, err := os.Lstat(filepath.Join(fresh.dataDir, "agent_selection.json")); err != nil {
		t.Fatalf("selection receipt was not written: %v", err)
	}
	if created, err := record(fresh); err != nil || created {
		t.Fatalf("second selection: created=%v err=%v, want the folder reused", created, err)
	}

	planted := row(newWindowsTargetOwnedTestHome(t, target))
	outside := t.TempDir()
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", planted.dataDir, outside).CombinedOutput(); err != nil {
		t.Fatalf("create junction: %v: %s", err, output)
	}
	if _, err := record(planted); err == nil {
		t.Fatal("selection was recorded through a junction in place of the data dir")
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("junction target gained %d entries (err %v)", len(entries), err)
	}
}

func TestOpenOrCreateWindowsTargetDirectoryPublishesFinalDACLAtomically(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	path := filepath.Join(home, ".defenseclaw")
	descriptor, err := windowsTargetOwnedDirectorySecurityDescriptor(target)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("create descriptor DACL is unavailable: %v", err)
	}
	if err := validateWindowsUserPathProtectionACL(path, descriptor, dacl, target, true); err != nil {
		t.Fatalf("create descriptor is not the final canonical contract: %v", err)
	}
	if err := requireWindowsTestNoTargetOrOwnerRightsWriteDAC(target); err != nil {
		t.Fatal(err)
	}
	var child windows.Handle
	if err := runWindowsTestThreadImpersonatedAsSelf(func() error {
		parent, err := openWindowsTargetDirectoryRoot(home)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(parent)
		var created bool
		child, created, err = openOrCreateWindowsTargetDirectory(parent, ".defenseclaw", descriptor)
		if err != nil {
			return err
		}
		if !created {
			return errors.New("test target directory already existed")
		}
		// Validate through the exact handle returned by FILE_CREATE before any
		// other managed operation observes the published directory.
		if err := validateWindowsTargetOwnedDirectoryHandle(child, path, target); err != nil {
			return err
		}
		// Metadata-only opens are not governed by Windows share flags and are
		// safe once the final DACL was applied atomically.
		metadata, err := openWindowsTestDirectoryNoFollow(path)
		if err != nil {
			return fmt.Errorf("open final directory metadata while creator handle is live: %w", err)
		}
		if err := windows.CloseHandle(metadata); err != nil {
			return err
		}
		// On a limited token, OWNER RIGHTS must also deny an actual WRITE_DAC
		// open. An elevated test token intentionally receives that right through
		// the separately trusted Administrators ACE, so its structural contract
		// was asserted above instead of expecting a false denial here.
		administratorsEnabled, err := windowsTestEffectiveAdministratorsEnabled()
		if err != nil {
			return err
		}
		if !administratorsEnabled {
			if err := requireWindowsTestDirectoryAccessDenied(path, windows.WRITE_DAC); err != nil {
				return err
			}
		}
		// The zero-share creator handle still prevents data mutation until its
		// same-handle validation is complete.
		return requireWindowsTestDirectorySharingViolation(path, windows.FILE_WRITE_DATA)
	}); err != nil {
		if child != 0 {
			_ = windows.CloseHandle(child)
		}
		t.Fatalf("create atomically protected target directory: %v", err)
	}
	if err := windows.CloseHandle(child); err != nil {
		t.Fatalf("release canonical directory handle: %v", err)
	}
	child = 0
	reopened, err := openWindowsTestDirectoryNoFollow(path)
	if err != nil {
		t.Fatalf("open canonical directory after exclusive handle release: %v", err)
	}
	if err := windows.CloseHandle(reopened); err != nil {
		t.Fatalf("close canonical directory verification handle: %v", err)
	}
	assertWindowsTargetOwnedCanonicalDirectory(t, path, target)
}

func newWindowsTargetOwnedTestHome(t *testing.T, target *windows.SID) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	setWindowsTestPathExactOwner(t, home, target)
	if err := setWindowsUserPathProtection(home, target, true); err != nil {
		t.Fatal(err)
	}
	return home
}

// setWindowsTestPathExactOwner establishes the fixture precondition that a
// real target profile already has its enrolled user's owner SID. Elevated
// Windows tokens may otherwise assign BUILTIN\Administrators as the default
// owner. This helper is test-only and intentionally changes only OWNER; the
// production protection helper must still apply and validate the exact DACL.
func setWindowsTestPathExactOwner(
	t *testing.T,
	path string,
	target *windows.SID,
) {
	t.Helper()
	owner, err := windowsPathOwnerNoFollow(path)
	if err != nil {
		t.Fatal(err)
	}
	if owner == nil || !owner.Equals(target) {
		// Elevated Windows runners can assign BUILTIN\Administrators as the
		// default owner even though the process token user is the test target.
		// Pin the fixture to that exact user before exercising production's
		// deliberate wrong-owner refusal.
		extended, err := winpath.Extended(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(
			extended,
			windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION,
			target,
			nil,
			nil,
			nil,
		); err != nil {
			t.Fatalf("assign exact test path owner on %s: %v", path, err)
		}
	}
}

func assertWindowsTargetOwnedCanonicalDirectory(
	t *testing.T,
	path string,
	target *windows.SID,
) {
	t.Helper()
	if err := validateWindowsUserPathElement(path, target, true, true, true); err != nil {
		t.Fatalf("validate explicit target ownership on %s: %v", path, err)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(target) {
		t.Fatalf("managed directory owner = %v, want exact target %s (error %v)", owner, target, err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("managed directory DACL is unavailable: %v", err)
	}
	expected, err := windowsUserPathAppliedCanonicalACEs(target, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) != 7 {
		t.Fatalf("directory security contract has %d applied ACEs, want 7", len(expected))
	}
	if int(dacl.AceCount) != len(expected) {
		t.Fatalf("managed directory has %d applied ACEs, want exactly %d", dacl.AceCount, len(expected))
	}
}

func requireWindowsTestDirectoryAccessDenied(path string, access uint32) error {
	handle, err := openWindowsTestDirectoryNoFollowAccess(path, access)
	if err == nil && handle != 0 && handle != windows.InvalidHandle {
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("competing directory open with access 0x%x unexpectedly succeeded", access)
	}
	if err == nil {
		return fmt.Errorf("competing directory open returned invalid handle %v without an error", handle)
	}
	if handle != 0 && handle != windows.InvalidHandle {
		_ = windows.CloseHandle(handle)
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("competing directory open error = %v, want access denied", err)
	}
	return nil
}

func requireWindowsTestNoTargetOrOwnerRightsWriteDAC(target *windows.SID) error {
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		return err
	}
	expected, err := windowsUserPathAppliedCanonicalACEs(target, true)
	if err != nil {
		return err
	}
	if len(expected) != 7 {
		return fmt.Errorf("directory create contract has %d ACEs, want exactly 7", len(expected))
	}
	for _, ace := range expected {
		if (ace.sid.Equals(target) || ace.sid.Equals(ownerRights)) && ace.mask&windows.WRITE_DAC != 0 {
			return fmt.Errorf("directory create contract grants WRITE_DAC to target or OWNER RIGHTS")
		}
	}
	return nil
}

func windowsTestEffectiveAdministratorsEnabled() (bool, error) {
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, err
	}
	groups, err := windows.GetCurrentThreadEffectiveToken().GetTokenGroups()
	if err != nil {
		return false, err
	}
	for _, group := range groups.AllGroups() {
		if group.Sid != nil &&
			group.Sid.Equals(administrators) &&
			group.Attributes&windows.SE_GROUP_ENABLED != 0 &&
			group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			return true, nil
		}
	}
	return false, nil
}

func requireWindowsTestDirectorySharingViolation(path string, access uint32) error {
	handle, err := openWindowsTestDirectoryNoFollowAccess(path, access)
	if err == nil && handle != 0 && handle != windows.InvalidHandle {
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("competing directory open with access 0x%x unexpectedly bypassed creator sharing", access)
	}
	if err == nil {
		return fmt.Errorf("competing open returned invalid handle %v without an error", handle)
	}
	if handle != 0 && handle != windows.InvalidHandle {
		_ = windows.CloseHandle(handle)
	}
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return fmt.Errorf("competing open error = %v, want sharing violation", err)
	}
	return nil
}

func openWindowsTestDirectoryNoFollow(path string) (windows.Handle, error) {
	return openWindowsTestDirectoryNoFollowAccess(
		path,
		windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
	)
}

func openWindowsTestDirectoryNoFollowAccess(path string, access uint32) (windows.Handle, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return 0, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(
		ptr,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
}
