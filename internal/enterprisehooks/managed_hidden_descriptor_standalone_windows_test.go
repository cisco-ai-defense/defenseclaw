//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// g582 review 4 F1: an account that owns a DefenseClaw machine file or folder
// or holds WRITE_DAC on it can hide its descriptor from SYSTEM and
// Administrators (an OWNER RIGHTS entry without READ_CONTROL, no SYSTEM or
// Administrators entry). The standalone refusal took that for trusted drift,
// so the privileged re-stamp that runs next adopted the object and every
// reader then trusted bytes that account chose. The selector and a policy
// folder holding a DefenseClaw marker are now refused and left as they are.

const (
	f1HiddenWriterFile   = "O:BAG:SYD:P(A;;0x140080;;;OW)(A;;FA;;;BG)"
	f1HiddenWriterFolder = "O:BAG:SYD:P(A;OICI;0x140080;;;OW)(A;OICI;FA;;;BG)"
	f1RestoreSDDL        = "O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"
)

// hideF1Descriptor stamps sddl, checks this token can no longer open the
// object with READ_CONTROL without privileges, and gives it back at cleanup.
//
// It also pins the managed profile to standalone: in production the policy
// writer's standalone decision is managed.StandaloneRefusesContentDrift, and
// only standalone (or strict) assessments re-read a hidden descriptor with
// the repair privileges (g582 review 5 M1).
func hideF1Descriptor(t *testing.T, path, sddl string) {
	t.Helper()
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	disableBackupPrivilegesForTest(t)
	stampGAP633SDDL(t, path, sddl)
	t.Cleanup(func() { stampGAP633SDDL(t, path, f1RestoreSDDL) })
	if f1DescriptorReadable(t, path) {
		t.Skipf("this token still reads the descriptor of %s without privileges", path)
	}
}

func f1Open(path string) (windows.Handle, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	name, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

// f1DescriptorReadable reports whether this token opens path with
// READ_CONTROL without enabling a privilege.
func f1DescriptorReadable(t *testing.T, path string) bool {
	t.Helper()
	handle, err := f1Open(path)
	if err == nil {
		_ = windows.CloseHandle(handle)
		return true
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("open %s: %v", path, err)
	}
	return false
}

// f1PrivilegedDescriptor is path's owner and DACL as SDDL, read with backup
// semantics.
func f1PrivilegedDescriptor(t *testing.T, path string) string {
	t.Helper()
	var text string
	if err := managed.RunWithWindowsRepairPrivileges(func() error {
		handle, err := f1Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = windows.CloseHandle(handle) }()
		descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		text = descriptor.String()
		return nil
	}); err != nil {
		t.Fatalf("privileged read of %s: %v", path, err)
	}
	return text
}

func TestStandaloneSelectorWithAHiddenDescriptorIsNotRestamped(t *testing.T) {
	requireGAP633Elevated(t)
	setGAP633Profile(t, true, nil)
	path := filepath.Join(t.TempDir(), windowsManagedRuntimeSelectorFile)
	if err := os.WriteFile(path, []byte(`{"schema_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	hideF1Descriptor(t, path, f1HiddenWriterFile)
	before := f1PrivilegedDescriptor(t, path)

	err := validateWindowsManagedRuntimeSelectorForRead(path)

	if after := f1PrivilegedDescriptor(t, path); after != before {
		t.Fatalf("the hidden selector was re-stamped in place: %s -> %s (err %v)", before, after, err)
	}
	var refused *managed.StandaloneContentDriftError
	if !errors.As(err, &refused) || !strings.Contains(err.Error(), path) {
		t.Fatalf("err = %v, want a standalone refusal naming %s", err, path)
	}
}

// The re-stamp also asks the trust walk every reader runs: a file the
// reader refuses is not re-stamped even when its own descriptor shows only
// trusted drift.
func TestStandaloneMachineFileRestampAsksTheReaderTrustWalk(t *testing.T) {
	requireGAP633Elevated(t)
	for _, tc := range []struct {
		name       string
		standalone bool
		refused    bool
	}{
		{name: "standalone, the reader walk refuses", standalone: true, refused: true},
		{name: "twin: Secure Client, the reader walk refuses"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), windowsManagedRuntimeSelectorFile)
			if err := os.WriteFile(path, []byte(`{"schema_version":1}`), 0o600); err != nil {
				t.Fatal(err)
			}
			stampGAP633SDDL(t, path, gap633NoUsersReadFile)
			readerRefusal := fmt.Errorf("reader walk refuses %s", path)
			setGAP633Profile(t, tc.standalone, func(candidate string) error {
				if strings.EqualFold(filepath.Clean(candidate), filepath.Clean(path)) {
					return readerRefusal
				}
				return nil
			})
			before := gap633Descriptor(t, path)
			repaired, err := repairWindowsManagedMachineFile(path, true, func(string) error {
				return validateWindowsManagedMachineFileDescriptor(path, true)
			})
			after := gap633Descriptor(t, path)
			if !tc.refused {
				if !repaired || err != nil || after == before {
					t.Fatalf("Secure Client: repaired %t, err %v, descriptor %s -> %s; want the re-stamp", repaired, err, before, after)
				}
				return
			}
			var refused *managed.StandaloneContentDriftError
			if repaired || !errors.As(err, &refused) || !errors.Is(err, readerRefusal) {
				t.Fatalf("repaired %t, err %v; want the reader's refusal as a standalone refusal", repaired, err)
			}
			if after != before {
				t.Fatalf("the refused file was re-stamped: %s -> %s", before, after)
			}
		})
	}
}

func TestStandalonePolicyFolderWithAHiddenDescriptorIsNotTakenOver(t *testing.T) {
	requireGAP633Elevated(t)
	setGAP633Profile(t, true, nil)
	folder := filepath.Join(t.TempDir(), "managed-settings.d")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, windowsClaudeManagedStateFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	hideF1Descriptor(t, folder, f1HiddenWriterFolder)
	before := f1PrivilegedDescriptor(t, folder)

	err := repairWindowsManagedPolicyFolder(folder, validateWindowsManagedPolicyDirectoryDescriptor)

	if after := f1PrivilegedDescriptor(t, folder); after != before {
		t.Fatalf("the hidden policy folder was taken over in place: %s -> %s (err %v)", before, after, err)
	}
	var refused *managed.StandaloneContentDriftError
	if !errors.As(err, &refused) || !strings.Contains(err.Error(), folder) {
		t.Fatalf("err = %v, want a standalone refusal naming %s", err, folder)
	}
}

// disableBackupPrivilegesForTest disables SeBackupPrivilege and
// SeRestorePrivilege on the process token for the test, as on an elevated
// prompt (an elevated SSH or SYSTEM token has them enabled, and backup
// semantics then read any descriptor). The repair privileges helpers still
// enable them on their own impersonation thread.
func disableBackupPrivilegesForTest(t *testing.T) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = token.Close() })
	for _, name := range []string{"SeBackupPrivilege", "SeRestorePrivilege"} {
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
			t.Fatal(err)
		}
		state := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid}}}
		var previous windows.Tokenprivileges
		var size uint32
		if err := windows.AdjustTokenPrivileges(token, false, &state, uint32(unsafe.Sizeof(previous)), &previous, &size); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if previous.PrivilegeCount > 0 {
				_ = windows.AdjustTokenPrivileges(token, false, &previous, 0, nil, nil)
			}
		})
	}
}
