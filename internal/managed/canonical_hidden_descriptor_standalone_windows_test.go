//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// g582 review 4 F1: an account that owns a managed object or holds WRITE_DAC
// on it can hide its descriptor from SYSTEM and Administrators (an OWNER
// RIGHTS entry with no READ_CONTROL, no SYSTEM or Administrators entry). The
// read-only assessment every standalone refusal asks took that for trusted
// drift (Accepted), so the privileged repair that runs next, which does read
// the descriptor, re-stamped or adopted the object in place. The assessment
// now reads it the same way, and on standalone an object it still cannot
// read is a boundary. Secure Client keeps the old verdict.

const (
	// hiddenWriterFileSDDL: Administrators own the file, Guests may write
	// it, and the OWNER RIGHTS entry leaves the owner only
	// FILE_READ_ATTRIBUTES, SYNCHRONIZE and WRITE_DAC, so neither SYSTEM nor
	// Administrators can open it with READ_CONTROL.
	hiddenWriterFileSDDL = "O:BAG:SYD:P(A;;0x140080;;;OW)(A;;FA;;;BG)"
	// hiddenWriterFolderSDDL is the folder form; it denies listing too.
	hiddenWriterFolderSDDL = "O:BAG:SYD:P(A;OICI;0x140080;;;OW)(A;OICI;FA;;;BG)"
	// hiddenGuestOwnedFileSDDL: Guests own the file, and everyone else may
	// only read its attributes (a user-owned data file hidden from SYSTEM
	// and Administrators).
	hiddenGuestOwnedFileSDDL = "O:BGG:SYD:P(A;;FA;;;BG)(A;;0x100080;;;WD)"
	// hiddenRestoreSDDL gives the fixture back so the temp folder can be
	// removed.
	hiddenRestoreSDDL = "O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"
)

func requireHiddenDescriptorElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token (the Windows CI runners and the native test hosts run elevated)")
	}
}

// stampHiddenDescriptorForTest stamps sddl's owner, group and protected DACL
// with the repair privileges, checks this token can no longer read the
// descriptor without them, and gives the object back at cleanup.
func stampHiddenDescriptorForTest(t *testing.T, path, sddl string) {
	t.Helper()
	disableBackupPrivilegesForTest(t)
	stamp := func(sddl string) error {
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return err
		}
		owner, _, err := descriptor.Owner()
		if err != nil {
			return err
		}
		group, _, err := descriptor.Group()
		if err != nil {
			return err
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			return err
		}
		extended, err := winpath.Extended(path)
		if err != nil {
			return err
		}
		info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION |
			windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
		return RunWithWindowsRepairPrivileges(func() error {
			return windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, info, owner, group, dacl, nil)
		})
	}
	if err := stamp(sddl); err != nil {
		t.Fatalf("stamp %s on %s: %v", sddl, path, err)
	}
	t.Cleanup(func() {
		if err := stamp(hiddenRestoreSDDL); err != nil {
			t.Errorf("give %s back: %v", path, err)
		}
	})
	handle, err := openCanonicalObject(path, uint32(windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES))
	if err == nil {
		_ = windows.CloseHandle(handle)
		t.Skipf("this token still reads the descriptor of %s without privileges", path)
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("open %s: %v, want access denied", path, err)
	}
}

// privilegedDescriptorForTest is the owner and DACL of path as SDDL, read
// with backup semantics.
func privilegedDescriptorForTest(t *testing.T, path string) string {
	t.Helper()
	var text string
	if err := RunWithWindowsRepairPrivileges(func() error {
		handle, err := openCanonicalObject(path, uint32(windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES))
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

func TestStandaloneHiddenDescriptorIsRefusedNotRestamped(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	for _, tc := range []struct {
		name       string
		directory  bool
		sddl       string
		standalone bool
	}{
		{name: "file, Guests write, descriptor hidden", sddl: hiddenWriterFileSDDL, standalone: true},
		{name: "folder, Guests write, descriptor and listing hidden", directory: true, sddl: hiddenWriterFolderSDDL, standalone: true},
		{name: "twin: Secure Client, file, Guests write, descriptor hidden", sddl: hiddenWriterFileSDDL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(TrustStrictAncestorsEnv, "")
			path := filepath.Join(t.TempDir(), "object")
			kind := ObjectAdminFile
			if tc.directory {
				kind = ObjectAdminDirectory
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			stampHiddenDescriptorForTest(t, path, tc.sddl)
			pinTrustProfileForTest(t, tc.standalone)
			before := privilegedDescriptorForTest(t, path)

			assessed, err := AssessCanonical(path, kind, CanonicalOptions{Quiet: true})
			if err != nil {
				t.Fatal(err)
			}
			refusal := RefuseStandaloneInPlaceRepair(path, kind)
			if after := privilegedDescriptorForTest(t, path); after != before {
				t.Fatalf("the read-only assessment changed the descriptor: %s -> %s", before, after)
			}
			if !tc.standalone {
				if refusal != nil {
					t.Fatalf("Secure Client refused: %v", refusal)
				}
				return
			}
			if assessed.Outcome != CanonicalBoundary {
				t.Fatalf("assessment = %+v, want a boundary: Guests can write the hidden object", assessed)
			}
			var refused *StandaloneContentDriftError
			if !errors.As(refusal, &refused) || !strings.Contains(refusal.Error(), path) {
				t.Fatalf("RefuseStandaloneInPlaceRepair = %v, want a standalone refusal naming %s", refusal, path)
			}
		})
	}
}

func TestStandaloneManagedDataPathsRepairRefusesAHiddenDataFile(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	for _, tc := range []struct {
		name string
		sddl string
	}{
		{name: "Administrators owner, Guests write, descriptor hidden", sddl: hiddenWriterFileSDDL},
		{name: "Guests owner, descriptor hidden, owner transfer allowed", sddl: hiddenGuestOwnedFileSDDL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(TrustStrictAncestorsEnv, "")
			dataDir := filepath.Join(t.TempDir(), "runtime")
			if err := os.Mkdir(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(dataDir, "gateway.log")
			if err := os.WriteFile(logPath, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			stampHiddenDescriptorForTest(t, logPath, tc.sddl)
			pinTrustProfileForTest(t, true)
			before := privilegedDescriptorForTest(t, logPath)
			results := RepairWindowsManagedDataPaths(
				ManagedDataPaths{DataDir: dataDir, LogPaths: []string{logPath}},
				CanonicalOptions{Quiet: true, GatewayServiceAccount: "DefenseClawGateway", AllowUntrustedOwnerTransfer: true},
			)
			result, ok := installResultFor(results, logPath)
			if !ok {
				t.Fatalf("no result for %s in %+v", logPath, results)
			}
			if after := privilegedDescriptorForTest(t, logPath); after != before {
				t.Fatalf("the hidden data file was re-stamped or adopted in place: %s -> %s (result %+v)", before, after, result)
			}
			if result.Outcome != CanonicalBoundary || !strings.Contains(result.RepairError, "/remove:g") {
				t.Fatalf("result = %+v, want a boundary refusal naming the way out", result)
			}
		})
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
