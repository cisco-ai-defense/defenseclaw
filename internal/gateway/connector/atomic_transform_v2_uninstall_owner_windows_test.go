// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

func TestAtomicTransformV2UninstallConvergesEnrolledOwner(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "profile", ".claude", "settings.json")
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"hook":"managed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := windows.StringToSid("S-1-5-21-111-222-333-1017")
	if err != nil {
		t.Fatal(err)
	}
	current, err := defaultWindowsEffectiveUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if target.Equals(current) {
		t.Fatal("test target SID unexpectedly equals effective user")
	}
	if !windows.GetCurrentProcessToken().IsElevated() && !current.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("setting a synthetic enrolled owner requires an elevated token")
	}
	// An elevated token may restore a synthetic owner's SID without creating
	// an account. The fixture has exactly one link and an ordinary inherited DACL.
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_OWNER,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.GROUP_SECURITY_INFORMATION)
	if err != nil {
		windows.CloseHandle(handle)
		t.Fatal(err)
	}
	group, _, err := descriptor.Group()
	if err != nil || group == nil {
		windows.CloseHandle(handle)
		t.Fatalf("read fixture group: %v", err)
	}
	setErr := setAtomicTransformV2PriorOwnerGroup(handle, target, group)
	closeErr := windows.CloseHandle(handle)
	if setErr != nil || closeErr != nil {
		t.Fatalf("set synthetic enrolled owner: %v, close: %v", setErr, closeErr)
	}
	if err := atomicTransformFileV2(path, stateDir, 0o600,
		atomicTransformV2Options{expectedOwner: target},
		func([]byte, bool) (atomicTransformResult, error) {
			return atomicTransformResult{Data: []byte(`{"hook":"other"}`)}, nil
		}); err != nil {
		t.Fatalf("converge enrolled user's settings: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != `{"hook":"other"}` {
		t.Fatalf("settings after transform = %s, %v", after, err)
	}
	security, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := security.Owner()
	if err != nil || owner == nil || !owner.Equals(target) {
		t.Fatalf("published owner = %v, %v; want enrolled user", owner, err)
	}
	for _, trustee := range []string{target.String(), "SY", "BA"} {
		if !strings.Contains(security.String(), ";;;"+trustee+")") {
			t.Fatalf("converged DACL lacks %s: %s", trustee, security.String())
		}
	}
	wantSecurity, err := atomicTransformPrivateSecurityDescriptorForOwner(target, true)
	if err != nil {
		t.Fatal(err)
	}
	wantDACL, err := atomicTransformV2WindowsCanonicalDACLFromSDDL(wantSecurity.String())
	if err != nil {
		t.Fatal(err)
	}
	gotDACL, err := atomicTransformV2WindowsCanonicalDACLFromSDDL(security.String())
	if err != nil || gotDACL != wantDACL {
		t.Fatalf("converged exact DACL = %q, %v; want %q", gotDACL, err, wantDACL)
	}
	convergedProtection := security.String()
	t.Logf("converged owner and DACL: %s", convergedProtection)
	removed, err := TransformWindowsClaudeSettingsForUninstall(path, stateDir, target.String(),
		func([]byte) ([]byte, int, error) {
			return []byte(`{"hook":"unrelated"}`), 1, nil
		})
	if err != nil || removed != 1 {
		t.Fatalf("enrolled uninstall transform removed %d: %v", removed, err)
	}
	security, err = windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || security.String() != convergedProtection {
		t.Fatalf("uninstall changed converged owner or DACL: before=%s after=%v err=%v",
			convergedProtection, security, err)
	}
}

func TestAtomicTransformV2UninstallRefusesWrongOwner(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "profile", ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"hook":"managed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	foreign, err := windows.StringToSid("S-1-5-21-111-222-333-1018")
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicTransformFileV2(path, filepath.Join(root, "state"), 0o600,
		atomicTransformV2Options{expectedOwner: foreign},
		func([]byte, bool) (atomicTransformResult, error) {
			return atomicTransformResult{Data: []byte(`{"hook":"other"}`)}, nil
		}); err == nil || !strings.Contains(err.Error(), "not owned by enrolled user") {
		t.Fatalf("wrong enrolled owner was accepted: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != `{"hook":"managed"}` {
		t.Fatalf("wrong-owner settings changed: %s, %v", data, err)
	}
}

// GAP-1437: a SYSTEM uninstall (purge) of an enrolled user's Claude settings
// meets the target-local legacy compare-and-swap namespace that the user's
// own connector setup created beside them. The user owns it, so it is
// accepted as that user's private directory; a directory another account
// owns, or one that grants anyone else access, is still refused.
func TestAtomicTransformV2UninstallAcceptsEnrolledUsersLegacyNamespace(t *testing.T) {
	target, err := windows.StringToSid("S-1-5-21-111-222-333-1017")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := windows.StringToSid("S-1-5-21-111-222-333-1018")
	if err != nil {
		t.Fatal(err)
	}
	current, err := defaultWindowsEffectiveUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if !windows.GetCurrentProcessToken().IsElevated() && !current.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("setting a synthetic enrolled owner requires an elevated token")
	}
	setOwner := func(t *testing.T, path string, owner *windows.SID, directory bool) {
		t.Helper()
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
		if directory {
			flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
		}
		handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_OWNER,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, flags, 0)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.GROUP_SECURITY_INFORMATION)
		if err != nil {
			windows.CloseHandle(handle)
			t.Fatal(err)
		}
		group, _, err := descriptor.Group()
		if err != nil || group == nil {
			windows.CloseHandle(handle)
			t.Fatalf("read fixture group: %v", err)
		}
		setErr := setAtomicTransformV2PriorOwnerGroup(handle, owner, group)
		closeErr := windows.CloseHandle(handle)
		if setErr != nil || closeErr != nil {
			t.Fatalf("set synthetic owner: %v, close: %v", setErr, closeErr)
		}
	}
	setDACL := func(t *testing.T, path, sddl string) {
		t.Helper()
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	// inheritDACL gives the namespace's parent sddl (inheritable entries)
	// and makes the namespace an ordinary unprotected child of it, as a
	// copied or restored .claude folder is (GAP-1539).
	inheritDACL := func(t *testing.T, path, parentSDDL string) {
		t.Helper()
		setDACL(t, filepath.Dir(path), parentSDDL)
		emptyDescriptor, err := windows.SecurityDescriptorFromString("D:")
		if err != nil {
			t.Fatal(err)
		}
		empty, _, err := emptyDescriptor.DACL()
		if err != nil || empty == nil {
			t.Fatalf("empty DACL: %v", err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, empty, nil); err != nil {
			t.Fatal(err)
		}
		security, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		control, _, err := security.Control()
		if err != nil || control&windows.SE_DACL_PROTECTED != 0 {
			t.Fatalf("fixture namespace DACL is still protected: %s, %v", security.String(), err)
		}
	}
	// A managed install grants its gateway service read access on .claude
	// (GAP-1539): the pin is the virtual account the Setup passes.
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\DefenseClawGap1539Test`)
	gateway, err := managed.WindowsServiceAccountSID(`NT SERVICE\DefenseClawGap1539Test`)
	if err != nil || gateway == nil {
		t.Fatalf("derive the test gateway service SID: %v", err)
	}
	for _, tc := range []struct {
		name  string
		owner *windows.SID
		dacl  string
		// inherited puts dacl on the profile folder and lets the namespace
		// inherit it instead of setting a protected DACL on it.
		inherited bool
		ok        bool
		// knownIssue skips a row that fails under an elevated administrator
		// token without SeBackupPrivilege (the GitHub runner, the preflight
		// clones); LocalSystem passes it.
		knownIssue string
	}{
		{"enrolled user's private namespace", target, "D:P(A;;FA;;;SY)(A;;FA;;;" + target.String() + ")", false, true,
			"GAP-1738: known 1.0.4 issue, fixed in 1.0.5"},
		{"enrolled user's namespace with Administrators", target, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + target.String() + ")", false, true, ""},
		{"another account's namespace", foreign, "D:P(A;;FA;;;SY)(A;;FA;;;" + foreign.String() + ")", false, false, ""},
		{"enrolled user's namespace shared with everyone", target, "D:P(A;;FA;;;SY)(A;;FA;;;WD)(A;;FA;;;" + target.String() + ")", false, false, ""},
		{"enrolled user's namespace inheriting the profile's entries", target,
			"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + target.String() + ")", true, true, ""},
		{"enrolled user's namespace inheriting an entry for everyone", target,
			"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)(A;OICI;FA;;;" + target.String() + ")", true, false, ""},
		{"enrolled user's namespace inheriting the managed gateway's read entry", target,
			"D:P(A;;0x1200a9;;;" + gateway.String() + ")(A;OICIIO;GXGR;;;" + gateway.String() + ")" +
				"(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + target.String() + ")", true, true, ""},
		{"enrolled user's namespace inheriting a managed gateway write entry", target,
			"D:P(A;OICI;0x1301bf;;;" + gateway.String() + ")" +
				"(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + target.String() + ")", true, false, ""},
		{"another account's namespace inheriting the profile's entries", foreign,
			"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + foreign.String() + ")", true, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.knownIssue != "" && !current.IsWellKnown(windows.WinLocalSystemSid) {
				t.Skip(tc.knownIssue)
			}
			root := t.TempDir()
			path := filepath.Join(root, "profile", ".claude", "settings.json")
			stateDir := filepath.Join(root, "state")
			legacy := filepath.Join(filepath.Dir(path), ".defenseclaw-cas-state")
			if err := os.MkdirAll(legacy, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(`{"hook":"managed"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			setOwner(t, path, target, false)
			setOwner(t, legacy, tc.owner, true)
			if tc.inherited {
				inheritDACL(t, legacy, tc.dacl)
			} else {
				setDACL(t, legacy, tc.dacl)
			}
			err := atomicTransformFileV2(path, stateDir, 0o600,
				atomicTransformV2Options{preserveExistingProtection: true, expectedOwner: target},
				func([]byte, bool) (atomicTransformResult, error) {
					return atomicTransformResult{Data: []byte(`{"hook":"other"}`)}, nil
				})
			after, readErr := os.ReadFile(path)
			if tc.ok {
				if err != nil || readErr != nil || string(after) != `{"hook":"other"}` {
					t.Fatalf("uninstall transform = %v; settings %s, %v", err, after, readErr)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "legacy compare-and-swap state directory") {
				t.Fatalf("unsafe legacy namespace error = %v", err)
			}
			if readErr != nil || string(after) != `{"hook":"managed"}` {
				t.Fatalf("refused transform changed settings: %s, %v", after, readErr)
			}
		})
	}
}
