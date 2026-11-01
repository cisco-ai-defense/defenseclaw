// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

// GAP-2096: an elevated cleanup of an enrolled user's Claude settings that
// finds nothing to remove keeps the file and its inherited DACL as found; it
// converged the DACL to the protected private form on every upgrade.
func TestAtomicTransformV2UninstallNoopKeepsTheInheritedDACL(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "profile", ".claude", "settings.json")
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"hooks":{}}`), 0o600); err != nil {
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
	if !windows.GetCurrentProcessToken().IsElevated() && !current.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("setting a synthetic enrolled owner requires an elevated token")
	}
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
	before, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if control, _, err := before.Control(); err != nil || control&windows.SE_DACL_PROTECTED != 0 ||
		!strings.Contains(before.String(), ";ID;") {
		t.Fatalf("fixture DACL is not the inherited form: %s (%v)", before.String(), err)
	}
	removed, err := TransformWindowsClaudeSettingsForUninstall(path, stateDir, target.String(),
		func(raw []byte) ([]byte, int, error) {
			return raw, 0, nil
		})
	if err != nil || removed != 0 {
		t.Fatalf("no-op enrolled cleanup removed %d: %v", removed, err)
	}
	after, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if after.String() != before.String() {
		t.Fatalf("no-op cleanup changed the owner or DACL: before=%s after=%s", before.String(), after.String())
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != `{"hooks":{}}` {
		t.Fatalf("no-op cleanup changed the settings: %q, %v", data, err)
	}
}

// enrolledInheritedSettingsFixture makes <root>\profile\.claude\settings.json
// the way a managed Windows profile holds it: the .claude folder grants
// SYSTEM, Administrators and the enrolled user full access and the gateway
// service gatewayMask, all inheritable, and the file inherits that DACL and is
// owned by the enrolled user. It returns the path and the user's SID.
func enrolledInheritedSettingsFixture(t *testing.T, gatewayMask string) (string, *windows.SID) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "profile", ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
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
	if !windows.GetCurrentProcessToken().IsElevated() && !current.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("setting a synthetic enrolled owner requires an elevated token")
	}
	gateway, err := managed.WindowsServiceAccountSID(managed.DefaultGatewayServiceAccount)
	if err != nil || gateway == nil {
		t.Fatalf("derive gateway service SID: %v", err)
	}
	folder, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)(A;OICI;%s;;;%s)", target, gatewayMask, gateway))
	if err != nil {
		t.Fatal(err)
	}
	folderDACL, _, err := folder.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(filepath.Dir(path), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, folderDACL, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"hooks":{"PreToolUse":"managed"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// os.WriteFile inherits the folder DACL; make the enrolled user the owner.
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
	before, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if control, _, err := before.Control(); err != nil || control&windows.SE_DACL_PROTECTED != 0 ||
		!strings.Contains(before.String(), ";ID;") || !strings.Contains(before.String(), gateway.String()) {
		t.Fatalf("fixture DACL is not the inherited profile form: %s (%v)", before.String(), err)
	}
	return path, target
}

// A real SYSTEM edit of an enrolled user's settings.json (the 1.0.2 hook
// removal of a published 1.0.2 -> 1.0.5 upgrade) keeps the DACL the file
// inherits from the profile, gateway read included, when that DACL is as
// private as the converged one (GAP-2096).
func TestAtomicTransformV2EnrolledEditKeepsTheInheritedProfileDACL(t *testing.T) {
	path, target := enrolledInheritedSettingsFixture(t, "0x1200a9")
	stateDir := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(path))), "state")
	before, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := TransformWindowsClaudeSettingsForUninstall(path, stateDir, target.String(),
		func([]byte) ([]byte, int, error) {
			return []byte(`{"hooks":{}}`), 1, nil
		})
	if err != nil || removed != 1 {
		t.Fatalf("enrolled cleanup removed %d: %v", removed, err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != `{"hooks":{}}` {
		t.Fatalf("settings after the edit = %q, %v", data, err)
	}
	after, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if control, _, err := after.Control(); err != nil || control&windows.SE_DACL_PROTECTED != 0 {
		t.Fatalf("the edit made the inherited DACL protected: before=%s after=%s (%v)", before.String(), after.String(), err)
	}
	if after.String() != before.String() {
		t.Fatalf("the edit changed the owner or the inherited DACL: before=%s after=%s", before.String(), after.String())
	}
}

// An inherited DACL that gives the gateway more than read and execute is not
// the profile form DefenseClaw makes, so the edit still converges it to the
// protected private DACL.
func TestAtomicTransformV2EnrolledEditConvergesAnInheritedGatewayWrite(t *testing.T) {
	path, target := enrolledInheritedSettingsFixture(t, "0x1301bf")
	stateDir := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(path))), "state")
	removed, err := TransformWindowsClaudeSettingsForUninstall(path, stateDir, target.String(),
		func([]byte) ([]byte, int, error) {
			return []byte(`{"hooks":{}}`), 1, nil
		})
	if err != nil || removed != 1 {
		t.Fatalf("enrolled cleanup removed %d: %v", removed, err)
	}
	after, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	want, err := atomicTransformPrivateSecurityDescriptorForOwner(target, true)
	if err != nil {
		t.Fatal(err)
	}
	wantDACL, err := atomicTransformV2WindowsCanonicalDACLFromSDDL(want.String())
	if err != nil {
		t.Fatal(err)
	}
	gotDACL, err := atomicTransformV2WindowsCanonicalDACLFromSDDL(after.String())
	if err != nil || gotDACL != wantDACL {
		t.Fatalf("DACL after the edit = %q, %v; want the private %q", gotDACL, err, wantDACL)
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
	}{
		{"enrolled user's private namespace", target, "D:P(A;;FA;;;SY)(A;;FA;;;" + target.String() + ")", false, true},
		{"enrolled user's namespace with Administrators", target, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + target.String() + ")", false, true},
		{"another account's namespace", foreign, "D:P(A;;FA;;;SY)(A;;FA;;;" + foreign.String() + ")", false, false},
		{"enrolled user's namespace shared with everyone", target, "D:P(A;;FA;;;SY)(A;;FA;;;WD)(A;;FA;;;" + target.String() + ")", false, false},
		{"enrolled user's namespace inheriting the profile's entries", target,
			"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + target.String() + ")", true, true},
		{"enrolled user's namespace inheriting an entry for everyone", target,
			"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)(A;OICI;FA;;;" + target.String() + ")", true, false},
		{"enrolled user's namespace inheriting the managed gateway's read entry", target,
			"D:P(A;;0x1200a9;;;" + gateway.String() + ")(A;OICIIO;GXGR;;;" + gateway.String() + ")" +
				"(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + target.String() + ")", true, true},
		{"enrolled user's namespace inheriting a managed gateway write entry", target,
			"D:P(A;OICI;0x1301bf;;;" + gateway.String() + ")" +
				"(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + target.String() + ")", true, false},
		{"another account's namespace inheriting the profile's entries", foreign,
			"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + foreign.String() + ")", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			// Production runs this transform only as the LocalSystem guardian
			// or as the enrolled user: the uninstall reports another user's
			// settings pending when it is not LocalSystem, and reconcile
			// requires LocalSystem. Every fixture DACL grants SYSTEM, so an
			// elevated test token opens the namespace the way SYSTEM does
			// (GAP-1738). Without that the open is refused, and a refusal row
			// passes for that reason instead of for the ownership check.
			err := runAsTheUninstallGuardian(current, func() error {
				return atomicTransformFileV2(path, stateDir, 0o600,
					atomicTransformV2Options{preserveExistingProtection: true, expectedOwner: target},
					func([]byte, bool) (atomicTransformResult, error) {
						return atomicTransformResult{Data: []byte(`{"hook":"other"}`)}, nil
					})
			})
			after, readErr := os.ReadFile(path)
			if tc.ok {
				if err != nil || readErr != nil || string(after) != `{"hook":"other"}` {
					t.Fatalf("uninstall transform = %v; settings %s, %v", err, after, readErr)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "validate legacy compare-and-swap state directory") {
				t.Fatalf("unsafe legacy namespace error = %v", err)
			}
			if readErr != nil || string(after) != `{"hook":"managed"}` {
				t.Fatalf("refused transform changed settings: %s, %v", after, readErr)
			}
		})
	}
}

// runAsTheUninstallGuardian runs fn with the access the LocalSystem guardian
// has to a fixture whose DACL grants SYSTEM. LocalSystem runs fn unchanged.
// An elevated administrator runs it on a locked thread that impersonates its
// own token with SeBackupPrivilege and SeRestorePrivilege enabled: an
// elevated runner (GitHub, the preflight clones) holds both but does not
// enable them.
func runAsTheUninstallGuardian(current *windows.SID, fn func() error) error {
	if current.IsWellKnown(windows.WinLocalSystemSid) {
		return fn()
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("impersonate the test token: %w", err)
			return
		}
		var token windows.Token
		err := windows.OpenThreadToken(windows.CurrentThread(),
			windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false, &token)
		for _, name := range []string{"SeBackupPrivilege", "SeRestorePrivilege"} {
			if err != nil {
				break
			}
			var namePtr *uint16
			var luid windows.LUID
			if namePtr, err = windows.UTF16PtrFromString(name); err == nil {
				err = windows.LookupPrivilegeValue(nil, namePtr, &luid)
			}
			if err == nil {
				state := windows.Tokenprivileges{PrivilegeCount: 1,
					Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
				err = windows.AdjustTokenPrivileges(token, false, &state, 0, nil, nil)
				if err == nil && errors.Is(windows.GetLastError(), windows.ERROR_NOT_ALL_ASSIGNED) {
					err = fmt.Errorf("the elevated test token does not hold %s", name)
				}
			}
		}
		if token != 0 {
			token.Close()
		}
		if err == nil {
			err = fn()
		}
		if revertErr := windows.RevertToSelf(); revertErr != nil {
			// Leave the thread locked so Go retires it with the token.
			result <- fmt.Errorf("revert the test thread: %v (after %v)", revertErr, err)
			return
		}
		runtime.UnlockOSThread()
		result <- err
	}()
	return <-result
}
