//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// testWindowsTrust stands in for the machine trust rules inside a temp tree
// (which the test user owns): below root, an element is trusted only when it
// is not a reparse point, Administrators or LocalSystem own it, and no
// Users, Authenticated Users or Everyone entry can replace its children.
func testWindowsTrust(t *testing.T, root string) {
	t.Helper()
	check := func(path string, leaf bool) error {
		// Like the production rules, a reparse point is never trusted.
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		attributes, err := windows.GetFileAttributes(name)
		if err != nil {
			return err
		}
		if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("%s: reparse point", path)
		}
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return err
		}
		if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid) {
			return fmt.Errorf("%s: owner %s is not trusted", path, owner)
		}
		dacl, _, err := sd.DACL()
		if err != nil || dacl == nil {
			return fmt.Errorf("%s: no DACL", path)
		}
		for i := uint16(0); i < dacl.AceCount; i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
				return err
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
				continue
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			untrusted := sid.IsWellKnown(windows.WinBuiltinUsersSid) || sid.IsWellKnown(windows.WinAuthenticatedUserSid) || sid.IsWellKnown(windows.WinWorldSid)
			if untrusted && managed.WindowsAncestorReplaceAccess(ace.Mask) {
				return fmt.Errorf("%s: %s may replace children", path, sid)
			}
			// Leaf rule: no unprivileged principal may add or change entries.
			const leafWrite = windows.ACCESS_MASK(0x2 | 0x4 | 0x10 | 0x100 | 0x40000000)
			if untrusted && leaf && ace.Mask&leafWrite != 0 {
				return fmt.Errorf("%s: %s may add entries", path, sid)
			}
		}
		return nil
	}
	below := func(path string) bool {
		rel, err := filepath.Rel(root, path)
		return err == nil && rel != "." && !strings.HasPrefix(rel, "..")
	}
	walkFrom := func(path string, leaf bool) error {
		for cur := path; below(cur); cur = filepath.Dir(cur) {
			if err := check(cur, leaf && cur == path); err != nil {
				return err
			}
		}
		return nil
	}
	previousDir, previousLeaf, previousFile, previousReclaim := validateTrustedDir, validateTrustedLeafDir, validateTrustedFile, reclaimDirHandle
	validateTrustedDir = func(path string) error { return walkFrom(path, false) }
	validateTrustedLeafDir = func(path string) error { return walkFrom(path, true) }
	validateTrustedFile = func(path string) error { return walkFrom(path, false) }
	reclaimDirHandle = func(_ string, reclaim func() error) error { return reclaim() }
	t.Cleanup(func() {
		validateTrustedDir, validateTrustedLeafDir, validateTrustedFile, reclaimDirHandle = previousDir, previousLeaf, previousFile, previousReclaim
	})
}

func windowsTestOptions(t *testing.T) Options {
	t.Helper()
	root := t.TempDir()
	programData := filepath.Join(root, "ProgramData")
	if err := createProtectedDir(programData); err != nil {
		t.Fatal(err)
	}
	testWindowsTrust(t, programData)
	return Options{
		GOOS:                "windows",
		HookBinary:          `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		WindowsProgramFiles: `C:\Program Files`,
		WindowsProgramData:  programData,
		StateDir:            filepath.Join(root, "state", "machine-policy"),
		Now:                 func() time.Time { return time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC) },
	}
}

// userCreatedDir makes a directory the way a standard user's mkdir in
// ProgramData leaves it: Users may add, change and delete its children.
func userCreatedDir(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;BU)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	name, _ := windows.UTF16PtrFromString(path)
	if err := windows.CreateDirectory(name, &attributes); err != nil {
		t.Fatal(err)
	}
}

func descriptorOf(t *testing.T, path string) (*windows.SID, *windows.SECURITY_DESCRIPTOR) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	return owner, sd
}

func requireProtected(t *testing.T, path string) {
	t.Helper()
	owner, sd := descriptorOf(t, path)
	if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		t.Fatalf("%s owner = %s, want Administrators", path, owner)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("%s DACL is not protected (control %#x, %v)", path, control, err)
	}
	if err := validateTrustedDir(path); err != nil {
		t.Fatal(err)
	}
}

// Missing vendor directories are created with DefenseClaw's owner and
// protected DACL in one call; an object that is already there when a
// missing component is created is refused, never adopted.
func TestWindowsPolicyDirsAreCreatedProtectedAndNeverAdopted(t *testing.T) {
	opts := windowsTestOptions(t)
	dir := filepath.Join(opts.WindowsProgramData, "GitHub", "Copilot", "policy.d")
	created, err := ensurePolicyDir(opts, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 3 {
		t.Fatalf("created = %v", created)
	}
	for _, path := range created {
		requireProtected(t, path)
	}
	planted := filepath.Join(opts.WindowsProgramData, "OpenAI")
	userCreatedDir(t, planted)
	if err := createProtectedDir(planted); err == nil || !strings.Contains(err.Error(), "refusing to adopt") {
		t.Fatalf("an object that appeared at a missing path must be refused, got %v", err)
	}
	if _, sd := descriptorOf(t, planted); !strings.Contains(sd.String(), "FA;;;BU)") {
		t.Fatalf("the refused directory must not have been re-ACLed: %s", sd)
	}
}

// A standard user who creates the Copilot vendor directory first no longer
// blocks Copilot's machine policy: reconcile takes the directory back by
// handle, without touching what is inside it, and publishes the drop-in.
func TestWindowsCopilotTakesBackAUserCreatedVendorDir(t *testing.T) {
	opts := windowsTestOptions(t)
	github := filepath.Join(opts.WindowsProgramData, "GitHub")
	userCreatedDir(t, github)
	sibling := filepath.Join(github, "user-notes.txt")
	if err := os.WriteFile(sibling, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateTrustedDir(github); err == nil {
		t.Fatal("test setup: the user-created directory must start untrusted")
	}
	state, err := copilotTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatalf("a user-created vendor directory must not block reconcile: %v", err)
	}
	mustNoConflicts(t, state)
	if !state.Covered || !strings.Contains(strings.Join(state.Details, " "), "took back") {
		t.Fatalf("state: %+v", state)
	}
	requireProtected(t, github)
	// Nothing propagated to the directory's existing children: the
	// sibling keeps the full-control entry it inherited before.
	if _, sd := descriptorOf(t, sibling); !strings.Contains(sd.String(), "FA;;;BU)") {
		t.Fatalf("take-back must not rewrite existing children: %s", sd)
	}
}

// A policy file inside policy.d that an unprivileged principal controls is
// reported: Copilot's handling of such files is only verified on unix.
func TestWindowsCopilotUntrustedForeignPolicyFileIsAConflict(t *testing.T) {
	opts := windowsTestOptions(t)
	if _, err := (copilotTarget{}).Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	dir, _ := CopilotPolicyDir(opts)
	foreign := filepath.Join(dir, "user.json")
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;BU)(A;;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, []byte(`{"version":1,"hooks":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	dacl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(foreign, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	state, err := copilotTarget{}.Verify(opts)
	if err != nil {
		t.Fatal(err)
	}
	if state.Covered || !hasConflict(state, "not administrator-controlled") {
		t.Fatalf("a user-controlled policy file must be a conflict on Windows: %+v", state)
	}
}

// A 90-defenseclaw.json an unprivileged principal planted in a trusted
// policy.d is replaced, not left to fail every reconcile.
func TestWindowsCopilotReplacesAnUntrustedDefenseClawDropIn(t *testing.T) {
	opts := windowsTestOptions(t)
	dir := filepath.Join(opts.WindowsProgramData, "GitHub", "Copilot", "policy.d")
	if _, err := ensurePolicyDir(opts, dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, DefenseClawDropInName)
	if err := os.WriteFile(path, []byte(`{"version":1,"hooks":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sd, _ := windows.SecurityDescriptorFromString("D:P(A;;FA;;;BU)(A;;FA;;;BA)")
	dacl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	state, err := copilotTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatalf("reconcile must replace an untrusted drop-in: %v", err)
	}
	mustNoConflicts(t, state)
	if !state.Covered || !strings.Contains(readFile(t, path), "copilot") {
		t.Fatalf("state %+v", state)
	}
	if err := validateTrustedFile(path); err != nil {
		t.Fatalf("the replacement must carry DefenseClaw's descriptor: %v", err)
	}
}

// A reparse point an administrator put at a vendor path is neither taken
// over nor removed: it is the administrator's to fix.
func TestWindowsReclaimRefusesAnAdministratorsReparsePoint(t *testing.T) {
	opts := windowsTestOptions(t)
	target := filepath.Join(filepath.Dir(opts.WindowsProgramData), "elsewhere")
	userCreatedDir(t, target)
	link := filepath.Join(opts.WindowsProgramData, "GitHub")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J unavailable: %v %s", err, out)
	}
	ownAs(t, link, wellKnownSID(t, windows.WinBuiltinAdministratorsSid))
	if _, err := (copilotTarget{}).Reconcile(opts); err == nil || !strings.Contains(err.Error(), "an administrator must") {
		t.Fatalf("an administrator's junction at the vendor path must be refused, got %v", err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("the administrator's junction must stay: %v", err)
	}
	if _, sd := descriptorOf(t, target); !strings.Contains(sd.String(), "FA;;;BU)") {
		t.Fatalf("the junction target must not have been re-ACLed: %s", sd)
	}
}

// A policy directory an administrator created normally inherits
// ProgramData's "Users may create files" entry. The ancestor rules accept
// that, but it lets a standard user add Copilot policy files that apply to
// every user: verify reports it and reconcile takes the directory back.
func TestWindowsCopilotPolicyDirUsersCanAddToIsTakenBack(t *testing.T) {
	opts := windowsTestOptions(t)
	github := filepath.Join(opts.WindowsProgramData, "GitHub")
	copilot := filepath.Join(github, "Copilot")
	for _, dir := range []string{github, copilot} {
		if err := createProtectedDir(dir); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(copilot, "policy.d")
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200af;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	name, _ := windows.UTF16PtrFromString(dir)
	if err := windows.CreateDirectory(name, &attributes); err != nil {
		t.Fatal(err)
	}
	if err := validateTrustedDir(dir); err != nil {
		t.Fatalf("test setup: the ancestor rules accept add-file: %v", err)
	}
	verifyOnly := withPolicy(opts, "copilot", func(p *config.EnterpriseConnectorPolicy) { p.Ownership = "verify_only" })
	state, err := copilotTarget{}.Verify(verifyOnly)
	if err != nil {
		t.Fatal(err)
	}
	if !hasConflict(state, "unprivileged users can add policy files") {
		t.Fatalf("verify must report a user-writable policy directory: %+v", state.Conflicts)
	}
	merge := withPolicy(opts, "copilot", func(p *config.EnterpriseConnectorPolicy) { p.Ownership = "merge" })
	state, err = copilotTarget{}.Reconcile(merge)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	if !state.Covered {
		t.Fatalf("state %+v", state)
	}
	requireProtected(t, dir)
	if err := validateTrustedLeafDir(dir); err != nil {
		t.Fatal(err)
	}
}

// ownAs makes sid the owner of path itself, never of a reparse point's
// target, the way a standard user's objects carry their own SID. Naming
// another principal as owner needs SeRestorePrivilege, which elevated test
// runs hold.
func ownAs(t *testing.T, path string, sid *windows.SID) {
	t.Helper()
	err := withThreadPrivilege("SeRestorePrivilege", func() error {
		handle, err := openDirNoFollow(path, windows.WRITE_OWNER)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(handle)
		return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil)
	})
	if err != nil {
		t.Skipf("setting the test owner needs SeRestorePrivilege: %v", err)
	}
}

func withThreadPrivilege(name string, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		return err
	}
	defer windows.RevertToSelf()
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false, &token); err != nil {
		return err
	}
	defer token.Close()
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return err
	}
	state := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
	if err := windows.AdjustTokenPrivileges(token, false, &state, 0, nil, nil); err != nil {
		return err
	}
	return fn()
}

func wellKnownSID(t *testing.T, kind windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(kind)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// plantAsUser creates what a standard user could leave at path before
// DefenseClaw: a file, a junction to a directory the user controls, or a
// directory with content; the user's SID (BUILTIN\Users here) owns it.
func plantAsUser(t *testing.T, path, kind string) string {
	t.Helper()
	var target string
	switch kind {
	case "file":
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	case "junction":
		target = filepath.Join(t.TempDir(), "user-target")
		userCreatedDir(t, target)
		if err := os.WriteFile(filepath.Join(target, "user.json"), []byte(`{"version":1,"hooks":{}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", path, target).CombinedOutput(); err != nil {
			t.Skipf("mklink /J unavailable: %v %s", err, out)
		}
	case "directory":
		userCreatedDir(t, path)
		if err := os.WriteFile(filepath.Join(path, "keep.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	case "empty directory":
		userCreatedDir(t, path)
	default:
		t.Fatalf("unknown kind %q", kind)
	}
	ownAs(t, path, wellKnownSID(t, windows.WinBuiltinUsersSid))
	return target
}

// displacedEntries lists the hidden names displacePlanted moved objects to.
func displacedEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".defenseclaw-displaced-") {
			names = append(names, entry.Name())
		}
	}
	return names
}

// A standard user who leaves a file or a junction at a vendor path part no
// longer blocks Copilot's machine policy: reconcile removes the link itself
// (never its target) or moves the file aside, creates the directory
// protected in its place, and publishes the drop-in. Removal later deletes
// the directory it created.
func TestWindowsCopilotReplacesObjectsPlantedAtVendorPathParts(t *testing.T) {
	for _, part := range []string{"GitHub", `GitHub\Copilot`, `GitHub\Copilot\policy.d`} {
		for _, kind := range []string{"file", "junction"} {
			t.Run(part+"/"+kind, func(t *testing.T) {
				opts := windowsTestOptions(t)
				planted := filepath.Join(opts.WindowsProgramData, part)
				if parent := filepath.Dir(planted); parent != opts.WindowsProgramData {
					if _, err := ensurePolicyDir(opts, parent); err != nil {
						t.Fatal(err)
					}
				}
				target := plantAsUser(t, planted, kind)
				if validateTrustedDir(planted) == nil {
					t.Fatal("test setup: the planted object must start untrusted")
				}
				state, err := copilotTarget{}.Reconcile(opts)
				if err != nil {
					t.Fatalf("a planted %s must not block reconcile: %v", kind, err)
				}
				mustNoConflicts(t, state)
				details := strings.Join(state.Details, " ")
				if !state.Covered || !strings.Contains(details, planted) {
					t.Fatalf("state: %+v", state)
				}
				requireProtected(t, planted)
				path, _ := copilotDropInPath(opts)
				if !strings.Contains(readFile(t, path), "copilot") {
					t.Fatal("the drop-in was not published")
				}
				switch kind {
				case "junction":
					if !strings.Contains(details, "its target is untouched") {
						t.Fatalf("details: %s", details)
					}
					if _, err := os.Stat(filepath.Join(target, "user.json")); err != nil {
						t.Fatalf("the junction target must survive: %v", err)
					}
					if _, sd := descriptorOf(t, target); !strings.Contains(sd.String(), "FA;;;BU)") {
						t.Fatalf("the junction target must not have been re-ACLed: %s", sd)
					}
				case "file":
					aside := displacedEntries(t, filepath.Dir(planted))
					if len(aside) != 1 {
						t.Fatalf("the planted file must be moved aside: %v", aside)
					}
					owner, _ := descriptorOf(t, filepath.Join(filepath.Dir(planted), aside[0]))
					if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
						t.Fatalf("the moved file must be DefenseClaw's, owner %s", owner)
					}
				}
				if _, err := (copilotTarget{}).RemoveOwned(opts); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(filepath.Join(opts.WindowsProgramData, "GitHub", "Copilot", "policy.d")); !os.IsNotExist(err) {
					t.Fatalf("removal must delete the empty directories DefenseClaw created: %v", err)
				}
			})
		}
	}
}

// A directory, junction or empty directory a standard user left at the
// drop-in name is cleared, so the drop-in can be written; what a
// non-empty directory holds is moved aside intact under a name Copilot
// does not load.
func TestWindowsCopilotClearsObjectsPlantedAtTheDropInName(t *testing.T) {
	for _, kind := range []string{"directory", "empty directory", "junction"} {
		t.Run(kind, func(t *testing.T) {
			opts := windowsTestOptions(t)
			dir := filepath.Join(opts.WindowsProgramData, "GitHub", "Copilot", "policy.d")
			if _, err := ensurePolicyDir(opts, dir); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, DefenseClawDropInName)
			target := plantAsUser(t, path, kind)
			state, err := copilotTarget{}.Reconcile(opts)
			if err != nil {
				t.Fatalf("a planted %s at the drop-in name must not block reconcile: %v", kind, err)
			}
			mustNoConflicts(t, state)
			if !state.Covered || !strings.Contains(readFile(t, path), "copilot") {
				t.Fatalf("state %+v", state)
			}
			if err := validateTrustedFile(path); err != nil {
				t.Fatalf("the drop-in must carry DefenseClaw's descriptor: %v", err)
			}
			aside := displacedEntries(t, dir)
			switch kind {
			case "directory":
				if len(aside) != 1 || strings.HasSuffix(strings.ToLower(aside[0]), ".json") {
					t.Fatalf("the directory must be moved aside under a name Copilot does not load: %v", aside)
				}
				if _, err := os.Stat(filepath.Join(dir, aside[0], "keep.txt")); err != nil {
					t.Fatalf("the moved directory must keep its content: %v", err)
				}
			case "junction":
				if len(aside) != 0 {
					t.Fatalf("a junction is removed, not moved: %v", aside)
				}
				if _, err := os.Stat(filepath.Join(target, "user.json")); err != nil {
					t.Fatalf("the junction target must survive: %v", err)
				}
			default:
				if len(aside) != 0 {
					t.Fatalf("an empty directory is removed, not moved: %v", aside)
				}
			}
		})
	}
}

// A policy file a standard user planted in policy.d before DefenseClaw took
// the directory back is moved aside and taken from its owner, so it can no
// longer run as a machine-wide hook; an administrator's policy file stays.
func TestWindowsCopilotMovesAsidePolicyFilesAUserPlanted(t *testing.T) {
	opts := windowsTestOptions(t)
	github := filepath.Join(opts.WindowsProgramData, "GitHub")
	copilot := filepath.Join(github, "Copilot")
	for _, dir := range []string{github, copilot} {
		if err := createProtectedDir(dir); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(copilot, "policy.d")
	userCreatedDir(t, dir)
	planted := filepath.Join(dir, "10-user.json")
	if err := os.WriteFile(planted, []byte(`{"version":1,"hooks":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ownAs(t, planted, wellKnownSID(t, windows.WinBuiltinUsersSid))
	admin := filepath.Join(dir, "20-admin.json")
	if err := os.WriteFile(admin, []byte(`{"version":1,"hooks":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applySDDL(admin, publicFileSDDL); err != nil {
		t.Fatal(err)
	}
	state, err := copilotTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	if !state.Covered {
		t.Fatalf("state %+v", state)
	}
	requireProtected(t, dir)
	if _, err := os.Lstat(planted); !os.IsNotExist(err) {
		t.Fatalf("the planted policy file must no longer be in force: %v", err)
	}
	aside := displacedEntries(t, dir)
	if len(aside) != 1 || strings.HasSuffix(strings.ToLower(aside[0]), ".json") {
		t.Fatalf("the planted file must be moved aside under a name Copilot does not load: %v", aside)
	}
	owner, sd := descriptorOf(t, filepath.Join(dir, aside[0]))
	if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || strings.Contains(sd.String(), ";;;BU)") {
		t.Fatalf("the moved file must be DefenseClaw's and private: %s %s", owner, sd)
	}
	if _, err := os.Stat(admin); err != nil {
		t.Fatalf("an administrator's policy file must stay: %v", err)
	}
}

// An object planted again between its removal and the directory's creation
// is cleared again, a bounded number of times; a user who keeps winning
// that race fails the reconcile rather than being adopted.
func TestWindowsCopilotClearsAnObjectPlantedAgainDuringReplacement(t *testing.T) {
	for _, replants := range []int{1, plantedAttempts} {
		t.Run(fmt.Sprint(replants), func(t *testing.T) {
			opts := windowsTestOptions(t)
			github := filepath.Join(opts.WindowsProgramData, "GitHub")
			plantAsUser(t, github, "file")
			count := 0
			previous := plantedCleared
			plantedCleared = func(path string) {
				if count < replants {
					count++
					plantAsUser(t, path, "file")
				}
			}
			t.Cleanup(func() { plantedCleared = previous })
			state, err := copilotTarget{}.Reconcile(opts)
			if replants == plantedAttempts {
				if err == nil || !strings.Contains(err.Error(), "refusing to adopt") {
					t.Fatalf("a user who keeps re-planting must fail the reconcile, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			mustNoConflicts(t, state)
			if !state.Covered || len(displacedEntries(t, opts.WindowsProgramData)) != 2 {
				t.Fatalf("both planted files must be moved aside: %+v", state)
			}
			requireProtected(t, github)
		})
	}
}

// A regular opencode.json or opencode.jsonc a standard user left in
// %ProgramData%\opencode before DefenseClaw took the folder back stays
// editable by that user, and OpenCode loads it as managed config for every
// account. Reconcile moves it aside, as for Copilot, and publishes
// DefenseClaw's managed config in its place.
func TestWindowsOpenCodeMovesAsideAConfigAUserPlanted(t *testing.T) {
	for _, name := range []string{"opencode.json", "opencode.jsonc"} {
		t.Run(name, func(t *testing.T) {
			opts := windowsOpenCodeTestOptions(t)
			dir := filepath.Join(opts.WindowsProgramData, "opencode")
			userCreatedDir(t, dir)
			planted := filepath.Join(dir, name)
			if err := os.WriteFile(planted, []byte(`{"plugin": ["file:///C:/Users/a/tool.js"]}`), 0o644); err != nil {
				t.Fatal(err)
			}
			ownAs(t, planted, wellKnownSID(t, windows.WinBuiltinUsersSid))

			result, err := PublishWindowsGoOwned(opts, []string{ConnectorOpenCode})
			if err != nil {
				t.Fatalf("a planted config must not block OpenCode's machine policy: %v", err)
			}
			if len(result.MachinePolicyConnectors) != 1 || result.MachinePolicyConnectors[0] != ConnectorOpenCode {
				t.Fatalf("OpenCode must be published through machine policy: %+v", result)
			}
			requireProtected(t, dir)
			if name == "opencode.jsonc" {
				if _, err := os.Lstat(planted); !os.IsNotExist(err) {
					t.Fatalf("the planted config must no longer be in force: %v", err)
				}
			}
			aside := displacedEntries(t, dir)
			if len(aside) != 1 || strings.HasSuffix(strings.ToLower(aside[0]), ".json") || strings.HasSuffix(strings.ToLower(aside[0]), ".jsonc") {
				t.Fatalf("the planted config must be moved aside under a name OpenCode does not load: %v", aside)
			}
			owner, sd := descriptorOf(t, filepath.Join(dir, aside[0]))
			if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || strings.Contains(sd.String(), ";;;BU)") {
				t.Fatalf("the moved file must be DefenseClaw's and private: %s %s", owner, sd)
			}
			config, err := OpenCodeManagedConfigPath(opts)
			if err != nil || filepath.Base(config) != "opencode.json" {
				t.Fatalf("managed config path: %s %v", config, err)
			}
			body, err := os.ReadFile(config)
			if err != nil || strings.Contains(string(body), "tool.js") || !strings.Contains(string(body), strings.ReplaceAll(opts.OpenCodePluginPath, `\`, `\\`)) {
				t.Fatalf("the managed config must be DefenseClaw's alone: %v\n%s", err, body)
			}
			if err := validateTrustedFile(config); err != nil {
				t.Fatalf("the published config must be trusted: %v", err)
			}
		})
	}
}

// Every account's Amp reads %ProgramData%\ampcode. The guardian
// holds it: a folder a standard account made is reported, then taken back
// with what that account put there moved aside.
func TestPublishWindowsGoOwnedHoldsTheAmpMachineFolder(t *testing.T) {
	opts := windowsTestOptions(t)
	dir := filepath.Join(opts.WindowsProgramData, "ampcode")
	userCreatedDir(t, dir)
	planted := filepath.Join(dir, "AGENTS.md")
	if err := os.WriteFile(planted, []byte("marker"), 0o644); err != nil {
		t.Fatal(err)
	}
	ownAs(t, planted, wellKnownSID(t, windows.WinBuiltinUsersSid))
	if problems := InspectWindowsAmpMachineFolder(opts); len(problems) == 0 {
		t.Fatal("a user-created Amp machine folder must be reported")
	}
	if _, err := PublishWindowsGoOwned(opts, nil); err != nil {
		t.Fatal(err)
	}
	requireProtected(t, dir)
	if _, err := os.Lstat(planted); !os.IsNotExist(err) {
		t.Fatalf("the planted guidance must no longer be in force: %v", err)
	}
	if problems := InspectWindowsAmpMachineFolder(opts); len(problems) != 0 {
		t.Fatalf("a held Amp machine folder must not be reported: %v", problems)
	}
}

// A standard user who created the Codex vendor folder first, with a
// requirements file in it, no longer stops the first delivery: the folder
// and its OpenAI parent are taken back and her file is moved aside to a
// hidden name, as for the Copilot and OpenCode folders (GAP-0565).
func TestWindowsTakeBackVendorPolicyFolderTakesBackAUserCreatedCodexFolder(t *testing.T) {
	opts := windowsTestOptions(t)
	openAI := filepath.Join(opts.WindowsProgramData, "OpenAI")
	codex := filepath.Join(openAI, "Codex")
	plantAsUser(t, openAI, "empty directory")
	plantAsUser(t, codex, "empty directory")
	planted := filepath.Join(codex, "requirements.toml")
	if err := os.WriteFile(planted, []byte("# user marker"), 0o644); err != nil {
		t.Fatal(err)
	}
	ownAs(t, planted, wellKnownSID(t, windows.WinBuiltinUsersSid))
	notes, err := TakeBackVendorPolicyFolder(opts, codex)
	if err != nil {
		t.Fatalf("a user-created Codex folder must be taken back: %v (%v)", err, notes)
	}
	requireProtected(t, openAI)
	requireProtected(t, codex)
	if _, err := os.Lstat(planted); !errors.Is(err, os.ErrNotExist) || len(displacedEntries(t, codex)) != 1 {
		t.Fatalf("the user's requirements file was not moved aside: %v %v", err, displacedEntries(t, codex))
	}
	missing := filepath.Join(opts.WindowsProgramData, "Cursor")
	if notes, err := TakeBackVendorPolicyFolder(opts, missing); err != nil || len(notes) != 0 {
		t.Fatalf("a missing folder: %v %v", notes, err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a missing folder was created: %v", err)
	}
}
