//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// GAP-0633 (g582 review 2 N1): on standalone the hook guardian re-stamped a
// DefenseClaw machine policy file or folder that an untrusted account could
// write or owned, so every reader then trusted bytes that account chose (a
// Claude Code state record naming another hook executable, a Codex
// requirements.toml with its hooks removed). It now leaves such an object as
// it is and names it; trusted-only drift, the lock files and Secure Client
// keep the repair.

const (
	gap633CanonicalFile       = "O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)"
	gap633UsersModifyFile     = "O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)(A;;0x1301bf;;;BU)"
	gap633UsersOwnerFile      = "O:BUG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)"
	gap633NoUsersReadFile     = "O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)"
	gap633UsersModifyFolder   = "O:BAG:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1301bf;;;BU)"
	gap633UsersOwnerFolder    = "O:BUG:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)"
	gap633CanonicalFolderSDDL = "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
)

func requireGAP633Elevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token (the Windows CI runners and the native test hosts run elevated)")
	}
}

// setGAP633Profile pins the standalone decision and a strict reader check
// that accepts everything (the temp folders above the fixture are not
// trusted), and resets the once-per-finding log.
func setGAP633Profile(t *testing.T, standalone bool, strict func(string) error) {
	t.Helper()
	previousStandalone := windowsManagedPolicySelfHealRefusesContentDrift
	previousStrict := windowsManagedPolicyFileTrustCheck
	previousOwner := windowsManagedPolicyOwnerSID
	windowsManagedPolicySelfHealRefusesContentDrift = func() bool { return standalone }
	if strict == nil {
		strict = func(string) error { return nil }
	}
	windowsManagedPolicyFileTrustCheck = strict
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) {
		return windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	}
	t.Cleanup(func() {
		windowsManagedPolicySelfHealRefusesContentDrift = previousStandalone
		windowsManagedPolicyFileTrustCheck = previousStrict
		windowsManagedPolicyOwnerSID = previousOwner
	})
}

func stampGAP633SDDL(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	group, _, err := descriptor.Group()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := RunWithWindowsOwnerRestorePrivilege(func() error {
		return windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, info, owner, group, dacl, nil)
	}); err != nil {
		t.Fatalf("stamp %s on %s: %v", sddl, path, err)
	}
}

// gap633Descriptor is the owner and DACL of path as SDDL.
func gap633Descriptor(t *testing.T, path string) string {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor.String()
}

func gap633UsersCanWrite(sddl string) bool {
	return strings.Contains(sddl, ";0x1301bf;;;BU)") || strings.HasPrefix(sddl, "O:BU")
}

// gap633Reported is the boundary finding the self-heal logged for key, or "".
func gap633Reported(key string) string {
	value, ok := windowsManagedPolicySelfHealReported.Load(key)
	if !ok {
		return ""
	}
	line, _ := value.(string)
	if !strings.HasPrefix(line, managed.MarkerBoundary+"\x00") {
		return ""
	}
	return strings.TrimPrefix(line, managed.MarkerBoundary+"\x00")
}

func gap633ReadOnly(t *testing.T, path string) bool {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := windows.GetFileAttributes(name)
	if err != nil {
		t.Fatal(err)
	}
	return attributes&windows.FILE_ATTRIBUTE_READONLY != 0
}

func setGAP633ReadOnly(t *testing.T, path string) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetFileAttributes(name, windows.FILE_ATTRIBUTE_READONLY); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsManagedPolicySelfHealStandaloneNeverRestampsAnUntrustedWriterInPlace(t *testing.T) {
	requireGAP633Elevated(t)
	stateFile := windowsManagedPolicySelfHealFile{
		name: windowsClaudeManagedStateFile, userReadable: true,
		clear: windowsManagedPolicyStateAttributes, exact: true, marker: true,
	}
	lockFile := windowsManagedPolicySelfHealFile{
		name: windowsClaudeManagedLockFile, userReadable: true,
		clear: windowsManagedPolicyLockAttributes, exact: true, lock: true,
	}
	requirementsFile := windowsManagedPolicySelfHealFile{
		name: "requirements.toml", userReadable: true, clear: windowsManagedPolicyStateAttributes, exact: true,
	}
	cursorHooks := windowsManagedPolicySelfHealFile{
		name: "hooks.json", userReadable: true, clear: windowsManagedPolicyStateAttributes,
	}
	strictRefuses := func(path string) error {
		return errors.New("managed policy file " + path + " has an untrusted writer above it")
	}
	for _, tc := range []struct {
		name       string
		file       windowsManagedPolicySelfHealFile
		sddl       string
		readOnly   bool
		standalone bool
		strict     func(string) error
		refused    bool
	}{
		{name: "Claude or Codex state, Users Modify", file: stateFile, sddl: gap633UsersModifyFile, readOnly: true, standalone: true, refused: true},
		{name: "Claude or Codex state, Users owner", file: stateFile, sddl: gap633UsersOwnerFile, standalone: true, refused: true},
		{name: "Codex requirements.toml, Users Modify", file: requirementsFile, sddl: gap633UsersModifyFile, standalone: true, refused: true},
		{name: "Cursor hooks.json, Users Modify", file: cursorHooks, sddl: gap633UsersModifyFile, standalone: true, refused: true},
		{name: "trusted-only drift the reader walk refuses", file: stateFile, sddl: gap633NoUsersReadFile, standalone: true, strict: strictRefuses, refused: true},
		// Twins: trusted-only drift, a lock file and Secure Client keep the repair.
		{name: "twin: missing Users read is repaired", file: stateFile, sddl: gap633NoUsersReadFile, readOnly: true, standalone: true},
		{name: "twin: lock file with Users Modify is repaired", file: lockFile, sddl: gap633UsersModifyFile, standalone: true},
		{name: "twin: Secure Client state with Users Modify is repaired", file: stateFile, sddl: gap633UsersModifyFile, readOnly: true},
		{name: "twin: Secure Client requirements.toml with Users Modify is repaired", file: requirementsFile, sddl: gap633UsersModifyFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setGAP633Profile(t, tc.standalone, tc.strict)
			path := filepath.Join(t.TempDir(), tc.file.name)
			if err := os.WriteFile(path, []byte(`{"policy_sha256":"x"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			stampGAP633SDDL(t, path, tc.sddl)
			if tc.readOnly {
				setGAP633ReadOnly(t, path)
			}
			before := gap633Descriptor(t, path)
			windowsManagedPolicySelfHealReported.Delete(path)
			t.Cleanup(func() {
				windowsManagedPolicySelfHealReported.Delete(path)
				windowsManagedPolicySelfHealReported.Delete(path + "#attributes")
				if name, err := windows.UTF16PtrFromString(path); err == nil {
					_ = windows.SetFileAttributes(name, windows.FILE_ATTRIBUTE_NORMAL)
				}
			})

			repairWindowsManagedPolicySelfHealFile(path, tc.file)

			after := gap633Descriptor(t, path)
			reported := gap633Reported(path)
			if tc.refused {
				if after != before {
					t.Fatalf("the guardian re-stamped a refused file in place: %s -> %s", before, after)
				}
				if tc.readOnly && !gap633ReadOnly(t, path) {
					t.Fatal("the guardian cleared the attributes of a refused file")
				}
				for _, want := range []string{path, "does not repair this file in place", "/remove:g", "/setowner *S-1-5-32-544", "/ensure"} {
					if !strings.Contains(reported, want) {
						t.Fatalf("boundary finding %q does not name %q", reported, want)
					}
				}
				return
			}
			if reported != "" {
				t.Fatalf("a repairable file was logged as a boundary: %s", reported)
			}
			if err := validateWindowsManagedMachineFileDescriptor(path, tc.file.userReadable); err != nil || gap633UsersCanWrite(after) {
				t.Fatalf("the guardian did not repair %s: %s (%v)", tc.sddl, after, err)
			}
			if tc.readOnly && gap633ReadOnly(t, path) {
				t.Fatal("the guardian left the ReadOnly attribute on a repaired file")
			}
		})
	}
}

func TestWindowsManagedPolicySelfHealStandaloneNeverRestampsAnUntrustedFolderInPlace(t *testing.T) {
	requireGAP633Elevated(t)
	for _, tc := range []struct {
		name       string
		sddl       string
		exact      bool
		standalone bool
		refused    bool
	}{
		{name: "Claude or Codex folder, Users Modify", sddl: gap633UsersModifyFolder, standalone: true, refused: true},
		{name: "Cursor folder (exact), Users Modify", sddl: gap633UsersModifyFolder, exact: true, standalone: true, refused: true},
		{name: "Cursor folder (exact), Users owner", sddl: gap633UsersOwnerFolder, exact: true, standalone: true, refused: true},
		{name: "twin: Cursor folder (exact) with a trusted extra entry is repaired", sddl: gap633CanonicalFolderSDDL + "(A;OICI;FR;;;NS)", exact: true, standalone: true},
		{name: "twin: Secure Client folder with Users Modify is repaired", sddl: gap633UsersModifyFolder, exact: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setGAP633Profile(t, tc.standalone, nil)
			folder := filepath.Join(t.TempDir(), "policy")
			if err := os.Mkdir(folder, 0o700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(folder, windowsClaudeManagedStateFile)
			if err := os.WriteFile(marker, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			stampGAP633SDDL(t, marker, gap633CanonicalFile)
			stampGAP633SDDL(t, folder, tc.sddl)
			before := gap633Descriptor(t, folder)
			windowsManagedPolicySelfHealReported.Delete(folder)
			t.Cleanup(func() { windowsManagedPolicySelfHealReported.Delete(folder) })

			repairWindowsManagedPolicySelfHealFolder(windowsManagedPolicySelfHealFolder{
				path:  folder,
				exact: tc.exact,
				files: []windowsManagedPolicySelfHealFile{{
					name: windowsClaudeManagedStateFile, userReadable: true,
					clear: windowsManagedPolicyStateAttributes, exact: true, marker: true,
				}},
			})

			after := gap633Descriptor(t, folder)
			reported := gap633Reported(folder)
			if tc.refused {
				if after != before {
					t.Fatalf("the guardian re-stamped a refused folder in place: %s -> %s", before, after)
				}
				if !strings.Contains(reported, folder) || !strings.Contains(reported, "/remove:g") {
					t.Fatalf("boundary finding %q does not name the folder and the way out", reported)
				}
				return
			}
			if reported != "" {
				t.Fatalf("a repairable folder was logged as a boundary: %s", reported)
			}
			if err := validateWindowsManagedPolicyDirectoryDescriptor(folder); err != nil || gap633UsersCanWrite(after) {
				t.Fatalf("the guardian did not repair the folder: %s (%v)", after, err)
			}
		})
	}
}

// The review's scenario end to end: a standard user with a write entry on the
// Claude Code ownership record. On standalone the guardian pass leaves the
// entry and logs it, and the drift restore refuses the record, so no drop-in
// is rendered from it. The Secure Client twin keeps the re-stamp and the
// restore.
func TestWindowsClaudeManagedPolicyDriftNeverRendersFromAnUntrustedRecord(t *testing.T) {
	requireGAP633Elevated(t)
	for _, standalone := range []bool{true, false} {
		name := "standalone"
		if !standalone {
			name = "twin: Secure Client"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
			if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
				t.Fatal(err)
			}
			previousIdentity := windowsEnterpriseMutationIdentityCheck
			windowsEnterpriseMutationIdentityCheck = func() error { return nil }
			previousStandalone := windowsManagedPolicySelfHealRefusesContentDrift
			windowsManagedPolicySelfHealRefusesContentDrift = func() bool { return standalone }
			t.Cleanup(func() {
				windowsEnterpriseMutationIdentityCheck = previousIdentity
				windowsManagedPolicySelfHealRefusesContentDrift = previousStandalone
			})
			statePath := filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedStateFile)
			windowsManagedPolicySelfHealReported.Delete(statePath)
			t.Cleanup(func() { windowsManagedPolicySelfHealReported.Delete(statePath) })
			drifted := strings.Replace(gap633Descriptor(t, statePath), ")", ")(A;;0x1301bf;;;BU)", 1)
			stampGAP633SDDL(t, statePath, "O:"+fixture.targetSID.String()+"G:SY"+drifted[strings.Index(drifted, "D:"):])
			if err := os.Remove(fixture.policyPath); err != nil {
				t.Fatal(err)
			}

			repairWindowsManagedPolicySelfHealFile(statePath, windowsManagedPolicySelfHealFile{
				name: windowsClaudeManagedStateFile, userReadable: true,
				clear: windowsManagedPolicyStateAttributes, exact: true, marker: true,
			})
			restored, err := RestoreWindowsClaudeManagedPolicyDrift()
			_, statErr := os.Lstat(fixture.policyPath)
			if standalone {
				if !gap633UsersCanWrite(gap633Descriptor(t, statePath)) {
					t.Fatal("the guardian re-stamped the untrusted record in place")
				}
				if gap633Reported(statePath) == "" {
					t.Fatal("the guardian did not log the untrusted record")
				}
				if restored || err == nil || statErr == nil {
					t.Fatalf("the restore rendered a drop-in from an untrusted record: restored=%v err=%v", restored, err)
				}
				return
			}
			if !restored || err != nil || statErr != nil {
				t.Fatalf("Secure Client: restored=%v err=%v stat=%v, want the re-stamp and the restore", restored, err, statErr)
			}
		})
	}
}

// A record with a trusted descriptor that names another hook executable,
// with the matching digest, is refused on standalone: the restore renders only
// for this install's own native hook.
func TestWindowsClaudeManagedPolicyDriftRefusesARecordNamingAnotherHook(t *testing.T) {
	requireGAP633Elevated(t)
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
		t.Fatal(err)
	}
	previousIdentity := windowsEnterpriseMutationIdentityCheck
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	previousStandalone := windowsManagedPolicySelfHealRefusesContentDrift
	windowsManagedPolicySelfHealRefusesContentDrift = func() bool { return true }
	t.Cleanup(func() {
		windowsEnterpriseMutationIdentityCheck = previousIdentity
		windowsManagedPolicySelfHealRefusesContentDrift = previousStandalone
	})
	statePath := filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedStateFile)
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var record windowsClaudeManagedPolicyState
	if err := decodeWindowsClaudeManagedPolicyState(data, &record); err != nil {
		t.Fatal(err)
	}
	record.HookExecutable = filepath.Join(filepath.Dir(fixture.hookExe), "other", "defenseclaw-hook.exe")
	body, err := renderWindowsClaudeRecordedPolicy(record, "", true)
	if err != nil {
		t.Fatal(err)
	}
	record.PolicySHA256 = windowsManagedPolicyDigest(body)
	data, err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := windowsManagedPolicyWriter(statePath, data, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fixture.policyPath); err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreWindowsClaudeManagedPolicyDrift()
	if restored || err == nil || !strings.Contains(err.Error(), "not this install's") {
		t.Fatalf("restored=%v err=%v, want a refusal naming the hook executable", restored, err)
	}
	if _, statErr := os.Lstat(fixture.policyPath); statErr == nil {
		t.Fatal("the restore wrote a drop-in for another hook executable")
	}
}
