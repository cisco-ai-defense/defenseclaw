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

package managed

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsWriteLikeAccess(t *testing.T) {
	for name, mask := range map[string]windows.ACCESS_MASK{
		"generic write": windows.GENERIC_WRITE,
		"write data":    windows.FILE_WRITE_DATA,
		"delete child":  0x00000040,
		"change dacl":   windows.WRITE_DAC,
	} {
		t.Run(name, func(t *testing.T) {
			if !windowsWriteLikeAccess(mask) {
				t.Fatalf("windowsWriteLikeAccess(0x%x) = false, want true", uint32(mask))
			}
		})
	}
	if windowsWriteLikeAccess(windows.GENERIC_READ | windows.FILE_READ_DATA) {
		t.Fatal("read-only access classified as write-like")
	}
}

func TestRejectUntrustedWindowsWriteACEsAllowsOnlyExactServiceSID(t *testing.T) {
	serviceSID, err := windows.StringToSid("S-1-5-80-111-222-333-444-555")
	if err != nil {
		t.Fatalf("StringToSid service: %v", err)
	}
	otherServiceSID, err := windows.StringToSid("S-1-5-80-999-888-777-666-555")
	if err != nil {
		t.Fatalf("StringToSid other service: %v", err)
	}
	sddl := "D:P(A;;GA;;;S-1-5-80-111-222-333-444-555)(A;;GA;;;BA)(A;;GR;;;BU)"
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("SecurityDescriptorFromString: %v", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("DACL: %v", err)
	}
	// x/sys/windows may report the control-bit presence flag as false for
	// an in-memory SDDL descriptor even though it returns its DACL.
	if dacl == nil {
		t.Fatal("test descriptor has no DACL")
	}
	if err := rejectUntrustedWindowsWriteACEsWithWriter("runtime", dacl, serviceSID, false); err != nil {
		t.Fatalf("exact service SID rejected: %v", err)
	}
	if err := rejectUntrustedWindowsWriteACEsWithWriter("runtime", dacl, otherServiceSID, false); err == nil {
		t.Fatal("foreign service SID write ACE was accepted")
	}
	if err := rejectUntrustedWindowsWriteACEs("config", dacl); err == nil {
		t.Fatal("service SID write ACE was accepted for strict administrator path")
	}
}

func TestWindowsTrustedPathOwnerAllowsExactServiceOnlyForScopedValidator(t *testing.T) {
	serviceSID, err := windows.StringToSid("S-1-5-80-111-222-333-444-555")
	if err != nil {
		t.Fatalf("StringToSid service: %v", err)
	}
	otherServiceSID, err := windows.StringToSid("S-1-5-80-999-888-777-666-555")
	if err != nil {
		t.Fatalf("StringToSid other service: %v", err)
	}
	if windowsTrustedOwner(serviceSID) {
		t.Fatal("strict administrator owner check accepted service SID")
	}
	if !windowsTrustedPathOwner(serviceSID, serviceSID) {
		t.Fatal("scoped service runtime owner check rejected exact service SID")
	}
	if windowsTrustedPathOwner(serviceSID, otherServiceSID) {
		t.Fatal("scoped service runtime owner check accepted foreign service SID")
	}
}

func TestWindowsVirtualServiceSIDRejectsBroadOrMalformedAccounts(t *testing.T) {
	for _, account := range []string{
		"BUILTIN\\Users",
		"LocalSystem",
		`NT SERVICE\`,
		`NT SERVICE\DefenseClaw Gateway`,
		`NT SERVICE\DefenseClawGateway\Other`,
	} {
		if _, err := windowsVirtualServiceSID(account); err == nil {
			t.Fatalf("windowsVirtualServiceSID(%q) succeeded, want rejection", account)
		}
	}
}

func TestRejectWindowsReparsePoint(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "regular")
	if err := os.WriteFile(regular, []byte("ok"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := rejectWindowsReparsePoint(regular, "test"); err != nil {
		t.Fatalf("regular file rejected as reparse point: %v", err)
	}

	link := filepath.Join(root, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Skipf("Windows symlink creation unavailable: %v", err)
	}
	err := rejectWindowsReparsePoint(link, "test")
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "reparse") {
		t.Fatalf("rejectWindowsReparsePoint error = %v, want reparse refusal", err)
	}
}

func TestWindowsTrustedOwner(t *testing.T) {
	for _, raw := range []string{
		"S-1-5-18",     // LocalSystem
		"S-1-5-32-544", // Builtin Administrators
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // TrustedInstaller
	} {
		sid, err := windows.StringToSid(raw)
		if err != nil {
			t.Fatalf("StringToSid(%q): %v", raw, err)
		}
		if !windowsTrustedOwner(sid) {
			t.Fatalf("windowsTrustedOwner(%q) = false, want true", raw)
		}
	}

	standardUser, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatalf("StringToSid standard user: %v", err)
	}
	if windowsTrustedOwner(standardUser) {
		t.Fatal("standard user SID classified as trusted owner")
	}
	if windowsTrustedOwner(nil) {
		t.Fatal("nil SID classified as trusted owner")
	}
}

func TestRejectUntrustedWindowsWriteACEs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sddl    string
		wantErr string
	}{
		{
			name: "standard users read only",
			sddl: "D:P(A;;GR;;;BU)(A;;GA;;;BA)",
		},
		{
			name:    "standard users generic write",
			sddl:    "D:P(A;;GW;;;BU)(A;;GA;;;BA)",
			wantErr: "untrusted Windows principal",
		},
		{
			name: "local system write",
			sddl: "D:P(A;;GA;;;SY)(A;;GA;;;BA)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatalf("SecurityDescriptorFromString: %v", err)
			}
			dacl, _, err := descriptor.DACL()
			if err != nil {
				t.Fatalf("DACL: %v", err)
			}
			// x/sys/windows may report the control-bit presence flag as false
			// for an in-memory SDDL descriptor even though it returns its DACL.
			if dacl == nil {
				t.Fatal("test descriptor has no DACL")
			}
			err = rejectUntrustedWindowsWriteACEs("test-path", dacl)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("rejectUntrustedWindowsWriteACEs: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("rejectUntrustedWindowsWriteACEs error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestWindowsAncestorAllowsCreateOnlyButRejectsReplacementRights(t *testing.T) {
	for _, test := range []struct {
		name    string
		mask    string
		wantErr bool
	}{
		{name: "list and add-file only", mask: "0x00000003"},
		{name: "add-subdirectory only", mask: "0x00000004"},
		{name: "delete child", mask: "0x00000040", wantErr: true},
		{name: "delete", mask: "SD", wantErr: true},
		{name: "change dacl", mask: "WD", wantErr: true},
		{name: "change owner", mask: "WO", wantErr: true},
		{name: "generic write", mask: "GW", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(
				"D:P(A;;" + test.mask + ";;;BU)(A;;GA;;;BA)",
			)
			if err != nil {
				t.Fatalf("SecurityDescriptorFromString: %v", err)
			}
			dacl, _, err := descriptor.DACL()
			if err != nil {
				t.Fatalf("DACL: %v", err)
			}
			if dacl == nil {
				t.Fatal("test descriptor has no DACL")
			}
			err = rejectUntrustedWindowsWriteACEsWithWriter("ancestor", dacl, nil, true)
			if test.wantErr && err == nil {
				t.Fatal("ancestor replacement rights accepted")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("limited ancestor create rights rejected: %v", err)
			}
		})
	}
}

// Stock system roots grant these rights to BUILTIN\Users and Authenticated
// Users, so both keep the relaxed ancestor rule. Everyone answers to the leaf rule.
func TestWindowsAncestorHoldsEveryoneToTheLeafRule(t *testing.T) {
	for _, test := range []struct {
		name    string
		trustee string
		wantErr bool
	}{
		{name: "builtin users create only", trustee: "S-1-5-32-545"},
		{name: "authenticated users create only", trustee: "S-1-5-11"},
		{name: "everyone create only", trustee: "S-1-1-0", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(
				"D:P(A;;0x00000003;;;" + test.trustee + ")(A;;GA;;;BA)",
			)
			if err != nil {
				t.Fatalf("SecurityDescriptorFromString: %v", err)
			}
			dacl, _, err := descriptor.DACL()
			if err != nil {
				t.Fatalf("DACL: %v", err)
			}
			if dacl == nil {
				t.Fatal("test descriptor has no DACL")
			}
			err = rejectUntrustedWindowsWriteACEsWithWriter("ancestor", dacl, nil, true)
			if test.wantErr && err == nil {
				t.Fatal("world-wide ancestor write grant accepted")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("stock BUILTIN\\Users ancestor grant rejected: %v", err)
			}
		})
	}
}

func TestWindowsDefaultKnownFolderAncestorsAreTrusted(t *testing.T) {
	for _, envName := range []string{"ProgramFiles", "ProgramData"} {
		path := os.Getenv(envName)
		if path == "" {
			t.Fatalf("%s is unset", envName)
		}
		t.Run(envName, func(t *testing.T) {
			if err := ValidateTrustedDirectoryAncestor(path, "known-folder ancestor"); err != nil {
				t.Fatalf("default %s trust probe failed for %s: %v", envName, path, err)
			}
		})
	}
}

func TestValidateTrustedFilePathRejectsRawPerLogonDriveAliasToTrustedTree(t *testing.T) {
	windowsDir, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	volume := filepath.VolumeName(windowsDir)
	if len(volume) != 2 {
		t.Skipf("Windows directory has no drive-letter volume: %s", windowsDir)
	}
	volumePtr, err := windows.UTF16PtrFromString(volume)
	if err != nil {
		t.Fatal(err)
	}
	targetBuffer := make([]uint16, 1024)
	n, err := windows.QueryDosDevice(volumePtr, &targetBuffer[0], uint32(len(targetBuffer)))
	if err != nil || n == 0 {
		t.Fatalf("resolve Windows drive device target: %v", err)
	}
	rawTarget := windows.UTF16ToString(targetBuffer[:n]) +
		strings.TrimPrefix(filepath.Clean(windowsDir), volume)

	alias, ok := unusedManagedTestDriveLetter()
	if !ok {
		t.Skip("no unused drive letter available")
	}
	aliasPtr, err := windows.UTF16PtrFromString(alias)
	if err != nil {
		t.Fatal(err)
	}
	targetPtr, err := windows.UTF16PtrFromString(rawTarget)
	if err != nil {
		t.Fatal(err)
	}
	const noBroadcast = 0x00000008
	if err := windows.DefineDosDevice(
		windows.DDD_RAW_TARGET_PATH|noBroadcast,
		aliasPtr,
		targetPtr,
	); err != nil {
		t.Skipf("cannot create per-logon raw DOS alias: %v", err)
	}
	t.Cleanup(func() {
		if err := windows.DefineDosDevice(
			windows.DDD_REMOVE_DEFINITION|
				windows.DDD_EXACT_MATCH_ON_REMOVE|
				windows.DDD_RAW_TARGET_PATH|
				noBroadcast,
			aliasPtr,
			targetPtr,
		); err != nil {
			t.Errorf("remove raw DOS alias %s: %v", alias, err)
		}
	})

	aliasedPowerShell := filepath.Join(
		alias+`\`,
		"System32",
		"WindowsPowerShell",
		"v1.0",
		"powershell.exe",
	)
	if info, err := os.Stat(aliasedPowerShell); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("trusted file is not reachable through raw alias: %v", err)
	}
	err = ValidateTrustedFilePath(aliasedPowerShell, "raw-alias regression")
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "mount-manager") {
		t.Fatalf("ValidateTrustedFilePath error = %v, want mount-manager refusal", err)
	}
}

func unusedManagedTestDriveLetter() (string, bool) {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return "", false
	}
	const letter = byte('O')
	if mask&(uint32(1)<<(letter-'A')) != 0 {
		return "", false
	}
	return `O:`, true
}

// GAP-0672: the rule-pack check walks into the pack: the manifest and a file
// in the rules folder are checked, not only the pack folder and its parents,
// and the first refusal stops the walk.
func TestWalkWindowsRulePackTreeChecksEveryFileInThePack(t *testing.T) {
	pack := t.TempDir()
	rules := filepath.Join(pack, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filepath.Join(pack, "defenseclaw-pack.json"), filepath.Join(rules, "markers.yaml")} {
		if err := os.WriteFile(name, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var checked []string
	err := walkWindowsRulePackTree(pack, func(path string, isDir bool) error {
		checked = append(checked, path)
		if path == filepath.Join(rules, "markers.yaml") {
			return &UntrustedPrincipalError{Path: path, SID: "S-1-5-11"}
		}
		return nil
	})
	var principal *UntrustedPrincipalError
	if !errors.As(err, &principal) || principal.Path != filepath.Join(rules, "markers.yaml") {
		t.Fatalf("walk = %v, want the refusal of the rules file", err)
	}
	for _, want := range []string{filepath.Join(pack, "defenseclaw-pack.json"), rules} {
		found := false
		for _, path := range checked {
			found = found || path == want
		}
		if !found {
			t.Fatalf("checked %q, want %s among them", checked, want)
		}
	}
}

// GAP-0953: the fix Setup prints for a refused config runs as printed in
// PowerShell and leaves the folder and the config to SYSTEM and
// Administrators. A new folder under C:\ on a Windows client edition holds
// Authenticated Users Modify as its own entry, which /inheritance:r keeps;
// the old fix failed to parse in PowerShell, kept that entry and, with /T,
// left the config with an empty DACL.
func TestDescribeUntrustedSourceFixRunsInPowerShell(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the fixed folder is readable only by SYSTEM and Administrators")
	}
	powershell, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("Windows PowerShell is not available")
	}
	root := t.TempDir()
	folder := filepath.Join(root, "Staging")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	daclOf := func(path string) *windows.ACL {
		t.Helper()
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil || dacl == nil {
			t.Fatalf("DACL of %s: %v", path, err)
		}
		return dacl
	}
	clientEdition, err := windows.SecurityDescriptorFromString(
		"D:P(A;OICI;0x1301bf;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	own, _, err := clientEdition.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(folder, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, own, nil); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(folder, "config.yaml")
	if err := os.WriteFile(config, []byte("deployment_mode: managed_enterprise\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	refused := rejectUntrustedWindowsWriteACEs(config, daclOf(config))
	text, ok := DescribeUntrustedSource("config", config, refused)
	if !ok {
		t.Fatalf("refusal %v is not described", refused)
	}
	_, commands, _ := strings.Cut(text, "From an elevated prompt run ")
	commands, _, _ = strings.Cut(commands, ", and run it again")
	for i, command := range strings.Split(commands, ", then ") {
		script := filepath.Join(root, fmt.Sprintf("fix%d.ps1", i))
		body := "$ErrorActionPreference = 'Stop'\r\n" + command + "\r\nexit $LASTEXITCODE\r\n"
		if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script).CombinedOutput()
		if err != nil {
			t.Fatalf("printed fix %q failed in PowerShell: %v\n%s", command, err, out)
		}
	}
	for _, path := range []string{folder, config} {
		dacl := daclOf(path)
		if dacl.AceCount == 0 {
			t.Fatalf("the printed fix left %s with an empty DACL", path)
		}
		if err := rejectUntrustedWindowsWriteACEs(path, dacl); err != nil {
			t.Fatalf("after the printed fix: %v", err)
		}
	}
}
