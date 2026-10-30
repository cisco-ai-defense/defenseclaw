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
	"os"
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
	if err := rejectUntrustedWindowsWriteACEsWithWriter("runtime", "managed runtime dir", dacl, serviceSID, windowsTrustLeaf); err != nil {
		t.Fatalf("exact service SID rejected: %v", err)
	}
	if err := rejectUntrustedWindowsWriteACEsWithWriter("runtime", "managed runtime dir", dacl, otherServiceSID, windowsTrustLeaf); err == nil {
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

func TestWindowsVirtualServiceSIDForDeletedService(t *testing.T) {
	// This name has no SCM row, but sc.exe showsid computes a stable service
	// SID. The exact expected value was independently recorded from Windows.
	const name = "DefenseClawRecoveryNoSuchServiceProbe_48A6"
	const expected = "S-1-5-80-557343067-3914267301-595778489-1841644181-1709292513"
	account := `NT SERVICE\` + name
	if _, _, _, err := windows.LookupSID("", account); !errors.Is(err, windows.ERROR_NONE_MAPPED) {
		t.Fatalf("absent service LookupSID error = %v, want ERROR_NONE_MAPPED", err)
	}
	sid, err := windowsVirtualServiceSID(account)
	if err != nil {
		t.Fatalf("resolve absent service SID: %v", err)
	}
	if sid.String() != expected {
		t.Fatalf("absent service SID = %s, want %s", sid, expected)
	}
	upper, err := windowsVirtualServiceSID(`NT SERVICE\` + strings.ToUpper(name))
	if err != nil || upper.String() != expected {
		t.Fatalf("case-folded absent service SID = %v, %v, want %s", upper, err, expected)
	}
	// The config loader calls this exact validator for managed data_dir. Its
	// trusted Windows system directory has no service writer ACE, so this
	// exercises the retired-account resolution without changing product ACLs.
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatalf("GetSystemDirectory: %v", err)
	}
	if err := ValidateTrustedServiceRuntimeDir(systemDir, "managed data_dir", account); err != nil {
		t.Fatalf("config runtime trust check with absent service SID: %v", err)
	}
}

func TestWindowsDeterministicServiceSIDMatchesInstalledService(t *testing.T) {
	const name = "TrustedInstaller"
	resolved, _, _, err := windows.LookupSID("", `NT SERVICE\`+name)
	if err != nil {
		t.Fatalf("LookupSID installed service: %v", err)
	}
	computed, err := windowsDeterministicServiceSID(name)
	if err != nil {
		t.Fatalf("compute installed service SID: %v", err)
	}
	if !resolved.Equals(computed) {
		t.Fatalf("resolved SID %s differs from deterministic SID %s", resolved, computed)
	}
}

func TestParseWindowsServiceSIDOutputRejectsAmbiguousOrPartial(t *testing.T) {
	const sid = "S-1-5-80-557343067-3914267301-595778489-1841644181-1709292513"
	for _, output := range []string{
		"no service SID",
		sid + "\n" + sid,
		"SERVICE SID: " + sid + "-1",
		"SERVICE SID: " + sid + "1",
	} {
		if _, err := parseWindowsServiceSIDOutput(output); err == nil {
			t.Fatalf("accepted ambiguous or partial SID output %q", output)
		}
	}
	parsed, err := parseWindowsServiceSIDOutput("SERVICE SID: " + sid + "\r\nSTATUS: Inactive")
	if err != nil || parsed.String() != sid {
		t.Fatalf("valid service SID output = %v, %v", parsed, err)
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

// The mask boundary is asserted with windowsTrustNamedDir, which narrows the
// mask without downgrading verdicts. windowsTrustAncestor applies the same
// classification but turns the verdict into an advisory (AIFW-34262); that
// downgrade is covered by TestWindowsAncestorScopeDowngradesReplacementRights
// so this test measures the classification itself, not the kill switch.
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
			err = rejectUntrustedWindowsWriteACEsWithWriter("ancestor", "managed ancestor", dacl, nil, windowsTrustNamedDir)
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
			err = rejectUntrustedWindowsWriteACEsWithWriter("ancestor", "managed ancestor", dacl, nil, windowsTrustNamedDir)
			if test.wantErr && err == nil {
				t.Fatal("world-wide ancestor write grant accepted")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("stock BUILTIN\\Users ancestor grant rejected: %v", err)
			}
		})
	}
}

// windowsTrustNamedDir and windowsTrustAncestor share one mask rule and differ
// only in whether the verdict is fatal. A directory DefenseClaw created and
// ACLed itself (hook-guardian manifests, managed policy, namespace purge) must
// still refuse an untrusted replacement grant; only the shared Cisco Secure
// Client parents above it are advisory.
func TestWindowsAncestorScopeDowngradesReplacementRights(t *testing.T) {
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;BU)(A;;GA;;;BA)")
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

	if err := rejectUntrustedWindowsWriteACEsWithWriter(
		"named", "managed directory ancestor", dacl, nil, windowsTrustNamedDir,
	); err == nil {
		t.Fatal("named directory accepted an untrusted replacement grant")
	}

	advisories := captureTrustAdvisories(t)
	if err := rejectUntrustedWindowsWriteACEsWithWriter(
		"parent", "managed directory ancestor", dacl, nil, windowsTrustAncestor,
	); err != nil {
		t.Fatalf("ancestor scope refused instead of warning: %v", err)
	}
	if len(*advisories) != 1 {
		t.Fatalf("advisories = %v, want exactly one", *advisories)
	}

	t.Setenv(TrustStrictAncestorsEnv, "1")
	if err := rejectUntrustedWindowsWriteACEsWithWriter(
		"parent", "managed directory ancestor", dacl, nil, windowsTrustAncestor,
	); err == nil {
		t.Fatal("strict pin did not restore the fatal ancestor verdict")
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

// An allow ACE type this walk cannot decode is a structural failure, not a
// permission verdict: ace.Mask and ace.SidStart do not describe the grant, so
// the advisory downgrade would turn "cannot evaluate" into "trusted".
func TestWindowsUnsupportedAllowACETypesStayFatalInAdvisoryScope(t *testing.T) {
	// (A;;GA;;;BA) with the ACE type byte rewritten to each unsupported allow
	// type. Building the descriptor from SDDL and patching the header is the
	// only way to get these types past GetAce.
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;BA)")
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
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatalf("GetAce: %v", err)
	}
	original := ace.Header.AceType

	for name, aceType := range map[string]uint8{
		"allow object":          0x5,
		"allow callback object": 0xB,
	} {
		t.Run(name, func(t *testing.T) {
			ace.Header.AceType = aceType
			t.Cleanup(func() { ace.Header.AceType = original })
			for scopeName, scope := range map[string]windowsTrustScope{
				"leaf":              windowsTrustLeaf,
				"named dir":         windowsTrustNamedDir,
				"advisory ancestor": windowsTrustAncestor,
			} {
				advisories := captureTrustAdvisories(t)
				err := rejectUntrustedWindowsWriteACEsWithWriter(
					`C:\ProgramData\Cisco`, "managed ancestor", dacl, nil, scope,
				)
				if err == nil || !strings.Contains(err.Error(), "unsupported allow ACE type") {
					t.Fatalf("%s scope error = %v, want an unsupported-ACE refusal", scopeName, err)
				}
				if len(*advisories) != 0 {
					t.Fatalf("%s scope advisories = %v, want none", scopeName, *advisories)
				}
			}
		})
	}
}

// A callback (conditional) allow entry shares the ACCESS_ALLOWED_ACE layout, so
// its trustee and mask are judged like a plain entry instead of refusing it.
func TestWindowsCallbackAllowACEIsJudgedByTrustee(t *testing.T) {
	for _, tc := range []struct {
		sddl    string
		wantErr bool
	}{
		{sddl: "D:P(A;;GA;;;BA)", wantErr: false},
		{sddl: "D:P(A;;GA;;;BU)", wantErr: true},
	} {
		descriptor, err := windows.SecurityDescriptorFromString(tc.sddl)
		if err != nil {
			t.Fatalf("SecurityDescriptorFromString: %v", err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil || dacl == nil {
			t.Fatalf("DACL: %v", err)
		}
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, 0, &ace); err != nil {
			t.Fatalf("GetAce: %v", err)
		}
		ace.Header.AceType = 0x9
		err = rejectUntrustedWindowsWriteACEsWithWriter(`C:\x`, "managed file", dacl, nil, windowsTrustLeaf)
		if (err != nil) != tc.wantErr {
			t.Fatalf("%s callback entry error = %v, want error %t", tc.sddl, err, tc.wantErr)
		}
	}
}

// The advisory downgrade is scoped to the platform installer's roots, so a
// parent outside them keeps the pre-AIFW-34262 fatal verdict while retaining the
// narrow mask that stock known-folder grants depend on.
func TestWindowsAncestorScopeFollowsInstallerOwnedRoots(t *testing.T) {
	inside := filepath.Join(`C:\ProgramData\Cisco`, "Cisco Secure Client", "DefenseClaw")
	if scope := windowsAncestorScope(inside); !scope.advisory || !scope.narrowMask {
		t.Errorf("windowsAncestorScope(%q) = %+v, want advisory and narrow-mask", inside, scope)
	}
	for _, outside := range []string{`C:\`, `C:\ProgramData`, os.TempDir()} {
		scope := windowsAncestorScope(outside)
		if scope.advisory {
			t.Errorf("windowsAncestorScope(%q) is advisory outside the installer roots", outside)
		}
		if !scope.narrowMask {
			t.Errorf("windowsAncestorScope(%q) lost the narrow ancestor mask", outside)
		}
	}
}

// A service started with a stripped or partially redirected environment still
// has to recognise the canonical per-machine tree, or the managed state root
// itself would be judged foreign and every ancestor verdict would turn fatal.
func TestPlatformInstallerOwnedRootsAlwaysCoverCanonicalProgramData(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"stripped":            {"ProgramData": "", "ProgramFiles": "", "ProgramFiles(x86)": ""},
		"programdata missing": {"ProgramData": "", "ProgramFiles": `C:\Program Files`},
		"programdata moved":   {"ProgramData": `D:\AppData`},
	} {
		t.Run(name, func(t *testing.T) {
			for key, value := range env {
				t.Setenv(key, value)
			}
			if !PlatformInstallerOwnedPath(`C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw`) {
				t.Fatalf("roots = %v, want the canonical tree covered", PlatformInstallerOwnedRoots())
			}
		})
	}

	t.Setenv("ProgramData", `C:\ProgramData`)
	roots := PlatformInstallerOwnedRoots()
	seen := 0
	for _, root := range roots {
		if strings.EqualFold(root, `C:\ProgramData\Cisco`) {
			seen++
		}
	}
	if seen != 1 {
		t.Fatalf("roots = %v, want exactly one canonical ProgramData entry, got %d", roots, seen)
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

type fakeServiceToken struct {
	user   *windows.SID
	groups []windows.SIDAndAttributes
}

func (token fakeServiceToken) GetTokenUser() (*windows.Tokenuser, error) {
	return &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: token.user}}, nil
}

func (token fakeServiceToken) GetTokenGroups() (*windows.Tokengroups, error) {
	if len(token.groups) == 0 {
		return &windows.Tokengroups{}, nil
	}
	if len(token.groups) != 1 {
		panic("fakeServiceToken models at most one group")
	}
	return &windows.Tokengroups{GroupCount: 1, Groups: [1]windows.SIDAndAttributes{token.groups[0]}}, nil
}

func TestWindowsTokenRunsAsService(t *testing.T) {
	serviceSID, err := windows.StringToSid("S-1-5-80-1858176940-1394861675-2895326486-505287571-2610476274")
	if err != nil {
		t.Fatal(err)
	}
	otherServiceSID, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	if err != nil {
		t.Fatal(err)
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	enabled := uint32(windows.SE_GROUP_ENABLED | windows.SE_GROUP_ENABLED_BY_DEFAULT | windows.SE_GROUP_MANDATORY)
	for _, test := range []struct {
		name  string
		token fakeServiceToken
		want  bool
	}{
		{"legacy virtual account user", fakeServiceToken{user: serviceSID}, true},
		{"localsystem with enabled service group", fakeServiceToken{
			user:   localSystem,
			groups: []windows.SIDAndAttributes{{Sid: serviceSID, Attributes: enabled}},
		}, true},
		{"localsystem without service group", fakeServiceToken{user: localSystem}, false},
		{"localsystem with another service group", fakeServiceToken{
			user:   localSystem,
			groups: []windows.SIDAndAttributes{{Sid: otherServiceSID, Attributes: enabled}},
		}, false},
		{"localsystem with disabled service group", fakeServiceToken{
			user:   localSystem,
			groups: []windows.SIDAndAttributes{{Sid: serviceSID, Attributes: windows.SE_GROUP_MANDATORY}},
		}, false},
		{"localsystem with deny-only service group", fakeServiceToken{
			user: localSystem,
			groups: []windows.SIDAndAttributes{{
				Sid: serviceSID, Attributes: enabled | windows.SE_GROUP_USE_FOR_DENY_ONLY,
			}},
		}, false},
		{"interactive user with service group", fakeServiceToken{
			user:   user,
			groups: []windows.SIDAndAttributes{{Sid: serviceSID, Attributes: enabled}},
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := windowsTokenRunsAsService(test.token, serviceSID)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("windowsTokenRunsAsService = %v, want %v", got, test.want)
			}
		})
	}
	if _, err := windowsTokenRunsAsService(fakeServiceToken{user: localSystem}, nil); err == nil {
		t.Fatal("nil service SID was accepted")
	}
}

func TestAdoptWindowsGatewayServiceDefaultOwner(t *testing.T) {
	serviceSID, err := windows.StringToSid("S-1-5-80-1858176940-1394861675-2895326486-505287571-2610476274")
	if err != nil {
		t.Fatal(err)
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	enabled := uint32(windows.SE_GROUP_ENABLED | windows.SE_GROUP_ENABLED_BY_DEFAULT | windows.SE_GROUP_MANDATORY)
	gatewayGroup := []windows.SIDAndAttributes{{Sid: serviceSID, Attributes: enabled}}
	resolve := func() (*windows.SID, error) { return serviceSID, nil }
	for _, test := range []struct {
		name    string
		token   fakeServiceToken
		applied bool
	}{
		{"localsystem gateway takes service SID owner", fakeServiceToken{user: localSystem, groups: gatewayGroup}, true},
		{"virtual account gateway is unchanged", fakeServiceToken{user: serviceSID}, false},
		{"localsystem without gateway SID is unchanged", fakeServiceToken{user: localSystem}, false},
		{"interactive user is unchanged", fakeServiceToken{user: user, groups: gatewayGroup}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var set *windows.SID
			applied, err := adoptWindowsGatewayServiceDefaultOwner(test.token, resolve, func(owner *windows.SID) error {
				set = owner
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if applied != test.applied || (set != nil) != test.applied {
				t.Fatalf("applied=%v set=%v, want applied=%v", applied, set, test.applied)
			}
			if test.applied && !set.Equals(serviceSID) {
				t.Fatalf("owner set to %v, want %v", set, serviceSID)
			}
		})
	}

	_, err = adoptWindowsGatewayServiceDefaultOwner(
		fakeServiceToken{user: localSystem, groups: gatewayGroup},
		resolve,
		func(*windows.SID) error { return windows.ERROR_INVALID_OWNER },
	)
	if err == nil || !strings.Contains(err.Error(), "set token owner to service SID") {
		t.Fatalf("setter failure error = %v", err)
	}

	// A pin that does not resolve must not stop a virtual-account gateway or
	// an interactive process: the token user is checked first.
	badPin := func() (*windows.SID, error) { return nil, errors.New("unresolvable pin") }
	for _, token := range []fakeServiceToken{{user: serviceSID}, {user: user, groups: gatewayGroup}} {
		applied, err := adoptWindowsGatewayServiceDefaultOwner(token, badPin, func(*windows.SID) error {
			t.Fatal("owner set for a non-LocalSystem token")
			return nil
		})
		if err != nil || applied {
			t.Fatalf("non-LocalSystem token with bad pin: applied=%v err=%v", applied, err)
		}
	}
	// For a LocalSystem process the resolution error is still reported.
	if _, err := adoptWindowsGatewayServiceDefaultOwner(
		fakeServiceToken{user: localSystem, groups: gatewayGroup},
		badPin,
		func(*windows.SID) error { return nil },
	); err == nil || !strings.Contains(err.Error(), "unresolvable pin") {
		t.Fatalf("LocalSystem bad pin error = %v", err)
	}
}
