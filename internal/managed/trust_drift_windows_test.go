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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func captureTrustDrift(t *testing.T) *[]string {
	t.Helper()
	reports := make([]string, 0, 4)
	previous := ReportTrustDrift
	ReportTrustDrift = func(path, label, reason string) {
		reports = append(reports, strings.Join([]string{path, label, reason}, " | "))
	}
	t.Cleanup(func() { ReportTrustDrift = previous })
	return &reports
}

func testDACL(t *testing.T, sddl string) *windows.ACL {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
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
	return dacl
}

// setTestFileDACL stamps an SDDL DACL on a file the test owns. The owner's
// implicit WRITE_DAC makes this work without elevation.
func setTestFileDACL(t *testing.T, path string, dacl *windows.ACL, protected bool) {
	t.Helper()
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if protected {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil); err != nil {
		t.Fatalf("SetNamedSecurityInfo(%s): %v", path, err)
	}
}

func TestWindowsDriftScopeDowngradesLeafPermissionVerdicts(t *testing.T) {
	leaf := windowsTrustLeaf.tolerant()

	t.Run("untrusted write ACE", func(t *testing.T) {
		reports := captureTrustDrift(t)
		advisories := captureTrustAdvisories(t)
		dacl := testDACL(t, "D:P(A;;GW;;;BU)(A;;GA;;;BA)")
		if err := rejectUntrustedWindowsWriteACEsWithWriter("leaf", "broker test", dacl, nil, leaf); err != nil {
			t.Fatalf("drift scope refused an untrusted write ACE: %v", err)
		}
		if len(*reports) != 1 || !strings.Contains((*reports)[0], "untrusted Windows principal") {
			t.Fatalf("drift reports = %v, want one untrusted-principal report", *reports)
		}
		if len(*advisories) != 0 {
			t.Fatalf("ancestor advisories = %v, want none for a drift scope", *advisories)
		}
	})

	t.Run("unsupported ACE type", func(t *testing.T) {
		reports := captureTrustDrift(t)
		dacl := testDACL(t, "D:P(A;;GA;;;BA)")
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, 0, &ace); err != nil {
			t.Fatalf("GetAce: %v", err)
		}
		ace.Header.AceType = 0x5 // allow object
		if err := rejectUntrustedWindowsWriteACEsWithWriter("leaf", "broker test", dacl, nil, leaf); err != nil {
			t.Fatalf("drift scope refused an unsupported ACE type: %v", err)
		}
		if len(*reports) != 1 || !strings.Contains((*reports)[0], "unsupported allow ACE type") {
			t.Fatalf("drift reports = %v, want one unsupported-ACE report", *reports)
		}
	})

	t.Run("owner and null DACL verdicts", func(t *testing.T) {
		reports := captureTrustDrift(t)
		for _, verdict := range []error{
			errors.New("leaf: owner S-1-5-21-1-2-3-1001 is not trusted for broker test"),
			errors.New("leaf: null Windows DACL is not trusted"),
		} {
			if err := leaf.relaxVerdict("leaf", "broker test", verdict); err != nil {
				t.Fatalf("drift scope refused %q: %v", verdict, err)
			}
		}
		if len(*reports) != 2 {
			t.Fatalf("drift reports = %v, want two", *reports)
		}
		if err := windowsTrustLeaf.relaxVerdict("leaf", "broker test", errors.New("verdict")); err == nil {
			t.Fatal("non-drift leaf scope downgraded a verdict")
		}
	})
}

func TestValidateTrustedFilePathTolerantAcceptsDriftedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "drifted.bin")
	if err := os.WriteFile(path, []byte("ok"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Run("users write", func(t *testing.T) {
		setTestFileDACL(t, path, testDACL(t, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FW;;;BU)"), true)
		reports := captureTrustDrift(t)
		if err := ValidateTrustedFilePathTolerant(path, "drift test"); err != nil {
			t.Fatalf("ValidateTrustedFilePathTolerant: %v", err)
		}
		if !reportsMention(*reports, path, "untrusted Windows principal") {
			t.Fatalf("drift reports = %v, want an untrusted-principal report for %s", *reports, path)
		}
		if err := ValidateTrustedFilePath(path, "drift test"); err == nil {
			t.Fatal("ValidateTrustedFilePath accepted the drifted file; the strict API must be unchanged")
		}
	})

	t.Run("null DACL", func(t *testing.T) {
		setTestFileDACL(t, path, nil, true)
		t.Cleanup(func() {
			setTestFileDACL(t, path, testDACL(t, "D:P(A;;FA;;;OW)"), true)
		})
		reports := captureTrustDrift(t)
		if err := ValidateTrustedFilePathTolerant(path, "drift test"); err != nil {
			t.Fatalf("ValidateTrustedFilePathTolerant: %v", err)
		}
		if !reportsMention(*reports, path, "null Windows DACL") {
			t.Fatalf("drift reports = %v, want a null-DACL report for %s", *reports, path)
		}
	})
}

func TestValidateTrustedFileStructureTolerantSkipsLeafPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.bin")
	if err := os.WriteFile(path, []byte("ok"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	setTestFileDACL(t, path, testDACL(t, "D:P(A;;FA;;;OW)(A;;FW;;;BU)"), true)
	reports := captureTrustDrift(t)
	if err := ValidateTrustedFileStructureTolerant(path, "structure test"); err != nil {
		t.Fatalf("ValidateTrustedFileStructureTolerant: %v", err)
	}
	for _, report := range *reports {
		if strings.HasPrefix(report, path+" |") {
			t.Fatalf("leaf permission drift was reported by the walk: %v", *reports)
		}
	}
	if err := ValidateTrustedFileStructureTolerant(filepath.Dir(path), "structure test"); err == nil ||
		!strings.Contains(err.Error(), "expected regular") {
		t.Fatalf("directory as key error = %v, want expected-regular refusal", err)
	}
}

func TestValidateTrustedTolerantKeepsStructuralFailuresFatal(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "regular")
	if err := os.WriteFile(regular, []byte("ok"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	reports := captureTrustDrift(t)

	if err := ValidateTrustedFilePathTolerant(root, "structural test"); err == nil ||
		!strings.Contains(err.Error(), "expected regular") {
		t.Fatalf("directory as file error = %v, want expected-regular refusal", err)
	}
	if err := ValidateTrustedRuntimeDirTolerant(regular, "structural test"); err == nil ||
		!strings.Contains(err.Error(), "expected directory") {
		t.Fatalf("file as directory error = %v, want expected-directory refusal", err)
	}
	if err := ValidateTrustedFilePathTolerant(filepath.Join(root, "missing"), "structural test"); err == nil {
		t.Fatal("missing file accepted")
	}

	junction := filepath.Join(root, "junction")
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Skipf("junction creation unavailable: %v: %s", err, output)
	}
	if err := ValidateTrustedRuntimeDirTolerant(junction, "structural test"); err == nil ||
		!strings.Contains(strings.ToLower(err.Error()), "reparse") {
		t.Fatalf("junction error = %v, want reparse refusal", err)
	}
	for _, report := range *reports {
		if strings.Contains(report, "reparse") || strings.Contains(report, "expected directory") ||
			strings.Contains(report, "expected regular") {
			t.Fatalf("structural failure was downgraded to a drift report: %v", *reports)
		}
	}
}

func TestWindowsDriftScopeHonoursStrictPin(t *testing.T) {
	t.Setenv(TrustStrictAncestorsEnv, "1")
	reports := captureTrustDrift(t)
	dacl := testDACL(t, "D:P(A;;GW;;;BU)(A;;GA;;;BA)")
	if err := rejectUntrustedWindowsWriteACEsWithWriter(
		"leaf", "broker test", dacl, nil, windowsTrustLeaf.tolerant(),
	); err == nil {
		t.Fatal("strict pin did not make the drift verdict fatal")
	}

	unsupported := testDACL(t, "D:P(A;;GA;;;BA)")
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(unsupported, 0, &ace); err != nil {
		t.Fatalf("GetAce: %v", err)
	}
	ace.Header.AceType = 0x5 // allow object
	if err := rejectUntrustedWindowsWriteACEsWithWriter(
		"leaf", "broker test", unsupported, nil, windowsTrustLeaf.tolerant(),
	); err == nil {
		t.Fatal("strict pin did not keep the unsupported ACE type fatal")
	}

	path := filepath.Join(t.TempDir(), "drifted.bin")
	if err := os.WriteFile(path, []byte("ok"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	setTestFileDACL(t, path, testDACL(t, "D:P(A;;FA;;;OW)(A;;FW;;;BU)"), true)
	if err := ValidateTrustedFilePathTolerant(path, "strict test"); err == nil {
		t.Fatal("strict pin did not make the tolerant walk fatal")
	}
	if len(*reports) != 0 {
		t.Fatalf("drift reports under strict pin = %v, want none", *reports)
	}
}

func reportsMention(reports []string, path, reason string) bool {
	for _, report := range reports {
		if strings.HasPrefix(report, path+" |") && strings.Contains(report, reason) {
			return true
		}
	}
	return false
}

// Executable code is advisory: an untrusted writer is accepted, and also
// logged as a critical boundary finding with the principal.
func TestExecutableLeafLogsBoundaryForUntrustedWriter(t *testing.T) {
	advisoryLogDedupe.reset()
	t.Cleanup(advisoryLogDedupe.reset)
	var events []string
	previous := ReportResilienceEvent
	ReportResilienceEvent = func(marker string, fields map[string]string) {
		events = append(events, FormatResilienceEvent(marker, fields))
	}
	t.Cleanup(func() { ReportResilienceEvent = previous })
	_ = captureTrustDrift(t)

	leaf := windowsTrustLeaf.tolerant()
	leaf.code = true
	dacl := testDACL(t, "D:P(A;;FA;;;SY)(A;;0x1301bf;;;BU)")
	if err := rejectUntrustedWindowsWriteACEsWithWriter(`C:\bin\broker.exe`, "CMID broker executable", dacl, nil, leaf); err != nil {
		t.Fatalf("code leaf refused an untrusted writer: %v", err)
	}
	if len(events) != 1 || !strings.HasPrefix(events[0], MarkerBoundary) || !strings.Contains(events[0], "S-1-5-32-545") {
		t.Fatalf("events = %v, want one boundary naming BUILTIN\\Users", events)
	}
}

func TestAcceptUnreadableDescriptorScopes(t *testing.T) {
	t.Setenv(TrustStrictAncestorsEnv, "")
	if !acceptUnreadableDescriptor(windowsTrustAncestor, windows.ERROR_ACCESS_DENIED) {
		t.Fatal("advisory ancestor access denied should be drift")
	}
	if !acceptUnreadableDescriptor(windowsTrustLeaf.tolerant(), windows.ERROR_ACCESS_DENIED) {
		t.Fatal("tolerant leaf access denied should be drift")
	}
	if acceptUnreadableDescriptor(windowsTrustLeaf, windows.ERROR_ACCESS_DENIED) {
		t.Fatal("strict leaf access denied must stay fatal")
	}
	if acceptUnreadableDescriptor(windowsTrustAncestor, windows.ERROR_FILE_NOT_FOUND) {
		t.Fatal("not found must stay fatal")
	}
	t.Setenv(TrustStrictAncestorsEnv, "1")
	if acceptUnreadableDescriptor(windowsTrustAncestor, windows.ERROR_ACCESS_DENIED) {
		t.Fatal("strict mode must keep access denied fatal")
	}
}
