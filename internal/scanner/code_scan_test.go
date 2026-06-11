// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanCodeIncludesCodeGuardAndClawShield(t *testing.T) {
	dir := t.TempDir()

	codeGuardFile := filepath.Join(dir, "exec.py")
	if err := os.WriteFile(codeGuardFile, []byte("os.system(cmd)\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	clawShieldFile := filepath.Join(dir, "payload.sh")
	payload := "#!/bin/sh\nexec 3<>/dev/" + "tcp/127.0.0.1/4444\n"
	if err := os.WriteFile(clawShieldFile, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := ScanCode(t.Context(), dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Scanner != "codeguard" {
		t.Fatalf("top-level scanner = %q, want codeguard", result.Scanner)
	}
	if !scanHasFinding(result, "CG-EXEC-001", "codeguard") {
		t.Fatalf("combined code scan did not include CodeGuard finding: %+v", result.Findings)
	}
	if !scanHasFinding(result, "CS-MAL-RS-DEVTCP", "clawshield-malware") {
		t.Fatalf("combined code scan did not include ClawShield malware finding: %+v", result.Findings)
	}
}

func TestScanCodeRejectsSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.py")
	if err := os.WriteFile(target, []byte("print('ok')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.py")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not available: %v", err)
	}

	_, err := ScanCode(t.Context(), link, "")
	if err == nil {
		t.Fatal("ScanCode accepted a symlink target")
	}
	if !strings.Contains(err.Error(), "refusing to scan symlink") {
		t.Fatalf("error = %v, want symlink refusal", err)
	}
}

func TestScanCodeSkipsDirectorySymlinks(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.sh")
	payload := "#!/bin/sh\nexec 3<>/dev/" + "tcp/127.0.0.1/4444\n"
	if err := os.WriteFile(outside, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.sh")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink not available: %v", err)
	}

	result, err := ScanCode(t.Context(), dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if scanHasFinding(result, "CS-MAL-RS-DEVTCP", "clawshield-malware") {
		t.Fatalf("ScanCode followed a symlinked file outside the scan root: %+v", result.Findings)
	}
}

func scanHasFinding(result *ScanResult, id, scannerName string) bool {
	if result == nil {
		return false
	}
	for i := range result.Findings {
		if result.Findings[i].ID == id && result.Findings[i].Scanner == scannerName {
			return true
		}
	}
	return false
}
