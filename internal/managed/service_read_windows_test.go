//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// A rule-pack folder only SYSTEM and Administrators can read passed Setup's
// LocalSystem preflight, and the gateway service then failed to start
// (WIN-R1-21).
func TestValidateServiceCanReadTreeNamesAnUnreadableRulePack(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "rules.yaml"), []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setDACL := func(sddl string) {
		t.Helper()
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{root, filepath.Join(root, "rules.yaml")} {
			if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	const account = `NT SERVICE\TrustedInstaller`
	setDACL("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	err := ValidateServiceCanReadTree(root, "guardrail.rule_pack_dir", account)
	if err == nil || !strings.Contains(err.Error(), "cannot read") || !strings.Contains(err.Error(), account) {
		t.Fatalf("admin-only rule pack: %v", err)
	}
	setDACL("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)")
	if err := ValidateServiceCanReadTree(root, "guardrail.rule_pack_dir", account); err != nil {
		t.Fatalf("rule pack readable by Users: %v", err)
	}
}
