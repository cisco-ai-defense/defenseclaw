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
	parent := t.TempDir()
	previousParents := serviceReadParents
	t.Cleanup(func() { serviceReadParents = previousParents })
	serviceReadParents = func(string) []string { return []string{parent} }
	if got := previousParents(`C:\a\b`); len(got) != 2 || got[0] != `C:\a` || got[1] != `C:\` {
		t.Fatalf("parents of C:\\a\\b = %q", got)
	}
	root := filepath.Join(parent, "pack")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "rules.yaml"), []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setDACL := func(sddl string, paths ...string) {
		t.Helper()
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	const account = `NT SERVICE\TrustedInstaller`
	tree := []string{root, filepath.Join(root, "rules.yaml")}
	const readableParent = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
	setDACL(readableParent, parent)
	setDACL("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", tree...)
	err := ValidateServiceCanReadTree(root, "guardrail.rule_pack_dir", account)
	// The example icacls command is copyable as is: single backslashes
	// (GAP-1477), not Go-quoted ones.
	if err == nil || !strings.Contains(err.Error(), "cannot read") || !strings.Contains(err.Error(), account) ||
		!strings.Contains(err.Error(), `icacls "`+root+`" /grant`) {
		t.Fatalf("admin-only rule pack: %v", err)
	}
	setDACL("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)", tree...)
	if err := ValidateServiceCanReadTree(root, "guardrail.rule_pack_dir", account); err != nil {
		t.Fatalf("rule pack readable by Users: %v", err)
	}
	// A locked staging folder above a readable pack: traverse and read
	// control (RC,X) are not enough, the gateway lists the parent too.
	setDACL("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x20020;;;BU)", parent)
	err = ValidateServiceCanReadTree(root, "guardrail.rule_pack_dir", account)
	if err == nil || !strings.Contains(err.Error(), "parent folder "+parent) ||
		!strings.Contains(err.Error(), `icacls "`+parent+`" /grant`) {
		t.Fatalf("pack under a locked parent: %v", err)
	}
	setDACL(readableParent, parent)
	if err := ValidateServiceCanReadTree(root, "guardrail.rule_pack_dir", account); err != nil {
		t.Fatalf("parent readable by Users: %v", err)
	}
}
