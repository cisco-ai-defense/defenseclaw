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
	// GAP-1118: a jsonl destination needs the service to create files in
	// its folder; Read & execute is not enough.
	sink := filepath.Join(root, "sink.jsonl")
	if err := ValidateServiceCanWriteFile(sink, account); err == nil || !strings.Contains(err.Error(), "cannot create files in "+root) {
		t.Fatalf("folder the service can only read: %v", err)
	}
	setDACL("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301ff;;;BU)", root)
	if err := ValidateServiceCanWriteFile(sink, account); err != nil {
		t.Fatalf("folder the service may modify: %v", err)
	}
}

// A service may append and create files but still be unable to rotate or
// prune them when its folder lacks FILE_DELETE_CHILD (GAP-1123).
func TestValidateServiceCanWriteFileRequiresRotationPermission(t *testing.T) {
	folder := t.TempDir()
	path := filepath.Join(folder, "audit.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setDACL := func(path, sddl string) {
		t.Helper()
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	const account = `NT SERVICE\TrustedInstaller`
	// Folder: list, create, read attributes/control. File: append and read
	// attributes/control. Neither grants deletion.
	setDACL(folder, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x20083;;;BU)")
	setDACL(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x20084;;;BU)")
	if err := ValidateServiceCanWriteFile(path, account); err == nil {
		t.Fatal("accepted a JSONL destination that cannot rotate")
	}
	setDACL(folder, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x200c3;;;BU)")
	if err := ValidateServiceCanWriteFile(path, account); err != nil {
		t.Fatalf("folder permits rotation and pruning: %v", err)
	}
}

// A missing destination folder still needs the service to create it in the
// nearest existing parent.
func TestValidateServiceCanWriteFileChecksMissingFolderParent(t *testing.T) {
	parent := t.TempDir()
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	const account = `NT SERVICE\TrustedInstaller`
	sink := filepath.Join(parent, "new", "nested", "audit.jsonl")
	if err := ValidateServiceCanWriteFile(sink, account); err == nil || !strings.Contains(err.Error(), "cannot create a folder in "+parent) {
		t.Fatalf("missing JSONL folder under admin-only parent: %v", err)
	}
	descriptor, err = windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;OICI;0x1301ff;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err = descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateServiceCanWriteFile(sink, account); err != nil {
		t.Fatalf("service may create the missing folder: %v", err)
	}
}
