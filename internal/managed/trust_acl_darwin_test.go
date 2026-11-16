//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateTrustedPathElementRejectsWriteCapableDarwinACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("guardrail:\n  mode: action\n"), 0o600); err != nil {
		t.Fatalf("write ACL fixture: %v", err)
	}
	addDarwinACL(t, path, "everyone allow write,append,writeattr,writeextattr,writesecurity,chown")

	err := validateTrustedPathElement(path, false, "managed config", false)
	if err == nil || !strings.Contains(err.Error(), "write-capable macOS ACL") {
		t.Fatalf("validateTrustedPathElement error = %v, want ACL refusal", err)
	}
}

func TestValidateTrustedRuntimeDirElementRejectsWriteCapableDarwinACL(t *testing.T) {
	path := t.TempDir()
	addDarwinACL(t, path, "everyone allow add_file,add_subdirectory,delete_child,writeattr,writeextattr,writesecurity,chown")

	err := validateTrustedRuntimeDirElement(path, "managed data_dir", false)
	if err == nil || !strings.Contains(err.Error(), "write-capable macOS ACL") {
		t.Fatalf("validateTrustedRuntimeDirElement error = %v, want ACL refusal", err)
	}
}

func TestValidateTrustedPathACLAcceptsPathWithoutExtendedACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatalf("write ACL fixture: %v", err)
	}
	if err := validateTrustedPathACL(path); err != nil {
		t.Fatalf("ACL-free path rejected: %v", err)
	}
}

func countDarwinACLReads(t *testing.T) *int {
	t.Helper()
	reads := 0
	saved := darwinACLInspect
	darwinACLVerdicts = aclVerdictCache{}
	darwinACLInspect = func(path string) error {
		reads++
		return saved(path)
	}
	t.Cleanup(func() {
		darwinACLInspect = saved
		darwinACLVerdicts = aclVerdictCache{}
	})
	return &reads
}

// A managed hook call checks every element of the identity spool path; a
// burst of parallel calls started one ls process per element per call
// (GAP-1822). An unchanged clean path is read once.
func TestDarwinACLOfAnUnchangedCleanPathIsReadOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatalf("write ACL fixture: %v", err)
	}
	reads := countDarwinACLReads(t)
	for i := 0; i < 5; i++ {
		if err := validateTrustedPathACL(path); err != nil {
			t.Fatalf("check %d: %v", i, err)
		}
	}
	if *reads != 1 {
		t.Fatalf("ACL read %d times for an unchanged clean path, want 1", *reads)
	}
}

func TestDarwinACLAddedAfterACleanReadIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatalf("write ACL fixture: %v", err)
	}
	countDarwinACLReads(t)
	if err := validateTrustedPathACL(path); err != nil {
		t.Fatalf("clean path rejected: %v", err)
	}
	addDarwinACL(t, path, "everyone allow write,append")
	if err := validateTrustedPathACL(path); err == nil || !strings.Contains(err.Error(), "write-capable macOS ACL") {
		t.Fatalf("ACL added after a clean read: error = %v, want ACL refusal", err)
	}
}

func TestDarwinACLOfAReplacedPathIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatalf("write ACL fixture: %v", err)
	}
	countDarwinACLReads(t)
	if err := validateTrustedPathACL(path); err != nil {
		t.Fatalf("clean path rejected: %v", err)
	}
	next := filepath.Join(dir, "next.yaml")
	if err := os.WriteFile(next, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	addDarwinACL(t, next, "everyone allow write,append")
	if err := os.Rename(next, path); err != nil {
		t.Fatalf("replace path: %v", err)
	}
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
	if err := validateTrustedPathACL(path); err == nil || !strings.Contains(err.Error(), "write-capable macOS ACL") {
		t.Fatalf("replaced path: error = %v, want ACL refusal", err)
	}
}

func addDarwinACL(t *testing.T, path, entry string) {
	t.Helper()
	cmd := exec.Command("/bin/chmod", "+a", entry, path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("add macOS ACL: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
}
