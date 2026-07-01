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

	err := validateTrustedPathElement(path, false, "managed config")
	if err == nil || !strings.Contains(err.Error(), "write-capable macOS ACL") {
		t.Fatalf("validateTrustedPathElement error = %v, want ACL refusal", err)
	}
}

func TestValidateTrustedRuntimeDirElementRejectsWriteCapableDarwinACL(t *testing.T) {
	path := t.TempDir()
	addDarwinACL(t, path, "everyone allow add_file,add_subdirectory,delete_child,writeattr,writeextattr,writesecurity,chown")

	err := validateTrustedRuntimeDirElement(path, "managed data_dir")
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

func addDarwinACL(t *testing.T, path, entry string) {
	t.Helper()
	cmd := exec.Command("/bin/chmod", "+a", entry, path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("add macOS ACL: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
}
