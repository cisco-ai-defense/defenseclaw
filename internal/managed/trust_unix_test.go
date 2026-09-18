//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateTrustedRuntimeDirRejectsStandardUserOwnedPath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root-owned temp dirs are valid managed runtime dirs")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod temp dir: %v", err)
	}

	err := ValidateTrustedRuntimeDir(dir, "managed data_dir")
	if err == nil || !strings.Contains(err.Error(), "owner uid") {
		t.Fatalf("ValidateTrustedRuntimeDir error = %v, want untrusted owner refusal", err)
	}
}

func TestValidateTrustedRuntimeDirRejectsSymlink(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "runtime")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink runtime dir: %v", err)
	}

	err := ValidateTrustedRuntimeDir(link, "managed data_dir")
	if err == nil || !strings.Contains(err.Error(), "symlinks are not allowed") {
		t.Fatalf("ValidateTrustedRuntimeDir error = %v, want symlink refusal", err)
	}
}

func TestValidateTrustedRuntimeDirRejectsWritableDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod temp dir: %v", err)
	}

	err := ValidateTrustedRuntimeDir(dir, "managed data_dir")
	if err == nil || !strings.Contains(err.Error(), "group/other writable") {
		t.Fatalf("ValidateTrustedRuntimeDir error = %v, want writable-dir refusal", err)
	}
}

// AIFW-34262: the directories above the managed roots are maintained by the
// platform installer, so their owner/mode verdicts warn instead of failing.
func TestValidateTrustedElementsRelaxAncestorVerdicts(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod temp dir: %v", err)
	}

	t.Run("runtime dir ancestor", func(t *testing.T) {
		captured := captureTrustAdvisories(t)
		if err := validateTrustedRuntimeDirElement(dir, "managed data_dir", true); err != nil {
			t.Fatalf("ancestor runtime dir was fatal: %v", err)
		}
		if len(*captured) == 0 {
			t.Fatal("relaxed ancestor runtime dir did not warn")
		}
		if err := validateTrustedRuntimeDirElement(dir, "managed data_dir", false); err == nil {
			t.Fatal("named runtime dir accepted a world-writable directory")
		}
	})

	t.Run("config path ancestor", func(t *testing.T) {
		captured := captureTrustAdvisories(t)
		if err := validateTrustedPathElement(dir, true, "managed config", true); err != nil {
			t.Fatalf("ancestor config directory was fatal: %v", err)
		}
		if len(*captured) == 0 {
			t.Fatal("relaxed ancestor config directory did not warn")
		}
		if err := validateTrustedPathElement(dir, true, "managed config", false); err == nil {
			t.Fatal("named config directory accepted a world-writable directory")
		}
	})

	t.Run("strict pin restores refusal", func(t *testing.T) {
		t.Setenv(TrustStrictAncestorsEnv, "1")
		if err := validateTrustedRuntimeDirElement(dir, "managed data_dir", true); err == nil {
			t.Fatal("strict pin accepted a world-writable ancestor")
		}
		if err := validateTrustedPathElement(dir, true, "managed config", true); err == nil {
			t.Fatal("strict pin accepted a world-writable ancestor")
		}
	})
}

// The advisory downgrade is scoped to PlatformInstallerOwnedRoots, so a
// world-writable ancestor that nobody else has a claim on stays fatal even
// though it sits above the artifact rather than being the artifact. A temp
// directory is the canonical example: if it is world-writable, the leaf below it
// can be swapped, and no platform installer maintains those permissions.
func TestValidateTrustedFilePathRejectsForeignWritableAncestor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("a root-owned leaf under an untrusted ancestor requires root")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatalf("chmod parent: %v", err)
	}
	path := filepath.Join(parent, "authorization.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write authorization: %v", err)
	}
	if PlatformInstallerOwnedPath(parent) {
		t.Skipf("temp parent %s is inside a platform installer root", parent)
	}

	captured := captureTrustAdvisories(t)
	err := ValidateTrustedFilePath(path, "managed authorization")
	if err == nil || !strings.Contains(err.Error(), "group/other writable") {
		t.Fatalf("ValidateTrustedFilePath error = %v, want the ancestor verdict to stay fatal", err)
	}
	if len(*captured) != 0 {
		t.Fatalf("advisories = %v, want none for an ancestor outside the installer roots", *captured)
	}
}

// The same walk keeps the AIFW-34262 relaxation for an ancestor that IS inside a
// platform installer root, which is where AVC re-ACLs on its own schedule.
func TestValidateTrustedFilePathAllowsInstallerOwnedWritableAncestor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("writing under a platform installer root requires root")
	}
	roots := PlatformInstallerOwnedRoots()
	if len(roots) == 0 {
		t.Skip("no platform installer roots on this GOOS")
	}
	parent := filepath.Join(roots[0], "trust-advisory-test-"+t.Name())
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Skipf("cannot stage %s: %v", parent, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatalf("chmod parent: %v", err)
	}
	path := filepath.Join(parent, "authorization.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write authorization: %v", err)
	}

	captured := captureTrustAdvisories(t)
	if err := ValidateTrustedFilePath(path, "managed authorization"); err != nil {
		t.Fatalf("ValidateTrustedFilePath error = %v, want the ancestor verdict to be advisory", err)
	}
	found := false
	for _, advisory := range *captured {
		if strings.Contains(advisory, parent) && strings.Contains(advisory, "group/other writable") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("advisories = %v, want a warning for %s", *captured, parent)
	}

	t.Setenv(TrustStrictAncestorsEnv, "1")
	if err := ValidateTrustedFilePath(path, "managed authorization"); err == nil {
		t.Fatal("strict pin accepted a world-writable ancestor")
	}
}

func TestValidateTrustedFilePathRejectsEmptyPath(t *testing.T) {
	err := ValidateTrustedFilePath("", "managed authorization")
	if err == nil || !strings.Contains(err.Error(), "path is empty") {
		t.Fatalf("ValidateTrustedFilePath error = %v, want empty-path refusal", err)
	}
}

func TestValidateTrustedFilePathRejectsSymlinkLeaf(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "authorization.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "authorization-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink authorization: %v", err)
	}

	err := ValidateTrustedFilePath(link, "managed authorization")
	if err == nil || !strings.Contains(err.Error(), "symlinks are not allowed") {
		t.Fatalf("ValidateTrustedFilePath error = %v, want symlink refusal", err)
	}
}

func TestValidateTrustedFilePathRejectsWritableLeaf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorization.json")
	if err := os.WriteFile(path, []byte("{}"), 0o666); err != nil {
		t.Fatalf("write authorization: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatalf("chmod authorization: %v", err)
	}

	err := ValidateTrustedFilePath(path, "managed authorization")
	if err == nil || !strings.Contains(err.Error(), "group/other writable") {
		t.Fatalf("ValidateTrustedFilePath error = %v, want writable-file refusal", err)
	}
}

func TestValidateTrustedFilePathRejectsStandardUserOwnedLeaf(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root-owned temp files are valid managed files")
	}
	path := filepath.Join(t.TempDir(), "authorization.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write authorization: %v", err)
	}

	err := ValidateTrustedFilePath(path, "managed authorization")
	if err == nil || !strings.Contains(err.Error(), "owner uid") {
		t.Fatalf("ValidateTrustedFilePath error = %v, want untrusted owner refusal", err)
	}
}
