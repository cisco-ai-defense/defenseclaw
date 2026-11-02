//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func notAdminForTest(t *testing.T) {
	t.Helper()
	previous := darwinAdminMember
	darwinAdminMember = func(uint32) bool { return false }
	t.Cleanup(func() { darwinAdminMember = previous })
}

func writeTestFile(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), mode); err != nil {
		t.Fatal(err)
	}
	mustChmod(t, path, mode)
}

func TestValidateTrustedPolicyFilePathAcceptsPermissionDrift(t *testing.T) {
	t.Setenv(TrustStrictAncestorsEnv, "")
	notAdminForTest(t)
	events := captureResilienceEvents(t)
	path := filepath.Join(t.TempDir(), "targets.yaml")
	writeTestFile(t, path, 0o666)
	if err := ValidateTrustedFilePath(path, "manifest"); err == nil {
		t.Fatal("strict validation accepted a user-owned, world-writable file")
	}
	if err := ValidateTrustedPolicyFilePath(path, "manifest"); err != nil {
		t.Fatalf("policy validation refused permission drift: %v", err)
	}
	if markerCount(events(), MarkerBoundary) != 1 {
		t.Fatalf("events = %q, want one boundary line for the untrusted writer", events())
	}
	// A second pass in the same streak logs nothing new.
	_ = ValidateTrustedPolicyFilePath(path, "manifest")
	if markerCount(events(), MarkerBoundary) != 1 {
		t.Fatalf("events = %q, the boundary line repeated", events())
	}
}

func TestValidateTrustedPolicyFilePathStrictPinStaysFatal(t *testing.T) {
	t.Setenv(TrustStrictAncestorsEnv, "1")
	captureResilienceEvents(t)
	path := filepath.Join(t.TempDir(), "targets.yaml")
	writeTestFile(t, path, 0o666)
	if err := ValidateTrustedPolicyFilePath(path, "manifest"); err == nil {
		t.Fatal("strict pin accepted drift")
	}
}

func TestDarwinTolerantValidatorsKeepStructureFatal(t *testing.T) {
	t.Setenv(TrustStrictAncestorsEnv, "")
	captureResilienceEvents(t)
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	writeTestFile(t, victim, 0o644)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(dir, "hard")
	if err := os.Link(victim, hard); err != nil {
		t.Fatal(err)
	}
	for name, validate := range map[string]func(string, string) error{
		"policy":     ValidateTrustedPolicyFilePath,
		"executable": ValidateExecutableFilePath,
		"structure":  ValidateTrustedFileStructureTolerant,
	} {
		if err := validate(link, "object"); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("%s accepted a symlink: %v", name, err)
		}
		if err := validate(hard, "object"); err == nil || !strings.Contains(err.Error(), "hard links") {
			t.Fatalf("%s accepted a hard link: %v", name, err)
		}
		if err := validate(dir, "object"); err == nil {
			t.Fatalf("%s accepted a directory as a file", name)
		}
		if err := validate(filepath.Join(dir, "absent"), "object"); err == nil {
			t.Fatalf("%s accepted a missing file", name)
		}
	}
	if err := ValidateTrustedRuntimeDirTolerant(link, "runtime"); err == nil {
		t.Fatal("tolerant runtime dir accepted a symlink")
	}
}

func TestValidateExecutableFilePathIsAdvisory(t *testing.T) {
	t.Setenv(TrustStrictAncestorsEnv, "")
	notAdminForTest(t)
	events := captureResilienceEvents(t)
	path := filepath.Join(t.TempDir(), "libcmidapi.dylib")
	writeTestFile(t, path, 0o777)
	addDarwinACL(t, path, "everyone allow write")
	if err := ValidateExecutableFilePath(path, "cloud auth library"); err != nil {
		t.Fatalf("code integrity drift refused the library: %v", err)
	}
	if markerCount(events(), MarkerBoundary) != 1 {
		t.Fatalf("events = %q, want one boundary line", events())
	}
}

func TestAcceptServiceRuntimeFileDriftDarwin(t *testing.T) {
	captureResilienceEvents(t)
	dir := t.TempDir()
	tighter := filepath.Join(dir, "tighter.token")
	writeTestFile(t, tighter, 0o400)
	previous := darwinAdminMember
	darwinAdminMember = func(uint32) bool { return true }
	if err := AcceptServiceRuntimeFileDrift(tighter, "hook token", ""); err != nil {
		t.Fatalf("an administrator-owned, tighter token was refused: %v", err)
	}
	darwinAdminMember = func(uint32) bool { return false }
	t.Cleanup(func() { darwinAdminMember = previous })
	if err := AcceptServiceRuntimeFileDrift(tighter, "hook token", ""); err == nil {
		t.Fatal("a token owned by an untrusted user was accepted")
	}
	if err := AcceptServiceRuntimeFileDrift(filepath.Join(dir, "absent"), "hook token", ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing token error = %v", err)
	}
}

func TestValidateTrustedConfigPathRepairsPinnedConfig(t *testing.T) {
	t.Setenv(TrustStrictAncestorsEnv, "")
	enableTestSelfRepair(t)
	events := captureResilienceEvents(t)
	home := t.TempDir()
	config := filepath.Join(home, "etc", "config.yaml")
	writeTestFile(t, config, 0o640)
	mustChmod(t, filepath.Dir(config), 0o775)
	t.Setenv(DeploymentModeEnv, DeploymentModeManagedEnterprise)
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv(ConfigPathEnv, config)
	mustChmod(t, config, 0o664)
	addDarwinACL(t, config, "everyone allow write")

	if err := ValidateTrustedConfigPath(config); err != nil {
		t.Fatalf("drifted pinned config refused: %v", err)
	}
	if info, _ := os.Stat(config); info.Mode().Perm() != 0o640 {
		t.Fatalf("config mode = %04o, want 0640", info.Mode().Perm())
	}
	if info, _ := os.Stat(filepath.Dir(config)); info.Mode().Perm() != 0o755 {
		t.Fatalf("etc mode = %04o, want 0755", info.Mode().Perm())
	}
	if markerCount(events(), MarkerRepair) != 2 {
		t.Fatalf("events = %q, want two repair lines", events())
	}
}

func TestValidateTrustedConfigPathNeverRepairsUnpinnedPath(t *testing.T) {
	t.Setenv(TrustStrictAncestorsEnv, "")
	enableTestSelfRepair(t)
	captureResilienceEvents(t)
	home := t.TempDir()
	t.Setenv(DeploymentModeEnv, DeploymentModeManagedEnterprise)
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv(ConfigPathEnv, filepath.Join(home, "etc", "config.yaml"))
	other := filepath.Join(t.TempDir(), "config.yaml")
	writeTestFile(t, other, 0o664)
	_ = ValidateTrustedConfigPath(other)
	if info, _ := os.Stat(other); info.Mode().Perm() != 0o664 {
		t.Fatalf("an unpinned config was re-stamped to %04o", info.Mode().Perm())
	}
}

func TestValidateTrustedServiceRuntimeDirRepairsPinnedRuntime(t *testing.T) {
	t.Setenv(TrustStrictAncestorsEnv, "")
	enableTestSelfRepair(t)
	events := captureResilienceEvents(t)
	home := t.TempDir()
	runtimeDir := filepath.Join(home, "runtime")
	if err := os.Mkdir(runtimeDir, 0o777); err != nil {
		t.Fatal(err)
	}
	mustChmod(t, runtimeDir, 0o777)
	mustChflags(t, runtimeDir, "uchg")
	t.Cleanup(func() { _ = os.Chmod(runtimeDir, 0o755); mustChflags(t, runtimeDir, "nouchg") })
	t.Setenv(DeploymentModeEnv, DeploymentModeManagedEnterprise)
	t.Setenv("DEFENSECLAW_HOME", home)

	// The test user is not root, so the strict verdict still fails on the
	// owner; the repair must have run anyway.
	_ = ValidateTrustedServiceRuntimeDir(runtimeDir, "managed data_dir", "")
	info, _ := os.Stat(runtimeDir)
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("runtime mode = %04o, want 0750", info.Mode().Perm())
	}
	if markerCount(events(), MarkerRepair) != 1 {
		t.Fatalf("events = %q", events())
	}
}

func TestWriteServiceRuntimeFileReplacesDriftedFileDarwin(t *testing.T) {
	captureResilienceEvents(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	writeTestFile(t, path, 0o666)
	if err := validateExistingServiceRuntimeFile(path, "gateway dotenv", ""); err != nil {
		t.Fatalf("a drifted file about to be replaced was refused: %v", err)
	}
	if err := validateExistingServiceRuntimeFile(dir, "gateway dotenv", ""); err == nil {
		t.Fatal("a directory in place of the file was accepted")
	}
}

func TestAcceptTrustedFileDriftDarwin(t *testing.T) {
	t.Setenv(TrustStrictAncestorsEnv, "")
	captureResilienceEvents(t)
	path := filepath.Join(t.TempDir(), "protected_targets.json")
	writeTestFile(t, path, 0o640)
	addDarwinACL(t, path, "everyone allow read")
	previous := darwinAdminMember
	t.Cleanup(func() { darwinAdminMember = previous })

	darwinAdminMember = func(uint32) bool { return true }
	if err := AcceptTrustedFileDrift(path, "hook guardian authorization"); err != nil {
		t.Fatalf("administrator-owned record with a read ACL entry refused: %v", err)
	}
	darwinAdminMember = func(uint32) bool { return false }
	if err := AcceptTrustedFileDrift(path, "hook guardian authorization"); err == nil {
		t.Fatal("a record owned by an untrusted user was accepted")
	}
	link := filepath.Join(filepath.Dir(path), "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	darwinAdminMember = func(uint32) bool { return true }
	if err := AcceptTrustedFileDrift(link, "hook guardian authorization"); err == nil {
		t.Fatal("a symlinked record was accepted")
	}
}
