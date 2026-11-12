// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const createCanonicalTestAccount = `NT SERVICE\DefenseClawGateway`

// requireCanonicalCreation fails the test unless err is nil. A non-elevated
// test token cannot assign the Administrators owner, which the creator
// reports (and cleans up) instead of leaving owner drift; that case skips.
func requireCanonicalCreation(t *testing.T, path string, err error) {
	t.Helper()
	if errors.Is(err, ErrCanonicalOwnerUnavailable) {
		if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
			t.Fatalf("a refused owner must not leave the object behind: %v", statErr)
		}
		t.Skipf("the test token cannot own the object as Administrators: %v", err)
	}
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
}

// parentWithInheritedEveryoneEntry makes a folder whose children inherit an
// extra Everyone entry, the shape of a ProgramData parent with additional
// inherited ACEs (the EC2 hosts of GAP-0762).
func parentWithInheritedEveryoneEntry(t *testing.T) string {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString("D:(A;OICI;FA;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	parent := filepath.Join(t.TempDir(), "parent")
	pointer, err := windows.UTF16PtrFromString(parent)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.CreateDirectory(pointer, attributes); err != nil {
		t.Fatal(err)
	}
	return parent
}

// GAP-0762: a directory the product creates must already carry the canonical
// descriptor, so the Guardian has no repair to log on its first pass, even
// below a parent with an extra inherited entry.
func TestCreateCanonicalDirectoryIsCanonicalFromCreation(t *testing.T) {
	opts := CanonicalOptions{GatewayServiceAccount: createCanonicalTestAccount, Quiet: true}
	for name, parent := range map[string]string{
		"plain parent":                      t.TempDir(),
		"parent with extra inherited entry": parentWithInheritedEveryoneEntry(t),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(parent, "hooks")
			requireCanonicalCreation(t, path, CreateCanonicalDirectory(path, ObjectRuntimeDirectory, opts))
			result, err := AssessCanonical(path, ObjectRuntimeDirectory, opts)
			if err != nil {
				t.Fatalf("AssessCanonical: %v", err)
			}
			if result.Outcome != CanonicalOK {
				t.Fatalf("a created directory must be canonical at once, got %s: %v", result.Outcome, result.Drift)
			}
		})
	}
}

// The base behaviour this replaces: a plain mkdir inherits its parent
// entries unprotected, which the canonical check calls drift.
func TestPlainMkdirIsDriftTheGuardianWouldRepair(t *testing.T) {
	opts := CanonicalOptions{GatewayServiceAccount: createCanonicalTestAccount, Quiet: true}
	path := filepath.Join(parentWithInheritedEveryoneEntry(t), "hooks")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := AssessCanonical(path, ObjectRuntimeDirectory, opts)
	if err != nil {
		t.Fatalf("AssessCanonical: %v", err)
	}
	if result.Outcome == CanonicalOK || !strings.Contains(strings.Join(result.Drift, "; "), "inherits") {
		t.Fatalf("a plain directory should read as inheriting drift, got %s: %v", result.Outcome, result.Drift)
	}
}

func TestCreateCanonicalDirectoryRefusals(t *testing.T) {
	opts := CanonicalOptions{GatewayServiceAccount: createCanonicalTestAccount, Quiet: true}
	dir := t.TempDir()
	existing := filepath.Join(dir, "hooks")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CreateCanonicalDirectory(existing, ObjectRuntimeDirectory, opts); !errors.Is(err, os.ErrExist) {
		t.Fatalf("an existing path must fail like os.Mkdir, got %v", err)
	}
	if err := CreateCanonicalDirectory(filepath.Join(dir, "file"), ObjectRuntimeFile, opts); err == nil {
		t.Fatal("a file kind must be refused")
	}
	t.Setenv(WindowsServiceAccountEnv, "")
	unpinned := filepath.Join(dir, "unpinned")
	err := CreateCanonicalDirectory(unpinned, ObjectRuntimeDirectory, CanonicalOptions{Quiet: true})
	if !errors.Is(err, ErrCanonicalIdentityUnavailable) {
		t.Fatalf("an unresolved gateway identity must be reported, got %v", err)
	}
	if _, statErr := os.Lstat(unpinned); !os.IsNotExist(statErr) {
		t.Fatalf("nothing may be created without the gateway identity: %v", statErr)
	}
}

// GAP-0766: a lock file created lazily is canonical from creation, for each
// kind the product gives its lock files.
func TestCreateCanonicalFileIsCanonicalFromCreation(t *testing.T) {
	opts := CanonicalOptions{GatewayServiceAccount: createCanonicalTestAccount, Quiet: true}
	parent := parentWithInheritedEveryoneEntry(t)
	for _, kind := range []ObjectKind{ObjectConfigFile, ObjectRuntimeFile} {
		t.Run(string(kind), func(t *testing.T) {
			path := filepath.Join(parent, string(kind)+".lock")
			requireCanonicalCreation(t, path, CreateCanonicalFile(path, kind, opts))
			result, err := AssessCanonical(path, kind, opts)
			if err != nil {
				t.Fatalf("AssessCanonical: %v", err)
			}
			if result.Outcome != CanonicalOK {
				t.Fatalf("a created lock file must be canonical at once, got %s: %v", result.Outcome, result.Drift)
			}
			if err := CreateCanonicalFile(path, kind, opts); !errors.Is(err, os.ErrExist) {
				t.Fatalf("an existing lock file must fail like os.OpenFile with O_EXCL, got %v", err)
			}
		})
	}
	if err := CreateCanonicalFile(filepath.Join(parent, "dir"), ObjectRuntimeDirectory, opts); err == nil {
		t.Fatal("a directory kind must be refused")
	}
}

// GAP-0766: the ordinary lock-file creation path of a process pinned to the
// standalone profile; every other process keeps its ordinary file.
func TestEnsureCanonicalLockFileScope(t *testing.T) {
	home := t.TempDir()
	pin := func(profile string) {
		t.Setenv(DeploymentModeEnv, DeploymentModeManagedEnterprise)
		t.Setenv(EnterpriseProfileEnv, profile)
		t.Setenv(WindowsServiceAccountEnv, createCanonicalTestAccount)
		t.Setenv(managedHomeEnv, home)
		t.Setenv(managedConfigEnv, filepath.Join(home, "etc", "config.yaml"))
	}
	pin(ProfileStandalone)
	lock := filepath.Join(home, ".enterprise-enrollment.lock")
	requireCanonicalCreation(t, lock, EnsureCanonicalLockFile(lock, ObjectRuntimeFile))
	result, err := AssessCanonical(lock, ObjectRuntimeFile, CanonicalOptions{GatewayServiceAccount: createCanonicalTestAccount, Quiet: true})
	if err != nil || result.Outcome != CanonicalOK {
		t.Fatalf("the lock must be canonical, got %s %v: %v", result.Outcome, err, result.Drift)
	}
	if err := EnsureCanonicalLockFile(lock, ObjectRuntimeFile); err != nil {
		t.Fatalf("an existing lock is left alone: %v", err)
	}

	pin(ProfileSecureClient)
	secureClient := filepath.Join(home, "secure-client.lock")
	if err := EnsureCanonicalLockFile(secureClient, ObjectRuntimeFile); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(secureClient); !os.IsNotExist(err) {
		t.Fatalf("the Secure Client profile creates its lock files as before: %v", err)
	}
	pin(ProfileStandalone)
	outside := filepath.Join(t.TempDir(), "other.lock")
	if err := EnsureCanonicalLockFile(outside, ObjectConfigFile); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(outside); !os.IsNotExist(err) {
		t.Fatalf("a lock outside the managed tree is not ours to create: %v", err)
	}
}
