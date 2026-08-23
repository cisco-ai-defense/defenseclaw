// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"golang.org/x/sys/windows"
)

func TestWriteManagedTargetRuntimeFilePublishesExactCanonicalFile(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	path := filepath.Join(dir, "runtime.bundle")
	data := []byte("authenticated managed runtime\n")
	if err := WriteManagedTargetRuntimeFile(path, data); err != nil {
		t.Fatalf("publish managed target runtime file: %v", err)
	}
	target := windowsProcessUserSIDForTest(t)
	file := openManagedTargetRuntimeFileForTest(t, path)
	if err := validateWindowsManagedTargetRuntimeHandle(file, target, data); err != nil {
		_ = file.Close()
		t.Fatalf("validate canonical managed target runtime file: %v", err)
	}
	beforeIdentity, err := atomicTransformOpenFileIdentity(file)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if atomicFileAlreadyMatches(path, data, 0o600) {
		t.Fatal("generic two-ACE private-file comparator accepted the four-ACE managed contract")
	}

	wantModTime := time.Unix(1_710_000_000, 0)
	if err := os.Chtimes(path, wantModTime, wantModTime); err != nil {
		t.Fatal(err)
	}
	if err := WriteManagedTargetRuntimeFile(path, data); err != nil {
		t.Fatalf("repeat identical managed target runtime write: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	file = openManagedTargetRuntimeFileForTest(t, path)
	afterIdentity, identityErr := atomicTransformOpenFileIdentity(file)
	closeErr := file.Close()
	if identityErr != nil || closeErr != nil {
		t.Fatalf("read repeated-write identity: identity=%v close=%v", identityErr, closeErr)
	}
	if afterIdentity != beforeIdentity {
		t.Fatal("identical canonical managed target runtime file was replaced")
	}
	if !after.ModTime().Equal(wantModTime) {
		t.Fatalf("identical managed write changed mtime to %s, want %s", after.ModTime(), wantModTime)
	}
}

func TestWriteManagedTargetRuntimeFileReplacesGenericPrivateInode(t *testing.T) {
	path := filepath.Join(testenv.PrivateTempDir(t), "runtime.bundle")
	data := []byte("same bytes\n")
	if err := atomicWriteFile(path, data, 0o600); err != nil {
		t.Fatalf("seed generic private file: %v", err)
	}
	if !atomicFileAlreadyMatches(path, data, 0o600) {
		t.Fatal("generic private seed did not satisfy its own comparator")
	}
	before := openManagedTargetRuntimeFileForTest(t, path)
	beforeIdentity, err := atomicTransformOpenFileIdentity(before)
	if err != nil {
		_ = before.Close()
		t.Fatal(err)
	}
	if err := before.Close(); err != nil {
		t.Fatal(err)
	}

	if err := WriteManagedTargetRuntimeFile(path, data); err != nil {
		t.Fatalf("replace generic private file with managed contract: %v", err)
	}
	after := openManagedTargetRuntimeFileForTest(t, path)
	defer after.Close()
	afterIdentity, err := atomicTransformOpenFileIdentity(after)
	if err != nil {
		t.Fatal(err)
	}
	if afterIdentity == beforeIdentity {
		t.Fatal("generic private inode was incorrectly accepted as a managed no-op")
	}
	if err := validateWindowsManagedTargetRuntimeHandle(
		after,
		windowsProcessUserSIDForTest(t),
		data,
	); err != nil {
		t.Fatalf("validate replacement managed inode: %v", err)
	}
}

func TestWriteManagedTargetRuntimeFileReplacesHardLinkedMatch(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	path := filepath.Join(dir, "runtime.bundle")
	alias := filepath.Join(dir, "runtime.alias")
	data := []byte("managed\n")
	if err := WriteManagedTargetRuntimeFile(path, data); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, alias); err != nil {
		if errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
			errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
			t.Skipf("test volume does not support hard links: %v", err)
		}
		t.Fatal(err)
	}
	aliasFile := openManagedTargetRuntimeFileForTest(t, alias)
	aliasIdentity, err := atomicTransformOpenFileIdentity(aliasFile)
	if err != nil {
		_ = aliasFile.Close()
		t.Fatal(err)
	}
	if err := aliasFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := WriteManagedTargetRuntimeFile(path, data); err != nil {
		t.Fatalf("replace hard-linked managed match: %v", err)
	}
	final := openManagedTargetRuntimeFileForTest(t, path)
	defer final.Close()
	finalIdentity, err := atomicTransformOpenFileIdentity(final)
	if err != nil {
		t.Fatal(err)
	}
	if finalIdentity == aliasIdentity {
		t.Fatal("hard-linked managed match was incorrectly accepted as a no-op")
	}
	if err := validateWindowsManagedTargetRuntimeHandle(
		final,
		windowsProcessUserSIDForTest(t),
		data,
	); err != nil {
		t.Fatalf("validate single-link replacement: %v", err)
	}
}

func TestWriteManagedTargetRuntimeFileReplacesSymlinkWithoutFollowing(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	path := filepath.Join(dir, "runtime.bundle")
	victim := filepath.Join(dir, "operator.file")
	if err := os.WriteFile(victim, []byte("operator bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path); err != nil {
		if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) ||
			errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
			errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
			t.Skipf("test identity cannot create Windows symlinks: %v", err)
		}
		t.Fatal(err)
	}
	data := []byte("managed bytes")
	if err := WriteManagedTargetRuntimeFile(path, data); err != nil {
		t.Fatalf("replace managed target runtime symlink: %v", err)
	}
	operatorBytes, err := os.ReadFile(victim)
	if err != nil || string(operatorBytes) != "operator bytes" {
		t.Fatalf("symlink target bytes = %q, error = %v", operatorBytes, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("managed target runtime path remained a symlink")
	}
	file := openManagedTargetRuntimeFileForTest(t, path)
	defer file.Close()
	if err := validateWindowsManagedTargetRuntimeHandle(
		file,
		windowsProcessUserSIDForTest(t),
		data,
	); err != nil {
		t.Fatalf("validate no-follow replacement: %v", err)
	}
}

func TestPublishManagedTargetRuntimeFileNoReplacePreservesCollision(t *testing.T) {
	path := filepath.Join(testenv.PrivateTempDir(t), "immutable.bundle")
	if err := PublishManagedTargetRuntimeFileNoReplace(path, []byte("generation A")); err != nil {
		t.Fatalf("publish first immutable generation: %v", err)
	}
	before := openManagedTargetRuntimeFileForTest(t, path)
	beforeIdentity, err := atomicTransformOpenFileIdentity(before)
	if err != nil {
		_ = before.Close()
		t.Fatal(err)
	}
	if err := before.Close(); err != nil {
		t.Fatal(err)
	}
	err = PublishManagedTargetRuntimeFileNoReplace(path, []byte("generation B"))
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("immutable collision error = %v, want os.ErrExist", err)
	}
	after := openManagedTargetRuntimeFileForTest(t, path)
	defer after.Close()
	afterIdentity, err := atomicTransformOpenFileIdentity(after)
	if err != nil {
		t.Fatal(err)
	}
	if afterIdentity != beforeIdentity {
		t.Fatal("no-replace collision changed the published inode")
	}
	if err := validateWindowsManagedTargetRuntimeHandle(
		after,
		windowsProcessUserSIDForTest(t),
		[]byte("generation A"),
	); err != nil {
		t.Fatalf("validate preserved immutable generation: %v", err)
	}
}

func TestManagedTargetRuntimeDescriptorBindsExplicitTargetSID(t *testing.T) {
	target, err := windows.StringToSid("S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windowsManagedTargetRuntimeSecurityDescriptor(target)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if owner == nil || !owner.Equals(target) {
		t.Fatalf("managed target descriptor owner = %v, want %s", owner, target)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil || dacl.AceCount != 4 {
		t.Fatalf("managed target descriptor DACL = %v, want exactly four ACEs", dacl)
	}
}

func TestWriteManagedTargetRuntimeFileWinsDestinationRace(t *testing.T) {
	path := filepath.Join(testenv.PrivateTempDir(t), "runtime.bundle")
	managedTargetRuntimeBeforePublish = func(destination string) error {
		return os.WriteFile(destination, []byte("raced"), 0o600)
	}
	t.Cleanup(func() { managedTargetRuntimeBeforePublish = nil })
	data := []byte("authenticated generation")
	if err := WriteManagedTargetRuntimeFile(path, data); err != nil {
		t.Fatalf("publish after destination race: %v", err)
	}
	file := openManagedTargetRuntimeFileForTest(t, path)
	defer file.Close()
	if err := validateWindowsManagedTargetRuntimeHandle(
		file,
		windowsProcessUserSIDForTest(t),
		data,
	); err != nil {
		t.Fatalf("validate race-winning managed target file: %v", err)
	}
}

func openManagedTargetRuntimeFileForTest(t *testing.T, path string) *os.File {
	t.Helper()
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.GENERIC_READ|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		t.Fatalf("open managed target runtime fixture %s: %v", path, err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		t.Fatal(fmt.Errorf("wrap managed target runtime fixture handle"))
	}
	return file
}
