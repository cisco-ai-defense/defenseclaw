//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestJudgeBodyWindowsRejectsUntrustedWriteACL(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "protected")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := secureJudgeBodyPlatformPath(directory, true); err != nil {
		t.Fatal(err)
	}
	grantEveryoneWindowsWrite(t, directory, true)

	store, err := NewJudgeBodyStore(filepath.Join(directory, "judge_bodies.db"))
	if store != nil {
		_ = store.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "untrusted Windows principal") {
		t.Fatalf("NewJudgeBodyStore error = %v, want untrusted Windows principal", err)
	}
}

func TestJudgeBodyWindowsRejectsPermissiveExistingLeaf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "judge_bodies.db")
	store, err := NewJudgeBodyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	grantEveryoneWindowsWrite(t, path, false)

	store, err = NewJudgeBodyStore(path)
	if store != nil {
		_ = store.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "untrusted Windows principal") {
		t.Fatalf("NewJudgeBodyStore error = %v, want untrusted Windows principal", err)
	}
}

func TestJudgeBodyWindowsRejectsInheritedReadAccessForSQLiteSidecars(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "protected")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := secureJudgeBodyPlatformPath(directory, true); err != nil {
		t.Fatal(err)
	}
	grantEveryoneWindowsAccess(t, directory, windows.GENERIC_READ, true)

	store, err := NewJudgeBodyStore(filepath.Join(directory, "judge_bodies.db"))
	if store != nil {
		_ = store.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "untrusted Windows principal") {
		t.Fatalf("NewJudgeBodyStore error = %v, want inherited read rejection", err)
	}
}

func TestJudgeBodyWindowsRejectsMutableAncestor(t *testing.T) {
	grandparent := filepath.Join(t.TempDir(), "shared")
	parent := filepath.Join(grandparent, "defenseclaw")
	if err := os.Mkdir(grandparent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := secureJudgeBodyPlatformPath(grandparent, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := secureJudgeBodyPlatformPath(parent, true); err != nil {
		t.Fatal(err)
	}
	const fileDeleteChild windows.ACCESS_MASK = 0x40
	grantEveryoneWindowsAccess(
		t,
		grandparent,
		fileDeleteChild,
		true,
	)

	store, err := NewJudgeBodyStore(filepath.Join(parent, "judge_bodies.db"))
	if store != nil {
		_ = store.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "untrusted Windows principal") {
		t.Fatalf("NewJudgeBodyStore error = %v, want mutable-ancestor rejection", err)
	}
}

func TestJudgeBodyWindowsRejectsStaleWALReadACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "judge_bodies.db")
	first, err := NewJudgeBodyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close() //nolint:errcheck
	if err := first.InsertJudgeResponse(JudgeResponse{
		ID: "stale-wal", Kind: "test", Raw: `{}`,
	}); err != nil {
		t.Fatal(err)
	}
	walPath := path + "-wal"
	if _, err := os.Stat(walPath); err != nil {
		t.Fatalf("expected WAL after write: %v", err)
	}
	grantEveryoneWindowsAccess(t, walPath, windows.GENERIC_READ, false)

	second, err := NewJudgeBodyStore(path)
	if second != nil {
		_ = second.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "SQLite sidecar -wal") {
		t.Fatalf("NewJudgeBodyStore error = %v, want stale WAL ACL rejection", err)
	}
}

func TestJudgeBodyWindowsRejectsLeafReparsePoint(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.db")
	path := filepath.Join(directory, "judge_bodies.db")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("creating a Windows symlink requires unavailable privilege: %v", err)
	}
	assertJudgeBodyStorePathError(t, path, "symbolic link")
}

func TestJudgeBodyWindowsRejectsParentReparsePoint(t *testing.T) {
	directory := t.TempDir()
	realParent := filepath.Join(directory, "real")
	aliasParent := filepath.Join(directory, "alias")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realParent, aliasParent); err != nil {
		t.Skipf("creating a Windows directory symlink requires unavailable privilege: %v", err)
	}
	assertJudgeBodyStorePathError(t, filepath.Join(aliasParent, "judge_bodies.db"), "symbolic link")
}

func TestJudgeBodyWindowsRejectsWrongOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "judge_bodies.db")
	store, err := NewJudgeBodyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		everyone,
		nil,
		nil,
		nil,
	); err != nil {
		t.Skipf("changing Windows owner requires unavailable privilege: %v", err)
	}
	defer windows.SetNamedSecurityInfo( //nolint:errcheck
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		currentUser.User.Sid,
		nil,
		nil,
		nil,
	)

	store, err = NewJudgeBodyStore(path)
	if store != nil {
		_ = store.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("NewJudgeBodyStore error = %v, want untrusted owner", err)
	}
}

func TestJudgeBodyWindowsTrustRejectsWorldOwner(t *testing.T) {
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	if judgeBodyWindowsTrustedPrincipal(everyone) {
		t.Fatal("Everyone SID must never be a trusted judge-body owner")
	}
}

func grantEveryoneWindowsWrite(t *testing.T, path string, directory bool) {
	grantEveryoneWindowsAccess(t, path, windows.GENERIC_WRITE, directory)
}

func grantEveryoneWindowsAccess(t *testing.T, path string, access windows.ACCESS_MASK, directory bool) {
	t.Helper()
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = uint32(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(currentUser.User.Sid),
			},
		},
		{
			AccessPermissions: access,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(everyone),
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
}
