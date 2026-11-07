// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-0731: a write grant to another account on a folder is inherited by the
// plugin folder below it. The refusal named the child; the folder to fix is
// the one that carries the entry, and the fix is one icacls command.
func TestGAP0731ForeignWriteGrantNamesTheFolderThatCarriesTheEntry(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "opencode")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	ownWindowsTestPath(t, parent)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current token user: %v", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	setProtected := func(path string, entries ...windows.EXPLICIT_ACCESS) {
		t.Helper()
		acl, err := windows.ACLFromEntries(entries, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(
			path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, acl, nil,
		); err != nil {
			t.Fatal(err)
		}
	}
	inherit := func(entry windows.EXPLICIT_ACCESS) windows.EXPLICIT_ACCESS {
		entry.Inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
		return entry
	}

	// Benign twin: only this account and SYSTEM, so no grant is found.
	setProtected(parent,
		inherit(windowsAccessEntry(user.User.Sid, windows.GENERIC_ALL)),
		inherit(windowsAccessEntry(system, windows.GENERIC_ALL)),
	)
	child := filepath.Join(parent, "plugins")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if grant, ok := FirstForeignWriteGrant(child); ok {
		t.Fatalf("a private folder reported a grant: %+v", grant)
	}

	// Another account with Modify on the parent, inherited by the child.
	setProtected(parent,
		inherit(windowsAccessEntry(user.User.Sid, windows.GENERIC_ALL)),
		inherit(windowsAccessEntry(system, windows.GENERIC_ALL)),
		inherit(windowsAccessEntry(everyone, windows.GENERIC_WRITE)),
	)
	grandchild := filepath.Join(parent, "later")
	if err := os.Mkdir(grandchild, 0o700); err != nil {
		t.Fatal(err)
	}
	grant, ok := FirstForeignWriteGrant(grandchild)
	if !ok {
		t.Fatal("the inherited grant to another account was not found")
	}
	if !strings.EqualFold(grant.Folder, parent) {
		t.Fatalf("grant names %q, want the folder that carries the entry %q", grant.Folder, parent)
	}
	if !strings.Contains(grant.Account, "Everyone") {
		t.Fatalf("grant names account %q", grant.Account)
	}
	if fix := grant.Fix(); !strings.HasPrefix(fix, "icacls ") || !strings.Contains(fix, "/remove") || !strings.Contains(fix, parent) {
		t.Fatalf("fix %q", fix)
	}
}
