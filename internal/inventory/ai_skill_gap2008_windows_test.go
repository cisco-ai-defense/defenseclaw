// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// gap2008Me is this process's user SID.
func gap2008Me(t *testing.T) *windows.SID {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid
}

// gap2008Secure gives the file or folder at path owner and the protected
// access list dacl (SDDL entries). Only an elevated process may name the
// Administrators group as owner, so the test is skipped otherwise.
func gap2008Secure(t *testing.T, path string, owner *windows.SID, dacl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString("D:P" + dacl)
	if err != nil {
		t.Fatal(err)
	}
	list, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, nil, list, nil); err != nil {
		t.Skipf("set the owner and access list of %s (needs an elevated process): %v", path, err)
	}
}

func gap2008Administrators(t *testing.T) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// adminOnly is an administrator folder's access list: SYSTEM and
// Administrators may change it, Users only read.
const gap2008AdminOnly = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
const gap2008UsersRead = "(A;OICI;0x1200a9;;;BU)"

// GAP-1837: a folder reached through a junction is never managed, even when
// the junction leads into a folder an administrator owns.
func TestGAP1837AdminFolderThroughAJunctionIsNotManaged(t *testing.T) {
	system := os.Getenv("SystemRoot")
	if system == "" || !skillFolderManagedNow(system) {
		t.Fatalf("%q is not managed", system)
	}
	link := filepath.Join(t.TempDir(), "skills")
	mklinkJunction(t, link, system)
	for _, path := range []string{link, filepath.Join(link, "System32")} {
		if skillFolderManagedNow(path) {
			t.Fatalf("%s (through a junction to %s) is managed", path, system)
		}
	}
}

// GAP-1837: an administrator-owned folder is managed only when no ordinary
// account may add to it or change it, directly or through an entry its
// children inherit; CREATOR OWNER's inherit-only entry does not count.
func TestGAP1837AdminFolderOthersMayChangeIsNotManaged(t *testing.T) {
	admins := gap2008Administrators(t)
	base := t.TempDir()
	for _, tc := range []struct {
		name, dacl string
		managed    bool
	}{
		{"admin only, users read", gap2008AdminOnly + gap2008UsersRead + "(A;OICIIO;GA;;;CO)", true},
		{"users may add files and folders", gap2008AdminOnly + gap2008UsersRead + "(A;CI;0x6;;;BU)", false},
		{"one account may modify", gap2008AdminOnly + "(A;;0x1301bf;;;" + gap2008Me(t).String() + ")", false},
		{"authenticated users inherit file writes", gap2008AdminOnly + "(A;OIIO;FW;;;AU)", false},
		{"everyone full control", gap2008AdminOnly + "(A;;FA;;;WD)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(base, filepath.Base(t.Name()))
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			gap2008Secure(t, dir, admins, tc.dacl)
			if got := skillFolderManagedNow(dir); got != tc.managed {
				t.Fatalf("managed = %t, want %t", got, tc.managed)
			}
		})
	}
}

// GAP-2008: on Windows the home owner trust approves an administrator's
// folder only when its access list lets the home owner list it, and an
// administrator's file only when it lets the home owner read it.
func TestGAP2008WindowsTrustNeedsTheAccessList(t *testing.T) {
	admins, me := gap2008Administrators(t), gap2008Me(t)
	home := t.TempDir()
	gap2008Secure(t, home, me, gap2008AdminOnly+"(A;OICI;FA;;;"+me.String()+")")
	trust := skillHomeOwnerTrust(home)
	folder := func(name, dacl string, owner *windows.SID) string {
		dir := filepath.Join(home, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		gap2008Secure(t, dir, owner, dacl)
		return dir
	}
	closed := folder("closed", gap2008AdminOnly, admins)
	listed := folder("listed", gap2008AdminOnly+gap2008UsersRead, admins)
	own := folder("own", "(A;OICI;FA;;;"+me.String()+")", me)
	if trust(nil, closed) {
		t.Fatalf("%s: an administrator folder the home owner may not list is trusted", closed)
	}
	if !trust(nil, listed) || !trust(nil, own) {
		t.Fatal("an administrator folder Users may list, or the home owner's own folder, is not trusted")
	}
	file := func(name, dacl string) (string, *os.File) {
		path := filepath.Join(listed, name)
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		gap2008Secure(t, path, admins, dacl)
		handle, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = handle.Close() })
		return path, handle
	}
	keptPath, kept := file("kept.txt", "(A;;FA;;;SY)(A;;FA;;;BA)")
	readPath, read := file("read.txt", "(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)")
	if trust(kept, keptPath) {
		t.Fatalf("%s: an administrator file the home owner may not read is trusted", keptPath)
	}
	if !trust(read, readPath) {
		t.Fatalf("%s: an administrator file Users may read is not trusted", readPath)
	}
}

// GAP-2008: below a skill folder reached through a junctioned agent folder,
// a folder the home owner may not list stops the walk (symlink, no hash).
func TestGAP2008JunctionedSkillWalkRefusesAClosedFolder(t *testing.T) {
	admins, me := gap2008Administrators(t), gap2008Me(t)
	home := t.TempDir()
	gap2008Secure(t, home, me, gap2008AdminOnly+"(A;OICI;FA;;;"+me.String()+")")
	real := filepath.Join(home, "dotfiles", "claude", "skills", "s")
	writeSkillFiles(t, real, map[string]string{"SKILL.md": "---\nname: s\n---\n", `closed\x.txt`: "x"})
	mklinkJunction(t, filepath.Join(home, ".claude"), filepath.Join(home, "dotfiles", "claude"))
	s := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: home}}
	linked := filepath.Join(home, ".claude", "skills", "s")
	if facts := s.skillFacts(linked, false); facts == nil || facts.ContentStatus != SkillContentOK {
		t.Fatalf("before: %+v", facts)
	}
	gap2008Secure(t, filepath.Join(real, "closed"), admins, gap2008AdminOnly)
	s = &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: home}}
	if facts := s.skillFacts(linked, false); facts == nil || facts.ContentStatus != SkillContentSymlink || facts.ContentHash != "" {
		t.Fatalf("closed folder below a junctioned skill: %+v; want symlink, no hash", facts)
	}
}
