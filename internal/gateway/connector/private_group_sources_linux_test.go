// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"
)

const (
	stockNsswitch    = "passwd:         files systemd\ngroup:          files systemd\nshadow:         files\nhosts:          files dns\n"
	privateGroupSeal = 0o775
)

// privateGroupSourcesFixture makes a 0775 folder of this account group, points
// the local proof at account files that show a private group, and points the
// source files at a host with local accounts only (stock Ubuntu nsswitch, no
// sssd, no userdb). Nothing may start getent.
func privateGroupSourcesFixture(t *testing.T) (string, os.FileInfo, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".config")
	if err := os.MkdirAll(filepath.Join(dir, "opencode", "plugins"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, privateGroupSeal); err != nil {
		t.Fatal(err)
	}
	dropInheritedACLs(t, root)
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	uid := fmt.Sprint(os.Geteuid())
	gid := fmt.Sprint(info.Sys().(*syscall.Stat_t).Gid)
	oldUser, oldLookupGroup := privateGroupLookupUser, privateGroupLookupGroup
	privateGroupLookupUser = func(string) (*user.User, error) {
		return &user.User{Username: "me", Uid: uid, Gid: gid}, nil
	}
	privateGroupLookupGroup = func(string) (*user.Group, error) { return &user.Group{Gid: gid, Name: "me"}, nil }
	files := t.TempDir()
	passwd, groupFile, nsswitch := filepath.Join(files, "passwd"), filepath.Join(files, "group"), filepath.Join(files, "nsswitch.conf")
	for path, content := range map[string]string{
		passwd:    fmt.Sprintf("me:x:%s:%s::/home/x:/bin/sh\n", uid, gid),
		groupFile: fmt.Sprintf("me:x:%s:\n", gid),
		nsswitch:  stockNsswitch,
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sssd := filepath.Join(files, "sssd")
	userdb := filepath.Join(files, "userdb")
	if err := os.MkdirAll(filepath.Join(sssd, "conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(userdb, 0o755); err != nil {
		t.Fatal(err)
	}
	oldPasswd, oldGroup, oldGetent := privateGroupPasswdFile, privateGroupGroupFile, privateGroupGetent
	oldNsswitch, oldSSSD, oldUserdb := privateGroupNsswitchFile, privateGroupSSSDDir, privateGroupUserdbDirs
	privateGroupPasswdFile, privateGroupGroupFile = passwd, groupFile
	privateGroupNsswitchFile, privateGroupSSSDDir, privateGroupUserdbDirs = nsswitch, sssd, []string{userdb, filepath.Join(files, "absent")}
	privateGroupGetent = func(database, key string) (string, bool) {
		t.Errorf("the per-event proof started getent %s %s", database, key)
		return "", false
	}
	t.Cleanup(func() {
		privateGroupLookupUser, privateGroupLookupGroup = oldUser, oldLookupGroup
		privateGroupPasswdFile, privateGroupGroupFile, privateGroupGetent = oldPasswd, oldGroup, oldGetent
		privateGroupNsswitchFile, privateGroupSSSDDir, privateGroupUserdbDirs = oldNsswitch, oldSSSD, oldUserdb
	})
	return dir, info, files
}

func writeSourceFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// GAP-0905 review 2 MF1a: another account can hold the private group as its
// primary gid without being listed as a member, and the name service cannot
// list those accounts. The group is private only on a host whose accounts and
// groups are local files. The stock Ubuntu and sssd-without-domains layouts
// stay accepted.
func TestOwnerPrivateGroupLocalSourcesNeedsLocalAccountsOnly(t *testing.T) {
	dir, info, files := privateGroupSourcesFixture(t)
	nsswitch := filepath.Join(files, "nsswitch.conf")
	for _, tc := range []struct {
		name, content string
		extra         func(t *testing.T)
		want          bool
	}{
		{name: "stock ubuntu files systemd", content: stockNsswitch, want: true},
		{name: "files only", content: "passwd: files\ngroup: files\n", want: true},
		{name: "compat", content: "passwd: compat\ngroup: compat\n", want: true},
		{name: "comments and spacing", content: "# accounts\npasswd:\tfiles   systemd # local\n\ngroup: files systemd\n", want: true},
		{name: "action between sources", content: "passwd: files [SUCCESS=merge] systemd\ngroup: files [SUCCESS=merge] systemd\n", want: true},
		{name: "sss with no sssd configuration", content: "passwd: sss files systemd\ngroup: sss files systemd\n", want: true},
		{name: "sss with sssd.conf", content: "passwd: sss files\ngroup: sss files\n", extra: func(t *testing.T) {
			writeSourceFile(t, filepath.Join(files, "sssd", "sssd.conf"), "[sssd]\n")
		}},
		{name: "sss with a conf.d snippet", content: "passwd: sss files\ngroup: sss files\n", extra: func(t *testing.T) {
			writeSourceFile(t, filepath.Join(files, "sssd", "conf.d", "ad.conf"), "[domain/x]\n")
		}},
		{name: "ldap accounts", content: "passwd: files ldap\ngroup: files\n"},
		{name: "ldap groups", content: "passwd: files\ngroup: files ldap\n"},
		{name: "nis", content: "passwd: files nis\ngroup: files nis\n"},
		{name: "winbind", content: "passwd: files winbind\ngroup: files winbind\n"},
		{name: "extrausers", content: "passwd: files extrausers\ngroup: files extrausers\n"},
		{name: "unknown source", content: "passwd: files mystery\ngroup: files\n"},
		{name: "no group line", content: "passwd: files\n"},
		{name: "no passwd line", content: "group: files\n"},
		{name: "empty source list", content: "passwd:\ngroup: files\n"},
		{name: "passwd listed twice", content: "passwd: files\npasswd: files ldap\ngroup: files\n"},
		{name: "a systemd userdb user record", content: stockNsswitch, extra: func(t *testing.T) {
			writeSourceFile(t, filepath.Join(files, "userdb", "bob.user"), "{}\n")
		}},
		{name: "a systemd userdb group record", content: stockNsswitch, extra: func(t *testing.T) {
			writeSourceFile(t, filepath.Join(files, "userdb", "devs.group"), "{}\n")
		}},
		{name: "a systemd userdb membership record", content: stockNsswitch, extra: func(t *testing.T) {
			writeSourceFile(t, filepath.Join(files, "userdb", "bob:devs.membership"), "{}\n")
		}},
		{name: "an unrelated userdb file", content: stockNsswitch, extra: func(t *testing.T) {
			writeSourceFile(t, filepath.Join(files, "userdb", "README"), "x\n")
		}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeSourceFile(t, nsswitch, tc.content)
			if tc.extra != nil {
				tc.extra(t)
				t.Cleanup(func() {
					_ = os.RemoveAll(filepath.Join(files, "sssd"))
					_ = os.MkdirAll(filepath.Join(files, "sssd", "conf.d"), 0o755)
					_ = os.RemoveAll(filepath.Join(files, "userdb"))
					_ = os.MkdirAll(filepath.Join(files, "userdb"), 0o755)
				})
			}
			if got := ownerPrivateGroupLocalSources(dir, info); got != tc.want {
				t.Fatalf("local-sources proof=%v, want %v", got, tc.want)
			}
			if !ownerPrivateGroup(dir, info) {
				t.Fatal("the local files no longer show the stock private group")
			}
		})
	}
}

// A missing or unreadable nsswitch.conf, or an unreadable source directory,
// is not proof.
func TestOwnerPrivateGroupLocalSourcesRefusesWhatItCannotRead(t *testing.T) {
	dir, info, files := privateGroupSourcesFixture(t)
	if !ownerPrivateGroupLocalSources(dir, info) {
		t.Fatal("stock layout refused")
	}
	privateGroupNsswitchFile = filepath.Join(files, "absent-nsswitch.conf")
	if ownerPrivateGroupLocalSources(dir, info) {
		t.Fatal("a missing nsswitch.conf was accepted")
	}
	privateGroupNsswitchFile = filepath.Join(files, "nsswitch.conf")
	regular := filepath.Join(files, "not-a-dir")
	writeSourceFile(t, regular, "x\n")
	privateGroupUserdbDirs = []string{regular}
	if ownerPrivateGroupLocalSources(dir, info) {
		t.Fatal("an unreadable userdb directory was accepted")
	}
}

// GAP-0905 review 2 MF1b: nothing is remembered. A source added after the
// folder was accepted refuses on the next call, and removing it admits again.
func TestOwnerPrivateGroupLocalSourcesRevokesAtOnce(t *testing.T) {
	dir, info, files := privateGroupSourcesFixture(t)
	nsswitch := filepath.Join(files, "nsswitch.conf")
	for i := 0; i < 3; i++ {
		if !ownerPrivateGroupLocalSources(dir, info) {
			t.Fatal("stock private group refused")
		}
	}
	writeSourceFile(t, nsswitch, "passwd: files ldap\ngroup: files ldap\n")
	if ownerPrivateGroupLocalSources(dir, info) {
		t.Fatal("a directory service added after the first answer was still trusted")
	}
	writeSourceFile(t, nsswitch, stockNsswitch)
	writeSourceFile(t, filepath.Join(files, "userdb", "bob.user"), "{}\n")
	if ownerPrivateGroupLocalSources(dir, info) {
		t.Fatal("a userdb account added after the first answer was still trusted")
	}
	if err := os.Remove(filepath.Join(files, "userdb", "bob.user")); err != nil {
		t.Fatal(err)
	}
	if !ownerPrivateGroupLocalSources(dir, info) {
		t.Fatal("the stock layout stayed refused after the source went away")
	}
	// The local files still decide, whatever the sources say.
	privateGroupLookupGroup = func(string) (*user.Group, error) { return &user.Group{Name: "other"}, nil }
	if ownerPrivateGroupLocalSources(dir, info) {
		t.Fatal("the local files disagreed and the folder was accepted")
	}
}
