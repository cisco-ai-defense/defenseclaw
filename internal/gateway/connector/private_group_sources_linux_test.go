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
	resetPrivateGroupSources(t, files)
	oldPasswd, oldGroup, oldGetent := privateGroupPasswdFile, privateGroupGroupFile, privateGroupGetent
	oldNsswitch, oldSSSD, oldUserdb := privateGroupNsswitchFile, privateGroupSSSDDir, privateGroupUserdbDirs
	oldSocks, oldPAMConf, oldPAMDir := privateGroupUserdbSocks, privateGroupPAMGroupConf, privateGroupPAMGroupDir
	privateGroupPasswdFile, privateGroupGroupFile = passwd, groupFile
	privateGroupNsswitchFile, privateGroupSSSDDir = nsswitch, filepath.Join(files, "sssd")
	privateGroupUserdbDirs = []string{filepath.Join(files, "userdb"), filepath.Join(files, "host-userdb"), filepath.Join(files, "absent")}
	privateGroupUserdbSocks = filepath.Join(files, "run", "systemd", "userdb")
	privateGroupPAMGroupConf, privateGroupPAMGroupDir = filepath.Join(files, "security", "group.conf"), filepath.Join(files, "security", "group.d")
	privateGroupGetent = func(database, key string) (string, bool) {
		t.Errorf("the per-event proof started getent %s %s", database, key)
		return "", false
	}
	t.Cleanup(func() {
		privateGroupLookupUser, privateGroupLookupGroup = oldUser, oldLookupGroup
		privateGroupPasswdFile, privateGroupGroupFile, privateGroupGetent = oldPasswd, oldGroup, oldGetent
		privateGroupNsswitchFile, privateGroupSSSDDir, privateGroupUserdbDirs = oldNsswitch, oldSSSD, oldUserdb
		privateGroupUserdbSocks, privateGroupPAMGroupConf, privateGroupPAMGroupDir = oldSocks, oldPAMConf, oldPAMDir
	})
	return dir, info, files
}

// resetPrivateGroupSources lays the source files out as on a stock Ubuntu host:
// no sssd configuration, empty userdb directories, only the dynamic-user userdb
// service, and a group.conf with every rule commented out.
func resetPrivateGroupSources(t *testing.T, files string) {
	t.Helper()
	for _, dir := range []string{"sssd", "userdb", "host-userdb", "run", "security"} {
		if err := os.RemoveAll(filepath.Join(files, dir)); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{filepath.Join("sssd", "conf.d"), "userdb", "host-userdb"} {
		if err := os.MkdirAll(filepath.Join(files, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeSourceFile(t, filepath.Join(files, "run", "systemd", "userdb", "io.systemd.DynamicUser"), "")
	writeSourceFile(t, filepath.Join(files, "security", "group.conf"), "# stock: every rule commented out\n#*;*;*;Al0000-2400;audio\n\n")
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
		{name: "a userdb record in the host-shared directory", content: stockNsswitch, extra: func(t *testing.T) {
			writeSourceFile(t, filepath.Join(files, "host-userdb", "other.user"), "{}\n")
		}},
		{name: "a numeric alias of a userdb record", content: stockNsswitch, extra: func(t *testing.T) {
			writeSourceFile(t, filepath.Join(files, "host-userdb", "200123.user"), "{}\n")
		}},
		{name: "the built-in userdb services only", content: stockNsswitch, extra: func(t *testing.T) {
			for _, name := range []string{"io.systemd.Multiplexer", "io.systemd.NameServiceSwitch"} {
				writeSourceFile(t, filepath.Join(files, "run", "systemd", "userdb", name), "")
			}
		}, want: true},
		{name: "a homed userdb service", content: stockNsswitch, extra: func(t *testing.T) {
			writeSourceFile(t, filepath.Join(files, "run", "systemd", "userdb", "io.systemd.Home"), "")
		}},
		{name: "a machined userdb service", content: stockNsswitch, extra: func(t *testing.T) {
			writeSourceFile(t, filepath.Join(files, "run", "systemd", "userdb", "io.systemd.Machine"), "")
		}},
		{name: "a vendor userdb service", content: stockNsswitch, extra: func(t *testing.T) {
			writeSourceFile(t, filepath.Join(files, "run", "systemd", "userdb", "com.example.Directory"), "")
		}},
		{name: "initgroups from sss", content: "passwd: files\ngroup: files\ninitgroups: sss\n"},
		{name: "initgroups from sss with a domain", content: "passwd: files\ngroup: files\ninitgroups: sss\n", extra: func(t *testing.T) {
			writeSourceFile(t, filepath.Join(files, "sssd", "sssd.conf"), "[sssd]\n")
		}},
		{name: "initgroups from ldap", content: "passwd: files\ngroup: files\ninitgroups: files ldap\n"},
		{name: "initgroups from a source this check does not know", content: stockNsswitch + "initgroups: files mystery\n"},
		{name: "initgroups listed twice", content: stockNsswitch + "initgroups: files\ninitgroups: files\n"},
		{name: "initgroups with no source", content: stockNsswitch + "initgroups:\n"},
		{name: "initgroups from the local files", content: stockNsswitch + "initgroups: files\n", want: true},
		{name: "initgroups from the local files and systemd", content: stockNsswitch + "initgroups: files [SUCCESS=merge] systemd\n", want: true},
		{name: "a pam_group rule", content: stockNsswitch, extra: func(t *testing.T) {
			writeSourceFile(t, privateGroupPAMGroupConf, "*;*;*;Al0000-2400;devs\n")
		}},
		{name: "a pam_group rule in group.d", content: stockNsswitch, extra: func(t *testing.T) {
			writeSourceFile(t, filepath.Join(privateGroupPAMGroupDir, "devs.conf"), "# header\n*;*;me;Al0000-2400;devs\n")
		}},
		{name: "a commented group.d file", content: stockNsswitch, extra: func(t *testing.T) {
			writeSourceFile(t, filepath.Join(privateGroupPAMGroupDir, "devs.conf"), "# *;*;me;Al0000-2400;devs\n")
		}, want: true},
		{name: "an unrelated userdb file", content: stockNsswitch, extra: func(t *testing.T) {
			writeSourceFile(t, filepath.Join(files, "userdb", "README"), "x\n")
		}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeSourceFile(t, nsswitch, tc.content)
			if tc.extra != nil {
				tc.extra(t)
				t.Cleanup(func() { resetPrivateGroupSources(t, files) })
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

// GAP-0905 review 3 MF1c: nss-systemd also reads account records from
// /run/host/userdb, and from any Varlink service in /run/systemd/userdb. A
// record there can give a second account the folder group as its primary gid
// while /etc/passwd and /etc/group show only the owner. Both are sources the
// check must see, and the stock layout (the dynamic-user service only) stays
// accepted.
func TestOwnerPrivateGroupLocalSourcesSeesSystemdAccountSources(t *testing.T) {
	for _, dir := range []string{"/etc/userdb", "/run/userdb", "/run/host/userdb", "/usr/lib/userdb", "/var/lib/userdb", "/var/lib/systemd/home"} {
		found := false
		for _, have := range privateGroupUserdbDirs {
			found = found || filepath.Clean(have) == dir
		}
		if !found {
			t.Errorf("the production record directories omit %s", dir)
		}
	}
	if privateGroupUserdbSocks != "/run/systemd/userdb" {
		t.Errorf("the userdb service directory is %s", privateGroupUserdbSocks)
	}
	dir, info, files := privateGroupSourcesFixture(t)
	gid := info.Sys().(*syscall.Stat_t).Gid
	if !ownerPrivateGroupLocalSources(dir, info) {
		t.Fatal("the stock layout was refused")
	}
	record := filepath.Join(files, "host-userdb", "other.user")
	writeSourceFile(t, record, fmt.Sprintf("{\"userName\":\"other\",\"uid\":200123,\"gid\":%d}\n", gid))
	if err := os.Symlink("other.user", filepath.Join(files, "host-userdb", "200123.user")); err != nil {
		t.Fatal(err)
	}
	if ownerPrivateGroupLocalSources(dir, info) {
		t.Fatal("a second account with the folder group as primary gid, in the host-shared userdb directory, was not seen")
	}
}

// GAP-0905 review 3 MF1c: initgroups is its own nsswitch database, so a local
// second account can receive the private gid as a supplementary group from a
// remote source while passwd and group stay on the files.
func TestOwnerPrivateGroupLocalSourcesChecksSupplementaryGroupSource(t *testing.T) {
	dir, info, files := privateGroupSourcesFixture(t)
	writeSourceFile(t, filepath.Join(files, "nsswitch.conf"), "passwd: files\ngroup: files\ninitgroups: sss\n")
	if ownerPrivateGroupLocalSources(dir, info) {
		t.Fatal("a remote initgroups source was accepted")
	}
	writeSourceFile(t, filepath.Join(files, "nsswitch.conf"), "passwd: files\ngroup: files\ninitgroups: files\n")
	if !ownerPrivateGroupLocalSources(dir, info) {
		t.Fatal("a local initgroups source was refused")
	}
}
