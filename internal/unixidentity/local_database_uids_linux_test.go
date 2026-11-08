//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func localUIDSources(t *testing.T) (passwd, altfiles, userdb string) {
	t.Helper()
	oldPasswd, oldUserdb, oldAltfiles := localPasswdPath, UserdbRecordDirs, AltfilesPasswdFiles
	t.Cleanup(func() { localPasswdPath, UserdbRecordDirs, AltfilesPasswdFiles = oldPasswd, oldUserdb, oldAltfiles })
	dir := t.TempDir()
	localPasswdPath = filepath.Join(dir, "passwd")
	userdb = filepath.Join(dir, "userdb")
	altfiles = filepath.Join(dir, "lib-passwd")
	UserdbRecordDirs = []string{userdb, filepath.Join(dir, "absent")}
	AltfilesPasswdFiles = []string{altfiles, filepath.Join(dir, "absent-passwd")}
	if err := os.MkdirAll(userdb, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, localPasswdPath, "root:x:0:0::/root:/bin/sh\n")
	return localPasswdPath, altfiles, userdb
}

// LocalDatabaseUIDs keeps every uid of every source: a login name that two
// sources list under two uids is two accounts, where the name-keyed
// LocalDatabaseAccounts keeps the first.
func TestLocalDatabaseUIDsKeepsEveryUIDOfADuplicateName(t *testing.T) {
	passwd, altfiles, userdb := localUIDSources(t)
	writeTestFile(t, passwd, "root:x:0:0::/root:/bin/sh\nalex:x:2100:2100::/home/alex:/bin/sh\nalex:x:2101:2101::/home/alex2:/bin/sh\n")
	writeTestFile(t, altfiles, "alex:x:2200:2200::/home/alex:/bin/sh\n+@nis\n")
	writeTestFile(t, filepath.Join(userdb, "podu.user"), `{"userName":"podu","uid":2861}`)
	writeTestFile(t, filepath.Join(userdb, "nouid.user"), `{"userName":"nouid"}`)
	got, err := LocalDatabaseUIDs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sort.Ints(got)
	if want := []int{0, 2100, 2101, 2200, 2861}; !reflect.DeepEqual(got, want) {
		t.Fatalf("LocalDatabaseUIDs = %v, want %v", got, want)
	}
}

// A source that exists and cannot be read answers nothing, so there is no
// uid list to read an absence from; an absent source is simply not there.
func TestLocalDatabaseUIDsFailsOnASourceItCannotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	for name, setup := range map[string]func(t *testing.T, passwd, altfiles, userdb string){
		"altfiles file": func(t *testing.T, _, altfiles, _ string) {
			writeTestFile(t, altfiles, "alt:x:2200:2200::/home/alt:/bin/sh\n")
			if err := os.Chmod(altfiles, 0); err != nil {
				t.Fatal(err)
			}
		},
		"userdb record": func(t *testing.T, _, _, userdb string) {
			record := filepath.Join(userdb, "podu.user")
			writeTestFile(t, record, `{"userName":"podu","uid":2861}`)
			if err := os.Chmod(record, 0); err != nil {
				t.Fatal(err)
			}
		},
		"userdb record that is not JSON": func(t *testing.T, _, _, userdb string) {
			writeTestFile(t, filepath.Join(userdb, "broken.user"), `{`)
		},
		"passwd": func(t *testing.T, passwd, _, _ string) {
			if err := os.Remove(passwd); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			passwd, altfiles, userdb := localUIDSources(t)
			setup(t, passwd, altfiles, userdb)
			if got, err := LocalDatabaseUIDs(context.Background()); err == nil {
				t.Fatalf("LocalDatabaseUIDs = %v, want an error", got)
			}
		})
	}
	t.Run("absent sources are not an error", func(t *testing.T) {
		localUIDSources(t)
		if got, err := LocalDatabaseUIDs(context.Background()); err != nil || !reflect.DeepEqual(got, []int{0}) {
			t.Fatalf("LocalDatabaseUIDs = %v, %v", got, err)
		}
	})
}

// getent exits 2 for an account that is not there and for a directory that
// cannot answer. DirectoryShowsUIDUnused is nil only when no directory is
// configured or every one shows it answers.
func TestDirectoryShowsUIDUnusedNeedsTheDirectoryToAnswer(t *testing.T) {
	oldNSS := nsswitchPath
	t.Cleanup(func() { nsswitchPath = oldNSS })
	dir := t.TempDir()
	nsswitchPath = filepath.Join(dir, "nsswitch.conf")
	for name, tc := range map[string]struct {
		content string
		sssd    bool
		wantErr bool
	}{
		"files only":              {content: "passwd: files systemd\n"},
		"altfiles and files":      {content: "passwd: files altfiles\n"},
		"sss with no sssd config": {content: "passwd: files sss\n"},
		"sss configured, stopped": {content: "passwd: files sss\n", sssd: true, wantErr: true},
		"nis":                     {content: "passwd: files nis\n", wantErr: true},
		"a module with no check":  {content: "passwd: files aad\n", wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.sssd {
				sssdConfiguredHost(t)
			} else {
				oldConf, oldDir := sssdConfPath, sssdConfDir
				t.Cleanup(func() { sssdConfPath, sssdConfDir = oldConf, oldDir })
				sssdConfPath, sssdConfDir = filepath.Join(dir, "none.conf"), filepath.Join(dir, "none.d")
			}
			writeTestFile(t, nsswitchPath, tc.content)
			err := DirectoryShowsUIDUnused(context.Background(), 4321)
			if (err != nil) != tc.wantErr {
				t.Fatalf("DirectoryShowsUIDUnused = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
