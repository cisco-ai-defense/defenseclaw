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
	"testing"
)

// GAP-0026: a systemd-userdb drop-in account is in no /etc/passwd line.
// LocalDatabaseAccounts lists it, and the nss-altfiles accounts, besides
// the /etc/passwd ones; /etc/passwd keeps a name it already lists.
func TestLocalDatabaseAccountsListsTheUserdbAndAltfilesAccounts(t *testing.T) {
	oldPasswd, oldUserdb, oldAltfiles := localPasswdPath, UserdbRecordDirs, AltfilesPasswdFiles
	t.Cleanup(func() { localPasswdPath, UserdbRecordDirs, AltfilesPasswdFiles = oldPasswd, oldUserdb, oldAltfiles })
	dir := t.TempDir()
	localPasswdPath = filepath.Join(dir, "passwd")
	userdb := filepath.Join(dir, "userdb")
	altfiles := filepath.Join(dir, "lib-passwd")
	UserdbRecordDirs = []string{userdb, filepath.Join(dir, "absent")}
	AltfilesPasswdFiles = []string{altfiles, filepath.Join(dir, "absent-passwd")}
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(userdb, 0o755); err != nil {
		t.Fatal(err)
	}
	write(localPasswdPath, "alex:x:2100:2100::/home/alex:/bin/sh\n")
	write(filepath.Join(userdb, "podu.user"), `{"userName":"podu","uid":2861,"gid":100,"homeDirectory":"/home/podu","disposition":"regular"}`)
	if err := os.Symlink("podu.user", filepath.Join(userdb, "2861.user")); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(userdb, "alex.user"), `{"userName":"alex","uid":2999}`)
	write(filepath.Join(userdb, "nouid.user"), `{"userName":"nouid"}`)
	write(filepath.Join(userdb, "broken.user"), `{`)
	write(filepath.Join(userdb, "podu.group"), `{"groupName":"podu","gid":2861}`)
	write(altfiles, "alt:x:2200:2200::/home/alt:/bin/sh\n")

	got, err := LocalDatabaseAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"alex": 2100, "podu": 2861, "alt": 2200}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LocalDatabaseAccounts = %v, want %v", got, want)
	}
	only, err := LocalAccounts(context.Background())
	if err != nil || !reflect.DeepEqual(only, map[string]int{"alex": 2100}) {
		t.Fatalf("LocalAccounts = %v, %v; want /etc/passwd only", only, err)
	}
}
