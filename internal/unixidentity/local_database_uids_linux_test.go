//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
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
// cannot answer, and the combined lookup stops at the first miss when an NSS
// action says so. servicesShowUIDUnused asks each passwd service but files
// for the uid by itself: nil only when none holds it and each shows it
// answers.
func TestDirectoryShowsUIDUnusedAsksEveryPasswdServiceByItself(t *testing.T) {
	const uid = 4321
	held := commandResult{stdout: []byte("kim:x:4321:4321::/home/kim:/bin/sh\n")}
	for name, tc := range map[string]struct {
		services []string
		results  map[string]commandResult
		errs     map[string]error
		sssd     bool
		wantErr  bool
		wantHeld bool
	}{
		"files only":                                     {services: []string{"files"}},
		"files systemd altfiles, no match":               {services: []string{"files", "systemd", "altfiles"}},
		"sss with no sssd config":                        {services: []string{"files", "sss"}},
		"sss configured but stopped":                     {services: []string{"files", "sss"}, sssd: true, wantErr: true},
		"nis":                                            {services: []string{"files", "nis"}, wantErr: true},
		"a module with no check":                         {services: []string{"files", "aad"}, wantErr: true},
		"a service name that is not valid":               {services: []string{"files", "../x"}, wantErr: true},
		"sss holds the uid after files":                  {services: []string{"files", "sss"}, sssd: true, results: map[string]commandResult{"-s sss passwd 4321": held}, wantErr: true, wantHeld: true},
		"extrausers holds the uid":                       {services: []string{"files", "extrausers"}, results: map[string]commandResult{"-s extrausers passwd 4321": held}, wantErr: true, wantHeld: true},
		"db holds the uid":                               {services: []string{"files", "db"}, results: map[string]commandResult{"-s db passwd 4321": held}, wantErr: true, wantHeld: true},
		"usrfiles holds the uid":                         {services: []string{"files", "usrfiles"}, results: map[string]commandResult{"-s usrfiles passwd 4321": held}, wantErr: true, wantHeld: true},
		"mymachines holds the uid":                       {services: []string{"files", "mymachines"}, results: map[string]commandResult{"-s mymachines passwd 4321": held}, wantErr: true, wantHeld: true},
		"a local service that cannot be asked":           {services: []string{"files", "extrausers"}, results: map[string]commandResult{"-s extrausers passwd 4321": {exitCode: 1}}, wantErr: true},
		"a service lookup that fails":                    {services: []string{"files", "db"}, errs: map[string]error{"-s db passwd 4321": errors.New("timed out")}, wantErr: true},
		"extrausers, db, usrfiles, mymachines, no match": {services: []string{"files", "extrausers", "db", "usrfiles", "mymachines"}},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			oldConf, oldSocket := sssdConfPath, sssdNSSSocket
			t.Cleanup(func() { sssdConfPath, sssdNSSSocket = oldConf, oldSocket })
			sssdConfPath, sssdNSSSocket = filepath.Join(dir, "none.conf"), filepath.Join(dir, "no-sssd", "nss")
			if tc.sssd {
				writeTestFile(t, sssdConfPath, "[sssd]\ndomains = corp.example.com\n")
			}
			runner := &fakeRun{results: tc.results, errs: tc.errs}
			asked := false
			err := servicesShowUIDUnused(tc.services, uid, func() (*NSSResolver, error) {
				asked = true
				return newFakeNSS(runner), nil
			})
			if (err != nil) != tc.wantErr || errors.Is(err, ErrUIDHeld) != tc.wantHeld {
				t.Fatalf("servicesShowUIDUnused = %v, wantErr %v, wantHeld %v", err, tc.wantErr, tc.wantHeld)
			}
			if len(tc.services) == 1 && asked {
				t.Fatal("a host with only files needs no getent")
			}
		})
	}
}

// The passwd line of nsswitch.conf keeps listing the services an action
// such as [NOTFOUND=return] sits before, so each is asked.
func TestPasswdProvidersKeepsTheServicesAnNSSActionStopsBefore(t *testing.T) {
	oldNSS := nsswitchPath
	t.Cleanup(func() { nsswitchPath = oldNSS })
	nsswitchPath = filepath.Join(t.TempDir(), "nsswitch.conf")
	writeTestFile(t, nsswitchPath, "passwd: files [NOTFOUND=return] sss extrausers\n")
	got, err := passwdProviders()
	if err != nil || !reflect.DeepEqual(got, []string{"files", "sss", "extrausers"}) {
		t.Fatalf("passwdProviders = %v, %v", got, err)
	}
}

// A clause with two actions is read whole, so a deleted uid still gets its
// absence proof on the valid line, and a service that holds the uid after
// the clause is still found.
func TestDirectoryShowsUIDUnusedReadsAMultiActionNSSLine(t *testing.T) {
	const uid = 4321
	held := commandResult{stdout: []byte("kim:x:4321:4321::/home/kim:/bin/sh\n")}
	for name, tc := range map[string]struct {
		line     string
		results  map[string]commandResult
		wantErr  bool
		wantHeld bool
	}{
		"two actions, uid deleted":              {line: "passwd: files [SUCCESS=return NOTFOUND=continue] systemd\n"},
		"one action, uid deleted":               {line: "passwd: files [SUCCESS=return] systemd\n"},
		"two actions, systemd holds uid":        {line: "passwd: files [SUCCESS=return NOTFOUND=continue] systemd\n", results: map[string]commandResult{"-s systemd passwd 4321": held}, wantErr: true, wantHeld: true},
		"form feed, one action, uid deleted":    {line: "passwd: files\f[NOTFOUND=continue]\fsystemd\n"},
		"vertical tab, one action, uid deleted": {line: "passwd: files\v[NOTFOUND=continue]\vsystemd\n"},
		"form feed, two actions, uid deleted":   {line: "passwd: files\f[SUCCESS=return\fNOTFOUND=continue]\fsystemd\n"},
		"form feed, systemd holds uid":          {line: "passwd: files\f[NOTFOUND=continue]\fsystemd\n", results: map[string]commandResult{"-s systemd passwd 4321": held}, wantErr: true, wantHeld: true},
		"vertical tab, systemd holds uid":       {line: "passwd: files\v[NOTFOUND=continue]\vsystemd\n", results: map[string]commandResult{"-s systemd passwd 4321": held}, wantErr: true, wantHeld: true},
		"one action, systemd holds uid":         {line: "passwd: files [SUCCESS=return] systemd\n", results: map[string]commandResult{"-s systemd passwd 4321": held}, wantErr: true, wantHeld: true},
	} {
		t.Run(name, func(t *testing.T) {
			oldNSS := nsswitchPath
			t.Cleanup(func() { nsswitchPath = oldNSS })
			nsswitchPath = filepath.Join(t.TempDir(), "nsswitch.conf")
			writeTestFile(t, nsswitchPath, tc.line)
			services, err := passwdProviders()
			if err != nil {
				t.Fatal(err)
			}
			err = servicesShowUIDUnused(services, uid, func() (*NSSResolver, error) {
				return newFakeNSS(&fakeRun{results: tc.results}), nil
			})
			if (err != nil) != tc.wantErr || errors.Is(err, ErrUIDHeld) != tc.wantHeld {
				t.Fatalf("servicesShowUIDUnused(%v) = %v, wantErr %v, wantHeld %v", services, err, tc.wantErr, tc.wantHeld)
			}
		})
	}
}
