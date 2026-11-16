//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func crossServiceFiles(t *testing.T, passwdServices, initgroupsServices, localGroups string) {
	t.Helper()
	oldPasswd, oldGroup, oldNSS := localPasswdPath, localGroupPath, nsswitchPath
	t.Cleanup(func() { localPasswdPath, localGroupPath, nsswitchPath = oldPasswd, oldGroup, oldNSS })
	dir := t.TempDir()
	localPasswdPath, localGroupPath, nsswitchPath = filepath.Join(dir, "passwd"), filepath.Join(dir, "group"), filepath.Join(dir, "nsswitch.conf")
	for path, content := range map[string]string{
		localPasswdPath: "",
		localGroupPath:  localGroups,
		nsswitchPath:    "passwd: " + passwdServices + "\ninitgroups: " + initgroupsServices + "\ngroup: " + initgroupsServices + "\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func crossServiceResults() map[string]commandResult {
	const first = "alex:x:80001:80001::/home/alex:/bin/sh\n"
	const second = "alex:x:90001:90001::/home/alex:/bin/sh\n"
	return map[string]commandResult{
		"passwd 80001":                  {stdout: []byte(first)},
		"passwd 90001":                  {stdout: []byte(second)},
		"passwd alex":                   {stdout: []byte(first)},
		"-s himmelblau passwd 80001":    {stdout: []byte(first)},
		"-s himmelblau passwd alex":     {stdout: []byte(first)},
		"-s ldap passwd 90001":          {stdout: []byte(second)},
		"-s ldap passwd alex":           {stdout: []byte(second)},
		"initgroups alex":               {stdout: []byte("alex 80001 5000 9500 90001\n")},
		"-s himmelblau initgroups alex": {stdout: []byte("alex 80001 5000\n")},
		"-s ldap initgroups alex":       {stdout: []byte("alex 90001 9500\n")},
		"-s ldap group":                 {stdout: []byte("other-team:x:9500:\n")},
		"group 5000 80001":              {stdout: []byte("directory-team:x:5000:\ndirectory-primary:x:80001:\n")},
		"group 9500 90001":              {stdout: []byte("other-team:x:9500:\nother-primary:x:90001:\n")},
		"group 5000 9500 80001 90001":   {stdout: []byte("directory-team:x:5000:\nother-team:x:9500:\ndirectory-primary:x:80001:\nother-primary:x:90001:\n")},
	}
}

func TestDirectoryGroupsBindToServiceThatOwnsUID(t *testing.T) {
	// An nslcd that completes every search (nslcdSearchesComplete).
	startFakeNSLCD(t, &fakeNSLCD{})
	for _, tc := range []struct {
		name, order, firstName string
	}{
		{"first service", "himmelblau ldap", "himmelblau"},
		{"second service", "ldap himmelblau", "ldap"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crossServiceFiles(t, "files "+tc.order, "files "+tc.order, "")
			results := crossServiceResults()
			if tc.firstName == "ldap" {
				results["passwd alex"] = results["passwd 90001"]
			}
			r := newFakeNSS(&fakeRun{results: results})
			for _, account := range []struct {
				uid, gid  int
				ids       []int
				names     []string
				directory useridentity.Directory
			}{
				{80001, 80001, []int{5000, 80001}, []string{"directory-team", "directory-primary"}, useridentity.DirectoryEntraID},
				{90001, 90001, []int{9500, 90001}, []string{"other-team", "other-primary"}, useridentity.DirectoryLDAP},
			} {
				ids, err := r.GroupIDs(Account{Name: "alex", UID: account.uid, GID: account.gid})
				if err != nil || !reflect.DeepEqual(ids, account.ids) {
					t.Errorf("uid %d group ids = %v, %v; want %v", account.uid, ids, err, account.ids)
				}
				facts, err := r.DirectoryFactsForUID(account.uid, time.Now())
				if err != nil || facts.Directory != account.directory || !reflect.DeepEqual(facts.Groups, account.names) {
					t.Errorf("uid %d facts = %+v, %v; want groups %v", account.uid, facts, err, account.names)
				}
			}
		})
	}
}

func TestDirectoryGroupsFollowEligibleNSSServices(t *testing.T) {
	// An nslcd that completes every search (nslcdSearchesComplete).
	startFakeNSLCD(t, &fakeNSLCD{})
	for _, tc := range []struct {
		name, passwdServices, initgroupsServices, localGroups string
		extraPasswd, extraInitgroups                          commandResult
		ldapPasswd                                            *commandResult
		globalInitgroups                                      string
		want                                                  []int
		wantErr                                               bool
	}{
		{
			name: "service without a passwd account", passwdServices: "files himmelblau ldap", initgroupsServices: "files himmelblau ldap systemd",
			extraInitgroups: commandResult{stdout: []byte("alex 6000\n")}, want: []int{5000, 6000, 80001},
		},
		{
			name: "local group included", passwdServices: "files himmelblau ldap", initgroupsServices: "files himmelblau ldap",
			localGroups: "local-team:x:7000:alex\n", want: []int{5000, 7000, 80001},
		},
		{
			name: "local group excluded", passwdServices: "files himmelblau ldap", initgroupsServices: "himmelblau ldap",
			localGroups: "local-team:x:7000:alex\n", want: []int{5000, 80001},
		},
		{
			name: "service with matching uid", passwdServices: "files himmelblau ldap", initgroupsServices: "files himmelblau ldap systemd",
			extraPasswd:     commandResult{stdout: []byte("alex:x:80001:80001::/home/alex:/bin/sh\n")},
			extraInitgroups: commandResult{stdout: []byte("alex 6000\n")}, want: []int{5000, 6000, 80001},
		},
		{
			name: "initgroups-only service", passwdServices: "files himmelblau", initgroupsServices: "files himmelblau ldap",
			want: []int{5000, 80001},
		},
		{
			name: "service lookup error", passwdServices: "files himmelblau ldap", initgroupsServices: "files himmelblau ldap",
			ldapPasswd: &commandResult{exitCode: 1}, wantErr: true,
		},
		{
			name: "no shared name", passwdServices: "files himmelblau ldap", initgroupsServices: "files himmelblau ldap",
			ldapPasswd: &commandResult{exitCode: getentExitNotFound}, globalInitgroups: "alex 80001 6100\n", want: []int{6100, 80001},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crossServiceFiles(t, tc.passwdServices, tc.initgroupsServices, tc.localGroups)
			results := crossServiceResults()
			if tc.extraInitgroups.stdout != nil {
				results["-s systemd initgroups alex"] = tc.extraInitgroups
			}
			if tc.extraPasswd.stdout != nil {
				results["-s systemd passwd alex"] = tc.extraPasswd
			}
			if tc.ldapPasswd != nil {
				results["-s ldap passwd alex"] = *tc.ldapPasswd
			}
			if tc.globalInitgroups != "" {
				results["initgroups alex"] = commandResult{stdout: []byte(tc.globalInitgroups)}
			}
			ids, err := newFakeNSS(&fakeRun{results: results}).GroupIDs(Account{Name: "alex", UID: 80001, GID: 80001})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("service lookup succeeded with ids %v", ids)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(ids, tc.want) {
				t.Fatalf("group ids = %v, %v; want %v", ids, err, tc.want)
			}
		})
	}
}

func TestDirectoryGroupsWithoutNSSConfiguration(t *testing.T) {
	crossServiceFiles(t, "files himmelblau ldap", "files himmelblau ldap", "")
	if err := os.Remove(nsswitchPath); err != nil {
		t.Fatal(err)
	}
	ids, err := newFakeNSS(&fakeRun{results: crossServiceResults()}).GroupIDs(Account{Name: "alex", UID: 80001, GID: 80001})
	if err != nil || !reflect.DeepEqual(ids, []int{5000, 9500, 80001, 90001}) {
		t.Fatalf("groups with default NSS configuration = %v, %v", ids, err)
	}
}

func TestSSSDSIDlessGroupConfirmationBindsToUID(t *testing.T) {
	// An nslcd that completes every search (nslcdSearchesComplete).
	startFakeNSLCD(t, &fakeNSLCD{})
	for _, tc := range []struct {
		name     string
		ldapUser commandResult
		want     []int
		wantErr  bool
	}{
		{"different uid", commandResult{stdout: []byte("alex:x:90001:90001::/home/alex:/bin/sh\n")}, []int{5000, 80001}, false},
		{"no passwd account", commandResult{exitCode: getentExitNotFound}, []int{5000, 9500, 80001}, false},
		{"matching uid", commandResult{stdout: []byte("alex:x:80001:80001::/home/alex:/bin/sh\n")}, []int{5000, 9500, 80001}, false},
		{"service lookup error", commandResult{exitCode: 1}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crossServiceFiles(t, "files sss ldap", "files sss ldap", "")
			const domainSID = "S-1-5-21-1-2-3"
			startFakeSSSD(t, map[string]string{"gid:5000": domainSID + "-5000"})
			sssd, err := dialSSSDNSS(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer sssd.Close()
			r := newFakeNSS(&fakeRun{results: map[string]commandResult{
				"-s ldap passwd alex":     tc.ldapUser,
				"-s ldap initgroups alex": {stdout: []byte("alex 90001 9500\n")},
			}})
			ids, err := r.sssdGroupsOfDomain(sssd, []int{5000, 9500, 80001}, Account{Name: "alex", UID: 80001, GID: 80001}, domainSID)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("service lookup succeeded with groups %v", ids)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(ids, tc.want) {
				t.Fatalf("confirmed groups = %v, %v; want %v", ids, err, tc.want)
			}
		})
	}
}
