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

func TestAccountGroupsBelongToVerifiedUID(t *testing.T) {
	// An nslcd that completes every search (nslcdSearchesComplete).
	startFakeNSLCD(t, &fakeNSLCD{})
	for _, tc := range []struct {
		name, service, directoryName string
	}{
		{"AD short name", "sss", "alex"},
		{"AD qualified name", "sss", "alex@corp.example.com"},
		{"LDAP via SSSD", "sss", "alex"},
		{"LDAP via NSS", "ldap", "alex"},
		{"Entra via Himmelblau", "himmelblau", "alex"},
		{"Entra via aad", "aad", "alex"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldPasswd, oldGroup, oldNSS := localPasswdPath, localGroupPath, nsswitchPath
			t.Cleanup(func() { localPasswdPath, localGroupPath, nsswitchPath = oldPasswd, oldGroup, oldNSS })
			dir := t.TempDir()
			localPasswdPath, localGroupPath, nsswitchPath = filepath.Join(dir, "passwd"), filepath.Join(dir, "group"), filepath.Join(dir, "nsswitch.conf")
			for path, content := range map[string]string{
				localPasswdPath: "alex:x:2100:2100::/home/alex:/bin/sh\n",
				localGroupPath:  "local-primary:x:2100:\nlocal-team:x:7000:alex\n",
				nsswitchPath:    "passwd: files " + tc.service + "\ninitgroups: files " + tc.service + "\ngroup: files " + tc.service + "\n",
			} {
				if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.service == "sss" {
				startFakeSSSD(t, nil)
			}
			localLine := "alex:x:2100:2100::/home/alex:/bin/sh\n"
			directoryLine := tc.directoryName + ":x:80001:80001::/home/directory:/bin/sh\n"
			results := map[string]commandResult{
				"passwd 2100":                        {stdout: []byte(localLine)},
				"passwd 80001":                       {stdout: []byte(directoryLine)},
				"passwd alex":                        {stdout: []byte(localLine)},
				"-s " + tc.service + " passwd 80001": {stdout: []byte(directoryLine)},
				"-s " + tc.service + " passwd " + tc.directoryName: {stdout: []byte(directoryLine)},
				"initgroups alex":                                      {stdout: []byte("alex 2100 5000 7000\n")},
				"initgroups " + tc.directoryName:                       {stdout: []byte(tc.directoryName + " 80001 5000\n")},
				"-s " + tc.service + " initgroups " + tc.directoryName: {stdout: []byte(tc.directoryName + " 80001 5000\n")},
				"group 2100 5000 7000":                                 {stdout: []byte("local-primary:x:2100:\npolicy-team:x:5000:\nlocal-team:x:7000:\n")},
				"group 2100 5000 7000 80001":                           {stdout: []byte("local-primary:x:2100:\npolicy-team:x:5000:\nlocal-team:x:7000:\ndirectory-primary:x:80001:\n")},
				"group 5000 80001":                                     {stdout: []byte("policy-team:x:5000:\ndirectory-primary:x:80001:\n")},
			}
			if tc.directoryName == "alex" {
				results["initgroups alex"] = commandResult{stdout: []byte("alex 2100 5000 7000 80001\n")}
			}
			r := newFakeNSS(&fakeRun{results: results})
			local := Account{Name: "alex", UID: 2100, GID: 2100}
			ids, err := r.GroupIDs(local)
			if err != nil || !reflect.DeepEqual(ids, []int{2100, 7000}) {
				t.Errorf("local account group ids = %v, %v", ids, err)
			}
			localFacts, err := r.DirectoryFactsForUID(2100, time.Now())
			if err != nil || localFacts.Directory != useridentity.DirectoryLocal || !reflect.DeepEqual(localFacts.Groups, []string{"local-primary", "local-team"}) {
				t.Errorf("local account facts = %+v, %v", localFacts, err)
			}
			directory := Account{Name: tc.directoryName, UID: 80001, GID: 80001}
			ids, err = r.GroupIDs(directory)
			if err != nil || !reflect.DeepEqual(ids, []int{5000, 80001}) {
				t.Errorf("directory account group ids = %v, %v", ids, err)
			}
			directoryFacts, err := r.DirectoryFactsForUID(80001, time.Now())
			if err != nil || !reflect.DeepEqual(directoryFacts.Groups, []string{"policy-team", "directory-primary"}) {
				t.Errorf("directory account facts = %+v, %v", directoryFacts, err)
			}
			if err := os.WriteFile(localGroupPath, []byte("local-primary:x:2100:\nlocal-team:x:7000:\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			localFacts, err = r.DirectoryFactsForUID(2100, time.Now())
			if err != nil || !reflect.DeepEqual(localFacts.Groups, []string{"local-primary"}) {
				t.Errorf("local account without supplementary membership = %+v, %v", localFacts, err)
			}
		})
	}
}

func TestSSSDGroupConfirmationUsesAccountUID(t *testing.T) {
	oldPasswd, oldGroup, oldNSS := localPasswdPath, localGroupPath, nsswitchPath
	t.Cleanup(func() { localPasswdPath, localGroupPath, nsswitchPath = oldPasswd, oldGroup, oldNSS })
	dir := t.TempDir()
	localPasswdPath, localGroupPath, nsswitchPath = filepath.Join(dir, "passwd"), filepath.Join(dir, "group"), filepath.Join(dir, "nsswitch.conf")
	for path, content := range map[string]string{
		localPasswdPath: "alex:x:2100:2100::/home/alex:/bin/sh\n",
		localGroupPath:  "local-team:x:7000:alex\n",
		nsswitchPath:    "passwd: files sss\ninitgroups: files sss\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const domainSID = "S-1-5-21-1-2-3"
	startFakeSSSD(t, map[string]string{"gid:5000": domainSID + "-5000"})
	sssd, err := dialSSSDNSS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sssd.Close()
	account := Account{Name: "alex", UID: 80001, GID: 80001}
	ids, err := newFakeNSS(&fakeRun{}).sssdGroupsOfDomain(sssd, []int{5000, 7000, 80001}, account, domainSID)
	if err != nil || !reflect.DeepEqual(ids, []int{5000, 80001}) {
		t.Fatalf("verified directory groups = %v, %v; want only the uid's memberships", ids, err)
	}
}

func TestQualifiedDirectoryGroupsBelongToAccountUID(t *testing.T) {
	for _, name := range []string{"alex", "alex@corp.example.com"} {
		t.Run(name, func(t *testing.T) {
			oldPasswd, oldGroup, oldNSS := localPasswdPath, localGroupPath, nsswitchPath
			t.Cleanup(func() { localPasswdPath, localGroupPath, nsswitchPath = oldPasswd, oldGroup, oldNSS })
			dir := t.TempDir()
			localPasswdPath, localGroupPath, nsswitchPath = filepath.Join(dir, "passwd"), filepath.Join(dir, "group"), filepath.Join(dir, "nsswitch.conf")
			for path, content := range map[string]string{
				localPasswdPath: name + ":x:2100:2100::/home/local:/bin/sh\n",
				localGroupPath:  "local-team:x:7000:" + name + "\n",
				nsswitchPath:    "passwd: files sss\ninitgroups: files sss\n",
			} {
				if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			r := newFakeNSS(&fakeRun{results: map[string]commandResult{
				`initgroups corp.example.com\alex`: {stdout: []byte("corp.example.com\\alex 80001 5000\n")},
			}})
			ids, qualified, err := r.accountGroupIDs(Account{Name: name, UID: 80001, GID: 80001}, "corp.example.com")
			if err != nil || !qualified || !reflect.DeepEqual(ids, []int{5000, 80001}) {
				t.Fatalf("qualified directory groups = %v, %t, %v; want only the directory uid's groups", ids, qualified, err)
			}
		})
	}
}
