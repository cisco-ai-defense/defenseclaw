//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// GAP-1280: the /etc/group groups that list an SSSD account were added to
// the groups of its domain-qualified initgroups answer also when
// nsswitch.conf leaves files out of initgroups, so login never gives the
// account those groups, and a membership the OS ignores selected a group
// profile. They are added only when initgroups (or group, which glibc uses
// without an initgroups line) reads /etc/group; GAP-0729 stays: with files,
// or with no list at all, they are added.
func TestLocalGroupsFollowTheInitgroupsServices(t *testing.T) {
	origNSS, origGroup := nsswitchPath, localGroupPath
	t.Cleanup(func() { nsswitchPath, localGroupPath = origNSS, origGroup })
	dir := t.TempDir()
	nsswitchPath, localGroupPath = filepath.Join(dir, "nsswitch.conf"), filepath.Join(dir, "group")
	if err := os.WriteFile(localGroupPath, []byte("docker:x:7000:alice\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := newFakeNSS(&fakeRun{results: map[string]commandResult{
		`initgroups corp.example.com\alice`: {stdout: []byte("corp.example.com\\alice 80001 5000\n")},
	}})
	withLocal, withoutLocal := []int{5000, 7000, 80001}, []int{5000, 80001}
	for _, tc := range []struct {
		nsswitch string // "" for no nsswitch.conf
		want     []int
	}{
		{"", withLocal},
		{"passwd: files sss\n", withLocal},
		{"passwd: files sss\ngroup: files sss\n", withLocal},
		{"passwd: files sss\ngroup: files [SUCCESS=merge] sss\n", withLocal},
		{"passwd: files sss\ngroup: compat sss\n", withLocal},
		{"passwd: files sss\ninitgroups: sss files\ngroup: sss\n", withLocal},
		{"passwd: files sss\ngroup: sss\n", withoutLocal},
		{"passwd: files sss\ninitgroups: sss\ngroup: files sss\n", withoutLocal},
		{"passwd: files sss\ninitgroups: [SUCCESS=continue] sss\n", withoutLocal},
	} {
		_ = os.Remove(nsswitchPath)
		if tc.nsswitch != "" {
			if err := os.WriteFile(nsswitchPath, []byte(tc.nsswitch), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		ids, qualified, err := r.accountGroupIDs(Account{Name: "alice", UID: 80001, GID: 80001}, "corp.example.com")
		if err != nil || !qualified || !reflect.DeepEqual(ids, tc.want) {
			t.Errorf("nsswitch %q: groups = %v, %v, %v; want %v", tc.nsswitch, ids, qualified, err, tc.want)
		}
	}
}
