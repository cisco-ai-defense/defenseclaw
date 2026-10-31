// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package unixidentity

import (
	"errors"
	"testing"
)

type localNodeFakeResolver struct {
	Resolver
	holders map[int]string
}

func (r localNodeFakeResolver) LookupUID(uid int) (Account, error) {
	name, ok := r.holders[uid]
	if !ok {
		return Account{}, ErrNotFound
	}
	return Account{Name: name, UID: uid}, nil
}

// GAP-0551 on macOS: os/user names a bound Active Directory account (from
// Open Directory's cache during an outage), and profile explain took it for
// a local account because ConfirmLocalAccount always said yes there. Only an
// account the local directory node holds with the uid, and no mobile
// account cached from a directory, is a local one.
func TestMacLocalAccountProofNeedsTheLocalDirectoryNode(t *testing.T) {
	local := map[string]LocalAccountRecord{"bob": {UID: 502}, "carol": {UID: 503}}
	record := func(name string) (LocalAccountRecord, bool, error) {
		found, ok := local[name]
		if !ok {
			return LocalAccountRecord{}, false, errors.New("dscl exited 56")
		}
		return found, true, nil
	}
	mobile := func() (map[string]string, error) {
		return map[string]string{"carol": "/Active Directory/CORP/corp.example.com"}, nil
	}
	r := localNodeFakeResolver{holders: map[int]string{502: "bob", 503: "carol", 1261896283: "alice", 504: "dave"}}
	if err := confirmLocalNodeAccount(r, 502, "bob", record, mobile); err != nil {
		t.Fatalf("local account bob: %v", err)
	}
	for _, c := range []struct {
		uid  int
		name string
		why  string
	}{
		{1261896283, "alice", "a directory account the local node does not hold"},
		{503, "carol", "a mobile account"},
		{504, "bob", "a local account named with another uid"},
		{502, "bob/../x", "a name dscl would read as a path"},
	} {
		if err := confirmLocalNodeAccount(r, c.uid, c.name, record, mobile); err == nil {
			t.Fatalf("%s (%s, uid %d) was taken for a local account", c.why, c.name, c.uid)
		}
	}
	shared := localNodeFakeResolver{holders: map[int]string{502: "alice"}}
	if err := confirmLocalNodeAccount(shared, 502, "bob", record, mobile); err == nil {
		t.Fatal("a uid the account database gives another account was taken for the local account bob")
	}
	unread := func() (map[string]string, error) { return nil, errors.New("dscl timed out") }
	if err := confirmLocalNodeAccount(r, 502, "bob", record, unread); err == nil {
		t.Fatal("an account whose mobile state could not be read was taken for a local account")
	}
}
