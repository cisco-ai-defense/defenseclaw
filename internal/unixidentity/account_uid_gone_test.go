// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package unixidentity

import (
	"context"
	"errors"
	"testing"
)

// GAP-1864 (checker note on 3ab01870ba): a deleted macOS local account
// whose name another account now holds was read as present by a check of
// the name alone, so the deleted uid's identity record was relisted every
// guardian pass. The uid has left when the name's record holds another uid
// and no record across the search policy holds this one; every unclear
// answer keeps the record.
func TestAccountUIDGoneWhenTheNameNowHoldsAnotherUID(t *testing.T) {
	const uid = 507
	found := func(out string) func() (commandResult, error) {
		return func() (commandResult, error) { return commandResult{stdout: []byte(out)}, nil }
	}
	notFound := func() (commandResult, error) { return commandResult{exitCode: 56}, nil }
	failed := func() (commandResult, error) { return commandResult{}, errors.New("unixidentity: dscl timed out") }
	online, offline := func() bool { return false }, func() bool { return true }
	cases := []struct {
		name    string
		read    func() (commandResult, error)
		search  func() (commandResult, error)
		offline func() bool
		want    bool
	}{
		{"no record of the name", notFound, failed, online, true},
		{"no record of the name, a node offline", notFound, found(""), offline, false},
		{"the name still holds the uid", found("UniqueID: 507\n"), found(""), online, false},
		{"the name still holds the uid, value on the next line", found("UniqueID:\n 507\n"), found(""), online, false},
		{"the name holds another uid and no record holds this one", found("UniqueID: 1607\n"), found("\n"), online, true},
		{"the name holds another uid on the next line and no record holds this one", found("UniqueID:\n 1607\n"), found(""), online, true},
		{"the name holds another uid but another name holds this one", found("UniqueID: 1607\n"), found("pidmz\t\tUniqueID = (\n    507\n)\n"), online, false},
		{"the name holds another uid, the search fails", found("UniqueID: 1607\n"), failed, online, false},
		{"the name holds another uid, the search exits non-zero", found("UniqueID: 1607\n"), func() (commandResult, error) { return commandResult{exitCode: 14}, nil }, online, false},
		{"the name holds another uid, a node offline", found("UniqueID: 1607\n"), found(""), offline, false},
		{"the read fails", failed, found(""), online, false},
		{"the read exits with another DS error", func() (commandResult, error) { return commandResult{exitCode: 14}, nil }, found(""), online, false},
		{"the read has no UniqueID", found("RecordName: pidmu\n"), found(""), online, false},
		{"the read has two UniqueIDs", found("UniqueID: 1607 1608\n"), found(""), online, false},
		{"the read has an invalid UniqueID", found("UniqueID: abc\n"), found(""), online, false},
	}
	for _, tc := range cases {
		if got := dsclAccountUIDGone(uid, tc.read, tc.search, tc.offline); got != tc.want {
			t.Errorf("%s: dsclAccountUIDGone = %v, want %v", tc.name, got, tc.want)
		}
	}
	for _, name := range []string{"", "a/b", "a b"} {
		if AccountUIDGone(context.Background(), name, uid) {
			t.Errorf("AccountUIDGone(%q) = true for an invalid name", name)
		}
	}
	if AccountUIDGone(context.Background(), "pidmu", 0) {
		t.Error("AccountUIDGone(uid 0) = true")
	}
}
