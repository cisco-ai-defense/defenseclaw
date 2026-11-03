// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procprobe

import (
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// p0-round GAP-1389: the Linux event source reads the uid of a process as
// its creation event arrives, and the account name once a lookup answered,
// so a session that exits before a poll still has an owner.
func TestOwnerOfAProcessIsItsUIDAndTheCachedAccountName(t *testing.T) {
	useDirectoryAccounts(t, &directoryAccounts{accounts: map[int]unixidentity.Account{
		os.Getuid(): {Name: "lane-local", UID: os.Getuid(), Home: "/home/lane-local"},
	}})
	if OwnerNameOfUID(os.Getuid()) != "lane-local" {
		t.Fatal("the account database did not name this uid")
	}
	uid, name := OwnerOfPID(os.Getpid())
	if uid == nil || *uid != os.Geteuid() || name != "lane-local" {
		t.Fatalf("OwnerOfPID(self) = %v %q, want uid %d and the account database's name", uid, name, os.Geteuid())
	}
	if uid, name := OwnerOfPID(1 << 30); uid != nil || name != "" {
		t.Fatalf("OwnerOfPID(no such process) = %v %q, want none", uid, name)
	}
}
