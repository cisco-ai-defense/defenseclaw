// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procprobe

import (
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// p0-round GAP-1389: the Linux event source names the account of a process
// as its creation event arrives, so a session that exits before a poll still
// has an owner.
func TestOwnerOfAProcessIsNamedByItsPID(t *testing.T) {
	useDirectoryAccounts(t, &directoryAccounts{accounts: map[int]unixidentity.Account{
		os.Getuid(): {Name: "lane-local", UID: os.Getuid(), Home: "/home/lane-local"},
	}})
	if got := OwnerOfPID(os.Getpid()); got != "lane-local" {
		t.Fatalf("OwnerOfPID(self) = %q, want the account database's name", got)
	}
	if got := OwnerOfPID(1 << 30); got != "" {
		t.Fatalf("OwnerOfPID(no such process) = %q, want none", got)
	}
}
