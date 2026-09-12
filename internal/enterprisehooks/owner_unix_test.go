//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os/user"
	"strconv"
	"strings"
	"testing"
)

func TestResolveOwnerBindsGIDToUIDAccount(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid == 0 {
		t.Skip("test requires a resolvable non-root account")
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveOwner(t.TempDir(), uid, gid); err != nil {
		t.Fatalf("matching account identity rejected: %v", err)
	}
	if _, _, err := resolveOwner(t.TempDir(), uid, gid+1); err == nil || !strings.Contains(err.Error(), "primary gid") {
		t.Fatalf("mismatched gid error = %v, want primary-gid refusal", err)
	}
}
