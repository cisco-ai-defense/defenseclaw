//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"os/user"
	"strconv"
	"testing"
)

// A real folder with an entry for root keeps the account rule open and the
// strict rule closed; an entry for everyone is refused by both.
func TestValidatePathACLForAccountOnARealFolder(t *testing.T) {
	account, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Skipf("account name unavailable: %v", err)
	}
	dir := t.TempDir()
	addDarwinACL(t, dir, "user:root allow add_file,delete_child")
	if err := ValidatePathACLForAccount(dir, os.Geteuid(), account.Username); err != nil {
		t.Fatalf("an entry for root refused: %v", err)
	}
	if err := ValidatePathACL(dir); err == nil {
		t.Fatal("the strict rule accepted an entry for root")
	}
	other := t.TempDir()
	addDarwinACL(t, other, "everyone allow add_file,delete_child")
	if err := ValidatePathACLForAccount(other, os.Geteuid(), account.Username); err == nil {
		t.Fatal("an entry for everyone was accepted")
	}
}
