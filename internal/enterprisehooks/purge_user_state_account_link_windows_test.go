// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPurgeWindowsUserStateIdentifiesOnlyTheAccountFolderLink(t *testing.T) {
	previous := windowsEnterpriseMutationIdentityCheck
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	t.Cleanup(func() { windowsEnterpriseMutationIdentityCheck = previous })
	sid := currentWindowsTestSID(t)
	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	outside, canary := outsideDataDirTree(t, home)
	link := filepath.Join(home, ".defenseclaw")
	plantWindowsAccountJunction(t, link, outside, sid)
	if err := PurgeWindowsUserState(home, sid.String(), ""); !errors.Is(err, ErrWindowsUserStateOnlyLink) {
		t.Fatalf("account folder link = %v, want only-link result", err)
	}
	requireOutsideDataDirTreeUnchanged(t, outside, canary)
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("the account's link changed: %v", err)
	}

	// A second cleanup failure must retain the ordinary failed-purge result.
	rollback := filepath.Join(home, ".defenseclaw.rollback-0123456789abcdef0123456789abcdef")
	plantWindowsAccountJunction(t, rollback, outside, sid)
	if err := PurgeWindowsUserState(home, sid.String(), ""); errors.Is(err, ErrWindowsUserStateOnlyLink) {
		t.Fatalf("account link and rollback link were reported as one remaining link: %v", err)
	}
	requireOutsideDataDirTreeUnchanged(t, outside, canary)

	plainHome := filepath.Join(t.TempDir(), "plain-home")
	plain := filepath.Join(plainHome, ".defenseclaw")
	if err := os.MkdirAll(plain, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := PurgeWindowsUserState(plainHome, sid.String(), ""); err != nil {
		t.Fatalf("plain account folder: %v", err)
	}
}
