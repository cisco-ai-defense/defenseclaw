// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package useridentity

import (
	"os"
	"path/filepath"
	"testing"
)

// A FILE or DIR cache named by the user must belong to that user before its
// principal is used as a session claim.
func TestCredentialCacheFileRequiresEffectiveOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "krb5cc")
	if err := os.WriteFile(path, []byte{5, 4, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !regularFileOwnedByUID(info, os.Geteuid()) {
		t.Fatal("own regular cache was rejected")
	}
	if regularFileOwnedByUID(info, os.Geteuid()+1) {
		t.Fatal("another user cache was accepted")
	}
}
