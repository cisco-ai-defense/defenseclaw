// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"testing"
)

func createTestDirectoryRedirect(t *testing.T, link, target string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create directory symlink fixture: %v", err)
	}
}

// grantTestUntrustedWriter lets a principal outside the trusted set write
// path. On Unix that is the world-write bit.
func grantTestUntrustedWriter(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatalf("grant world write: %v", err)
	}
}
