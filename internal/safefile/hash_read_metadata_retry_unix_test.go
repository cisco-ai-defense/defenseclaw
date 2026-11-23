// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package safefile

import (
	"os"
	"testing"
)

// moveChangeTimeOnly changes the mode, which moves only ctime: size and mtime
// stay. Each call sets a mode other than the previous call's.
func moveChangeTimeOnly(t *testing.T, path string, call int) {
	t.Helper()
	mode := os.FileMode(0o600)
	if call%2 == 0 {
		mode = 0o620
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
