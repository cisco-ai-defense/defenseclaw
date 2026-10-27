// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The tests build their homes in the temporary directory, which macOS keeps
// below the /var -> /private/var link, and compare their own spelling of the
// home with resolved targets (GAP-0975), so they get the physical directory.
// A home below a link is a product case of its own (GAP-1725,
// gap1725_linked_home_test.go).
func TestMain(m *testing.M) {
	if runtime.GOOS != "windows" {
		if dir, err := filepath.EvalSymlinks(os.TempDir()); err == nil {
			_ = os.Setenv("TMPDIR", dir)
		}
	}
	os.Exit(m.Run())
}
