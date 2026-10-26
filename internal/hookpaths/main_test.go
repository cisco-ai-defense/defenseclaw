// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The gateway hands hookpaths a physical home (trustedPhysicalHome,
// GAP-0975): write targets are compared after their links are resolved. The
// tests build their homes in the temporary directory, which macOS keeps below
// the /var -> /private/var link, so they get the physical directory too.
func TestMain(m *testing.M) {
	if runtime.GOOS != "windows" {
		if dir, err := filepath.EvalSymlinks(os.TempDir()); err == nil {
			_ = os.Setenv("TMPDIR", dir)
		}
	}
	os.Exit(m.Run())
}
