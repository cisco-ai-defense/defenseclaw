// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
)

// The protected-write tests build the user's home in t.TempDir() and compare
// it with write targets whose links are resolved. macOS keeps the temporary
// directory below the /var -> /private/var link, so the test process uses the
// physical directory, as a real home under /Users is (GAP-0975). init runs
// before TestMain and every t.TempDir call.
func init() {
	if runtime.GOOS == "windows" {
		return
	}
	if dir, err := filepath.EvalSymlinks(os.TempDir()); err == nil && dir != os.TempDir() {
		_ = os.Setenv("TMPDIR", dir)
	}
}
