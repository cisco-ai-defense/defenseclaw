// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"path/filepath"
	"testing"
)

// realTempDir is a new temporary folder named by its real path. A scan that
// refuses links reads a home given through one as linked, and macOS names its
// temporary folders through /var, a link to /private/var, unless TMPDIR says
// otherwise (GAP-2156).
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
