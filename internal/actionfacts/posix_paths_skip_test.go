// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"runtime"
	"testing"
)

// skipPOSIXPathsOnWindows skips a test whose rows place POSIX directories
// (/repo, /home/alice) with the host's path functions, which read them as
// rooted paths of the current drive on Windows (GAP-1038).
func skipPOSIXPathsOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory rows (GAP-1038)")
	}
}
