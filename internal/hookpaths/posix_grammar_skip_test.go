// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"runtime"
	"testing"
)

// skipPOSIXGrammarOnWindows skips a test whose rows are POSIX shell commands
// judged against a POSIX home. Natively on Windows the test home is a
// C:\ path, which selects the Windows grammar, so the rows do not describe
// what they pin there (GAP-1038, GAP-1450). The Windows grammar has its own
// tests (action_windows_*_test.go).
func skipPOSIXGrammarOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-grammar rows need a POSIX home (GAP-1038)")
	}
}
