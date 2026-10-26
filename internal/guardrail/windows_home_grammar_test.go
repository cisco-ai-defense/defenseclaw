// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"runtime"
	"testing"
)

// skipNativeWindowsHomeGrammar skips a suite that pins the POSIX grammar.
// The decision reads a call by the form of its active home: a native
// Windows home, which every t.TempDir home is on Windows, selects the
// Windows grammar (actionWindowsCommandDecision, actionWindowsTargetMention)
// even for a Bash-tool call. GAP-1717 tracks reading POSIX-dialect calls on
// Windows with the POSIX grammar; these suites run on Windows again then.
func skipNativeWindowsHomeGrammar(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX grammar suite; a native Windows home selects the Windows grammar (GAP-1717)")
	}
}
