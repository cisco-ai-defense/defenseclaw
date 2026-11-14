// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"runtime"
	"testing"
)

// srdPOSIXHost makes the hook judge a shell call as a POSIX host does. The
// secret-read chain tests below send POSIX shell commands over POSIX paths.
// On a Windows host the hook reads a Bash call with the Windows dialect
// (windowsHookHost: Git Bash is told apart only when the call reads alone) and
// does not place a relative operand in a directory the gateway cannot see
// (toolChainDriveMounts); both readings join the chain on any call they cannot
// prove, so every row that expects no chain gives one there. Those rows state
// the POSIX reading, so they pin it the same way on every host. The Windows
// reading is judged by the Windows-dialect tests.
func srdPOSIXHost(t *testing.T) {
	t.Helper()
	savedHost, savedMounts := windowsHookHost, toolChainDriveMounts
	windowsHookHost = func() bool { return false }
	toolChainDriveMounts = false
	t.Cleanup(func() { windowsHookHost, toolChainDriveMounts = savedHost, savedMounts })
}

// srdShellPath is a directory of this host spelled for a POSIX shell command
// line (forward slashes; t.TempDir has backslashes on Windows).
func srdShellPath(dir string) string { return filepath.ToSlash(dir) }

// srdConservativeJoin is true for a call whose working directory exists on a
// Windows host: it is a C: path, which the POSIX reading of a shell call does
// not take as absolute, so no operand under it names one exact file and the
// chain joins the read and the upload it cannot tell apart. The row then may
// raise a chain the POSIX table does not expect (more alerts, never fewer): a
// row that expects a chain must still raise it. The same rows run without a
// working directory on the host judge the exact verdicts on Windows too.
func srdConservativeJoin(localCWD bool) bool { return localCWD && runtime.GOOS == "windows" }
