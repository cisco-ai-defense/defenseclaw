// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"os"
	"strings"
	"testing"
)

// IsShellStartupName reports an environment variable through which the
// account's shell startup reaches a hook reading: a startup file (BASH_ENV,
// ENV), an exported bash function (BASH_FUNC_*), and the options a
// non-interactive bash imports (BASHOPTS, SHELLOPTS, GLOBIGNORE). A
// developer shell, a shared host's dcenv or a RHEL profile (which exports
// the which function) can hold any of them (GAP-0293).
func IsShellStartupName(name string) bool {
	switch name {
	case "BASH_ENV", "ENV", "BASHOPTS", "SHELLOPTS", "GLOBIGNORE":
		return true
	}
	return strings.HasPrefix(name, "BASH_FUNC_")
}

// ClearShellStartup removes every shell startup variable from the process.
// TestMain calls it so no test reads the host's startup.
func ClearShellStartup() {
	for _, entry := range os.Environ() {
		if name, _, _ := strings.Cut(entry, "="); IsShellStartupName(name) {
			_ = os.Unsetenv(name)
		}
	}
}

// ClearShellStartupT removes the shell startup variables for one test and
// restores them afterwards. A test that needs a startup sets it after.
func ClearShellStartupT(t testing.TB) {
	t.Helper()
	for _, entry := range os.Environ() {
		if name, _, _ := strings.Cut(entry, "="); IsShellStartupName(name) {
			t.Setenv(name, "")
			if err := os.Unsetenv(name); err != nil {
				t.Fatalf("unset %s: %v", name, err)
			}
		}
	}
}
