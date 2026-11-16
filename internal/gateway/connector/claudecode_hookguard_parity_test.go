// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

// defenseclaw-hook-guard.exe (GAP-2467) is built from internal/hookguard
// alone, so its Windows absolute-path rule is its own copy: it must read every
// path as the connector's recognizers do, or Setup would write a guard argv
// the guard refuses.
func TestHookGuardAbsolutePathRuleMatchesTheConnector(t *testing.T) {
	for _, path := range []string{
		`C:\Users\u\.local\bin\defenseclaw-hook.exe`, `c:/Users/u/.local/bin/defenseclaw-hook.exe`,
		`\\server\share\defenseclaw-hook.exe`, `//server/share/defenseclaw-hook.exe`, `\\`, `//`,
		`C:`, `C:x`, `1:\x`, `/home/u/.local/bin/defenseclaw-hook.exe`, `defenseclaw-hook.exe`, ``,
	} {
		if got, want := hookguard.IsWindowsAbsolutePath(path), isWindowsAbsolutePath(path); got != want {
			t.Errorf("hookguard.IsWindowsAbsolutePath(%q) = %v, connector %v", path, got, want)
		}
	}
}
