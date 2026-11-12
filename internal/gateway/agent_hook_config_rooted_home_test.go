// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestAgentHookConfigRootedHomeOverrideIsALiteralFolder pins that a launch
// with a config home spelled as a rooted path (/tmp/x) is judged as a
// different hook configuration folder on every host, and that the agent home
// itself stays allowed, also in the Git Bash drive spelling on Windows.
func TestAgentHookConfigRootedHomeOverrideIsALiteralFolder(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	guard := newAgentHookConfigGuard(home, home)
	own := filepath.Join(home, ".claude")
	spelled := own
	if runtime.GOOS == "windows" {
		volume := filepath.VolumeName(own)
		spelled = "/" + strings.ToLower(strings.TrimSuffix(volume, ":")) + filepath.ToSlash(own[len(volume):])
	}
	for _, tc := range []struct {
		value    string
		override bool
	}{
		{"/tmp/x", true},
		{"/tmp/other_path", true},
		{spelled, false},
		{"~/.claude", false},
	} {
		got := agentHookConfigLiteralHomeOverride("CLAUDE_CONFIG_DIR", tc.value, guard, "claude") != ""
		if got != tc.override {
			t.Errorf("CLAUDE_CONFIG_DIR=%s: override=%t, want %t", tc.value, got, tc.override)
		}
	}
}
