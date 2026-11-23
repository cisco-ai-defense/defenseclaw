// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import "testing"

// A user registration an earlier release of this install wrote names the
// transition image or an earlier launch folder; the guardian keeps treating
// it as DefenseClaw's own until it rewrites it (GAP-0751). Another install's
// image, a copy and a staging folder stay foreign, and other platforms keep
// the exact binary.
func TestGuardOwnsAnEarlierHookImageOfTheSameInstall(t *testing.T) {
	const bin = `C:\Program Files\Cisco\DefenseClaw\bin`
	current := bin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`
	args := []any{"hook", "--connector", "claudecode", "--enterprise-managed"}
	req := GuardRequest{Connector: ConnectorClaudeCode, GOOS: "windows", HookBinary: current}
	for name, tc := range map[string]struct {
		binary string
		owned  bool
	}{
		"current launch image":    {current, true},
		"transition image":        {bin + `\defenseclaw-hook.exe`, true},
		"earlier launch folder":   {bin + `\hooks\aaaaaaaaaaaaaaaa\defenseclaw-hook.exe`, true},
		"another install root":    {`C:\Program Files\Other\bin\hooks\0123456789abcdef\defenseclaw-hook.exe`, false},
		"a copy outside bin":      {`C:\Users\Public\defenseclaw-hook.exe`, false},
		"a staging folder":        {bin + `\hooks\.staging-0123456789abcdef\defenseclaw-hook.exe`, false},
		"the guard of the folder": {bin + `\hooks\aaaaaaaaaaaaaaaa\defenseclaw-hook-guard.exe`, false},
	} {
		t.Run(name, func(t *testing.T) {
			handler := map[string]any{"type": "command", "command": tc.binary, "args": args}
			if got := req.ownedHandler(handler); got != tc.owned {
				t.Fatalf("ownedHandler(%s) = %v, want %v", tc.binary, got, tc.owned)
			}
		})
	}
	linux := GuardRequest{Connector: ConnectorClaudeCode, GOOS: "linux", HookBinary: testHookBinary}
	handler := map[string]any{"type": "command", "command": "/opt/defenseclaw/bin/hooks/0123456789abcdef/defenseclaw-hook", "args": args}
	if linux.ownedHandler(handler) {
		t.Fatal("a Linux registration of another path became owned")
	}
}
