// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-0016: every managed shell hook bakes the installer-owned fail mode. An
// inherited DEFENSECLAW_FAIL_MODE=open must not open a closed managed hook
// (codex, claude-code and cursor already did; these five honoured the env).
// Per-user hooks read no fail mode from the environment either (1.0.4 lead
// directive).
func TestManagedShellHooksIgnoreInheritedFailMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows uses the authenticated hook executor")
	}
	const override = "${DEFENSECLAW_FAIL_MODE:-"
	for _, tc := range []struct {
		conn   Connector
		script string
	}{
		{NewKiroConnector(), "kiro-hook.sh"},
		{NewDevinConnector(), "devin-hook.sh"},
		{NewHermesConnector(), "hermes-hook.sh"},
		{NewAntigravityConnector(), "antigravity-hook.sh"},
		{NewCodexConnector(), "codex-hook.sh"},
	} {
		for _, managed := range []bool{true, false} {
			name := tc.conn.Name() + "/per-user"
			if managed {
				name = tc.conn.Name() + "/managed"
			}
			t.Run(name, func(t *testing.T) {
				home := t.TempDir()
				hookDir := filepath.Join(home, "hooks")
				opts := SetupOpts{DataDir: home, APIAddr: "127.0.0.1:1", APIToken: "scoped-test-token", HookFailMode: "closed"}
				if managed {
					// A standalone managed install names its administrator-owned
					// hook binary, so the hook is not a Secure Client hook.
					opts.ManagedEnterprise = true
					opts.ManagedHookBinary = "/usr/local/libexec/defenseclaw-hook"
				}
				if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, tc.conn); err != nil {
					t.Fatal(err)
				}
				body, err := os.ReadFile(filepath.Join(hookDir, tc.script))
				if err != nil {
					t.Fatal(err)
				}
				script := string(body)
				if managed && strings.Contains(script, override) {
					t.Fatalf("managed %s reads DEFENSECLAW_FAIL_MODE from the environment", tc.script)
				}
				if managed && !strings.Contains(script, "\nFAIL_MODE=\"") {
					t.Fatalf("managed %s bakes no FAIL_MODE", tc.script)
				}
				if !managed && strings.Contains(script, override) {
					t.Fatalf("per-user %s reads DEFENSECLAW_FAIL_MODE from the environment", tc.script)
				}
			})
		}
	}
}
