// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-2278: the matrix verify refuses a shell setting or a condition on the
// handler that runs the PreToolUse guard. The Unix fallback registration has
// refused both since GAP-0322; the Windows launcher guard handler is the same
// enforcement point, and a shell setting changes how Claude Code starts it.
func TestGAP2278WindowsMatrixVerifyRefusesShellOrConditionOnPreToolUseGuard(t *testing.T) {
	// The registration of a Windows account: the native launcher behind the
	// cmd.exe guard. The verify reads the registration only; the launcher
	// never runs, so a placeholder file stands in for it.
	account := t.TempDir()
	dataDir := filepath.Join(account, ".defenseclaw")
	launcher := filepath.Join(account, ".local", "bin", windowsHookBinaryName)
	if err := os.MkdirAll(filepath.Dir(launcher), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcher, []byte("launcher placeholder"), 0o700); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: dataDir, HookExecutable: launcher}
	hooksDir := filepath.Join(dataDir, "hooks")
	command, args := claudeCodeHookInvocation(opts, filepath.Join(hooksDir, "claude-code-hook.sh"))
	if err := ensureClaudeChain(launcher); err != nil {
		t.Fatalf("install the guard chain: %v", err)
	}
	hooks := map[string]interface{}{}
	if err := appendClaudeCodeHookMatrixForSetup(hooks, command, args, opts); err != nil {
		t.Fatal(err)
	}
	verify := func() error { return verifyClaudeCodeHookMatrixForSetup(hooks, command, args, hooksDir, opts) }
	if err := verify(); err != nil {
		t.Fatalf("registered matrix: %v", err)
	}
	guard := hooks["PreToolUse"].([]interface{})[0].(map[string]interface{})["hooks"].([]interface{})[0].(map[string]interface{})
	for _, tc := range []struct {
		name  string
		key   string
		value interface{}
	}{
		{"shell setting", "shell", "powershell"},
		{"empty shell setting", "shell", ""},
		{"condition", "if", "Bash(ls)"},
	} {
		guard[tc.key] = tc.value
		if err := verify(); err == nil {
			t.Errorf("the matrix verify accepted a PreToolUse guard handler with a %s", tc.name)
		}
		delete(guard, tc.key)
	}
	if err := verify(); err != nil {
		t.Fatalf("restored matrix: %v", err)
	}
}
