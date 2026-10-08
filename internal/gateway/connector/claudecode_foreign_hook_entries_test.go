// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-2031: a settings.json copied from another account runs that account's
// generated hook (<home>/.defenseclaw/hooks/claude-code-hook.sh). Setup must
// replace those entries and Teardown must not restore them; the user's own
// hooks stay.
func TestClaudeCode_SetupReplacesForeignDefenseClawHookEntries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows registers the native hook launcher")
	}
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")
	ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = "" })

	foreign := filepath.ToSlash(filepath.Join(dir, "other", ".defenseclaw", "hooks", "claude-code-hook.sh"))
	own := "/usr/local/bin/my-review-hook.sh"
	handler := func(command string) map[string]interface{} {
		return map[string]interface{}{"type": "command", "command": command}
	}
	data, err := json.Marshal(map[string]interface{}{"hooks": map[string]interface{}{
		"PreToolUse": []interface{}{
			map[string]interface{}{"matcher": "*", "hooks": []interface{}{handler(foreign), handler(own)}},
		},
		"Stop": []interface{}{
			map[string]interface{}{"hooks": []interface{}{handler(foreign)}},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{
		DataDir:       filepath.Join(dir, "self"),
		ProxyAddr:     "127.0.0.1:4000",
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "api-token",
		OTLPPathToken: strings.Repeat("a", 64),
	}
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	c := NewClaudeCodeConnector()
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	after := mustReadClaudeSettingsForTest(t, settingsPath)
	if strings.Contains(after, foreign) {
		t.Fatalf("Setup kept the foreign DefenseClaw hook entries: %s", after)
	}
	if !strings.Contains(after, own) || !strings.Contains(after, filepath.ToSlash(filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh"))) {
		t.Fatalf("Setup lost the user's hook or did not register its own: %s", after)
	}

	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	after = mustReadClaudeSettingsForTest(t, settingsPath)
	if strings.Contains(after, foreign) || !strings.Contains(after, own) {
		t.Fatalf("Teardown settings = %s, want the user's hook only", after)
	}

	for _, command := range []string{
		"/opt/other/hooks/claude-code-hook.sh",
		foreign + " --flag",
		"/home/u/.defenseclaw/hooks/other-hook.sh",
		".defenseclaw/hooks/claude-code-hook.sh",
	} {
		if hookUsesForeignDefenseClawClaudeCodeScript(handler(command)) {
			t.Errorf("claimed %q as a DefenseClaw hook", command)
		}
	}
}

func mustReadClaudeSettingsForTest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// GAP-0542: after an account rename or a home move the registered hook path
// is gone and the shell exits 127, which Claude Code treats as non-blocking,
// so tool calls ran unguarded. The per-user command blocks (exit 2) with one
// sentence when its script cannot start, passes the script exit through
// otherwise, and an old-home guarded entry is still claimed for repair.
func TestClaudeCode_PerUserHookCommandFailsClosedWhenScriptMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows registers the native hook launcher")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, ".defenseclaw", "hooks", "claude-code-hook.sh")
	command, _ := claudeCodeHookInvocation(SetupOpts{DataDir: filepath.Join(dir, ".defenseclaw")}, script)
	if !strings.HasPrefix(command, script+" ") {
		t.Fatalf("command %q does not start with the hook script", command)
	}
	run := func() (int, string) {
		cmd := exec.Command("/bin/sh", "-c", command)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		err := cmd.Run()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), stderr.String()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0, stderr.String()
	}
	if code, stderr := run(); code != 2 || !strings.Contains(stderr, "Rerun the DefenseClaw installer") {
		t.Fatalf("missing script: exit %d stderr %q, want a block (2) that names the repair", code, stderr)
	}
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{0, 2, 3} {
		if err := os.WriteFile(script, []byte(fmt.Sprintf("#!/bin/sh\nexit %d\n", want)), 0o700); err != nil {
			t.Fatal(err)
		}
		if code, stderr := run(); code != want || stderr != "" {
			t.Fatalf("script exit %d: command exit %d stderr %q", want, code, stderr)
		}
	}
	oldHome, _ := claudeCodeHookInvocation(SetupOpts{}, "/home/old/.defenseclaw/hooks/claude-code-hook.sh")
	if !hookUsesForeignDefenseClawClaudeCodeScript(map[string]interface{}{"command": oldHome}) {
		t.Fatalf("an old-home guarded entry %q is not claimed for repair", oldHome)
	}
}
