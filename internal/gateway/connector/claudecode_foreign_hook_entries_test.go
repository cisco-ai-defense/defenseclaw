// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
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
