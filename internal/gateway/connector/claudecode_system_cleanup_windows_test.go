// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsClaudeSettingsUninstallPrivateCASTransaction(t *testing.T) {
	root := os.Getenv("DEFENSECLAW_CI26_PROBE_ROOT")
	if root == "" {
		root = t.TempDir()
	}
	settings := filepath.Join(root, "home", ".claude", "settings.json")
	stateDir := filepath.Join(root, "state", "DefenseClaw", "claude-settings-teardown")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	const managed = `C:\probe\.local\bin\defenseclaw-hook.exe`
	const unrelated = `other-hook`
	fixture, err := json.Marshal(map[string]any{
		"hooks": map[string]any{"PreToolUse": []any{map[string]any{
			"hooks": []any{map[string]any{"command": managed}, map[string]any{"command": unrelated}},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve fixture owner: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(settings, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil); err != nil {
		t.Fatalf("set copied settings owner: %v", err)
	}
	removed, err := TransformWindowsClaudeSettingsForUninstall(settings, stateDir, func(raw []byte) ([]byte, int, error) {
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			return nil, 0, err
		}
		groups := document["hooks"].(map[string]any)["PreToolUse"].([]any)
		hooks := groups[0].(map[string]any)["hooks"].([]any)
		kept := make([]any, 0, len(hooks))
		count := 0
		for _, hook := range hooks {
			if hook.(map[string]any)["command"] == managed {
				count++
			} else {
				kept = append(kept, hook)
			}
		}
		groups[0].(map[string]any)["hooks"] = kept
		out, err := json.Marshal(document)
		return out, count, err
	})
	if err != nil {
		t.Fatalf("transform with state directory %s: %v", stateDir, err)
	}
	after, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 || strings.Contains(string(after), managed) || !strings.Contains(string(after), unrelated) {
		t.Fatalf("removed=%d settings=%s", removed, after)
	}
	t.Logf("removed=%d settings=%s", removed, after)
}
