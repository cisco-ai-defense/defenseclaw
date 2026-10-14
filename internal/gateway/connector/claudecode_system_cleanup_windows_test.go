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
	root := t.TempDir()
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
	removed, err := TransformWindowsClaudeSettingsForUninstall(settings, stateDir, user.User.Sid.String(), func(raw []byte) ([]byte, int, error) {
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

// A settings file owned by the enrolled SID is edited without changing its
// owner or DACL, and a different enrolled SID is refused.
func TestWindowsClaudeSettingsUninstallEnrolledOwner(t *testing.T) {
	root := t.TempDir()
	settings := filepath.Join(root, "home", ".claude", "settings.json")
	stateDir := filepath.Join(root, "state", "DefenseClaw", "claude-settings-teardown")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"command":"C:\\probe\\defenseclaw-hook.exe"},{"command":"other-hook"}]}]}}`)
	if err := os.WriteFile(settings, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve fixture owner: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(settings, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil); err != nil {
		t.Fatalf("set settings owner: %v", err)
	}
	ownerSID := user.User.Sid.String()
	before, err := windows.GetNamedSecurityInfo(settings, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TransformWindowsClaudeSettingsForUninstall(settings, stateDir,
		"S-1-5-32-544", func(raw []byte) ([]byte, int, error) { return raw, 0, nil }); err == nil || !strings.Contains(err.Error(), "not owned by enrolled user") {
		t.Fatalf("foreign enrolled SID must be refused: %v", err)
	}
	removed, err := TransformWindowsClaudeSettingsForUninstall(settings, stateDir, ownerSID, func(raw []byte) ([]byte, int, error) {
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			return nil, 0, err
		}
		groups := document["hooks"].(map[string]any)["PreToolUse"].([]any)
		hooks := groups[0].(map[string]any)["hooks"].([]any)
		kept := make([]any, 0, len(hooks))
		count := 0
		for _, hook := range hooks {
			if strings.Contains(hook.(map[string]any)["command"].(string), "defenseclaw-hook.exe") {
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
		t.Fatal(err)
	}
	after, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 || strings.Contains(string(after), "defenseclaw-hook.exe") || !strings.Contains(string(after), "other-hook") {
		t.Fatalf("removed=%d settings=%s", removed, after)
	}
	afterProtection, err := windows.GetNamedSecurityInfo(settings, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || before.String() != afterProtection.String() {
		t.Fatalf("owner or DACL changed: before=%s after=%v err=%v", before.String(), afterProtection, err)
	}
	t.Logf("removed=%d settings=%s", removed, after)
}
