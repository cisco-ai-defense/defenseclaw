// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestClaudeCodeRehomedNativeHandlersReplaced(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("per-user native registration is Linux-only")
	}
	root := t.TempDir()
	oldHome := filepath.Join(root, "previous")
	currentHome := filepath.Join(root, "current")
	t.Setenv("HOME", currentHome)
	dataDir := filepath.Join(currentHome, ".defenseclaw")
	hooksDir := filepath.Join(dataDir, "hooks")
	binDir := filepath.Join(currentHome, ".local", "bin")
	for _, dir := range []string{hooksDir, binDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"defenseclaw-hook-user", "defenseclaw-hook-post"} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte("fixture\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(hooksDir, ".gateway-helper"),
		[]byte(filepath.Join(binDir, "defenseclaw-gateway")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(root, "settings.json")
	ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = "" })

	oldBin := filepath.Join(oldHome, ".local", "bin")
	oldGuard := filepath.Join(oldBin, "defenseclaw-hook-post")
	oldNative := filepath.Join(oldBin, "defenseclaw-hook-user")
	oldArgs := []string{"guard-user-hook", oldNative, "hook", "--connector", "claudecode", "--hook-home", filepath.Join(oldHome, ".defenseclaw")}
	hooks := map[string]interface{}{}
	appendClaudeCodeHookMatrix(hooks, oldGuard, oldArgs)
	foreign := map[string]interface{}{"type": "command", "command": "/usr/local/bin/ordinary-hook", "timeout": 30}
	stop := hooks["Stop"].([]interface{})
	stop = append(stop, map[string]interface{}{"hooks": []interface{}{foreign}})
	hooks["Stop"] = stop
	data, err := json.Marshal(map[string]interface{}{"hooks": hooks})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	opts := SetupOpts{DataDir: dataDir, HookExecutable: filepath.Join(binDir, "defenseclaw-hook-user")}
	if err := NewClaudeCodeConnector().patchClaudeCodeHooks(opts, filepath.Join(hooksDir, "claude-code-hook.sh")); err != nil {
		t.Fatalf("reconcile Claude Code hooks: %v", err)
	}
	after, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), oldHome) {
		t.Fatal("old-home handler remains in settings")
	}
	if !strings.Contains(string(after), currentHome) || !strings.Contains(string(after), "/usr/local/bin/ordinary-hook") {
		t.Fatalf("current registration or unrelated hook missing: %s", after)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(after, &settings); err != nil {
		t.Fatal(err)
	}
	currentCommand, currentArgs := claudeCodeHookInvocation(opts, filepath.Join(hooksDir, "claude-code-hook.sh"))
	if err := verifyClaudeCodeHookMatrixForSetup(settings["hooks"].(map[string]interface{}), currentCommand, currentArgs, hooksDir, opts); err != nil {
		t.Fatalf("current hook matrix: %v", err)
	}
}

func TestClaudeCodeRehomedNativeOwnershipRequiresConsistentPaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("per-user native registration is Linux-only")
	}
	oldHome := filepath.Join(t.TempDir(), "previous")
	currentHooks := filepath.Join(t.TempDir(), ".defenseclaw", "hooks")
	bin := filepath.Join(oldHome, ".local", "bin")
	guard := filepath.Join(bin, "defenseclaw-hook-post")
	native := filepath.Join(bin, "defenseclaw-hook-user")
	home := filepath.Join(oldHome, ".defenseclaw")
	guardArgs := []string{"guard-user-hook", native, "hook", "--connector", "claudecode", "--hook-home", home}
	fallbackArgs := []string{"fallback-guard-user-hook", guard, "hook", "--connector", "claudecode", "--hook-home", home}
	for _, tc := range []struct {
		name    string
		command string
		args    []string
		owned   bool
	}{
		{"guard", guard, guardArgs, true},
		{"fallback", native, fallbackArgs, true},
		{"different executable", filepath.Join(t.TempDir(), "defenseclaw-hook-user"), fallbackArgs, false},
		{"different home", native, append(append([]string(nil), fallbackArgs[:6]...), filepath.Join(t.TempDir(), ".defenseclaw")), false},
		{"extra argument", native, append(append([]string(nil), fallbackArgs...), "--other"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := map[string]interface{}{"type": "command", "command": tc.command, "args": tc.args}
			if got := isOwnedHookHandler(handler, currentHooks); got != tc.owned {
				t.Fatalf("owned = %v, want %v", got, tc.owned)
			}
		})
	}
	if isOwnedHookHandler(map[string]interface{}{
		"type": "prompt", "command": native, "args": fallbackArgs,
	}, currentHooks) {
		t.Fatal("non-command handler was claimed")
	}
}

func TestClaudeCodeRehomedNativeShellOwnership(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("per-user native registration is Linux-only")
	}
	oldHome := filepath.Join(t.TempDir(), "previous account")
	native := filepath.Join(oldHome, ".local", "bin", "defenseclaw-hook-user")
	dataDir := filepath.Join(oldHome, ".defenseclaw")
	command := posixHookCommandWord(native) + " hook --connector claudecode --hook-home " + posixHookCommandWord(dataDir)
	currentHooks := filepath.Join(t.TempDir(), ".defenseclaw", "hooks")
	for _, tc := range []struct {
		name    string
		command string
		owned   bool
	}{
		{"native shell", claudeCodeMissingHookGuard(command), true},
		{"loopback endpoint", claudeCodeMissingHookGuard(command + " --api-addr 127.0.0.1:18970"), true},
		{"different home", claudeCodeMissingHookGuard(posixHookCommandWord(native) + " hook --connector claudecode --hook-home " + posixHookCommandWord(t.TempDir())), false},
		{"extra argument", claudeCodeMissingHookGuard(command + " --other"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := map[string]interface{}{"type": "command", "command": tc.command}
			if got := isOwnedHookHandler(handler, currentHooks); got != tc.owned {
				t.Fatalf("owned = %v, want %v", got, tc.owned)
			}
		})
	}
	if isOwnedHookHandler(map[string]interface{}{
		"type": "command", "command": claudeCodeMissingHookGuard(command), "args": []string{"other"},
	}, currentHooks) {
		t.Fatal("shell command with separate arguments was claimed")
	}
	if isOwnedHookHandler(map[string]interface{}{
		"type": "prompt", "command": claudeCodeMissingHookGuard(command),
	}, currentHooks) {
		t.Fatal("non-command shell handler was claimed")
	}
}
