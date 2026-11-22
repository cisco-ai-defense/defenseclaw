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

func TestClaudeCodePerUserUnixSelectsNativeHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix registration")
	}
	root := t.TempDir()
	profile := filepath.Join(root, "profile")
	t.Setenv("HOME", profile)
	dataDir := filepath.Join(profile, ".defenseclaw")
	native := filepath.Join(profile, ".local", "bin", "defenseclaw-hook-user")
	if err := os.MkdirAll(filepath.Dir(native), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(native, []byte("fixture\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	guard := filepath.Join(filepath.Dir(native), "defenseclaw-hook-post")
	if err := os.WriteFile(guard, []byte("fixture\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	hooks := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, ".gateway-helper"),
		[]byte(filepath.Join(filepath.Dir(native), "defenseclaw-gateway")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
	opts := SetupOpts{DataDir: dataDir, HookExecutable: native}
	command, args := claudeCodeHookInvocation(opts, script)
	wantArgs := []string{"guard-user-hook", native, "hook", "--connector", "claudecode", "--hook-home", dataDir}
	if command != guard || !codexValueMatches(args, wantArgs) {
		t.Fatalf("native command = %q, %q; want %q, %q", command, args, guard, wantArgs)
	}
	if !claudeCodeHandlerTargetsCurrentRuntime(map[string]interface{}{
		"type": "command", "command": command, "args": args,
	}, opts) {
		t.Fatal("native registration is not recognized")
	}
	opts.APIAddr = "127.0.0.1:18971"
	command, args = claudeCodeHookInvocation(opts, script)
	if command != guard || !codexValueMatches(args, append(wantArgs, "--api-addr", opts.APIAddr)) ||
		!claudeCodeHandlerTargetsCurrentRuntime(map[string]interface{}{
			"type": "command", "command": command, "args": args,
		}, opts) {
		t.Fatalf("configured address is not retained in %q, %q", command, args)
	}
}

func TestClaudeCodePerUserUnixScriptTwin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix registration")
	}
	root := t.TempDir()
	profile := filepath.Join(root, "profile")
	t.Setenv("HOME", profile)
	dataDir := filepath.Join(profile, ".defenseclaw")
	script := filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
	opts := SetupOpts{DataDir: dataDir, HookExecutable: filepath.Join(root, "absent", "defenseclaw-hook-user")}
	command, args := claudeCodeHookInvocation(opts, script)
	if !strings.HasPrefix(command, posixHookCommandWord(script)) || args != nil {
		t.Fatalf("script twin = %q, %q", command, args)
	}
	if !claudeCodeHandlerTargetsCurrentRuntime(map[string]interface{}{
		"type": "command", "command": command,
	}, opts) {
		t.Fatal("script twin is not recognized")
	}
	opts.HookExecutable = filepath.Join(root, ".local", "bin", "defenseclaw-hook-user")
	if err := os.MkdirAll(filepath.Dir(opts.HookExecutable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opts.HookExecutable, []byte("fixture\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(script), ".gateway-helper"),
		[]byte(filepath.Join(filepath.Dir(opts.HookExecutable), "defenseclaw-gateway")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts.APIAddr = "example.test:18970"
	command, _ = claudeCodeHookInvocation(opts, script)
	if !strings.HasPrefix(command, posixHookCommandWord(script)) {
		t.Fatalf("nonlocal address changed script twin: %q", command)
	}
	opts.APIAddr = ""
	opts.SecureClientHookDelivery = true
	command, _ = claudeCodeHookInvocation(opts, script)
	if !strings.HasPrefix(command, posixHookCommandWord(script)) {
		t.Fatalf("Secure Client delivery changed script twin: %q", command)
	}
	opts.SecureClientHookDelivery = false
	opts.ManagedEnterprise = true
	command, _ = claudeCodeHookInvocation(opts, script)
	if !strings.Contains(command, posixHookCommandWord(script)) || strings.Contains(command, "defenseclaw-hook-user") {
		t.Fatalf("managed delivery changed script twin: %q", command)
	}
	opts.ManagedEnterprise = false
	opts.DataDir = filepath.Join(root, "custom-data")
	customScript := filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh")
	command, _ = claudeCodeHookInvocation(opts, customScript)
	if !strings.HasPrefix(command, posixHookCommandWord(customScript)) {
		t.Fatalf("custom data root changed script twin: %q", command)
	}
}
