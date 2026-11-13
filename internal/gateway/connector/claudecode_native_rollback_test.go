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

func TestClaudeCodeNativeUnixRollbackKeepsEarlierHookShape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix registration")
	}
	root := t.TempDir()
	profile := filepath.Join(root, "profile with spaces")
	t.Setenv("HOME", profile)
	home := filepath.Join(profile, ".defenseclaw")
	script := filepath.Join(home, "hooks", "claude-code-hook.sh")
	native := filepath.Join(profile, ".local", "bin", "defenseclaw-hook-user")
	for _, dir := range []string{filepath.Dir(script), filepath.Dir(native)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(native, []byte("fixture\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(script), ".gateway-helper"),
		[]byte(filepath.Join(filepath.Dir(native), "defenseclaw-gateway")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	owned := func(path string) bool { return path == native }
	for _, addr := range []string{"127.0.0.1:18970", "[::1]:18970"} {
		t.Run(addr, func(t *testing.T) {
			command, _ := claudeCodeHookInvocation(SetupOpts{
				DataDir: home, HookExecutable: native, APIAddr: addr,
			}, script)
			if !strings.HasPrefix(command, posixHookCommandWord(native)) {
				t.Fatalf("native registration was not selected: %q", command)
			}
			handler := map[string]interface{}{"command": command}
			if !claudeCodeHandlerInEarlierReleaseForm(handler, runtime.GOOS, script, owned) || handler["command"] != script {
				t.Fatalf("rollback form = %#v", handler)
			}
		})
	}
	for _, addr := range []string{"example.test:18970", "'[::1]:18970' extra", "'[::1]:18970"} {
		command := claudeCodeMissingHookGuard(posixHookCommandWord(native) +
			" hook --connector claudecode --hook-home " + posixHookCommandWord(home) +
			" --api-addr " + addr)
		handler := map[string]interface{}{"command": command}
		if claudeCodeHandlerInEarlierReleaseForm(handler, runtime.GOOS, script, owned) || handler["command"] != command {
			t.Fatalf("non-generated address changed: %q", addr)
		}
	}
	foreign := map[string]interface{}{"command": claudeCodeMissingHookGuard(
		posixHookCommandWord(filepath.Join(root, "elsewhere", "defenseclaw-hook-user")) +
			" hook --connector claudecode --hook-home " + posixHookCommandWord(home))}
	if claudeCodeHandlerInEarlierReleaseForm(foreign, runtime.GOOS, script, owned) {
		t.Fatalf("foreign command changed: %#v", foreign)
	}
	guard := filepath.Join(filepath.Dir(native), "defenseclaw-hook-post")
	for _, addr := range []string{"", "[::1]:18970"} {
		args := []string{"guard-user-hook", native, "hook", "--connector", "claudecode", "--hook-home", home}
		if addr != "" {
			args = append(args, "--api-addr", addr)
		}
		guarded := map[string]interface{}{"command": guard, "args": args}
		if !claudeCodeHandlerInEarlierReleaseForm(guarded, runtime.GOOS, script, owned) ||
			guarded["command"] != script || guarded["args"] != nil {
			t.Fatalf("guard rollback form for %q = %#v", addr, guarded)
		}
	}
	foreignGuard := map[string]interface{}{
		"command": filepath.Join(root, "profile", ".local", "bin", "defenseclaw-hook-post"),
		"args":    []string{"guard-user-hook", native, "hook", "--connector", "claudecode", "--hook-home", home},
	}
	if claudeCodeHandlerInEarlierReleaseForm(foreignGuard, runtime.GOOS, script, owned) {
		t.Fatalf("foreign guard changed: %#v", foreignGuard)
	}
}
