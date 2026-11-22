// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func gap0322ClaudeRegistrationFixture(t *testing.T) (string, []string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix registration")
	}
	account := t.TempDir()
	t.Setenv("HOME", account)
	dataDir := filepath.Join(account, ".defenseclaw")
	hooks := filepath.Join(dataDir, "hooks")
	bin := filepath.Join(account, ".local", "bin")
	for _, dir := range []string{hooks, bin} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fixture := "#!/bin/bash -p\nread -r value\ncase \"$value\" in\n  protected|down) echo 'review denied' >&2; exit 2;;\n  ordinary) echo '{\"action\":\"allow\"}'; exit 0;;\nesac\nexit 2\n"
	script := filepath.Join(hooks, "claude-code-hook.sh")
	guard := filepath.Join(bin, "defenseclaw-hook-post")
	native := filepath.Join(bin, "defenseclaw-hook-user")
	for _, file := range []string{script, guard, native} {
		if err := os.WriteFile(file, []byte(fixture), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(hooks, ".gateway-helper"),
		[]byte(filepath.Join(bin, "defenseclaw-gateway")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command, args := claudeCodeHookInvocation(SetupOpts{DataDir: dataDir, HookExecutable: native}, script)
	startup := filepath.Join(account, "startup.sh")
	if err := os.WriteFile(startup, []byte("exit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return command, args, startup
}

func gap0322RunRegistered(t *testing.T, command string, args []string, input string, extras ...string) (int, string) {
	t.Helper()
	var cmd *exec.Cmd
	if args == nil {
		cmd = exec.Command("/bin/bash", "-c", command)
	} else {
		cmd = exec.Command(command, args...)
	}
	cmd.Env = append(os.Environ(), extras...)
	cmd.Stdin = strings.NewReader(input + "\n")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return exit.ExitCode(), string(out)
	}
	t.Fatalf("start registered hook: %v", err)
	return -1, ""
}

func TestGAP0322ClaudeRegisteredLaunchUnderShellOptions(t *testing.T) {
	command, args, startup := gap0322ClaudeRegistrationFixture(t)
	if args == nil {
		t.Fatal("Claude Code registration has no direct arguments")
	}
	for _, tc := range []struct {
		name string
		env  []string
	}{
		{"noexec", []string{"SHELLOPTS=noexec"}},
		{"errexit", []string{"SHELLOPTS=noexec:errexit"}},
		{"posix", []string{"SHELLOPTS=noexec:posix"}},
		{"startup", []string{"SHELLOPTS=noexec", "BASH_ENV=" + startup}},
		{"combined", []string{"SHELLOPTS=noexec", "BASH_ENV=" + startup, "FUNCNEST=1", "BASHOPTS=failglob:nullglob"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, input := range []string{"protected", "down"} {
				code, output := gap0322RunRegistered(t, command, args, input, tc.env...)
				if code != 2 || !strings.Contains(output, "review denied") {
					t.Fatalf("%s: exit %d, output %q", input, code, output)
				}
			}
			code, output := gap0322RunRegistered(t, command, args, "ordinary", tc.env...)
			if code != 0 || !strings.Contains(output, `"allow"`) {
				t.Fatalf("ordinary: exit %d, output %q", code, output)
			}
		})
	}
}

func TestGAP0322ClaudeOrdinaryRegistrationTwin(t *testing.T) {
	command, args, _ := gap0322ClaudeRegistrationFixture(t)
	code, output := gap0322RunRegistered(t, command, args, "ordinary")
	if code != 0 || !strings.Contains(output, `"allow"`) {
		t.Fatalf("ordinary: exit %d, output %q", code, output)
	}
}

func TestGAP0322ClaudeMissingGuardFallbackRegistration(t *testing.T) {
	command, args, _ := gap0322ClaudeRegistrationFixture(t)
	opts := SetupOpts{DataDir: args[6], HookExecutable: args[1]}
	hooks := map[string]interface{}{}
	if err := appendClaudeCodeHookMatrixForSetup(hooks, command, args, opts); err != nil {
		t.Fatal(err)
	}
	if err := verifyClaudeCodeHookMatrixForSetup(hooks, command, args, filepath.Join(opts.DataDir, "hooks"), opts); err != nil {
		t.Fatalf("registered matrix: %v", err)
	}
	groups := hooks["PreToolUse"].([]interface{})
	handlers := groups[0].(map[string]interface{})["hooks"].([]interface{})
	if len(handlers) != 2 {
		t.Fatalf("PreToolUse handlers = %d, want 2", len(handlers))
	}
	fallback := handlers[1].(map[string]interface{})
	wantArgs := append([]string{"fallback-guard-user-hook", command}, args[2:]...)
	if fallback["command"] != args[1] || !codexValueMatches(fallback["args"], wantArgs) {
		t.Fatalf("fallback registration = %#v", fallback)
	}
	groups[0].(map[string]interface{})["hooks"] = handlers[:1]
	if err := verifyClaudeCodeHookMatrixForSetup(hooks, command, args, filepath.Join(opts.DataDir, "hooks"), opts); err == nil {
		t.Fatal("missing fallback was accepted")
	}
	groups[0].(map[string]interface{})["hooks"] = handlers
	fallback["if"] = "Bash(ls)"
	if err := verifyClaudeCodeHookMatrixForSetup(hooks, command, args, filepath.Join(opts.DataDir, "hooks"), opts); err == nil {
		t.Fatal("conditional fallback was accepted")
	}
	delete(fallback, "if")
	fallback["shell"] = "bash"
	if err := verifyClaudeCodeHookMatrixForSetup(hooks, command, args, filepath.Join(opts.DataDir, "hooks"), opts); err == nil {
		t.Fatal("shell fallback was accepted")
	}
	delete(fallback, "shell")
	script := filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh")
	settings := map[string]interface{}{"hooks": hooks}
	changed := claudeCodeHooksInEarlierReleaseForm(settings, runtime.GOOS, script, func(path string) bool {
		return path == args[1]
	})
	if changed < 2 {
		t.Fatalf("rollback changed %d handlers, want the guard pair", changed)
	}
	rolled := hooks["PreToolUse"].([]interface{})[0].(map[string]interface{})["hooks"].([]interface{})
	if len(rolled) != 1 || rolled[0].(map[string]interface{})["command"] != script {
		t.Fatalf("rollback PreToolUse handlers = %#v", rolled)
	}
}
