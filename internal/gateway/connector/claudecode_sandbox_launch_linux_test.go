// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// TestClaudeCodeSandboxRunHookLaunchOnBashAsSh checks the hook file mounted
// over a verified image drop-in for a sandbox run.
func TestClaudeCodeSandboxRunHookLaunchOnBashAsSh(t *testing.T) {
	rt, err := resolveSandboxTarget("claudecode", claudeRunTarget)
	if err != nil {
		t.Fatal(err)
	}
	image, err := renderClaudeCodeSandboxDropIn(rt)
	if err != nil {
		t.Fatal(err)
	}
	runFiles, err := NewClaudeCodeConnector().SandboxRunFiles(claudeRunTarget, SandboxRunConfig{})
	if err != nil {
		t.Fatal(err)
	}
	run := runFileMap(t, runFiles)
	hookDropIn := run[ClaudeCodeSandboxDropInPath]
	if len(hookDropIn) == 0 {
		// Before the per-run replacement, Claude reads the image file.
		hookDropIn = image
	}
	source, err := stageClaudeCodeManagedSettings(map[string][]byte{
		claudeCodeSandboxDropInName: hookDropIn, claudeCodeSandboxRunDropInName: run[ClaudeCodeSandboxRunDropInPath],
	})
	if err != nil {
		t.Fatal(err)
	}
	hooks, _ := source.settings["hooks"].(map[string]interface{})
	groups, _ := hooks["PreToolUse"].([]interface{})
	var handlers []map[string]interface{}
	for _, raw := range groups {
		group, _ := raw.(map[string]interface{})
		for _, rawHandler := range group["hooks"].([]interface{}) {
			handler, _ := rawHandler.(map[string]interface{})
			handlers = append(handlers, handler)
		}
	}
	if len(handlers) != 1 {
		t.Fatalf("PreToolUse handlers = %d, want one", len(handlers))
	}
	root := t.TempDir()
	sh := filepath.Join(root, "sh")
	if err := os.Symlink("/bin/bash", sh); err != nil {
		t.Fatal(err)
	}
	hook := filepath.Join(root, "hook.sh")
	marker := filepath.Join(root, "calls")
	body := "#!/bin/bash -p\nread -r input\nprintf '%s\\n' \"$input\" >> " + shellSingleQuote(marker) +
		"\nif [ \"$input\" = protected ]; then exit 2; fi\n"
	if err := os.WriteFile(hook, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, call := range []struct {
		name  string
		block bool
	}{{"ordinary", false}, {"protected", true}, {"missing", true}} {
		t.Run(call.name, func(t *testing.T) {
			if call.name == "missing" {
				if err := os.Remove(hook); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(marker, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			blocked := false
			for _, handler := range handlers {
				command := strings.ReplaceAll(handler["command"].(string), path.Join(SandboxHookDir, "claude-code-hook.sh"), hook)
				var cmd *exec.Cmd
				if rawArgs, ok := handler["args"].([]interface{}); ok {
					args := make([]string, len(rawArgs))
					for i, raw := range rawArgs {
						args[i] = strings.ReplaceAll(raw.(string), path.Join(SandboxHookDir, "claude-code-hook.sh"), hook)
					}
					cmd = exec.Command(command, args...)
				} else {
					cmd = exec.Command(sh, "-c", command)
				}
				cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root, "SHELLOPTS=noexec", "BASHOPTS=nullglob"}
				cmd.Stdin = strings.NewReader(call.name + "\n")
				err := cmd.Run()
				var exit *exec.ExitError
				switch {
				case err == nil:
				case errors.As(err, &exit) && exit.ExitCode() == 2:
					blocked = true
				default:
					t.Fatalf("hook launch: %v", err)
				}
			}
			calls, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal(err)
			}
			wantCalls := call.name + "\n"
			if call.name == "missing" {
				wantCalls = ""
			}
			if blocked != call.block || call.name != "ordinary" && string(calls) != wantCalls ||
				call.name == "ordinary" && string(calls) != "" && string(calls) != wantCalls {
				t.Fatalf("blocked=%t, hook calls=%q; want block=%t", blocked, calls, call.block)
			}
		})
	}
}

func TestClaudeCodeSandboxRunKeepsBashToolScripts(t *testing.T) {
	rt, err := resolveSandboxTarget("claudecode", claudeRunTarget)
	if err != nil {
		t.Fatal(err)
	}
	image, err := renderClaudeCodeSandboxDropIn(rt)
	if err != nil {
		t.Fatal(err)
	}
	runFiles, err := NewClaudeCodeConnector().SandboxRunFiles(claudeRunTarget, SandboxRunConfig{})
	if err != nil {
		t.Fatal(err)
	}
	run := runFileMap(t, runFiles)
	hookDropIn := run[ClaudeCodeSandboxDropInPath]
	if len(hookDropIn) == 0 {
		hookDropIn = image
	}
	source, err := stageClaudeCodeManagedSettings(map[string][]byte{
		claudeCodeSandboxDropInName:    hookDropIn,
		claudeCodeSandboxRunDropInName: run[ClaudeCodeSandboxRunDropInPath],
	})
	if err != nil {
		t.Fatal(err)
	}
	managed, _ := source.settings["env"].(map[string]interface{})
	root := t.TempDir()
	marker := filepath.Join(root, "tool-script-output")
	script := filepath.Join(root, "tool-script.sh")
	body := "#!/bin/bash\nprintf 'first\\n' >> " + shellSingleQuote(marker) +
		"\nprintf 'second\\n' >> " + shellSingleQuote(marker) + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", "-c", "set -o onecmd; "+shellSingleQuote(script))
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root}
	for _, name := range []string{"SHELLOPTS", "BASHOPTS"} {
		if value, present := managed[name]; present {
			cmd.Env = append(cmd.Env, name+"="+value.(string))
		}
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Bash tool script: %v (%s)", err, output)
	}
	output, err := os.ReadFile(marker)
	if err != nil || string(output) != "first\nsecond\n" {
		t.Fatalf("Bash tool script output = %q, err %v", output, err)
	}
}
