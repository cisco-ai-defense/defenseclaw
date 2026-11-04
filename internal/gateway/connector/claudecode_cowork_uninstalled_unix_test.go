// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCoworkPluginHookAllowsOnceDefenseClawIsUninstalled runs the PreToolUse
// handler of the rendered plugin as Claude runs a shell-form hook (sh -c,
// and bash -c where present). With the hook script present its verdicts pass
// through unchanged (deny exit 2, allow exit 0 with its JSON). After the
// per-user uninstall deleted the hooks folder, it answers exit 0 with a
// systemMessage that says to remove the plugin, so Cowork keeps working
// (GAP-0051). A script that exists and cannot run still blocks.
func TestCoworkPluginHookAllowsOnceDefenseClawIsUninstalled(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data dir")
	script := filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SaveHookContractLockEntry(dataDir, HookContractLockEntry{Connector: "claudecode", ContractID: "claudecode-test"}); err != nil {
		t.Fatal(err)
	}
	writeScript := func(body string) {
		t.Helper()
		if err := os.WriteFile(script, []byte("#!/bin/sh\nevent=$(cat)\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeScript("exit 0\n")
	raw, err := CoworkPluginHooks(SetupOpts{DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Hooks map[string][]struct {
			Hooks []map[string]interface{} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	command, _ := doc.Hooks["PreToolUse"][0].Hooks[0]["command"].(string)
	if command == "" {
		t.Fatal("no PreToolUse command")
	}
	for event, entries := range doc.Hooks {
		if _, ok := entries[0].Hooks[0]["onFailure"]; ok {
			t.Fatalf("%s: shell-form handler sets onFailure", event)
		}
		if entries[0].Hooks[0]["command"] != command {
			t.Fatalf("%s: handler differs from PreToolUse", event)
		}
	}
	shells := [][]string{{"/bin/sh", "-c"}}
	if bash, err := exec.LookPath("bash"); err == nil {
		shells = append(shells, []string{bash, "-c"})
	}
	run := func(shell []string) (int, string, string) {
		t.Helper()
		cmd := exec.Command(shell[0], shell[1], command)
		cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo between-check"}}`)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		code := 0
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, stdout.String(), stderr.String()
	}
	allow := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`
	for _, shell := range shells {
		writeScript("echo 'DefenseClaw denied this tool call' >&2\nexit 2\n")
		if code, stdout, stderr := run(shell); code != 2 || stdout != "" || strings.TrimSpace(stderr) != "DefenseClaw denied this tool call" {
			t.Fatalf("%s deny: exit %d stdout %q stderr %q", shell[0], code, stdout, stderr)
		}
		writeScript("echo '" + allow + "'\nexit 0\n")
		if code, stdout, _ := run(shell); code != 0 || strings.TrimSpace(stdout) != allow {
			t.Fatalf("%s allow: exit %d stdout %q", shell[0], code, stdout)
		}
		writeScript("exit 127\n") // the script own 127 is not "uninstalled"
		if code, _, stderr := run(shell); code != 2 || !strings.Contains(stderr, coworkMissingHookGuardMessage) {
			t.Fatalf("%s script exit 127: exit %d stderr %q", shell[0], code, stderr)
		}
		if err := os.Chmod(script, 0o600); err != nil {
			t.Fatal(err)
		}
		if code, _, stderr := run(shell); code != 2 || !strings.Contains(stderr, coworkMissingHookGuardMessage) {
			t.Fatalf("%s not executable: exit %d stderr %q, want the blocking sentence", shell[0], code, stderr)
		}
		if err := os.RemoveAll(filepath.Join(dataDir, "hooks")); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := run(shell)
		if code != 0 {
			t.Fatalf("%s uninstalled: exit %d, want 0 (allow)", shell[0], code)
		}
		var answer map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &answer); err != nil || len(answer) != 1 || answer["systemMessage"] != coworkUninstalledMessage {
			t.Fatalf("%s uninstalled: stdout %q (%v), want one systemMessage", shell[0], stdout, err)
		}
		if !strings.Contains(stderr, coworkUninstalledMessage) {
			t.Fatalf("%s uninstalled: stderr %q", shell[0], stderr)
		}
		if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range coworkUninstalledMessage {
		if strings.ContainsRune("'\"&|<>()^%`$\\", r) {
			t.Fatalf("the uninstalled sentence holds %q", r)
		}
	}
}

// TestCoworkPluginHookRunsTheRealClaudeCodeScript renders the real Claude Code
// hook script (fail mode closed, the test gateway stand-in) and runs the
// plugin PreToolUse handler next to the script itself: the exit codes and
// output are the same, so the plugin keeps the Claude Code fail mode while
// DefenseClaw is installed. With the hooks folder deleted it allows.
func TestCoworkPluginHookRunsTheRealClaudeCodeScript(t *testing.T) {
	for _, failMode := range []string{"closed"} {
		t.Run(failMode, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "data dir")
			if err := os.MkdirAll(home, 0o700); err != nil {
				t.Fatal(err)
			}
			installNativeGatewayForHookTest(t, home)
			hookDir := filepath.Join(home, "hooks")
			opts := SetupOpts{DataDir: home, APIAddr: "127.0.0.1:1", APIToken: "test-hook-token", HookFailMode: failMode}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewClaudeCodeConnector()); err != nil {
				t.Fatal(err)
			}
			if err := SaveHookContractLockEntry(home, HookContractLockEntry{Connector: "claudecode", ContractID: "claudecode-test"}); err != nil {
				t.Fatal(err)
			}
			raw, err := CoworkPluginHooks(SetupOpts{DataDir: home})
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Hooks map[string][]struct {
					Hooks []map[string]interface{} `json:"hooks"`
				} `json:"hooks"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			command, _ := doc.Hooks["PreToolUse"][0].Hooks[0]["command"].(string)
			event := `{"hook_event_name":"PreToolUse","session_id":"s1","cwd":"/","tool_name":"Bash","tool_input":{"command":"echo between-check"}}`
			run := func(line string) (int, string) {
				cmd := exec.Command("/bin/sh", "-c", line)
				cmd.Stdin = strings.NewReader(event)
				cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
				var stdout bytes.Buffer
				cmd.Stdout = &stdout
				err := cmd.Run()
				if exitErr, ok := err.(*exec.ExitError); ok {
					return exitErr.ExitCode(), stdout.String()
				} else if err != nil {
					t.Fatal(err)
				}
				return 0, stdout.String()
			}
			script := shellSingleQuote(filepath.Join(hookDir, "claude-code-hook.sh"))
			directCode, directOut := run(script)
			pluginCode, pluginOut := run(command)
			if pluginCode != directCode || pluginOut != directOut {
				t.Fatalf("plugin exit %d %q, script exit %d %q", pluginCode, pluginOut, directCode, directOut)
			}
			t.Logf("fail mode %s, no gateway: script and plugin exit %d", failMode, pluginCode)
			if err := os.RemoveAll(hookDir); err != nil {
				t.Fatal(err)
			}
			if code, out := run(command); code != 0 || !strings.Contains(out, coworkUninstalledMessage) {
				t.Fatalf("uninstalled: exit %d %q", code, out)
			}
		})
	}
}
