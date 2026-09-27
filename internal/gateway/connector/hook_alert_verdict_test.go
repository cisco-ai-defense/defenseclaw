// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The gateway answers an advisory finding (a HIGH rule such as a webhook
// catcher in the command, action mode) with action "alert" and would_block
// false, plus the harness's notice in claude_code_output / codex_output. The
// tool must run and the harness show the notice; the native hook runner
// already does that (hookexec TestAlertRemainsAdvisoryUnderClosedFailMode).
// These tests pin the same for the shell hooks, on the host and in the
// sandbox, where an alert used to be "invalid or missing action", a
// fail-closed block that also left a hook-failure record.

const alertNotice = `{"systemMessage":"DefenseClaw observed a HIGH Claude Code hook finding: advisory"}`

// alertVerdict is the shape the gateway returns for an advisory finding on a
// PreToolUse.
const alertVerdict = `{"action":"alert","raw_action":"alert","would_block":false,"severity":"HIGH",` +
	`"reason":"advisory","claude_code_output":` + alertNotice + `,"codex_output":` + alertNotice + `}`

func TestSandboxHooksTreatAlertAsAdvisory(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required")
	}
	codexArgs := []string{"--event", "PreToolUse", "--hook-contract", "codex-hooks-v4"}
	for _, tc := range []struct {
		connector, version, script string
		args                       []string
		stdin                      string
		// notice is the stdout an alert with its notice must produce.
		notice string
	}{
		{"claudecode", "2.1.156", "claude-code-hook.sh", nil, claudePreToolUse, alertNotice},
		{"codex", "0.146.0", "codex-hook.sh", codexArgs, codexPreToolUse, alertNotice},
		{"copilot", "1.0.88", "copilot-hook.sh", copilotPreToolUseArgs, copilotPreToolUse, ""},
		{"cursor", "2026.07.23-e383d2b", "cursor-hook.sh", nil, cursorPreToolUse, ""},
		{"kiro", "2.24.1", "kiro-hook.sh", nil, kiroPreToolUse, ""},
		{"devin", "3000.4.25", "devin-hook.sh", nil, devinPreToolUse, ""},
	} {
		rt, err := resolveSandboxTarget(tc.connector, SandboxRenderTarget{IngressPort: 18971, AgentVersion: tc.version})
		if err != nil {
			t.Fatal(err)
		}
		files, err := renderSandboxHookFiles(tc.connector, rt)
		if err != nil {
			t.Fatal(err)
		}
		h := newSandboxHookHarnessFiles(t, files, SandboxHookPATH)
		env := map[string]string{SandboxTokenEnv: "tok", "CLAUDE_TOOL_NAME": "Bash"}
		for name, reply := range map[string]string{
			"with-notice": alertVerdict,
			"bare":        `{"action":"alert","would_block":false}`,
		} {
			t.Run(tc.script+"/"+name, func(t *testing.T) {
				run := h.run(t, SandboxHookDir+"/"+tc.script, tc.args, tc.stdin, env, []string{"200|" + reply})
				if run.exitCode != 0 {
					t.Fatalf("exit %d, want 0 (an alert lets the tool run); stdout=%q stderr=%s", run.exitCode, run.stdout, run.stderr)
				}
				if len(run.calls) != 1 {
					t.Fatalf("calls = %d, want 1", len(run.calls))
				}
				if strings.Contains(run.stderr, "invalid or missing action") {
					t.Fatalf("the alert was taken for a bad reply: %s", run.stderr)
				}
				if name == "with-notice" && tc.notice != "" && strings.TrimSpace(run.stdout) != tc.notice {
					t.Fatalf("stdout = %q, want the harness notice %s", run.stdout, tc.notice)
				}
				if name == "bare" && (tc.connector == "claudecode" || tc.connector == "codex") && run.stdout != "" {
					t.Fatalf("stdout = %q, want nothing without a notice", run.stdout)
				}
			})
		}
	}
}

// TestHostHooksTreatAlertAsAdvisory runs the host Claude Code and Codex hooks
// against a stubbed gateway in both fail modes: an alert exits 0 with the
// notice on stdout and records no hook failure.
func TestHostHooksTreatAlertAsAdvisory(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required")
	}
	dir := t.TempDir()
	if err := WriteHookScriptsWithToken(dir, "127.0.0.1:18970", "tok-test"); err != nil {
		t.Fatalf("WriteHookScriptsWithToken: %v", err)
	}
	stubDir := t.TempDir()
	stub := "#!/bin/sh\nprintf '%s\\n200' " + shellSingleQuoteForTest(alertVerdict) + "\n"
	if err := os.WriteFile(filepath.Join(stubDir, "curl"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	bakeHookPathForTest(t, filepath.Join(dir, "claude-code-hook.sh"), stubDir+":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")

	for _, tc := range []struct {
		script string
		args   []string
		stdin  string
	}{
		{"claude-code-hook.sh", nil, claudePreToolUse},
		{"codex-hook.sh", []string{"--event", "PreToolUse", "--hook-contract", "codex-hooks-v4"}, codexPreToolUse},
	} {
		for _, mode := range []string{"closed", "open"} {
			t.Run(tc.script+"/"+mode, func(t *testing.T) {
				dcHome := t.TempDir()
				cmd := exec.Command("bash", append([]string{filepath.Join(dir, tc.script)}, tc.args...)...)
				cmd.Env = append(os.Environ(), "DEFENSECLAW_HOME="+dcHome, "DEFENSECLAW_FAIL_MODE="+mode)
				cmd.Stdin = strings.NewReader(tc.stdin)
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				err := cmd.Run()
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					t.Fatalf("exit %d, want 0 (an alert lets the tool run); stderr=%s", exitErr.ExitCode(), stderr.String())
				} else if err != nil {
					t.Fatal(err)
				}
				if got := strings.TrimSpace(stdout.String()); got != alertNotice {
					t.Fatalf("stdout = %q, want the harness notice %s", got, alertNotice)
				}
				if data, err := os.ReadFile(filepath.Join(dcHome, "logs", "hook-failures.jsonl")); err == nil {
					t.Fatalf("an alert recorded a hook failure: %s", data)
				}
			})
		}
	}
}
