//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	awaitedHookChildEnv = "DEFENSECLAW_TEST_AWAITED_HOOK_CHILD"
	awaitedHookMarker   = "awaited-hook-fast-exit-marker"
	awaitedHookStdout   = `{"decision":"block","reason":"` + awaitedHookMarker + `"}`
	// awaitedHookCaseDeadline bounds the runs of one bridge, which take a few
	// seconds, so a bridge that never returns fails its case with the runs it
	// lost instead of hanging the package until the go test timeout.
	awaitedHookCaseDeadline = 2 * time.Minute
)

// init makes this test binary stand in for the release hook launcher when
// TestWindowsAwaitedHookCommandsReturnFastExitStatus runs it through a
// rendered command. It exits 2 (a block) as soon as it has read its payload,
// with the decision on stdout and a reason on stderr; 3 and 4 name a wrong
// argument list or a missing payload.
func init() {
	want, ok := os.LookupEnv(awaitedHookChildEnv)
	if !ok {
		return
	}
	data, _ := io.ReadAll(os.Stdin)
	switch {
	case !strings.Contains(string(data), awaitedHookMarker):
		os.Exit(4)
	case strings.Join(os.Args[1:], " ") != want:
		os.Exit(3)
	}
	os.Stdout.WriteString(awaitedHookStdout + "\n")
	os.Stderr.WriteString("blocked: " + awaitedHookMarker + "\n")
	os.Exit(2)
}

// Windows PowerShell 5.1's Start-Process -Wait -PassThru opened the launcher
// again by process ID after starting it, so a launcher that had already
// exited made PowerShell exit 1 ("the process has exited") and the block and
// the hook's output were lost. Run every generated bridge against a
// GUI-subsystem launcher that exits at once, many times and several at once
// so a busy host gives the fast exit its chance to win, the way each agent
// launches it. Every run must return 2 with the hook's stdout and stderr.
func TestWindowsAwaitedHookCommandsReturnFastExitStatus(t *testing.T) {
	gui := guiSubsystemCopyOfTestBinary(t)
	setHookBinaryOverride(t, gui)
	const contract = "codex-hooks-v4"
	cmdExe := filepath.Join(trustedWindowsSystemDirectory(), "cmd.exe")
	systemPowerShell := windowsSystemPowerShellExe()
	throughCmd := func(command string) func(context.Context) *exec.Cmd {
		return func(ctx context.Context) *exec.Cmd {
			cmd := exec.CommandContext(ctx, cmdExe)
			cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: `cmd.exe /d /s /c "` + command + `"`}
			return cmd
		}
	}
	direct := func(command string) func(context.Context) *exec.Cmd {
		return func(ctx context.Context) *exec.Cmd {
			argv := strings.Fields(command)
			return exec.CommandContext(ctx, argv[0], argv[1:]...)
		}
	}
	throughCommand := func(shell, script string) func(context.Context) *exec.Cmd {
		return func(ctx context.Context) *exec.Cmd {
			return exec.CommandContext(ctx, shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
		}
	}
	bareScript := func(arguments ...string) string {
		return strings.Join(append([]string{
			"$ErrorActionPreference='Stop'",
			"$env:NoDefaultCurrentDirectoryInExePath='1'",
		}, windowsAwaitedHookStatements(gui, arguments)...), "; ")
	}
	codexUser := windowsNativePowerShellHookCommandForCodexEvent("PreToolUse", contract, gui)
	copilotArgs := []string{"hook", "--connector", "copilot", "--enterprise-managed", "--event", "preToolUse"}
	cases := []struct {
		name  string
		args  string
		start func(context.Context) *exec.Cmd
	}{
		{"codex per-user through cmd", "hook --connector codex --event PreToolUse --hook-contract " + contract, throughCmd(codexUser)},
		{"codex standalone through cmd", "hook --connector codex --enterprise-managed --event PreToolUse --hook-contract " + contract,
			throughCmd(windowsCodexBoundManagedHookCommand(gui, "PreToolUse", contract))},
		{"antigravity direct", "hook --connector antigravity --event PreToolUse",
			direct(antigravityHookInvocationCommandForEvent("windows", "PreToolUse", ""))},
		{"copilot managed through powershell -Command", strings.Join(copilotArgs, " "),
			throughCommand(systemPowerShell, bareScript(copilotArgs...))},
		// WDAC or AppLocker script enforcement runs the bridge in Constrained
		// Language mode, which refuses the .NET calls.
		{"codex per-user in Constrained Language mode", "hook --connector codex --event PreToolUse --hook-contract " + contract,
			throughCommand(systemPowerShell, "$ExecutionContext.SessionState.LanguageMode='ConstrainedLanguage'; Invoke-Expression "+
				powershellQuoteLiteral(decodePowerShellEncodedCommandForTest(t, codexUser)))},
	}
	if pwsh, err := exec.LookPath("pwsh.exe"); err == nil {
		cases = append(cases, struct {
			name  string
			args  string
			start func(context.Context) *exec.Cmd
		}{"copilot managed through pwsh -Command", strings.Join(copilotArgs, " "), throughCommand(pwsh, bareScript(copilotArgs...))})
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			const runs, parallel = 32, 8
			ctx, cancel := context.WithTimeout(context.Background(), awaitedHookCaseDeadline)
			defer cancel()
			results := make(chan string, runs)
			slots := make(chan struct{}, parallel)
			for i := 0; i < runs; i++ {
				slots <- struct{}{}
				go func() {
					defer func() { <-slots }()
					cmd := testCase.start(ctx)
					// The killed bridge's launcher may still hold the output pipes.
					cmd.WaitDelay = 5 * time.Second
					cmd.Stdin = strings.NewReader(`{"tool":"` + awaitedHookMarker + `"}`)
					cmd.Env = append(os.Environ(), awaitedHookChildEnv+"="+testCase.args)
					var stdout, stderr strings.Builder
					cmd.Stdout, cmd.Stderr = &stdout, &stderr
					_ = cmd.Run()
					switch {
					case ctx.Err() != nil && (cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 2):
						results <- fmt.Sprintf("no result within %s: stdout=%q stderr=%q", awaitedHookCaseDeadline, stdout.String(), stderr.String())
					case cmd.ProcessState == nil:
						results <- "not started"
					case cmd.ProcessState.ExitCode() != 2:
						results <- fmt.Sprintf("exit %d: stdout=%q stderr=%q", cmd.ProcessState.ExitCode(), stdout.String(), stderr.String())
					case strings.TrimSpace(stdout.String()) != awaitedHookStdout:
						results <- fmt.Sprintf("stdout = %q, want %q", stdout.String(), awaitedHookStdout)
					case !strings.Contains(stderr.String(), "blocked: "+awaitedHookMarker):
						results <- fmt.Sprintf("stderr = %q, want the reason", stderr.String())
					default:
						results <- ""
					}
				}()
			}
			var lost []string
			for i := 0; i < runs; i++ {
				if result := <-results; result != "" {
					lost = append(lost, result)
				}
			}
			if len(lost) > 0 {
				t.Fatalf("%d of %d runs lost the hook's block or output; first: %s", len(lost), runs, lost[0])
			}
		})
	}
}
