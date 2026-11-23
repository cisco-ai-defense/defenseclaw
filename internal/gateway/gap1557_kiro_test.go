// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The hook rows use shellExtraKeyHook (POSIX hosts); kiroPwshOnWindows sets
// the Windows route.

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// kiroPwshOnWindows judges Kiro calls as a Windows host does, where kiro-cli
// runs execute_pwsh in PowerShell, for the rest of the test.
func kiroPwshOnWindows(t *testing.T, windows bool) {
	t.Helper()
	previous := kiroPwshRunsPowerShell
	kiroPwshRunsPowerShell = windows
	t.Cleanup(func() { kiroPwshRunsPowerShell = previous })
}

// TestGAP1557KiroExecutePwshUsesPowerShellCommandReading: where kiro-cli runs
// execute_pwsh in PowerShell, the command alone is also judged as PowerShell,
// so a PowerShell append to authorized_keys blocks as it does on the
// PowerShell tool (rel-1-0-10:GAP-1557). execute_bash, and execute_pwsh where
// Kiro does not run it in PowerShell, keep the shell reading alone: there the
// call is judged as the ACP terminal that runs the same command is.
func TestGAP1557KiroExecutePwshUsesPowerShellCommandReading(t *testing.T) {
	ctx := context.Background()
	for _, row := range []struct {
		windows bool
		tool    string
		want    bool
	}{
		{true, "execute_pwsh", true},
		{true, "Execute_Pwsh", true},
		{true, "execute_bash", false},
		{true, "shell", false},
		{false, "execute_pwsh", false},
	} {
		kiroPwshOnWindows(t, row.windows)
		if got := kiroPowerShellCommand(ctx, "kiro", &ToolInspectRequest{Tool: row.tool}, "shell"); got != row.want {
			t.Errorf("windows=%v %s: PowerShell reading %v, want %v", row.windows, row.tool, got, row.want)
		}
	}
	kiroPwshOnWindows(t, true)
	if kiroPowerShellCommand(ctx, "copilot", &ToolInspectRequest{Tool: "execute_pwsh"}, "shell") {
		t.Error("a Copilot call named execute_pwsh got the Kiro PowerShell reading")
	}
	// The shell reading stays the command's own reading.
	args := json.RawMessage(`{"command":"Get-ChildItem ."}`)
	if command, tool := sandboxShellCommand(ctx, "kiro", "PreToolUse", "execute_pwsh", "shell", args); len(command) == 0 || tool != "shell" {
		t.Fatalf("Kiro command %s judged as %q, want shell", command, tool)
	}

	const appendKeys = `"Add-Content -Path \"$HOME\\.ssh\\authorized_keys\" -Value k"`
	for _, row := range []struct {
		name, args string
		block      bool
	}{
		{"append", `{"command":` + appendKeys + `}`, true},
		{"append-extra", `{"command":` + appendKeys + `,"extra":"x"}`, true},
		{"append-cwd-case", `{"command":` + appendKeys + `,"Cwd":"{PROJ}"}`, true},
		{"benign-append", `{"command":"Add-Content -Path notes.txt -Value k"}`, false},
		{"benign-list", `{"command":"Get-ChildItem .","extra":"x"}`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			kiroPwshOnWindows(t, false)
			posix := shellExtraKeyHook(t, "kiro", "execute_pwsh", json.RawMessage(row.args))
			bash := shellExtraKeyHook(t, "kiro", "execute_bash", json.RawMessage(row.args))
			if hookResponseAction(posix) != hookResponseAction(bash) {
				t.Errorf("off Windows execute_pwsh = %.300s; execute_bash = %.300s", posix, bash)
			}
			kiroPwshOnWindows(t, true)
			got := shellExtraKeyHook(t, "kiro", "execute_pwsh", json.RawMessage(row.args))
			if row.block {
				if hookResponseAction(got) != "block" || !strings.Contains(got, "authorized_keys") {
					t.Fatalf("PowerShell append to authorized_keys = %.600s; want block", got)
				}
				return
			}
			if hookResponseAction(got) != "allow" {
				t.Fatalf("benign PowerShell call = %.600s; want allow", got)
			}
		})
	}
}

// TestGAP1940KiroPowerShellReadingKeepsTheShellReading: the PowerShell
// reading of a Kiro execute_pwsh command is added to the shell reading every
// shell call has, never put in its place. Judged as PowerShell alone, a
// second command key spelled Command next to rm -rf was allowed and two
// command keys lost their conflict (GAP-1940); with both readings each row
// keeps the verdict and rule it has off Windows.
func TestGAP1940KiroPowerShellReadingKeepsTheShellReading(t *testing.T) {
	const rm = `"rm -rf ~/"`
	for _, row := range []struct {
		name, args, rule string
	}{
		{"alone", `{"command":` + rm + `}`, "CMD-RM-RF"},
		{"extra", `{"command":` + rm + `,"extra":"x"}`, "CMD-RM-RF"},
		{"cwd-case", `{"command":` + rm + `,"Cwd":"{PROJ}"}`, "CMD-RM-RF"},
		{"command-case-extra", `{"command":` + rm + `,"Command":"true","extra":"x"}`, "CMD-RM-RF"},
		{"command-case-value-extra", `{"command":"true","Command":` + rm + `,"extra":"x"}`, conflictingToolArgumentsRuleID},
		{"no-command-key", `{"Command":` + rm + `,"extra":"x"}`, unverifiedShellCommandRuleID},
		{"empty-args", `{}`, unverifiedShellCommandRuleID},
		{"benign", `{"command":"ls","description":"x","timeout":5}`, "allow"},
		{"benign-extra", `{"command":"ls","extra":"x"}`, "allow"},
	} {
		t.Run(row.name, func(t *testing.T) {
			kiroPwshOnWindows(t, true)
			got := shellExtraKeyHook(t, "kiro", "execute_pwsh", json.RawMessage(row.args))
			if row.rule == "allow" {
				if hookResponseAction(got) != "allow" {
					t.Fatalf("benign call = %.600s", got)
				}
				return
			}
			if hookResponseAction(got) != "block" || !strings.Contains(got, row.rule) {
				t.Fatalf("verdict = %.600s; want block with %q", got, row.rule)
			}
		})
	}
}

// hookResponseAction is the action of a hook response body.
func hookResponseAction(body string) string {
	var verdict struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal([]byte(body), &verdict); err != nil {
		return "unreadable: " + err.Error()
	}
	return verdict.Action
}
