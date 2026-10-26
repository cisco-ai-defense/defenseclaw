// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A cmd /c prefix selects CMD grammar only when it is the whole PowerShell
// command line. A later PowerShell statement, pipeline, redirect or
// expansion keeps PowerShell grammar, so its protected write is judged.
func TestR104Loop1WindowsCMDPrefixKeepsPowerShell(t *testing.T) {
	for _, tc := range []struct {
		name, connector, tool, command string
		dialect                        actionfacts.Dialect
		block                          bool
	}{
		{"Codex cmd.exe then Add-Content", "codex", "exec_command", `cmd.exe /c "echo ok"; Add-Content -Path '~/.ssh/authorized_keys' -Value 'dummy-key'`, actionfacts.DialectPowerShell, true},
		{"Codex cmd then Set-Content", "codex", "exec_command", `cmd /c "echo ok"; Set-Content -Path '~/.ssh/authorized_keys' -Value 'dummy-key'`, actionfacts.DialectPowerShell, true},
		{"Copilot cmd /d then Out-File", "copilot", "powershell", `cmd /d /c "echo ok"; Out-File -FilePath '~/.ssh/authorized_keys' -InputObject 'dummy-key'`, actionfacts.DialectPowerShell, true},
		{"Hermes cmd then pipeline Add-Content", "hermes", "shell", `cmd.exe /c "echo ok" | Add-Content -Path '~/.ssh/authorized_keys'`, actionfacts.DialectPowerShell, true},
		{"Codex cmd then PowerShell append redirect", "codex", "exec_command", `cmd.exe /c "echo dummy-key" >> ~/.ssh/authorized_keys`, actionfacts.DialectPowerShell, true},
		{"Codex cmd uppercase then Add-Content", "codex", "exec_command", `CMD.EXE /C "echo ok" ; Add-Content -Path '~/.ssh/authorized_keys' -Value 'dummy-key'`, actionfacts.DialectPowerShell, true},
		{"Codex cmd then ordinary Add-Content", "codex", "exec_command", `cmd.exe /c "echo ok"; Add-Content -Path '~/report.txt' -Value 'dummy-key'`, actionfacts.DialectPowerShell, false},
		{"Copilot sole CMD protected write", "copilot", "powershell", `cmd.exe /c "echo dummy-key>>%USERPROFILE%\.ssh\authorized_keys"`, actionfacts.DialectCMD, true},
		{"Codex sole CMD protected write", "codex", "exec_command", `cmd /d /c "echo dummy-key>>%USERPROFILE%\.ssh\authorized_keys"`, actionfacts.DialectCMD, true},
		{"Copilot sole CMD ordinary write", "copilot", "powershell", `cmd.exe /c "echo marker>>%USERPROFILE%\report.txt"`, actionfacts.DialectCMD, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: agentHookTrustedActionTool(tc.connector, tc.tool, "windows"),
				Command: tc.command, CWD: `C:\Users\alice\project`, ActiveHome: `C:\Users\alice`}
			input.DialectHint = selectWindowsShellDialect(input.Tool, input.Command, input)
			// A PowerShell line keeps its PowerShell or inferred grammar.
			if (input.DialectHint == actionfacts.DialectCMD) != (tc.dialect == actionfacts.DialectCMD) {
				t.Fatalf("dialect=%q, want %q", input.DialectHint, tc.dialect)
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: tc.connector, EnforcementCapable: true,
			})
			finding := findingWithID(findings, "persistence.ssh_authorized_keys_command")
			if got := finding != nil && finding.contributesToEnforcement(); got != tc.block {
				t.Fatalf("registered %s proof: blocked=%v, want %v; findings=%v", tc.connector, got, tc.block, FindingStrings(findings))
			}
		})
	}
}

// A PowerShell double-quoted cmd body expands $ and backtick forms before
// cmd.exe runs, and a following redirect or pipeline belongs to PowerShell,
// so none of these is a sole CMD invocation.
func TestR104Loop1WindowsCMDSoleInvocation(t *testing.T) {
	for _, tc := range []struct {
		command string
		cmd     bool
	}{
		{`cmd.exe /c "echo ok"`, true},
		{`cmd /d /c "echo dummy-key>>%USERPROFILE%\.ssh\authorized_keys"`, true},
		{`cmd.exe /c "echo ok"; Add-Content -Path '~/.ssh/authorized_keys' -Value 'k'`, false},
		{`cmd.exe /c "echo ok" | Add-Content -Path '~/.ssh/authorized_keys'`, false},
		{`cmd.exe /c "echo ok" > $HOME\.ssh\authorized_keys`, false},
		{`cmd.exe /c "echo $(Add-Content -Path '~/.ssh/authorized_keys' -Value 'k')"`, false},
		{"cmd.exe /c \"echo `$x\"", false},
		{"cmd.exe /c \"echo ok\u201d; Add-Content -Path '~/.ssh/authorized_keys' -Value 'k'\"", false},
		{"cmd.exe\n/c \"echo ok\"", false},
		{"cmd.exe /c \"echo ok\"\nAdd-Content -Path '~/.ssh/authorized_keys' -Value 'k'", false},
		{`cmd.exe /c "echo a" "echo b"`, false},
	} {
		if got := soleCMDInvocation(tc.command); got != tc.cmd {
			t.Errorf("soleCMDInvocation(%q)=%v, want %v", tc.command, got, tc.cmd)
		}
	}
}

// Dynamic ordinary operands remain allowed. A protected link named inside an
// interpreter argument is protected named even if its output is ordinary.
func TestR104Loop1DynamicOperandDecisions(t *testing.T) {
	skipNativeWindowsHomeGrammar(t)
	home, cwd := r104ReviewHome(t)
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"awk dynamic input", `awk '{print}' "$input"`, false},
		{"awk field separator and dynamic input", `awk -F, '{print $1}' "$input"`, false},
		{"awk literal ordinary output with dynamic input", `awk '{print > "report.txt"}' "$input"`, false},
		{"awk computed output with dynamic input", `awk '{print > out}' "$input"`, false},
		{"awk pipe with dynamic input", `awk '{print | "sh"}' "$input"`, false},
		{"awk dynamic program", `awk "$program" input.txt`, false},
		{"python ordinary open with protected data and dynamic argument", `python3 -c 'open("out.txt","w").write("alias")' "$USER"`, true},
		{"wrapped python ordinary open with dynamic argument", `nice python3 -c 'open("out.txt","w").write("alias")' "$USER"`, true},
		{"node ordinary write with dynamic argument", `node -e 'require("fs").writeFileSync("out.txt","alias")' "$USER"`, true},
		{"python protected open with dynamic argument", `python3 -c 'open("alias","a").write("marker")' "$USER"`, true},
		{"wrapped python protected open with dynamic argument", `nice python3 -c 'open("alias","a").write("marker")' "$USER"`, true},
		{"python argv destination", `python3 -c 'import sys; open(sys.argv[1],"w").write("x")' "$USER"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, blocked := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				if blocked != tc.block {
					t.Fatalf("route %d blocked=%v, want %v", i, blocked, tc.block)
				}
			}
		})
	}
}

func TestR104Loop1WindowsCMDPrefixNative(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native registered Windows hook route")
	}
	for _, tc := range []struct {
		connector, event, tool, command, commandKey string
	}{
		{"codex", "PreToolUse", "exec_command", `cmd.exe /c "echo ok"; Add-Content -Path '~/.ssh/authorized_keys' -Value 'dummy-key'`, "cmd"},
		{"copilot", "preToolUse", "powershell", `cmd /c "echo ok"; Add-Content -Path '~/.ssh/authorized_keys' -Value 'dummy-key'`, "command"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = tc.connector
			api := &APIServer{scannerCfg: cfg}
			args, err := json.Marshal(map[string]string{tc.commandKey: tc.command})
			if err != nil {
				t.Fatal(err)
			}
			resp := api.evaluateAgentHook(t.Context(), agentHookRequest{
				ConnectorName: tc.connector, HookEventName: tc.event, ToolName: tc.tool, ToolArgs: args,
			})
			// RuleIDs come from the scan-finding emitter, which this bare
			// APIServer does not have; the response findings name the rule.
			named := containsString(resp.RuleIDs, "persistence.ssh_authorized_keys_command")
			for _, finding := range resp.Findings {
				named = named || strings.HasPrefix(finding, "persistence.ssh_authorized_keys_command:")
			}
			if resp.RawAction != "block" || resp.Action != "block" || !named {
				t.Fatalf("registered hook action=%q raw=%q rules=%v findings=%v", resp.Action, resp.RawAction, resp.RuleIDs, resp.Findings)
			}
		})
	}
}
