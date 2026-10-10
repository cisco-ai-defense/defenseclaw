// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestAgentHookTrustedActionToolNormalizesOpenCodeBashOnWindows(t *testing.T) {
	tests := []struct {
		name      string
		connector string
		tool      string
		platform  string
		want      string
	}{
		{
			name:      "OpenCode native Windows terminal",
			connector: "opencode",
			tool:      "bash",
			platform:  "windows",
			want:      "shell",
		},
		{
			name:      "OpenCode POSIX terminal",
			connector: "opencode",
			tool:      "bash",
			platform:  "linux",
			want:      "bash",
		},
		{
			name:      "other Windows connector",
			connector: "cursor",
			tool:      "bash",
			platform:  "windows",
			want:      "bash",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := agentHookTrustedActionTool(
				test.connector,
				test.tool,
				test.platform,
			); got != test.want {
				t.Fatalf("trusted action tool = %q, want %q", got, test.want)
			}
		})
	}
}

func TestKiroWindowsAuthorizedKeysPermissionCheck(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows shell grammar")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	path := strings.ReplaceAll(home, `/`, `\`) + `\.ssh\authorized_keys`
	tests := []struct {
		name, tool, command string
		block               bool
	}{
		{"add tilde", "execute_bash", `Add-Content -Path ~/.ssh/authorized_keys -Value marker`, true},
		{"add home", "shell", `Add-Content $HOME\.ssh\authorized_keys -Value marker`, true},
		{"out file profile", "execute_bash", `Out-File -Append -FilePath $env:USERPROFILE\.ssh\authorized_keys -InputObject marker`, true},
		{"echo tilde", "shell", `echo marker >> ~/.ssh/authorized_keys`, true},
		{"echo home", "execute_bash", `echo marker >> $HOME\.ssh\authorized_keys`, true},
		{"absolute", "execute_bash", `Add-Content -Path "` + path + `" -Value marker`, true},
		{"powershell wrapper", "shell", `powershell -Command "Add-Content -Path ~/.ssh/authorized_keys -Value marker"`, true},
		{"quoted home", "execute_bash", "Add-Content -Path \"$HOME\\.ssh\\authorized_keys\" -Value marker", true},
		{"benign", "execute_bash", `Add-Content -Path ~/project/notes.txt -Value marker`, false},
	}
	for _, mode := range []string{"action", "observe"} {
		for _, test := range tests {
			t.Run(mode+"/"+test.name, func(t *testing.T) {
				cfg := &config.Config{}
				cfg.Guardrail.Mode = mode
				cfg.Guardrail.Connector = "kiro"
				api := &APIServer{scannerCfg: cfg}
				args, err := json.Marshal(map[string]string{"command": test.command})
				if err != nil {
					t.Fatal(err)
				}
				resp := api.evaluateAgentHook(t.Context(), agentHookRequest{
					ConnectorName: "kiro", HookEventName: "preToolUse", ToolName: test.tool, ToolArgs: args,
				})
				wantAction := "allow"
				if test.block && mode == "action" {
					wantAction = "block"
				}
				if resp.Action != wantAction {
					t.Fatalf("action=%q raw=%q reason=%q rules=%v, want %q", resp.Action, resp.RawAction, resp.Reason, resp.RuleIDs, wantAction)
				}
				if test.block && (resp.RawAction != "block" ||
					!strings.Contains(resp.Reason, "persistence.ssh_authorized_keys_command")) {
					t.Fatalf("missing permission rule: raw=%q reason=%q", resp.RawAction, resp.Reason)
				}
				if !test.block && resp.RawAction != "allow" {
					t.Fatalf("benign raw action=%q, want allow", resp.RawAction)
				}
			})
		}
	}
}

func TestOpenCodeWindowsBashToolSelectsPowerShellActionFacts(t *testing.T) {
	const command = `Remove-Item -Force C:\ -Recurse`
	args, err := json.Marshal(map[string]any{
		"command": command,
	})
	if err != nil {
		t.Fatal(err)
	}
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool: agentHookTrustedActionTool("opencode", "bash", "windows"),
		Args: args,
	})
	if facts.Parse.Dialect != actionfacts.DialectPowerShell {
		t.Fatalf("dialect = %q, want %q", facts.Parse.Dialect, actionfacts.DialectPowerShell)
	}
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		t.Fatalf(
			"Windows OpenCode facts are not enforceable: status=%q commands=%d",
			facts.Parse.Status,
			len(facts.Commands),
		)
	}
	installDefaultProfileConnector(t, "opencode")
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:              actionfacts.Input{Tool: "shell", Args: args},
		LegacyText:         command,
		Connector:          "opencode",
		EnforcementCapable: true,
	})
	matched := findingWithID(findings, "CMD-RM-RF")
	if matched == nil || !matched.contributesToEnforcement() {
		t.Fatalf("Windows OpenCode command did not produce an enforceable CMD-RM-RF finding: %v", FindingStrings(findings))
	}
}

func TestOpenCodeWindowsBashToolKeepsProtectedSAMReadAdvisory(t *testing.T) {
	const command = `Get-Content -LiteralPath 'C:\Windows\System32\config\SAM'`
	args, err := json.Marshal(map[string]any{
		"command": command,
	})
	if err != nil {
		t.Fatal(err)
	}
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool: agentHookTrustedActionTool("opencode", "bash", "windows"),
		Args: args,
	})
	if facts.Parse.Dialect != actionfacts.DialectPowerShell {
		t.Fatalf("dialect = %q, want %q", facts.Parse.Dialect, actionfacts.DialectPowerShell)
	}
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		t.Fatalf(
			"Windows OpenCode SAM-read facts are not enforceable: status=%q commands=%d",
			facts.Parse.Status,
			len(facts.Commands),
		)
	}
	installDefaultProfileConnector(t, "opencode")
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:              actionfacts.Input{Tool: "shell", Args: args},
		LegacyText:         command,
		Connector:          "opencode",
		EnforcementCapable: true,
	})
	matched := findingWithID(findings, "PATH-WIN-SAM")
	if matched == nil || matched.contributesToEnforcement() || matched.Severity != "MEDIUM" {
		t.Fatalf("Windows OpenCode SAM read did not remain a MEDIUM advisory PATH-WIN-SAM finding: %#v", matched)
	}
}
