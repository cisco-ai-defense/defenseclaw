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
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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

// Cursor supplies a command on beforeShellExecution, without a tool name.
// The shared Windows shell selection must preserve write permission checks
// after that payload is projected onto the trusted shell shape.
func TestCursorWindowsShellPermissionChecks(t *testing.T) {
	const rule = "persistence.ssh_authorized_keys_command"
	const profile = "cursor-windows-shell-permission"
	installToolCallCorpusProfileConnector(t, profile, "default")
	tests := []struct {
		name, command string
		blocked       bool
	}{
		{"home append", `echo marker >> $HOME\.ssh\authorized_keys`, true},
		{"absolute append", `echo marker >> C:\Users\alice\.ssh\authorized_keys`, true},
		{"tilde overwrite", `echo marker > ~\.ssh\authorized_keys`, true},
		{"environment append", `Add-Content -Path $env:USERPROFILE\.ssh\authorized_keys -Value marker`, true},
		// /d makes the quoted CMD body independent of Command Processor AutoRun.
		{"cmd environment append", `cmd /d /c "echo marker >> %USERPROFILE%\.ssh\authorized_keys"`, true},
		{"out file append", `Out-File -Append -FilePath C:\ProgramData\ssh\administrators_authorized_keys -InputObject marker`, true},
		{"set content", `Set-Content -Path $HOME\.ssh\authorized_keys -Value marker`, true},
		{"tee", `echo marker | tee -Append $HOME\.ssh\authorized_keys`, true},
		{"home read", `Get-Content $HOME\.ssh\authorized_keys`, false},
		{"native read", `type C:\Users\alice\.ssh\authorized_keys`, false},
		{"cat read", `cat C:\Users\alice\.ssh\authorized_keys`, false},
		{"other curl output", `curl.exe -o C:\Users\alice\notes.txt https://example.com`, false},
		{"authorized curl output", `curl.exe -o C:\Users\alice\.ssh\authorized_keys https://example.com`, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload, err := json.Marshal(map[string]string{"command": test.command})
			if err != nil {
				t.Fatal(err)
			}
			args, _, ok := connector.CursorTrustedShellArgs("beforeShellExecution", payload)
			if !ok {
				t.Fatal("Cursor shell projection failed")
			}
			input := actionfacts.Input{
				Tool: "shell", Args: args, CWD: `C:\Users\alice\project`, ActiveHome: `C:\Users\alice`,
			}
			input.DialectHint = agentHookWindowsShellDialect(input)
			facts := actionfacts.Analyze(input)
			if !facts.Authoritative() || !facts.EnforcementEligible() {
				t.Fatalf("permission facts unavailable: dialect=%q status=%q", facts.Parse.Dialect, facts.Parse.Status)
			}
			if test.blocked {
				write := false
				for _, path := range facts.Paths {
					if strings.HasSuffix(strings.ToLower(path.Resolved), "authorized_keys") &&
						(path.Access == actionfacts.PathAccessWrite || path.Access == actionfacts.PathAccessAppend) {
						write = true
					}
				}
				if !write {
					t.Fatalf("permission facts have no authorized keys write: %+v", facts.Paths)
				}
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: profile, EnforcementCapable: true,
			})
			finding := findingWithID(findings, rule)
			if got := finding != nil && finding.contributesToEnforcement(); got != test.blocked {
				t.Fatalf("permission block=%t, want %t: %v", got, test.blocked, FindingStrings(findings))
			}
			if !test.blocked {
				for _, finding := range findings {
					if finding.contributesToEnforcement() {
						t.Fatalf("read-only permission check blocked: %v", FindingStrings(findings))
					}
				}
			}
		})
	}
	if runtime.GOOS == "windows" {
		for _, command := range []string{
			`echo marker >> $HOME\.ssh\authorized_keys`,
			`echo marker >> C:\Users\alice\.ssh\authorized_keys`,
		} {
			t.Run("hook/"+command, func(t *testing.T) {
				store, logger := testStoreAndLogger(t)
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = "cursor"
				api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
				response := api.evaluateAgentHook(t.Context(), agentHookRequest{
					ConnectorName: "cursor", HookEventName: "beforeShellExecution",
					ToolArgs: mustJSONMarshal(map[string]string{"command": command}),
				})
				if response.RawAction != "block" || !containsString(response.RuleIDs, rule) {
					t.Fatalf("hook permission result=%q rules=%v, want block for %s", response.RawAction, response.RuleIDs, rule)
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
