// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
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
