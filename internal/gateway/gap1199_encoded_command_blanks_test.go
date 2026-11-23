// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP1199EncodedCommandControlBlanksHookRoute sends a PowerShell host call
// whose -EncodedCommand word carries a tab, CR or LF (which .NET
// Convert.FromBase64String skips) over the trusted-action hook route. The host
// decodes and runs the script, so the verdict must read it like the clean word
// (rel-1-0-10:GAP-1199).
func TestGAP1199EncodedCommandControlBlanksHookRoute(t *testing.T) {
	const connector = "gap1199-blank-enc"
	installToolCallCorpusProfileConnector(t, connector, "default")
	home := `C:\Users\Alice`
	enc := func(body string) string {
		units := utf16.Encode([]rune(body))
		b := make([]byte, len(units)*2)
		for i, u := range units {
			b[2*i], b[2*i+1] = byte(u), byte(u>>8)
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	bad := enc(`Add-Content -Path $env:USERPROFILE\.ssh\authorized_keys -Value marker`)
	ok := enc(`Write-Output ready`)
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"clean baseline", `pwsh -EncodedCommand ` + bad, true},
		{"tab after", "pwsh -enc '" + bad + "\t'", true},
		{"tab before", "powershell -ec '\t" + bad + "'", true},
		{"tab inside", "pwsh -e '" + bad[:8] + "\t" + bad[8:] + "'", true},
		{"crlf inside", "pwsh -nop -EncodedCommand '" + bad[:16] + "\r\n" + bad[16:] + "'", true},
		{"lf inside double quoted", "powershell -enc \"" + bad[:20] + "\n" + bad[20:] + "\"", true},
		{"benign tab after", "pwsh -enc '" + ok + "\t'", false},
		{"benign tab inside", "pwsh -e '" + ok[:8] + "\t" + ok[8:] + "'", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]string{"command": tc.command})
			if err != nil {
				t.Fatal(err)
			}
			input := actionfacts.Input{Tool: "Bash", Args: args, CWD: home + `\project`, ActiveHome: home, DialectHint: actionfacts.DialectPowerShell}
			input.DialectHint = agentHookWindowsShellDialect(input)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, LegacyText: string(args), Connector: connector, EnforcementCapable: true})
			got := buildVerdict(findings, "tool_call").Action == guardrailActionBlock
			if got != tc.block {
				t.Fatalf("blocked=%t, want %t; findings=%v", got, tc.block, findingIDs(findings))
			}
		})
	}
}
