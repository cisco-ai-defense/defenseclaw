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

// TestGAP1197PaddedEncodedCommandHookRoute sends a PowerShell host call whose
// -EncodedCommand word carries the blanks .NET Convert.FromBase64String skips
// over the trusted-action hook route. The host decodes and runs the script, so
// the verdict must read it like the unpadded word (rel-1-0-10:GAP-1197).
func TestGAP1197PaddedEncodedCommandHookRoute(t *testing.T) {
	const connector = "gap1197-padded-enc"
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
		dialect       actionfacts.Dialect
		block         bool
	}{
		{"unpadded baseline", `pwsh -EncodedCommand ` + bad, actionfacts.DialectPowerShell, true},
		{"padded both ends", `pwsh -EncodedCommand ' ` + bad + ` '`, actionfacts.DialectPowerShell, true},
		{"leading blanks ec", `powershell -ec '  ` + bad + `'`, actionfacts.DialectPowerShell, true},
		{"trailing blank enc", `pwsh -nop -enc '` + bad + ` '`, actionfacts.DialectPowerShell, true},
		{"blank inside", `pwsh -e '` + bad[:8] + ` ` + bad[8:] + `'`, actionfacts.DialectPowerShell, true},
		{"cmd padded", `powershell -enc " ` + bad + ` "`, actionfacts.DialectCMD, true},
		{"padded benign", `pwsh -EncodedCommand ' ` + ok + ` '`, actionfacts.DialectPowerShell, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]string{"command": tc.command})
			if err != nil {
				t.Fatal(err)
			}
			input := actionfacts.Input{Tool: "Bash", Args: args, CWD: home + `\project`, ActiveHome: home, DialectHint: tc.dialect}
			if tc.dialect != actionfacts.DialectCMD {
				input.DialectHint = agentHookWindowsShellDialect(input)
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, LegacyText: string(args), Connector: connector, EnforcementCapable: true})
			got := buildVerdict(findings, "tool_call").Action == guardrailActionBlock
			if got != tc.block {
				t.Fatalf("blocked=%t, want %t; findings=%v", got, tc.block, findingIDs(findings))
			}
		})
	}
}
