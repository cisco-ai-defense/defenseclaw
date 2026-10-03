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

package gateway

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestTrustedActionPowerShellCommandBodyReduction(t *testing.T) {
	const connector = "powershell-command-body-test"
	const marker = "dccert-block-marker"
	installRedirectReductionRules(t, connector,
		redirectReductionRule("TEST-POWERSHELL-MARKER", marker,
			`f.commands.exists(c, "dccert-block-marker" in c.argv)`),
	)
	encoded := func(body string) string {
		units := utf16.Encode([]rune(body))
		bytes := make([]byte, 2*len(units))
		for i, unit := range units {
			binary.LittleEndian.PutUint16(bytes[2*i:], unit)
		}
		return base64.StdEncoding.EncodeToString(bytes)
	}
	tests := []struct {
		name    string
		command string
		block   bool
	}{
		{"outer redirect and list", `pwsh -Command "echo ` + marker + `" > C:/tmp/out.txt && echo done`, true},
		{"outer descriptor duplication and redirect", `pwsh -Command "echo ` + marker + `" 2>&1 > C:/tmp/out.txt`, true},
		{"body statement list and redirect", `pwsh -NoProfile -Command "echo ` + marker + ` > C:/tmp/out.txt; echo done"`, true},
		{"powershell short flag", `powershell -c "echo ` + marker + `; echo done"`, true},
		{"powershell exe and pipeline", `powershell.exe -NonInteractive -ExecutionPolicy Bypass -Command "echo ` + marker + ` | Out-Null"`, true},
		{"marker after pipeline stage", `pwsh -Command "Out-Null | echo ` + marker + `"`, true},
		{"all flags and all-stream redirect", `pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "echo ` + marker + ` *> C:/tmp/out.txt"`, true},
		{"script block", `pwsh -Command "& { echo ` + marker + `; echo done }"`, true},
		{"nested cmd", `pwsh -Command "cmd /c 'echo ` + marker + `'"`, true},
		{"nested cmd with double quotes", `pwsh -Command "cmd /c \"echo ` + marker + `\""`, true},
		{"encoded statement list", `pwsh -EncodedCommand ` + encoded("echo "+marker+"; echo done"), true},
		{"encoded flags", `powershell.exe -NoProfile -NonInteractive -EncodedCommand ` + encoded("echo "+marker+" | Out-Null"), true},
		{"wrapper after another command", `echo ready; pwsh -Command "echo ` + marker + `; echo done"`, true},
		{"wrapper after short circuit", `echo ready && powershell -c "echo ` + marker + `"`, true},
		{"body descriptor duplication", `pwsh -Command "echo ` + marker + ` 2>&1"`, true},
		{"marker after benign body statement", `pwsh -Command "echo ready; echo ` + marker + `"`, true},
		{"benign statement list", `pwsh -Command "echo safe; echo done"`, false},
		{"quoted marker text", `pwsh -Command "echo 'safe; echo ` + marker + `'; echo done"`, false},
		{"unreachable after exit", `pwsh -Command "exit; echo ` + marker + `"`, false},
		{"unresolved body", `pwsh -Command "if ($false) { echo ` + marker + ` }"`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var recorded actionfacts.Facts
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: actionfacts.Input{
					Tool:        "shell",
					Command:     test.command,
					CWD:         "C:/Users/alice/project",
					ActiveHome:  "C:/Users/alice",
					DialectHint: actionfacts.DialectPOSIX,
				},
				LegacyText:         test.command,
				Connector:          connector,
				EnforcementCapable: true,
				record: func(facts actionfacts.Facts, _ []RuleFinding) {
					recorded = facts
				},
			})
			want := guardrailActionAllow
			if test.block {
				want = guardrailActionBlock
			}
			if got := buildVerdict(findings, "tool_call").Action; got != want {
				t.Errorf("verdict = %q, want %q; parse=%+v findings=%v", got, want, recorded.Parse, FindingStrings(findings))
			}
			if recorded.Parse.Status == actionfacts.StatusComplete &&
				(test.name == "unresolved body" || test.name == "body statement list and redirect") {
				t.Errorf("uncertain body became complete: %+v", recorded.Parse)
			}
		})
	}
}
