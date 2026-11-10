// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A home folder with an apostrophe (a name like O'Brien, or the typographic
// one) is ordinary. A patch envelope that names the state file there, bound to
// a variable or given as a quoted argument, is the same write as the literal:
// the target is read as its value and quoted once, so the proof finds it.
func TestPowerShellBoundPatchTargetWithAQuoteInTheHomeIsProven(t *testing.T) {
	const connectorName = "ps-bound-quote-home"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	api := &APIServer{}
	for _, quote := range []string{"'", "\u2019"} {
		home := `C:\Users\O` + quote + `Brien`
		slashHome := "C:/Users/O" + quote + "Brien"
		resolved := map[string]string{}
		for _, value := range []string{slashHome + "/.defenseclaw", slashHome + "/.defenseclaw/config.yaml"} {
			resolved[value] = value
		}
		envelope := func(target string) string {
			return "*** Begin Patch`n*** Update File: " + target + "`n@@`n-a`n+b`n*** End Patch"
		}
		// single is text as a single-quoted PowerShell literal.
		single := func(text string) string { return "'" + strings.ReplaceAll(text, quote, quote+quote) + "'" }
		protected := envelope(slashHome + "/.defenseclaw/config.yaml")
		ordinary := envelope(slashHome + "/project/notes.txt")
		const codex = `& "C:\dc\codex.exe" --codex-run-as-apply-patch `
		for _, tc := range []struct {
			name, command string
			block         bool
		}{
			{"bound double-quoted patch, codex", `$patch = "` + protected + `"; ` + codex + `$patch`, true},
			{"bound double-quoted patch, apply_patch", `$patch = "` + protected + `"; apply_patch $patch`, true},
			{"bound single-quoted patch, codex", `$patch = ` + single(protected) + `; ` + codex + `$patch`, true},
			{"bound single-quoted patch, apply_patch", `$patch = ` + single(protected) + `; apply_patch $patch`, true},
			{"single-quoted patch argument", codex + single(protected), true},
			{"bound double-quoted ordinary patch", `$patch = "` + ordinary + `"; ` + codex + `$patch`, false},
			{"bound single-quoted ordinary patch", `$patch = ` + single(ordinary) + `; apply_patch $patch`, false},
			{"single-quoted ordinary patch argument", codex + single(ordinary), false},
			{"bound protected patch only printed", `$patch = "` + protected + `"; Write-Output $patch`, false},
			{"literal Set-Content", `Set-Content -LiteralPath ` + single(home+`\.defenseclaw\config.yaml`) + ` -Value x`, true},
			{"bound WriteAllText", `$p = ` + single(home+`\.defenseclaw\config.yaml`) + `; [IO.File]::WriteAllText($p, 'x')`, true},
			{"bound ordinary WriteAllText", `$p = ` + single(home+`\project\notes.txt`) + `; [IO.File]::WriteAllText($p, 'x')`, false},
		} {
			for _, managed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%q/%s/managed=%t", quote, tc.name, managed), func(t *testing.T) {
					args, _ := json.Marshal(map[string]string{"command": tc.command})
					input := actionfacts.Input{Tool: "shell_command", Args: args, CWD: home + `\project`, ActiveHome: home}
					input.DialectHint = agentHookWindowsShellDialect(input)
					findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
						Input: input, LegacyText: string(args), Connector: connectorName,
						EnforcementCapable: true, ResolvedWriteTargets: resolved, ProtectedHomeHook: managed,
					})
					verdict := buildVerdict(findings, "tool_call")
					if got := verdict.Action == "block"; got != tc.block {
						t.Fatalf("action %q, want block=%t (findings %v)", verdict.Action, tc.block, findingIDs(findings))
					}
					if got := api.provenActiveStateMutation(t.Context(), verdict); got != tc.block {
						t.Fatalf("observe-mode hard block=%t, want %t", got, tc.block)
					}
				})
			}
		}
	}
}
