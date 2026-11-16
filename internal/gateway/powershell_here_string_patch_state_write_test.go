// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A patch envelope bound to a PowerShell here-string variable, or piped into
// apply_patch, is the patch the run applies, as the same envelope given as
// the argument: a protected target blocks in observe mode, an ordinary one
// stays allowed.
func TestPowerShellHereStringAndPipedPatchStateWriteIsProven(t *testing.T) {
	const connectorName = "ps-here-patch"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	resolved := map[string]string{}
	for _, value := range []string{"C:/Users/Alice/.defenseclaw", "C:/Users/Alice/.defenseclaw/config.yaml"} {
		resolved[value] = value
	}
	envelope := func(target, eol string) string {
		return strings.Join([]string{"*** Begin Patch", "*** Update File: " + target, "@@", "-a", "+b", "*** End Patch"}, eol)
	}
	const state = `C:\Users\Alice\.defenseclaw\config.yaml`
	const project = `C:\Users\Alice\project\notes.txt`
	forms := []struct {
		name  string
		build func(target string) string
	}{
		{"expandable here-string run by codex", func(target string) string {
			return "$patch=@\"\n" + envelope(target, "\n") + "\n\"@; & codex.exe --codex-run-as-apply-patch $patch"
		}},
		{"literal here-string run by apply_patch", func(target string) string {
			return "$patch=@'\n" + envelope(target, "\n") + "\n'@\napply_patch $patch"
		}},
		{"literal CRLF here-string run by apply_patch", func(target string) string {
			return "$patch=@'\r\n" + envelope(target, "\r\n") + "\r\n'@\r\napply_patch $patch"
		}},
		{"here-string piped into apply_patch in pwsh", func(target string) string {
			return "pwsh -NoProfile -Command \"@'\n" + envelope(target, "\n") + "\n'@ | apply_patch\""
		}},
		{"bound here-string piped into apply_patch", func(target string) string {
			return "$patch=@'\n" + envelope(target, "\n") + "\n'@\n$patch | apply_patch"
		}},
	}
	type row struct {
		name, command string
		block         bool
	}
	var rows []row
	for _, form := range forms {
		rows = append(rows,
			row{form.name + ", state target", form.build(state), true},
			row{form.name + ", ordinary target", form.build(project), false})
	}
	rows = append(rows,
		row{"expandable here-string from the home variable", "$patch=@\"\n" + envelope(`$HOME\.defenseclaw\config.yaml`, "\n") + "\n\"@; apply_patch $patch", true},
		row{"bound here-string only printed", "$patch=@'\n" + envelope(state, "\n") + "\n'@\nWrite-Output $patch", false},
		row{"here-string piped into a printer", "@'\n" + envelope(state, "\n") + "\n'@ | Write-Output", false},
	)
	api := &APIServer{}
	for _, tc := range rows {
		for _, managed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/managed=%t", tc.name, managed), func(t *testing.T) {
				t.Parallel()
				args, _ := json.Marshal(map[string]string{"command": tc.command})
				input := actionfacts.Input{Tool: "shell_command", Args: args, CWD: home + `\project`, ActiveHome: home}
				input.DialectHint = agentHookWindowsShellDialect(input)
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: string(args), Connector: connectorName,
					EnforcementCapable: true, ResolvedWriteTargets: resolved, ProtectedHomeHook: managed,
				})
				verdict := buildVerdict(findings, "tool_call")
				if got := verdict.Action == "block" && api.provenActiveStateMutation(t.Context(), verdict); got != tc.block {
					t.Fatalf("observe-mode hard block=%t, want %t (action %q, findings %v)", got, tc.block, verdict.Action, findingIDs(findings))
				}
			})
		}
	}
}

// A path that reaches the state only through a link does not spell
// DefenseClaw; the reading follows a value the mention scan places in the
// state, so the write through the bound variable is read as the write of the
// link path. A sibling name the scan does not place there is not followed.
func TestPowerShellBoundValueFollowsAValueTheMentionScanPlacesInState(t *testing.T) {
	t.Parallel()
	const home = `C:\Users\Alice`
	const link = `C:\Users\Alice\project\lnkD\config.yaml`
	mentions := func(text string) bool { return strings.Contains(strings.ToLower(text), `\lnkd\`) }
	twin := func(path string) string { return "Set-Content -LiteralPath '" + path + "' -Value x" }
	for _, tc := range []struct {
		name, command, want string
		found               bool
	}{
		{"bound write in pwsh", `pwsh -NoProfile -Command "$p='` + link + `'; [System.IO.File]::WriteAllText($p,'x')"`, twin(link), true},
		{"bound write", `$p='` + link + `'; [System.IO.File]::WriteAllText($p,'x')`, twin(link), true},
		{"bound sibling", `$p='C:\Users\Alice\project\lnkDx\config.yaml'; [System.IO.File]::WriteAllText($p,'x')`, twin(`C:\Users\Alice\project\lnkDx\config.yaml`), false},
	} {
		forms, bounded, ok := powerShellStateWriteForms(tc.command, home, home+`\project`, nil, mentions)
		if bounded || !ok {
			t.Fatalf("%s: bounded=%t ok=%t", tc.name, bounded, ok)
		}
		if got := slices.Contains(forms, tc.want); got != tc.found {
			t.Fatalf("%s: twin %q found=%t, want %t (forms %q)", tc.name, tc.want, got, tc.found, forms)
		}
	}
}
