// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"
)

// TestGAP1660StartProcessMultiWordCommandBodyIsRead runs the eventvwr handler
// chain as a -Command body of several double-quoted words inside a
// Start-Process powershell -ArgumentList, through the codex hook in every
// pack. The child splits its command line with the CommandLineToArgvW rules
// and joins the words after -Command with blanks, so it runs the chain; the
// body was read as written (a run of string expressions that runs nothing)
// when it was not exactly one quoted word, so the call was allowed with no
// finding in all five tiers while the same chain sent plainly alerted (block
// in strict) (rel-1-0-10:GAP-1660). Benign bodies of several quoted words
// stay allowed with no finding.
func TestGAP1660StartProcessMultiWordCommandBodyIsRead(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	const rule = "privilege.windows_uac_autoelevation_hijack"
	parts := strings.Split(strings.ReplaceAll(gap1638Chain, `"`, `''`), "; ")
	words := `"` + strings.Join(parts, `;" "`) + `"`
	statements := `"` + strings.Join(parts, `" ; "`) + `"`
	list := `'"` + strings.Join(parts, `;"','"`) + `"'`
	cases := []struct {
		name, command string
		attack        bool
	}{
		{"line, one quoted word per statement", `Start-Process powershell -ArgumentList '-NoProfile -Command ` + words + `'`, true},
		{"line, quoted statements with bare separators", `Start-Process powershell -ArgumentList '-Command ` + statements + `' -Wait`, true},
		{"line, pwsh -c", `Start-Process pwsh -ArgumentList '-c ` + words + `'`, true},
		{"word list, one quoted word per statement", `Start-Process powershell -ArgumentList '-NoProfile','-Command',` + list, true},
		{"benign line, two quoted words", `Start-Process powershell -ArgumentList '-Command "Write-Output" "build ok"'`, false},
		{"benign line, quoted statements", `Start-Process powershell -ArgumentList '-Command "Get-Date" ; "Write-Output done"' -Wait`, false},
		{"benign word list, two quoted words", `Start-Process pwsh -ArgumentList '-NoLogo','-Command','"cd C:\work;"','"npm test"' -Wait`, false},
	}
	for _, pack := range gap0437Packs {
		server := gap0437Server(t, pack, "codex", "action")
		want := "alert"
		if pack.pack == "strict" {
			want = "block"
		}
		for _, test := range cases {
			got := server.evaluateCodexHook(context.Background(), codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: `C:\Users\alice\proj`,
				ToolInput: map[string]interface{}{"command": test.command},
			})
			switch {
			case test.attack && (got.Action != want || !findingIDsHave(got.RuleIDs, rule)):
				t.Errorf("%s, %s: action %q rules %v, want %q with %s", pack.name, test.name, got.Action, got.RuleIDs, want, rule)
			case !test.attack && (got.Action != "allow" || len(got.RuleIDs) != 0):
				t.Errorf("%s, %s: action %q rules %v, want allow with no finding", pack.name, test.name, got.Action, got.RuleIDs)
			}
		}
	}
}
