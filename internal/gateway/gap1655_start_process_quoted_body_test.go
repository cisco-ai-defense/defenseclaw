// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP1655StartProcessQuotedCommandBodyIsRead runs the eventvwr handler
// chain as a -Command body wrapped in double quotes inside a Start-Process
// powershell -ArgumentList command line, through the codex hook in every pack.
// The child splits its command line with the CommandLineToArgvW rules, which
// take off the quotes (and turn \" into "), and runs the chain; the body was
// read with the quotes on, a string expression that runs nothing, so the call
// was allowed with no finding in all five tiers, while the same chain sent
// plainly alerted (block in strict) (rel-1-0-10:GAP-1655). Benign command
// lines with quoted bodies stay allowed with no finding.
func TestGAP1655StartProcessQuotedCommandBodyIsRead(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	const rule = "privilege.windows_uac_autoelevation_hijack"
	escaped := strings.ReplaceAll(gap1638Chain, `"`, `\"`)
	single := strings.ReplaceAll(gap1638Chain, `"`, `''`)
	cases := []struct {
		name, command string
		attack        bool
	}{
		{"line, body with escaped quotes", `Start-Process powershell -ArgumentList '-NoProfile -Command "` + escaped + `"'`, true},
		{"line, body with single quotes", `Start-Process powershell -ArgumentList '-NoProfile -Command "` + single + `"'`, true},
		{"line with switches, body twice", `Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command "` + single + "; " + single + `"' -Wait`, true},
		{"line, pwsh -c", `Start-Process pwsh -ArgumentList '-c "` + escaped + `"'`, true},
		{"line, body with no -Command", `Start-Process powershell -ArgumentList '-NoProfile "` + single + `"'`, true},
		{"line after a statement", `Write-Output start; Start-Process powershell -ArgumentList '-Command "` + single + `"'`, true},
		{"word list, quoted body word", `Start-Process powershell -ArgumentList '-NoProfile','-Command','"` + single + `"'`, true},
		{"benign line, escaped quotes", `Start-Process powershell -ArgumentList '-NoProfile -Command "Get-Date; Write-Output \"done\""'`, false},
		{"benign line, npm", `Start-Process powershell -ArgumentList '-NoProfile -Command "cd C:\work; npm test"' -NoNewWindow -Wait`, false},
		{"benign line, unquoted body with a quoted path", `Start-Process powershell -ArgumentList '-Command Get-ItemProperty "HKCU:\Software\MyApp"' -Wait`, false},
		{"benign line, two quoted words", `Start-Process powershell -ArgumentList '-Command "Write-Output" "build ok"'`, false},
		{"benign word list, quoted body word", `Start-Process pwsh -ArgumentList '-NoLogo','-Command','"Write-Output build"' -Wait`, false},
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

// TestGAP1655StartProcessQuotedBodyReading: the child script of a
// Start-Process -ArgumentList command line whose body is one double-quoted
// word is the word with its quotes taken off by the CommandLineToArgvW rules;
// a body of several words is their join with blanks (rel-1-0-10:GAP-1660).
func TestGAP1655StartProcessQuotedBodyReading(t *testing.T) {
	body := `New-Item "HKCU:\x" -Force; Start-Process notepad.exe`
	for _, c := range []struct{ command, want string }{
		{`Start-Process powershell -ArgumentList '-Command "New-Item \"HKCU:\x\" -Force; Start-Process notepad.exe"'`, body},
		{`Start-Process powershell -ArgumentList '-NoProfile "New-Item ''HKCU:\x'' -Force; Start-Process notepad.exe"'`, `New-Item 'HKCU:\x' -Force; Start-Process notepad.exe`},
		{`Start-Process powershell -ArgumentList '-c','"New-Item \"HKCU:\x\" -Force; Start-Process notepad.exe"'`, body},
		{`Start-Process powershell -ArgumentList '-c "Set-Location C:\work\; Start-Process notepad.exe"'`, `Set-Location C:\work\; Start-Process notepad.exe`},
		{`Start-Process powershell -ArgumentList '-c "Start-Process notepad.exe" "x"'`, `Start-Process notepad.exe x`},
		{`Start-Process powershell -ArgumentList '-c ` + body + `'`, body},
	} {
		input := windowsHookShellCall(c.command, `C:\repo`)
		got := ""
		for _, twin := range actionfacts.HostScriptReadings(input, actionfacts.Analyze(input), 0, false).Twins {
			if strings.Contains(twin.Command, "notepad.exe") {
				got = twin.Command
			}
		}
		if got != c.want {
			t.Errorf("%s: child script %q, want %q", c.command, got, c.want)
		}
	}
}
