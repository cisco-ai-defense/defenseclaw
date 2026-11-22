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

// gap1638Chain is the eventvwr handler chain of GAP-1231 on one line.
const gap1638Chain = `New-Item "HKCU:\software\classes\mscfile\shell\open\command" -Force; ` +
	`Set-ItemProperty "HKCU:\software\classes\mscfile\shell\open\command" -Name "(default)" -Value "C:\Windows\System32\cmd.exe /c echo dccert-block-marker" -Force; ` +
	`Start-Process "C:\Windows\System32\eventvwr.msc"`

// TestGAP1638LauncherBodyWithQuotesIsRead runs the eventvwr handler chain,
// once and twice, as the -Command body of a powershell or pwsh launcher through
// the codex hook in every pack. A body that holds a double quote was left
// unread (psparse ps_legacy_quoting: Windows PowerShell 5.1 may drop the
// quote when it hands the word over), so no reading proved the chain and the
// call was allowed with no finding in all five tiers, while the same chain
// sent plainly alerted (block in strict). pwsh 7 and a caller that hands over
// the argv as is run the body as written, so that is read too
// (rel-1-0-10:GAP-1638). Benign launcher bodies with quotes stay allowed
// with no finding.
func TestGAP1638LauncherBodyWithQuotesIsRead(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	const rule = "privilege.windows_uac_autoelevation_hijack"
	twice := gap1638Chain + "; " + gap1638Chain
	benign := `New-Item "HKCU:\software\classes\myapp\shell\open\command" -Force; Start-Process notepad.exe`
	cases := []struct {
		name, command string
		attack        bool
	}{
		{"powershell -Command once", `powershell -Command '` + gap1638Chain + `'`, true},
		{"powershell -Command twice", `powershell -Command '` + twice + `'`, true},
		{"powershell.exe -NoProfile -Command twice", `powershell.exe -NoProfile -Command '` + twice + `'`, true},
		{"pwsh -c twice", `pwsh -c '` + twice + `'`, true},
		{"powershell -Command double-quoted twice", `powershell -Command "` + strings.ReplaceAll(twice, `"`, `\"`) + `"`, true},
		{"launcher after a statement", `Write-Output start; powershell -Command '` + gap1638Chain + `'`, true},
		{"Start-Process command line", `Start-Process powershell -ArgumentList '` + gap1638Chain + `'`, true},
		{"Start-Process command line with switches", `Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command ` + twice + `' -Wait`, true},
		{"Start-Process word list", `Start-Process powershell -ArgumentList '-NoProfile','-Command','` + twice + `'`, true},
		{"Start-Process after a statement", `Write-Output start; Start-Process pwsh -ArgumentList '-c ` + gap1638Chain + `'`, true},
		{"benign handler twice", `powershell -Command '` + benign + "; " + benign + `'`, false},
		{"benign quoted output", `powershell -NoProfile -Command 'Write-Output "build ok"; Get-Date'`, false},
		{"benign Start-Process command line", `Start-Process powershell -ArgumentList '-NoProfile -Command Write-Output "build ok"; Get-Date' -Wait`, false},
		{"benign Start-Process word list", `Start-Process powershell -ArgumentList '-c','Write-Output "build ok"'`, false},
		{"benign Start-Process handler", `Start-Process powershell -ArgumentList '` + benign + `'`, false},
		{"benign Start-Process file", `Start-Process powershell -ArgumentList '-File C:\tools\build.ps1' -Wait`, false},
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

// TestGAP1638LauncherBodyReading: the script of a launcher whose body holds a
// double quote is read as written, from the hook text and from an argv; a
// body psparse leaves unread for any other reason (a variable) stays unread.
func TestGAP1638LauncherBodyReading(t *testing.T) {
	body := `New-Item "HKCU:\x" -Force; Start-Process notepad.exe`
	for _, c := range []struct {
		name  string
		input actionfacts.Input
		want  string
	}{
		{"text", windowsHookShellCall(`powershell -Command '`+body+`'`, `C:\repo`), body},
		{"argv", actionfacts.Input{Tool: "shell", CWD: `C:\repo`, Argv: []string{"powershell.exe", "-Command", body}}, body},
		{"variable", windowsHookShellCall(`powershell -Command "New-Item $p -Force"`, `C:\repo`), ""},
	} {
		reading := actionfacts.HostScriptReadings(c.input, actionfacts.Analyze(c.input), 0, false)
		got := ""
		for _, twin := range reading.Twins {
			if twin.PowerShellLauncherBody {
				got = twin.Command
			}
		}
		if got != c.want {
			t.Errorf("%s: launcher body %q, want %q", c.name, got, c.want)
		}
	}
}

// TestGAP1638StartProcessCommandLineReading: Start-Process to a powershell or
// pwsh host reads the -ArgumentList as the child's command line, written as
// one string or as a word list, a double quote included; a list built at run
// time, -File and a program that is not the system host stay unread.
func TestGAP1638StartProcessCommandLineReading(t *testing.T) {
	body := `New-Item "HKCU:\x" -Force; Start-Process notepad.exe`
	for _, c := range []struct{ command, want string }{
		{`Start-Process powershell -ArgumentList '` + body + `'`, body},
		{`Start-Process powershell -ArgumentList '-NoProfile -WindowStyle Hidden -Command ` + body + `'`, body},
		{`Start-Process -ArgumentList '-c ` + body + `' -FilePath pwsh.exe`, body},
		{`Start-Process powershell -ArgumentList '-NoProfile','-Command','` + body + `'`, body},
		{`Start-Process powershell -ArgumentList "-c $p"`, ""},
		{`Start-Process powershell -ArgumentList '-File C:\tools\build.ps1'`, ""},
		{`Start-Process C:\tmp\powershell.exe -ArgumentList '` + body + `'`, ""},
	} {
		input := windowsHookShellCall(c.command, `C:\repo`)
		got := ""
		for _, twin := range actionfacts.HostScriptReadings(input, actionfacts.Analyze(input), 0, false).Twins {
			if strings.Contains(twin.Command, "notepad.exe") || strings.Contains(twin.Command, "build.ps1") || strings.Contains(twin.Command, "$p") {
				got = twin.Command
			}
		}
		if got != c.want {
			t.Errorf("%s: child script %q, want %q", c.command, got, c.want)
		}
	}
}

// TestGAP1638QuotedLauncherDefenderExclusion: a Defender exclusion of every
// .exe file sent through a powershell -Command launcher whose body holds a
// double quote is the exclusion the same body sent plainly or unquoted is
// (both matched before rel-1-0-10:GAP-1638); it was a near negative of
// TestWindowsExactSecurityControlNearNegativesStayQuiet only because the
// quoted body was left unread.
func TestGAP1638QuotedLauncherDefenderExclusion(t *testing.T) {
	const connector = "gap1638-defender-exclusion"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	for _, command := range []string{
		`powershell -Command 'Add-MpPreference -ExclusionExtension ".exe" -Force'`,
		`powershell -Command 'Add-MpPreference -ExclusionExtension .exe -Force'`,
		`Add-MpPreference -ExclusionExtension ".exe" -Force`,
	} {
		input := actionfacts.Input{Tool: "shell", Command: command, CWD: `C:\repo`, DialectHint: actionfacts.DialectPowerShell}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: command, Connector: connector, EnforcementCapable: true,
		})
		if findingWithID(findings, "defense_evasion.windows_defender_executable_exclusion") == nil {
			t.Errorf("%q: no defense_evasion.windows_defender_executable_exclusion finding: %v", command, FindingStrings(findings))
		}
	}
}
