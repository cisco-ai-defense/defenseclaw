// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// gap1232Home is the Windows home of the GAP-1232 rows: the PowerShell
// reading needs a drive-letter home, which a synthetic one gives on every OS.
const gap1232Home = `C:\Users\Alice`

// TestGAP1232StateWriteThroughABoundPrefix pins rel-1-0-10:GAP-1232. A
// prefix PowerShell binds to one parameter of the cmdlet it runs (-L and
// -LP: LiteralPath; -Fi and -Fil of Out-File and Tee-Object: FilePath) is
// that parameter, so a write of the DefenseClaw state through it keeps its
// proof in every tool that may run PowerShell and in both packs. Matched
// against one list shared by all cmdlets, -L also matched the alias LP and
// -Fi the Filter parameter of the other cmdlets, and 1b336923cc read both
// as parameters that only take a value, dropped them with the state path
// and allowed the write. A prefix that only valued parameters of the other
// cmdlets start, read with its value (-T x, -T:x), and the RV15-2 forms
// keep their block. mv -t <state folder> <file> is the GAP-1209 statement
// with the state folder: PowerShell refuses -t, the POSIX reading moves the
// file elsewhere, and it is allowed like the agent folder row.
func TestGAP1232StateWriteThroughABoundPrefix(t *testing.T) {
	state := `$HOME\.defenseclaw\config.yaml`
	backup := `$HOME\c.bak`
	resolved := map[string]string{"C:/Users/Alice/.defenseclaw": "C:/Users/Alice/.defenseclaw"}
	for _, name := range []string{"config.yaml", "c.bak"} {
		value := "C:/Users/Alice/.defenseclaw/" + name
		resolved[value] = value
	}
	rows := []struct {
		id, command string
		block       bool
	}{
		// GAP-1232: block at rel 1d8131d4e8, allowed at 1b336923cc.
		{"S01", "Remove-Item -L " + state, true},
		{"S02", `Remove-Item -L ` + gap1232Home + `\.defenseclaw -Recurse -Force`, true},
		{"S03", "'' | Out-File -Fi " + state, true},
		{"S04", "'' | Tee-Object -Fi " + state, true},
		{"S05", "Clear-Content -L " + state, true},
		{"S06", "Rename-Item -L " + state + " c.bak", true},
		{"S07", "Set-Content -L " + state + " x", true},
		{"S08", "Move-Item -L " + state + " " + backup, true},
		{"S10", "Out-File -Fil " + state + " -InputObject ''", true},
		{"S20", "Remove-Item -T:x " + state, true},
		// The alias spelled out, and -L bound with a colon or next to an
		// unresolved parameter (allowed at rel too: -L matched LiteralPath
		// and LP there).
		{"L01", "Remove-Item -LP " + state, true},
		{"L02", "Set-Content -LP " + state + " x", true},
		{"L03", "Move-Item -LP " + state + " " + backup, true},
		{"S09", "Remove-Item -L:" + state + " -Force", true},
		{"S13", "Clear-Content -L:" + state + " -Force", true},
		{"S14", "Rename-Item -L:" + state + " -NewName c.bak", true},
		{"S24", "Remove-Item -L " + state + " -T x", true},
		// Unchanged from rel.
		{"S11", "Remove-Item -I x " + state, true},
		{"S12", "Remove-Item " + state + " -E 0", true},
		{"S15", "Remove-Item -O x " + state, true},
		{"S16", "Remove-Item -T x " + state, true},
		{"S17", "Rename-Item " + state + " c.bak -Zz 1", true},
		{"S18", "Move-Item -Pa " + state + " -Dest " + backup, true},
		{"S19", "Rename-Item " + state + " c.bak -Fo", true},
		{"S21", "Copy-Item notes.txt " + state + " -I x", true},
		{"S22", "Move-Item -T x notes.txt " + state, true},
		{"S23", `mv -t $HOME\.defenseclaw notes.txt`, false},
		{"B01", "Remove-Item -L notes.txt; Get-Content " + state, false},
		{"B02", `mv -t $HOME\project notes.txt; Get-Content ` + state, false},
	}
	for _, profile := range []string{"default", "strict"} {
		connector := "gap1232-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, row := range rows {
			for _, tool := range []string{"Bash", "shell_command", "PowerShell"} {
				args, _ := json.Marshal(map[string]string{"command": row.command})
				input := actionfacts.Input{Tool: tool, Args: args, CWD: gap1232Home + `\project`, ActiveHome: gap1232Home}
				input.DialectHint = agentHookWindowsShellDialect(input)
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: string(args), Connector: connector,
					EnforcementCapable: true, ResolvedWriteTargets: resolved,
				})
				verdict := buildVerdict(findings, "tool_call")
				ids := findingIDs(findings)
				if row.block && (verdict.Action != "block" || !slices.Contains(ids, "tamper.detector_state_write")) {
					t.Errorf("%s %s %s: action %q %v, want block by tamper.detector_state_write", row.id, profile, tool, verdict.Action, ids)
				}
				if !row.block && verdict.Action != "allow" {
					t.Errorf("%s %s %s: action %q %v, want allow", row.id, profile, tool, verdict.Action, ids)
				}
			}
		}
	}
}

// TestGAP1232HookConfigWriteThroughABoundPrefix pins the agent hook config
// reading of rel-1-0-10:GAP-1232 and GAP-1209 through powerShellWriteReading,
// with a prover that takes any write, append or delete under the Claude Code
// settings folder (the guard's own prover needs a home it can stat). A
// write of settings.json through -L, -LP, -Fi or -L: is proven (H06-H08,
// H18-H19). mv -t <settings folder> <file> moves the file into the folder
// and proves nothing, also with $HOME, with a second resolved prefix or
// with a second unknown one (H01-H05, H13, H16: the GAP-1209 residuals).
// Moves and copies of the folder or of settings.json itself stay proven.
// mv -t <backup> <settings> (H09, H10) is no PowerShell statement either;
// the POSIX reading of the guard proves it (TestGAP1232HookConfigRoute).
func TestGAP1232HookConfigWriteThroughABoundPrefix(t *testing.T) {
	claude := gap1232Home + `\.claude`
	settings := claude + `\settings.json`
	rows := []struct {
		id, command string
		want        bool
	}{
		{"H01", "mv -t " + claude + " notes.txt", false},
		{"H02", `mv -t $HOME\.claude notes.txt`, false},
		{"H03", `mv -t $HOME\.claude $HOME\notes.txt`, false},
		{"H04", "mv -t " + claude + " -Fo notes.txt", false},
		{"H05", "mv -t " + claude + " -Zz notes.txt", false},
		{"H06", "Remove-Item -L " + settings, true},
		{"H07", "'' | Out-File -Fi " + settings, true},
		{"H08", "Move-Item -L " + settings + " " + gap1232Home + `\x.bak`, true},
		{"H09", "mv -t " + gap1232Home + `\backup ` + settings, false},
		{"H10", "mv -t " + gap1232Home + `\backup ` + claude, false},
		{"H11", "Move-Item -T x " + claude + " " + gap1232Home + `\dest`, true},
		{"H12", "cp -t " + claude + " settings.json", false},
		{"H13", "mv -t " + claude + " settings.json", false},
		{"H14", "Move-Item notes.txt " + settings + " -Force", true},
		{"H15", "Remove-Item -Recurse " + claude, true},
		{"H16", `mv -t "` + claude + `" notes.txt`, false},
		{"H17", "Copy-Item -T x notes.txt " + settings, true},
		{"H18", "Remove-Item -L:" + settings + " -Force", true},
		{"H19", "'' | Tee-Object -Fi " + settings, true},
		{"H20", "Set-Content -LP " + settings + " x", true},
	}
	follows := func(text string) bool {
		lower := strings.ToLower(text)
		return strings.Contains(lower, ".claude") || strings.Contains(lower, "settings.json")
	}
	proves := func(facts actionfacts.Facts, _ trustedActionRequest) bool {
		for _, candidate := range facts.Paths {
			switch candidate.Access {
			case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete:
			default:
				continue
			}
			target := candidate.Resolved
			if target == "" {
				target = candidate.Value
			}
			if strings.HasPrefix(strings.ToLower(strings.ReplaceAll(target, "/", `\`)), strings.ToLower(claude)) {
				return true
			}
		}
		return false
	}
	for _, row := range rows {
		args, _ := json.Marshal(map[string]string{"command": row.command})
		input := actionfacts.Input{Tool: "Bash", Args: args, CWD: gap1232Home + `\project`, ActiveHome: gap1232Home}
		input.DialectHint = agentHookWindowsShellDialect(input)
		request := trustedActionRequest{Input: input, LegacyText: string(args), Connector: "gap1232", EnforcementCapable: true, ResolvedWriteTargets: map[string]string{}}
		command, ok := powerShellReadingCommand(request)
		if !ok {
			t.Fatalf("%s: no PowerShell reading", row.id)
		}
		if got := powerShellWriteReading(request, command, follows, proves); got != row.want {
			t.Errorf("%s: proven %v, want %v", row.id, got, row.want)
		}
	}
}

// TestGAP1232HookConfigRoute pins rel-1-0-10:GAP-1232 and GAP-1209 on the
// Claude Code hook route. A Bash write of the user settings file through a
// prefix PowerShell binds to one parameter (-L, -LP, -Fi) is the hook config
// write on Windows, where the guard also reads the call as PowerShell (a
// drive-letter home): 1b336923cc allowed it. mv -t <backup> <settings> moves
// the settings file away in its POSIX reading on every OS, and mv -t
// <settings folder> <file> moves a file into the folder (allow, GAP-1209).
func TestGAP1232HookConfigRoute(t *testing.T) {
	h := newGAP0048Home(t)
	type row struct{ name, command, defaults, strict string }
	rows := []row{
		{"mv -t a backup folder, the user settings", "mv -t ~/backup ~/.claude/settings.json", "alert", "block"},
		{"mv -t into the settings folder", "mv -t ~/.claude notes.txt", "allow", "allow"},
	}
	if runtime.GOOS == "windows" {
		backup := filepath.Join(h.home, "x.bak")
		rows = append(rows,
			row{"Remove-Item -L of the user settings", "Remove-Item -L " + h.userSettings, "alert", "block"},
			row{"Set-Content -LP of the user settings", "Set-Content -LP " + h.userSettings + " x", "alert", "block"},
			row{"Move-Item -L of the user settings", "Move-Item -L " + h.userSettings + " " + backup, "alert", "block"},
			row{"Out-File -Fi of the user settings", "'' | Out-File -Fi " + h.userSettings, "alert", "block"},
			row{"Tee-Object -Fi of the user settings", "'' | Tee-Object -Fi " + h.userSettings, "alert", "block"},
		)
	}
	for _, profile := range []string{"default", "strict"} {
		t.Run(profile, func(t *testing.T) {
			judge := newHookConfigJudgeWith(t, "claudecode", profile, false)
			for _, row := range rows {
				want := row.defaults
				if profile == "strict" {
					want = row.strict
				}
				got := judge(h.project, false, "Bash", map[string]any{"command": row.command})
				if action := hookConfigAction(got); action != want {
					t.Errorf("%s: action %q, want %q: %.500s", row.name, action, want, got)
				}
				if want != "allow" && !strings.Contains(got, agentHookConfigWriteRuleID) {
					t.Errorf("%s: want rule %s: %.500s", row.name, agentHookConfigWriteRuleID, got)
				}
			}
		})
	}
}
