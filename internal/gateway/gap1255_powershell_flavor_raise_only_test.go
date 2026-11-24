// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestPowerShellToolOnPOSIXHostIsReadAsPowerShellRaiseOnly (DET111 ruling
// R1, rel-1-0-10:GAP-1255): on a Linux or macOS host the effect lane reads a
// PowerShell tool call as PowerShell placed with the host's POSIX paths; it
// read the script as a POSIX shell's text before (no hint: only a Windows
// hook picks a dialect). The change is raise only: for every form x target x
// spelling and both effect tiers, the lane's cell with the PowerShell reading
// is at least the cell of the old reading (the same call as POSIX shell
// text), and every project-file twin keeps the old cell (no benign raise).
// Each tier of the ruling's PowerShell rows is also above clean now.
func TestPowerShellToolOnPOSIXHostIsReadAsPowerShellRaiseOnly(t *testing.T) {
	useEffectsRulesMode(t, "on")
	home, cwd := "/home/u", "/home/u/proj"
	targets := []struct {
		rel    string
		attack bool
	}{
		{".defenseclaw/config.yaml", true},
		{".claude/settings.json", true},
		{".ssh/authorized_keys", true},
		{".aws/credentials", true},
		{".bashrc", true},
		{"proj/notes.txt", false},
		{"other/notes.txt", false},
	}
	spellings := []struct {
		name  string
		spell func(rel string) string
	}{
		{"abs", func(rel string) string { return filepath.Join(home, rel) }},
		{"tilde", func(rel string) string { return "~/" + rel }},
		{"tilde-bs", func(rel string) string { return `~\` + strings.ReplaceAll(rel, "/", `\`) }},
		{"home-var", func(rel string) string { return `"$HOME/` + rel + `"` }},
		{"env-home", func(rel string) string { return `"$env:HOME/` + rel + `"` }},
		{"dotdot", func(rel string) string { return "../" + rel }},
		{"dotdot-bs", func(rel string) string { return `..\` + strings.ReplaceAll(rel, "/", `\`) }},
	}
	forms := []string{
		"Set-Content -Path %s -Value x",
		"Add-Content -Path %s -Value x",
		"'x' | Out-File -FilePath %s",
		"New-Item -Path %s -Value x -Force",
		"Remove-Item -Path %s",
		"Copy-Item -Path notes.txt -Destination %s",
		"Move-Item -Path notes.txt -Destination %s",
		"Get-Content -Path %s",
		"'x' > %s",
		"& { Set-Content -Path %s -Value x }",
		"[IO.File]::WriteAllText(%s, 'x')",
		"cat %s",
		"echo x >> %s",
	}
	rank := map[string]int{guardrailActionAllow: 0, guardrailActionAlert: 1, guardrailActionBlock: 2}
	tierRank := map[string]int{string(effectTierClean): 0, string(effectTierUnknown): 1, string(effectTierRestricted): 2}
	run := func(tool, command string) []EffectShadowResult {
		return effectShadowRun(trustedActionRequest{
			Input:     actionfacts.Input{Tool: tool, Command: command, ActiveHome: home, CWD: cwd},
			Connector: "claudecode", EnforcementCapable: true,
		}, effectRulesOn, tierRestricted, tierFull)
	}
	cells, raised := 0, 0
	for _, form := range forms {
		for _, sp := range spellings {
			for _, target := range targets {
				command := fmt.Sprintf(form, sp.spell(target.rel))
				old, now := run("Bash", command), run("PowerShell", command)
				for i := range now {
					cells++
					where := fmt.Sprintf("tier %d %s %s %q", i, sp.name, target.rel, command)
					if rank[now[i].Action] < rank[old[i].Action] || tierRank[now[i].Tier] < tierRank[old[i].Tier] {
						t.Errorf("%s: PowerShell reading %s/%s below the old reading %s/%s", where, now[i].Tier, now[i].Action, old[i].Tier, old[i].Action)
					}
					if now[i].Action != old[i].Action || now[i].Tier != old[i].Tier {
						raised++
						if !target.attack {
							t.Errorf("%s: project file %s/%s, old reading %s/%s (benign raise)", where, now[i].Tier, now[i].Action, old[i].Tier, old[i].Action)
						}
					}
				}
			}
		}
	}
	for _, command := range []string{`New-Item -Path ~\.defenseclaw\config.yaml -Value x -Force`, `Set-Content -Path ..\.defenseclaw\config.yaml -Value x`} {
		for i, res := range run("PowerShell", command) {
			if res.Tier == string(effectTierClean) {
				t.Errorf("tier %d %q: clean, want the state write placed", i, command)
			}
		}
	}
	t.Logf("cells %d, raised %d", cells, raised)
	if raised == 0 {
		t.Error("no cell raised: the PowerShell tool is still read as POSIX shell text")
	}
}
