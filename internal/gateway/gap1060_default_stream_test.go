// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// gap1060Suffixes are spellings of the default data stream of a file: Win32
// opens the file itself for them, so a write replaces its main stream.
var gap1060Suffixes = []struct{ id, text string }{
	{"upper", "::$DATA"}, {"lower", "::$data"},
}

// gap1060Forms are the PowerShell write routes of the PowerShell state-write
// table (TestR105WindowsPowerShellStateWriteSpellings): redirection, the
// content cmdlets, the piped and positional forms, and the item cmdlets.
var gap1060Forms = []struct{ id, text string }{
	{"gt", "echo x > %s"}, {"gtgt", "echo x >> %s"}, {"tee", "echo x | tee %s"},
	{"setc", "Set-Content -Path %s -Value x"}, {"setcPos", "Set-Content %s x"},
	{"addc", "Add-Content %s x"}, {"outf", "Out-File -FilePath %s -InputObject x"},
	{"outfPipe", "'x' | Out-File %s"}, {"teeObj", "'x' | Tee-Object -FilePath %s"},
	{"clc", "Clear-Content %s"}, {"copy", "Copy-Item notes.txt %s"},
	{"move", "Move-Item notes.txt %s"}, {"rm", "Remove-Item %s"},
}

// TestGAP1060DefaultStreamPowerShellWriteIsStateWrite: a PowerShell write
// whose operand names the DefenseClaw config with the default-stream suffix
// gets the verdict of the plain spelling (a state write: block in the
// default and strict packs, alert in permissive) on every system
// (rel-1-0-10:GAP-1060). The
// PowerShell reading took the "::" for a provider qualifier and minted no
// path fact, so the call allowed in every tier. The same suffix on an
// ordinary project file stays allowed.
func TestGAP1060DefaultStreamPowerShellWriteIsStateWrite(t *testing.T) {
	const home = `C:\Users\Alice`
	targets := []struct{ id, text string }{
		{"back", home + `\.defenseclaw\config.yaml`},
		{"fwd", filepath.ToSlash(home) + "/.defenseclaw/config.yaml"},
	}
	cells := 0
	for _, posture := range []string{"default", "permissive", "strict"} {
		connectorName := "gap1060-" + posture
		installToolCallCorpusProfileConnector(t, connectorName, posture)
		decide := func(command string) (string, []string) {
			args, _ := json.Marshal(map[string]string{"command": command})
			input := actionfacts.Input{Tool: "PowerShell", Args: args, CWD: home + `\project`, ActiveHome: home}
			input.DialectHint = agentHookWindowsShellDialect(input)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: connectorName, EnforcementCapable: true,
			})
			return buildVerdict(findings, "tool_call").Action, findingIDs(findings)
		}
		for _, form := range gap1060Forms {
			for _, target := range targets {
				plain := fmt.Sprintf(form.text, "'"+target.text+"'")
				want, ids := decide(plain)
				if want == "allow" {
					t.Fatalf("%s/%s|%s: the plain config spelling: allow %v", posture, form.id, target.id, ids)
				}
				for _, suffix := range gap1060Suffixes {
					cells++
					command := fmt.Sprintf(form.text, "'"+target.text+suffix.text+"'")
					if got, ids := decide(command); got != want {
						t.Errorf("%s/%s|%s|%s: action %s %v, want %s as the plain config spelling", posture, form.id, target.id, suffix.id, got, ids, want)
					}
				}
			}
			benign := fmt.Sprintf(form.text, "'"+home+`\project\out.txt`+gap1060Suffixes[0].text+"'")
			if got, ids := decide(benign); got == "block" {
				t.Errorf("%s/%s: an ordinary project file's default stream: block %v", posture, form.id, ids)
			}
		}
	}
	t.Logf("GAP1060 default-stream PowerShell cells checked: %d", cells)
}

// TestGAP1060DefaultStreamWriteNativeEveryTier: on Windows, through the
// Claude Code hook, a write naming the real DefenseClaw config with the
// default-stream suffix blocks in all five tiers for both shell tools, as
// the plain spelling does (rel-1-0-10:GAP-1060, review rows setc, gt and tee
// of adsDataDirect). The PowerShell tool allowed in every tier.
func TestGAP1060DefaultStreamWriteNativeEveryTier(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the default data stream is an NTFS name; TestGAP1060DefaultStreamPowerShellWriteIsStateWrite runs everywhere")
	}
	home, cwd := gap1006Fixture(t)
	nat, fwd := home+`\.defenseclaw\config.yaml`, filepath.ToSlash(home)+"/.defenseclaw/config.yaml"
	cells := 0
	for _, tier := range gap1007Tiers {
		for _, tool := range []string{"Bash", "PowerShell"} {
			for _, form := range gap1060Forms {
				if tool == "Bash" && form.id != "gt" && form.id != "gtgt" && form.id != "tee" {
					continue
				}
				for _, target := range []string{nat, fwd} {
					for _, suffix := range gap1060Suffixes {
						cells++
						command := fmt.Sprintf(form.text, "'"+target+suffix.text+"'")
						if got := gap1007Decide(t, home, cwd, tier, tool, command); got != "block" {
							t.Errorf("%s/%s/%s|%s: action %s, want block (the config's default stream)", tier.name, tool, form.id, suffix.id, got)
						}
					}
				}
			}
			benign := "Set-Content -Path '" + filepath.ToSlash(cwd) + "/notes.txt" + gap1060Suffixes[0].text + "' -Value x"
			if tool == "PowerShell" {
				if got := gap1007Decide(t, home, cwd, tier, tool, benign); got == "block" {
					t.Errorf("%s/%s: an ordinary project file's default stream blocked", tier.name, tool)
				}
			}
		}
	}
	t.Logf("GAP1060 native default-stream cells checked: %d", cells)
}
