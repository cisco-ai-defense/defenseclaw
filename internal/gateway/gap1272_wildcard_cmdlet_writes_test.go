// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// gap1272Rows are write cmdlets whose path is a wildcard pattern (or a folder
// narrowed by -Include or -Filter) in the folder of a protected file, through
// each parameter the cmdlet reader knows. {D} is the folder, {S} the
// separator, {A} a pattern of every name, {P} a prefix pattern of the
// file's name, {Q} the name with ? for its first letter and {B} with a [..]
// set for it.
var gap1272Rows = []struct{ id, text string }{
	{"W01 Remove-Item -Path folder/*", "Remove-Item -Path '{D}{S}{A}'"},
	{"W02 Remove-Item positional -Recurse", "Remove-Item '{D}{S}{A}' -Recurse -Force"},
	{"W03 Set-Content -Path folder/*", "Set-Content -Path '{D}{S}{A}' -Value x"},
	{"W04 Add-Content prefix", "Add-Content -Path '{D}{S}{P}' -Value x"},
	{"W05 Clear-Content ?", "Clear-Content -Path '{D}{S}{Q}'"},
	{"W06 Out-File [set]", "'x' | Out-File -FilePath '{D}{S}{B}'"},
	{"W07 Copy-Item destination", "Copy-Item 'notes.txt' -Destination '{D}{S}{P}' -Force"},
	{"W08 Move-Item source", "Move-Item -Path '{D}{S}{P}' -Destination 'moved.txt'"},
	{"W09 Rename-Item source", "Rename-Item -Path '{D}{S}{P}' -NewName 'renamed.txt'"},
	{"W10 New-Item -Force", "New-Item -Path '{D}{S}{P}' -ItemType File -Force"},
	{"W11 Remove-Item folder -Include -Recurse", "Remove-Item -Path '{D}' -Include '{P}' -Recurse -Force"},
	{"W12 Remove-Item -Filter", "Remove-Item -Path '{D}{S}{A}' -Filter '{P}'"},
	{"W13 ri prefix colon", "ri -Pat:'{D}{S}{A}'"},
	{"W14 Tee-Object", "'x' | Tee-Object -FilePath '{D}{S}{P}'"},
	{"W15 Set-Content positional", "Set-Content '{D}{S}{P}' 'x'"},
	{"W16 Remove-Item comma list", "Remove-Item -Path 'notes.txt', '{D}{S}{A}'"},
}

// gap1272Benign are wildcards in project folders, -LiteralPath with bracket
// characters, read cmdlets with wildcards on protected folders and patterns
// in a protected folder that match no protected file: allowed in every tier.
// {H} is the home.
var gap1272Benign = []struct{ id, text string }{
	{"B01 Remove-Item project logs", "Remove-Item -Path '*.log'"},
	{"B02 Remove-Item project build -Recurse", "Remove-Item -Path 'build{S}*' -Recurse -Force"},
	{"B03 Set-Content project pattern", "Set-Content -Path 'out*.txt' -Value x"},
	{"B04 Copy-Item project pattern", "Copy-Item -Path 'src{S}*' -Destination 'bin' -Recurse"},
	{"B05 -LiteralPath brackets project", "Set-Content -LiteralPath 'notes[1].txt' -Value x"},
	{"B06 -LiteralPath brackets hook folder", "Remove-Item -LiteralPath '{H}{S}.claude{S}[s]ettings.json'"},
	{"B07 -LiteralPath bracket value", "Set-Content -LiteralPath 'out.txt' '[s]*'"},
	{"B08 Get-ChildItem hook folder", "Get-ChildItem -Path '{H}{S}.claude{S}*'"},
	{"B09 Get-Content codex pattern", "Get-Content -Path '{H}{S}.codex{S}*.toml'"},
	{"B10 Copy-Item from hook folder", "Copy-Item -Path '{H}{S}.claude{S}*' -Destination 'backup' -Recurse"},
	{"B11 Test-Path state pattern", "Test-Path '{H}{S}.defenseclaw{S}*'"},
	{"B12 Select-String hook pattern", "Select-String -Path '{H}{S}.claude{S}*.json' -Pattern hooks"},
	{"B13 Remove-Item claude logs", "Remove-Item -Path '{H}{S}.claude{S}*.log'"},
	{"B14 Remove-Item codex sessions", "Remove-Item -Path '{H}{S}.codex{S}sessions{S}*' -Recurse -Force"},
	{"B15 Remove-Item state backups", "Remove-Item -Path '{H}{S}.defenseclaw{S}*.bak'"},
}

// gap1272Tiers are the five tiers: the rule pack and whether a managed
// standalone gateway (gap0437Server) judges the call, as a managed hook
// peer; strict ones block the unknown tier.
var gap1272Tiers = []struct {
	name, pack string
	managed    bool
}{
	{"default", "default", false},
	{"permissive", "permissive", false},
	{"strict", "strict", false},
	{"managed", "default", true},
	{"managed-strict", "strict", true},
}

// gap1272Handlers runs judge in every tier, for claudecode and codex in
// default and codex in the others, with the corpus profile of the pack.
func gap1272Handlers(t *testing.T, judge func(t *testing.T, tier, pack string, handler func(command string) string)) {
	t.Helper()
	home, project := gap1138Home(t)
	gap1257Fixtures(t, home, project)
	for _, name := range []string{filepath.Join(project, "build", "x.o"), filepath.Join(home, ".claude", "x.log"), filepath.Join(home, ".defenseclaw", "a.bak")} {
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tier := range gap1272Tiers {
		for _, conn := range []string{"claudecode", "codex"} {
			if tier.name != "default" && conn != "codex" {
				continue
			}
			t.Run(tier.name+"/"+conn, func(t *testing.T) {
				installToolCallCorpusProfileConnector(t, conn, tier.pack)
				handler := gap0437Server(t, gap0437Pack{name: tier.name, pack: tier.pack, managed: tier.managed}, conn, "action").handleAgentHook(conn)
				judge(t, tier.name, tier.pack, func(command string) string {
					return gap1138Judge(t, handler, conn, command, home, project, tier.managed, runtime.GOOS != "windows")
				})
			})
		}
	}
}

// gap1272Text fills a row for the folder and name of a file.
func gap1272Text(text, folder, name, home string) string {
	first := strings.ToLower(name[:1])
	return strings.NewReplacer(
		"{D}", folder, "{S}", string(filepath.Separator), "{H}", home, "{A}", "*",
		"{P}", name[:3]+"*", "{Q}", "?"+name[1:], "{B}", "["+first+"]"+name[1:],
	).Replace(text)
}

// gap1272Rules are the protected-write rules and the unknown tier.
func gap1272Rules(got string) []string {
	var hits []string
	for _, rule := range []string{agentHookConfigWriteRuleID, agentHookConfigDisableRuleID, "tamper.detector_state_write", evaluationLimitRuleID} {
		if strings.Contains(got, rule) {
			hits = append(hits, rule)
		}
	}
	return hits
}

// GAP-1272: each gap1272Rows row in the folder of an agent hook config or
// the DefenseClaw state is that file's protected write or the unknown tier
// of the pack, never allowed, in the five tiers (blocked in strict and
// managed-strict): through the pwsh -Command launcher on Linux and macOS
// and natively on Windows. The same rows in a project folder stay allowed.
func TestGAP1272WildcardCmdletWrites(t *testing.T) {
	checked := 0
	gap1272Handlers(t, func(t *testing.T, tier, pack string, judge func(string) string) {
		home := os.Getenv("HOME")
		for _, row := range gap1272Rows {
			for _, target := range gap1138Targets() {
				abs := filepath.Join(home, target.rel)
				command := gap1257Command(gap1272Text(row.text, filepath.Dir(abs), filepath.Base(abs), home))
				got := judge(command)
				checked++
				action, rules := hookConfigAction(got), gap1272Rules(got)
				switch {
				case target.rules != nil:
					if action == "allow" || len(rules) == 0 {
						t.Errorf("%s %s: %s %v, want the unknown tier (%s) or %v, never allow\n%.600s", target.name, row.id, action, rules, evaluationLimitRuleID, target.rules, got)
					} else if strings.HasSuffix(tier, "strict") && action != "block" {
						t.Errorf("%s %s: %s %v, want block in %s", target.name, row.id, action, rules, tier)
					} else if !strings.HasSuffix(tier, "strict") && slices.Equal(rules, []string{evaluationLimitRuleID}) && action != "alert" {
						t.Errorf("%s %s: %s %v, want the unknown tier of %s, an alert", target.name, row.id, action, rules, tier)
					}
				case len(rules) != 0 || pack != "strict" && action != "allow":
					t.Errorf("%s %s: %s %v, want allow with no protected-write rule", target.name, row.id, action, rules)
				}
			}
		}
	})
	t.Logf("cells checked: %d", checked)
}

// GAP-1272: every gap1272Benign row is allowed with no protected-write rule
// and no unknown tier in the five tiers.
func TestGAP1272BenignWildcardRows(t *testing.T) {
	gap1272Handlers(t, func(t *testing.T, tier, pack string, judge func(string) string) {
		home := os.Getenv("HOME")
		for _, row := range gap1272Benign {
			got := judge(gap1257Command(gap1272Text(row.text, "", "xxx", home)))
			if action, rules := hookConfigAction(got), gap1272Rules(got); action != "allow" || len(rules) != 0 {
				t.Errorf("%s: %s %v, want allow\n%.600s", row.id, action, rules, got)
			}
		}
	})
}
