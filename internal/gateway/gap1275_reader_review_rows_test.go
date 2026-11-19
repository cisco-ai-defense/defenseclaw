// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// gap1275Tiers are the five tiers the review rows are judged in: the open
// source default, permissive and strict packs per user, and the default and
// strict packs behind a managed standalone gateway that judges the user's
// call (gap1138Judge peer).
var gap1275Tiers = []struct {
	name, pack string
	managed    bool
}{{"default", "default", false}, {"permissive", "permissive", false}, {"strict", "strict", false}, {"managed", "default", true}, {"managed-strict", "strict", true}}

// gap1275Handlers runs judge in every tier for claudecode and codex with
// the corpus profile of the tier's pack installed.
func gap1275Handlers(t *testing.T, judge func(t *testing.T, pack string, judge func(command string) string)) {
	t.Helper()
	home, project := gap1138Home(t)
	gap1257Fixtures(t, home, project)
	for _, tier := range gap1275Tiers {
		for _, conn := range []string{"claudecode", "codex"} {
			t.Run(tier.name+"/"+conn, func(t *testing.T) {
				installToolCallCorpusProfileConnector(t, conn, tier.pack)
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = conn
				// The pack decides the tier: the strict pack blocks a proven
				// state write that the default one alerts (GAP-0747 owner
				// tiering 2026-11-15T15:20Z).
				// Managed tiers read their own pack too: managed-strict is the
				// strict pack behind the managed standalone gateway, which
				// does not read the per-user install window (the peer home is
				// unreadable to it).
				cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), tier.pack)
				if tier.managed {
					cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
					cfg.Enterprise.Profile = managed.ProfileStandalone
				}
				store, logger := testStoreAndLogger(t)
				handler := (&APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}).handleAgentHook(conn)
				judge(t, tier.pack, func(command string) string {
					return gap1138Judge(t, handler, conn, command, home, project, tier.managed, runtime.GOOS != "windows")
				})
			})
		}
	}
}

// gap1275Check judges each row of an agent hook config or the DefenseClaw
// state (or of the folder holding it): the write rule of the file or the
// unknown tier of the pack, never allowed; every row of a project file stays
// allowed (gap1138Check).
func gap1275Check(t *testing.T, rows []gap1257Row) {
	checked := 0
	gap1275Handlers(t, func(t *testing.T, pack string, judge func(string) string) {
		home := os.Getenv("HOME")
		for _, row := range rows {
			for _, target := range gap1138Targets() {
				abs := filepath.Join(home, target.rel)
				if row.dir {
					abs = filepath.Dir(abs)
				}
				got := judge(gap1257Command(fmt.Sprintf(row.form.text, "'"+abs+"'")))
				checked++
				if problem := gap1138Check(got, row.form, target, pack); problem != "" {
					t.Errorf("%s %s: %s\n%.600s", target.name, row.form.id, problem, got)
				}
			}
		}
	})
	t.Logf("cells checked: %d", checked)
}

// gap1275Unknown is a review row whose write of a protected file is the
// unknown tier or stronger.
func gap1275Unknown(id, text string) gap1257Row {
	return gap1257Row{form: gap1138Form{id, text, "unknown", false}}
}

// GAP-1275 (s7-rv1257 N01 N02 N08 N10 N11 N14): the pipeline item of a
// ForEach-Object block is placed only when the whole element that feeds it
// is one Get-Item or Get-ChildItem of known paths; a feeder cut by a group,
// a script block or a nested pipeline leaves it unplaced.
func TestGAP1275PipelineItemWholeFeeder(t *testing.T) {
	gap1275Check(t, []gap1257Row{
		gap1275Unknown("N01 write-output group feed", "Write-Output (Get-Item %s) gi 'notes.txt' | ForEach-Object { $_.Delete() }"),
		gap1275Unknown("N02 script block feed", "& { Get-Item %s } gi 'notes.txt' | ForEach-Object { $_.Delete() }"),
		gap1275Unknown("N08 nested pipe", "Get-Item 'notes.txt' | ForEach-Object { Get-Item %s | ForEach-Object { $_.Delete() } }"),
		gap1275Unknown("N10 echo group feed openwrite", "echo (Get-Item %s) gi 'notes.txt' | ForEach-Object { $_.OpenWrite().Close() }"),
		{gap1138Form{"N11 item of folder delete recurse", "Get-Item %s | ForEach-Object { $_.Delete($true) }", "unknown", false}, true},
		gap1275Unknown("N14 write-output group gci", "Write-Output (Get-Item %s) gci 'notes.txt' | ForEach-Object { $_.Delete() }"),
	})
}

// GAP-1276 (s7-rv1257 N03 N04 N07 N09 N13): a command that may bind a
// variable by a name built at run time (Set-Variable with a computed name,
// the PSVariable API, a Get-Variable wildcard, Invoke-Expression of run-time
// text) leaves the pipeline item and every FileInfo variable unplaced, as
// does a second assignment the reader cannot place. N12, a copy of the
// variable itself, keeps the rule tier: TestGAP1315SameFileRebinds.
func TestGAP1276RunTimeVariableNames(t *testing.T) {
	gap1275Check(t, []gap1257Row{
		gap1275Unknown("N03 item set-variable char", "Get-Item 'notes.txt' | ForEach-Object { Set-Variable -Name ([char]95) -Value (Get-Item %s); $_.Delete() }"),
		gap1275Unknown("N04 var set-variable char", "$f = Get-Item 'notes.txt'; Set-Variable -Name ([char]102) -Value (Get-Item %s); $f.Delete()"),
		gap1275Unknown("N07 item psvariable set char", "Get-Item 'notes.txt' | ForEach-Object { $ExecutionContext.SessionState.PSVariable.Set([char]95, (Get-Item %s)); $_.Delete() }"),
		gap1275Unknown("N09 get-variable wildcard", "$f = Get-Item 'notes.txt'; (Get-Variable -Name '[e-g]').Value = (Get-Item %s); $f.Delete()"),
		gap1275Unknown("N13 iex char rebind", "$f = Get-Item 'notes.txt'; iex ([char]36 + [char]102 + ' = Get-Item ' + %s); $f.Delete()"),
	})
}

// GAP-1277 (s7-rv1257 N05 N06): a Get-Item path array is each of its paths,
// through the pipeline and through a variable.
func TestGAP1277PathArrays(t *testing.T) {
	gap1275Check(t, []gap1257Row{
		gap1275Unknown("N05 array path pipe", "Get-Item 'notes.txt',%s | ForEach-Object { $_.Delete() }"),
		gap1275Unknown("N06 array path var", "$f = Get-Item 'notes.txt',%s; $f.Delete()"),
		gap1275Unknown("N06b blank array path var", "$f = Get-Item 'notes.txt', %s; $f.Delete()"),
	})
}

// gap1278Benign are the s7-rv1257 C rows: ordinary project scripts, most
// next to a read of a hook config. unknown marks a row the reader still
// sends to the unknown tier, as at s7/g1230fix ad76d28e82 (an item filtered
// by Where-Object, an if block inside the item block, a foreach statement):
// never a protected-write rule.
var gap1278Benign = []struct {
	id, text string
	unknown  bool
}{
	{"C01 member read then delete", "$f = Get-Item 'out.txt'; Write-Host $f.FullName; $f.Delete()", false},
	{"C02 plain read then delete", "$f = Get-Item 'out.txt'; Write-Host $f; $f.Delete()", false},
	{"C03 if copy", "$log = Get-Item 'a.log'; if ($log.Length -gt 0) { $log.CopyTo('a.bak', $true) | Out-Null }", false},
	{"C04 cfg read + reassigned var", "$cfg = Get-Content ~/.claude/settings.json -Raw; $f = Get-Item 'a.log'; $f.Delete(); $f = Get-Item 'b.tmp'; $f.Delete()", false},
	{"C05 cfg read + plain read var", "$cfg = Get-Content ~/.claude/settings.json -Raw; $f = Get-Item 'out.txt'; Write-Host ('Removing ' + $f); $f.Delete()", false},
	{"C06 cfg read + item name + delete", "Get-Content ~/.claude/settings.json | Out-Null; Get-ChildItem 'bin' | ForEach-Object { Write-Host $_.Name; $_.Delete() }", false},
	{"C07 cfg read + where + delete", "Get-Content ~/.codex/config.toml | Out-Null; Get-ChildItem 'bin' | Where-Object { $_.Length -gt 0 } | ForEach-Object { $_.Delete() }", true},
	{"C08 if inside foreach", "Get-ChildItem 'bin' | ForEach-Object { if ($_.Length -gt 0) { $_.Delete() } }", false},
	{"C09 foreach statement", "foreach ($f in Get-ChildItem 'bin') { $f.Delete() }", false},
	{"C10 cfg read + if inside foreach", "$c = Get-Content ~/.claude/settings.json -Raw; Get-ChildItem 'bin' | ForEach-Object { if ($_.Length -gt 0) { $_.Delete() } }", true},
	{"C11 cfg read + foreach statement", "$c = Get-Content ~/.claude/settings.json -Raw; foreach ($f in Get-ChildItem 'bin') { $f.Delete() }", true},
	{"C12 cfg read + interpolated var", "$c = Get-Content ~/.codex/config.toml -Raw; $f = Get-Item 'out.txt'; Write-Host \"Removing $f\"; $f.Delete()", false},
	{"C13 cfg copy to project then rewrite", "Copy-Item ~/.claude/settings.json 'settings.bak'; $b = Get-Item 'settings.bak'; $b.LastWriteTime = Get-Date; $b.CopyTo('out.txt', $true) | Out-Null", false},
	{"C14 gci folder of project delete", "Get-ChildItem 'bin' | ForEach-Object { $_.Delete() }", false},
	{"C15 cfg read + set-variable literal", "$c = Get-Content ~/.claude/settings.json -Raw; Set-Variable -Name count -Value (Get-Date); $f = Get-Item 'out.txt'; $f.Delete()", false},
}

// GAP-1278: a plain read of a FileInfo variable (an argument, a string) binds
// nothing, and a re-assignment to another placed project file keeps the
// writes placed: every C row is allowed with no protected-write rule and no
// unknown tier in every tier (the unknown rows: never a protected-write
// rule).
func TestGAP1278FileInfoReadsAndRebinds(t *testing.T) {
	hookRules := []string{agentHookConfigWriteRuleID, agentHookConfigDisableRuleID, "tamper.detector_state_write"}
	gap1275Handlers(t, func(t *testing.T, pack string, judge func(string) string) {
		for _, row := range gap1278Benign {
			got := judge(gap1257Command(row.text))
			action := hookConfigAction(got)
			for _, rule := range append(hookRules, evaluationLimitRuleID) {
				if strings.Contains(got, rule) {
					action += " " + rule
				}
			}
			switch {
			case row.unknown:
				for _, rule := range hookRules {
					if strings.Contains(got, rule) {
						t.Errorf("%s: %s, want no protected-write rule\n%.600s", row.id, action, got)
					}
				}
			case action != "allow":
				t.Errorf("%s: %s, want allow\n%.600s", row.id, action, got)
			}
		}
	})
}
