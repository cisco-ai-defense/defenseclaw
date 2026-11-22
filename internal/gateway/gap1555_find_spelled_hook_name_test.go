// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestFindTestThatSpellsAHookFileFiveTiers (rel-1-0-10:GAP-1555): a find
// whose -name, -iname, -path or -ipath test spells a hook file by name (find
// . -name settings.json -delete, -path '*/.claude/settings.json') is judged
// on that file whether or not it exists when the hook runs: an earlier part
// of the chain or another process may create it before the walk. The verdict
// with the file absent is the verdict with it present, in every tier, as on
// c8090b1056 and rel. A wildcard test (-name '*', '*.json', -path '*') is a
// filter over what the walk finds, so in a project with no hook file it
// reaches none in any tier (the false block GAP-1555 removed), and with the
// file present it reaches it.
func TestFindTestThatSpellsAHookFileFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX find spellings; the hook route reads PowerShell on native Windows")
	}
	type hookFile struct{ base, rel string }
	files := []hookFile{
		{"settings.json", ".claude/settings.json"},
		{"defenseclaw.json", ".github/hooks/defenseclaw.json"},
		{"config.toml", ".codex/config.toml"},
	}
	spelled := func(f hookFile) []string {
		return []string{
			"find @R@ -name " + f.base + " -delete",
			"find @R@ -name '" + f.base + "' -type f -delete",
			"find @R@ -iname " + strings.ToUpper(f.base) + " -delete",
			"find @R@ -path @R@/" + f.rel + " -delete",
			"find @R@ -ipath @R@/" + strings.ToUpper(f.rel) + " -delete",
			"find @R@ -path '*/" + f.rel + "' -delete",
			"find @R@ -name " + f.base + " -exec rm {} +",
			"find @R@ -path '*/" + f.rel + "' -exec rm -f {} ';'",
		}
	}
	wildcards := []string{
		"find @R@ -name '*' -type f -delete",
		"find @R@ -name '*.json' -delete",
		"find @R@ -iname '*' -delete",
		"find @R@ -path '*' -delete",
		"find @R@ -name '*' -exec rm {} +",
		"find @R@ -path '*.json' -exec rm {} +",
	}
	rules := func(got string) string {
		var out []string
		for _, rule := range []string{agentHookConfigDisableRuleID, agentHookConfigWriteRuleID} {
			if strings.Contains(got, rule) {
				out = append(out, rule)
			}
		}
		return strings.Join(out, "+")
	}
	type cell struct {
		name, profile string
		managed       bool
	}
	cells := []cell{{"default", "default", false}, {"permissive", "permissive", false}, {"strict", "strict", false},
		{"managed", "default", true}, {"managed-strict", "strict", true}}
	for _, conn := range []string{"claudecode", "codex"} {
		for _, c := range cells {
			t.Run(conn+"/"+c.name, func(t *testing.T) {
				home := filepath.Join(t.TempDir(), "home")
				project := filepath.Join(home, "proj")
				t.Setenv("HOME", home)
				t.Setenv("USERPROFILE", home)
				t.Setenv("CLAUDE_CONFIG_DIR", "")
				t.Setenv("CODEX_HOME", "")
				judge := newHookConfigJudge(t, conn, c.profile)
				layout := func(rel string) {
					if err := os.RemoveAll(project); err != nil {
						t.Fatal(err)
					}
					if err := os.MkdirAll(project, 0o700); err != nil {
						t.Fatal(err)
					}
					if rel == "" {
						return
					}
					full := filepath.Join(project, filepath.FromSlash(rel))
					if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(full, []byte("{}\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				// verdicts judges each command with the folder spelled as .
				// and by its absolute path.
				verdicts := func(commands []string) map[string]string {
					out := map[string]string{}
					for _, command := range commands {
						for _, root := range []string{".", project} {
							call := strings.ReplaceAll(command, "@R@", root)
							got := judge(project, c.managed, "Bash", map[string]any{"command": call})
							out[call] = hookConfigAction(got) + " " + rules(got)
						}
					}
					return out
				}
				for _, f := range files {
					layout(f.rel)
					present := verdicts(spelled(f))
					layout("")
					absent := verdicts(spelled(f))
					for call, want := range present {
						if absent[call] != want {
							t.Errorf("%s with %s absent is %q, with it present %q", call, f.rel, absent[call], want)
						}
					}
				}
				for call, got := range verdicts(wildcards) {
					if rule := got[strings.Index(got, " ")+1:]; rule != "" {
						t.Errorf("%s in a project with no hook file reaches %q, want none (%s)", call, rule, got)
					}
				}
				layout(files[1].rel)
				for call, got := range verdicts(wildcards) {
					if !strings.Contains(got, agentHookConfigDisableRuleID) {
						t.Errorf("%s with %s present is %q, want the disable rule", call, files[1].rel, got)
					}
				}
			})
		}
	}
}
