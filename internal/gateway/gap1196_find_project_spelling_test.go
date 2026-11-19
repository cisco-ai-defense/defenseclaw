// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFindOverTheProjectIsOneVerdictInBothSpellings (rel-1-0-10:GAP-1196): a
// find that deletes over the project folder is judged on the hook files the
// folder holds, whether the call names the folder as . or by its absolute
// path. A project with no hook file reaches none (the walk deletes only what
// exists), so both spellings allow; a project whose Claude Code settings
// exist reaches them in both spellings (the hook config write rule); a
// project that holds the DefenseClaw hook file of an agent reaches it in both
// (the disable rule). A name filter that matches no hook file reaches none,
// and one that matches every name (-name '*') reaches only the hook files
// that exist (rel-1-0-10:GAP-1555).
func TestFindOverTheProjectIsOneVerdictInBothSpellings(t *testing.T) {
	type layout struct {
		name  string
		files []string
		// rule is the hook config rule a whole-tree delete carries ("" none).
		rule string
	}
	layouts := []layout{
		{"empty project", nil, ""},
		{"project with only ordinary files", []string{"build/out.o", "notes.txt"}, ""},
		{"project with its Claude Code settings", []string{".claude/settings.json", "notes.txt"}, agentHookConfigWriteRuleID},
		{"project with the DefenseClaw hook file of an agent", []string{".github/hooks/defenseclaw.json", "notes.txt"}, agentHookConfigDisableRuleID},
	}
	for _, conn := range []string{"claudecode", "codex"} {
		for _, profile := range []string{"default", "strict"} {
			for _, l := range layouts {
				t.Run(conn+"/"+profile+"/"+l.name, func(t *testing.T) {
					home := filepath.Join(t.TempDir(), "home")
					project := filepath.Join(home, "proj")
					if err := os.MkdirAll(project, 0o700); err != nil {
						t.Fatal(err)
					}
					for _, name := range l.files {
						full := filepath.Join(project, filepath.FromSlash(name))
						if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(full, []byte("{}\n"), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					t.Setenv("HOME", home)
					t.Setenv("USERPROFILE", home)
					t.Setenv("CLAUDE_CONFIG_DIR", "")
					t.Setenv("CODEX_HOME", "")
					judge := newHookConfigJudge(t, conn, profile)
					rules := func(got string) string {
						switch {
						case strings.Contains(got, agentHookConfigDisableRuleID):
							return agentHookConfigDisableRuleID
						case strings.Contains(got, agentHookConfigWriteRuleID):
							return agentHookConfigWriteRuleID
						}
						return ""
					}
					spellings := []string{
						"find . -type f -delete",
						"find " + project + " -type f -delete",
						"find " + project + "/ -type f -delete",
						"find ./ -type f -exec rm {} +",
						"find " + project + " -type f -exec rm {} +",
						// A name test that matches every name reaches only the
						// hook files that exist, as the walk does
						// (rel-1-0-10:GAP-1555).
						"find . -name '*' -type f -delete",
						"find " + project + " -name '*' -type f -delete",
						"find . -name '*' -exec rm {} +",
					}
					var first, firstAction string
					for i, command := range spellings {
						got := judge(project, false, "Bash", map[string]any{"command": command})
						rule, action := rules(got), hookConfigAction(got)
						if rule != l.rule {
							t.Errorf("%s: hook config rule %q, want %q: %s", command, rule, l.rule, strings.TrimSpace(got))
						}
						if i == 0 {
							first, firstAction = rule, action
						} else if rule != first || action != firstAction {
							t.Errorf("%s is %s %q, %s is %s %q", command, action, rule, spellings[0], firstAction, first)
						}
					}
					for _, command := range []string{
						"find . -name '*.o' -delete",
						"find . -name '*.md' -exec rm {} +",
						"find " + project + " -name '*.o' -delete",
						"find " + project + "/build -type f -delete",
					} {
						got := judge(project, false, "Bash", map[string]any{"command": command})
						if rule := rules(got); rule != "" {
							t.Errorf("%s: hook config rule %q, want none: %s", command, rule, strings.TrimSpace(got))
						}
					}
					// A name test for one hook file reaches it when it exists
					// and nothing when it does not (rel-1-0-10:GAP-1555).
					for name, rule := range map[string]string{"settings.json": agentHookConfigWriteRuleID, "defenseclaw.json": agentHookConfigDisableRuleID} {
						want := ""
						if rule == l.rule {
							want = rule
						}
						for _, command := range []string{"find . -name " + name + " -delete", "find . -name " + name + " -exec rm {} +"} {
							got := judge(project, false, "Bash", map[string]any{"command": command})
							if rule := rules(got); rule != want {
								t.Errorf("%s: hook config rule %q, want %q: %s", command, rule, want, strings.TrimSpace(got))
							}
						}
					}
				})
			}
		}
	}
}
