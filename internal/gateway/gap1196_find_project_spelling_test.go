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
// (the disable rule). A name filter that matches no hook file reaches none.
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
						"find " + project + " -name '*.o' -delete",
						"find " + project + "/build -type f -delete",
					} {
						got := judge(project, false, "Bash", map[string]any{"command": command})
						if rule := rules(got); rule != "" {
							t.Errorf("%s: hook config rule %q, want none: %s", command, rule, strings.TrimSpace(got))
						}
					}
				})
			}
		}
	}
}
