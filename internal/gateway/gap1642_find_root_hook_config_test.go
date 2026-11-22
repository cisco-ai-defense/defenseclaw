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

// TestGAP1642FindFromTheRootReachesTheHookFilesFindHomeReaches
// (rel-1-0-10:GAP-1642, P2): a find that deletes, or hands what it walks to
// rm or mv, from the file system root (find / on Linux and macOS) or from a
// Windows drive root in Git Bash (find C:/, find c:/, find /c/) walks the
// home too, so it reaches the agent hook files find ~ reaches and gets the
// verdict find ~ gets. The shared find reach tested each hook file against
// the root plus a separator; a root that already ends in one (/ and C:\)
// gave // and C:\\, which no path starts with, so find / and find C:/ missed
// the agent hook config guard and only alerted in the default pack while find
// ~ blocked. Git Bash's /c/ was joined to the working directory as a relative
// name, and c:/ missed the C: home by case. A cleanup name, a depth bound
// above the home and a listing stay quiet. Every tier: default, permissive,
// strict, managed and managed-strict.
func TestGAP1642FindFromTheRootReachesTheHookFilesFindHomeReaches(t *testing.T) {
	roots := []string{"/"}
	if runtime.GOOS == "windows" {
		// In Git Bash / is the Git install folder, not a folder above the
		// home (TestGAP0945WindowsGitBashFindFromTheDriveRoot).
		volume := filepath.VolumeName(t.TempDir())
		if len(volume) != 2 || volume[1] != ':' {
			t.Skipf("temp folder on %q, not on a drive letter", volume)
		}
		lower := strings.ToLower(volume)
		roots = []string{volume + "/", lower + "/", "/" + lower[:1] + "/", "/" + lower[:1]}
	}
	walks := []string{
		"-type f -delete",
		"-type f -exec rm {} +",
		"-type f -exec rm -f {} \\;",
		"-type f -exec mv {} /tmp/x/ \\;",
		"-name '*.json' -exec rm {} \\;",
	}
	quiet := []string{
		"-name '*.tmp' -delete",
		"-maxdepth 1 -type f -delete",
		"-name notes.txt",
	}
	tiers := []struct {
		name, profile string
		managed       bool
	}{{"default", "default", false}, {"permissive", "permissive", false}, {"strict", "strict", false},
		{"managed", "default", true}, {"managed-strict", "strict", true}}
	for _, conn := range []string{"claudecode", "codex"} {
		for _, tier := range tiers {
			profile, managed := tier.profile, tier.managed
			t.Run(conn+"/"+tier.name, func(t *testing.T) {
				home := filepath.Join(t.TempDir(), "home")
				project := filepath.Join(home, "proj")
				// The installed hook executables are in the home as on an
				// installed host: in the managed tiers they are the hook
				// files a find walk reaches (a named disable), so find ~
				// blocks there and the root must block the same.
				for _, name := range []string{".claude/settings.json", "proj/notes.txt",
					".local/bin/defenseclaw-hook-user", ".local/bin/defenseclaw-hook-post"} {
					full := filepath.Join(home, filepath.FromSlash(name))
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
				rule := func(got string) string {
					switch {
					case strings.Contains(got, agentHookConfigDisableRuleID):
						return agentHookConfigDisableRuleID
					case strings.Contains(got, agentHookConfigWriteRuleID):
						return agentHookConfigWriteRuleID
					}
					return ""
				}
				for _, walk := range walks {
					ref := judge(project, managed, "Bash", map[string]any{"command": "find ~ " + walk})
					refRule, refAction := rule(ref), hookConfigAction(ref)
					// Every -type f walk reaches a hook file from the home in every
					// tier; managed reads only the DefenseClaw hook files (a named
					// disable, which blocks), so the *.json walk stays parity only.
					if strings.HasPrefix(walk, "-type f") {
						if refRule == "" {
							t.Fatalf("find ~ %s: no hook config rule, the fixture is wrong: %s", walk, strings.TrimSpace(ref))
						}
						if managed && (refRule != agentHookConfigDisableRuleID || refAction != "block") {
							t.Errorf("find ~ %s: %s %q, want block %q in the managed tier", walk, refAction, refRule, agentHookConfigDisableRuleID)
						}
					}
					for _, root := range roots {
						command := "find " + root + " " + walk
						got := judge(project, managed, "Bash", map[string]any{"command": command})
						if r, a := rule(got), hookConfigAction(got); r != refRule || a != refAction {
							t.Errorf("%s: %s %q, find ~ %s: %s %q", command, a, r, walk, refAction, refRule)
						}
					}
				}
				for _, walk := range quiet {
					for _, root := range roots {
						command := "find " + root + " " + walk
						got := judge(project, managed, "Bash", map[string]any{"command": command})
						if r := rule(got); r != "" {
							t.Errorf("%s: hook config rule %q, want none: %s", command, r, strings.TrimSpace(got))
						}
					}
				}
			})
		}
	}
}
