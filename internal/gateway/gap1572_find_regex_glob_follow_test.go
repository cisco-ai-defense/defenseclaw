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

// TestFindRegexGlobAndLinkFollowKeepTheHookFileFiveTiers (rel-1-0-10:GAP-1572):
// the absent-file skip of GAP-1555 applies only to a generic test over a walk
// whose existence check is sound. A -regex or -iregex test, a glob that
// matches a hook file but not a decoy with its stem swapped (settings.jso[n],
// settings.js?n, settings.*, [s]ettings.json), and any test of a walk that
// follows links (-H, -L, -follow) are
// judged on the hook file whether or not it exists when the hook runs: an
// earlier part of the chain or another process may create the file or the
// link before the walk. The verdict with the file absent is the verdict with
// it present, in every tier. Generic tests over a walk that does not follow
// links (*, *.json, -regex '.*\.json', -P) still reach no absent hook file.
//
// It runs as one test per connector (rel-1-0-10:GAP-1874): the ten cells took up
// to 456 s under -race on a hosted runner, more than one gateway shard holds.
func TestFindRegexGlobAndLinkFollowKeepTheHookFileFiveTiersClaudeCode(t *testing.T) {
	findRegexGlobAndLinkFollowKeepTheHookFileFiveTiers(t, "claudecode")
}

func TestFindRegexGlobAndLinkFollowKeepTheHookFileFiveTiersCodex(t *testing.T) {
	findRegexGlobAndLinkFollowKeepTheHookFileFiveTiers(t, "codex")
}

func findRegexGlobAndLinkFollowKeepTheHookFileFiveTiers(t *testing.T, conn string) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX find spellings; the hook route reads PowerShell on native Windows")
	}
	type hookFile struct{ base, rel string }
	files := []hookFile{
		{"settings.json", ".claude/settings.json"},
		{"defenseclaw.json", ".github/hooks/defenseclaw.json"},
		{"config.toml", ".codex/config.toml"},
	}
	aimed := func(f hookFile) []string {
		stem, ext := strings.TrimSuffix(f.base, filepath.Ext(f.base)), filepath.Ext(f.base)
		escaped := strings.ReplaceAll(f.base, ".", `\.`)
		last := len(f.base) - 1
		// classed is the name with the last letter of its stem in a bracket
		// (setting[s]\.json), so no row spells the name literally.
		classed := stem[:len(stem)-1] + "[" + stem[len(stem)-1:] + "]" + strings.ReplaceAll(ext, ".", `\.`)
		dir := strings.Split(f.rel, "/")[0]
		return []string{
			// GNU word anchors, interval escapes and BSD -E are not read:
			// the parent reading (rel-1-0-10:GAP-1572).
			"find @R@ -regex '.*/\\<" + classed + "' -delete",
			"find @R@ -iregex '.*/\\<" + strings.ToUpper(classed) + "' -delete",
			"find @R@ -regextype posix-extended -regex '.*/\\<" + classed + "' -delete",
			"find @R@ -regex '.*/" + stem[:len(stem)-1] + "[" + stem[len(stem)-1:] + "]\\>" + strings.ReplaceAll(ext, ".", `\.`) + "' -delete",
			"find @R@ -regex '.*/" + stem[:1] + "\\{1\\}" + stem[1:] + strings.ReplaceAll(ext, ".", `\.`) + "' -delete",
			"find -E @R@ -regex '.*/" + stem[:1] + "{1}" + stem[1:] + strings.ReplaceAll(ext, ".", `\.`) + "' -delete",
			// Unions of the name with a decoy the pattern spells.
			"find @R@ -name '[" + stem[:1] + "z][" + stem[1:2] + "z]*" + ext + "' -delete",
			"find @R@ -regex '.*/\\(" + stem + "\\|zzsentinel\\)" + strings.ReplaceAll(ext, ".", `\.`) + "' -delete",
			"find @R@ -regextype posix-extended -regex '.*/(" + stem + "|zzsentinel)" + strings.ReplaceAll(ext, ".", `\.`) + "' -delete",
			"find @R@ -path '*/[.z][" + dir[1:2] + "z]*/[" + stem[:1] + "z]*" + ext + "' -delete",
			"find @R@ -regex '.*/" + escaped + "' -delete",
			"find @R@ -iregex '.*/" + strings.ToUpper(escaped) + "' -delete",
			"find @R@ -regex '@R@/" + f.rel + "' -exec rm {} +",
			"find @R@ -regextype posix-extended -regex '.*/(" + stem + ")" + strings.ReplaceAll(ext, ".", `\.`) + "' -delete",
			"find @R@ -name '" + f.base[:last] + "[" + f.base[last:] + "]' -delete",
			"find @R@ -name '" + f.base[:last-1] + "?" + f.base[last:] + "' -exec rm {} +",
			"find @R@ -iname '" + strings.ToUpper(f.base[:last]) + "[" + strings.ToUpper(f.base[last:]) + "]' -delete",
			"find @R@ -name '" + stem + ".*' -delete",
			"find @R@ -name '[" + f.base[:1] + "]" + f.base[1:] + "' -delete",
			"find -L @R@ -name '*' -type f -delete",
			"find @R@ -follow -name '*" + ext + "' -delete",
			"ln -s @H@/" + filepath.Dir(f.rel) + " @R@/d; find -L @R@ -name '*" + ext + "' -delete",
		}
	}
	generic := []string{
		"find @R@ -regex '.*\\.json' -delete",
		"find @R@ -iregex '.*' -delete",
		"find @R@ -name '*.json' -delete",
		"find @R@ -name '*' -type f -delete",
		"find -P @R@ -name '*' -type f -delete",
		"find @R@ -path '*' -delete",
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
	{
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
							call := strings.ReplaceAll(strings.ReplaceAll(command, "@R@", root), "@H@", home)
							got := judge(project, c.managed, "Bash", map[string]any{"command": call})
							out[call] = hookConfigAction(got) + " " + rules(got)
						}
					}
					return out
				}
				for _, f := range files {
					layout(f.rel)
					present := verdicts(aimed(f))
					layout("")
					absent := verdicts(aimed(f))
					for call, want := range present {
						if absent[call] != want {
							t.Errorf("%s with %s absent is %q, with it present %q", call, f.rel, absent[call], want)
						}
					}
				}
				layout("")
				for call, got := range verdicts(generic) {
					if rule := got[strings.Index(got, " ")+1:]; rule != "" {
						t.Errorf("%s in a project with no hook file reaches %q, want none (%s)", call, rule, got)
					}
				}
			})
		}
	}
}
