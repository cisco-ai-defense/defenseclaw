// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

type linkReachFixture struct {
	home, held, proj string
}

func newLinkReachFixture(t *testing.T) linkReachFixture {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	f := linkReachFixture{home: home, held: filepath.Join(home, ".claude", "skills", "held"), proj: filepath.Join(home, "proj")}
	for _, dir := range []string{f.held, f.proj, filepath.Join(home, "elsewhere", "skills", "thing")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.held, "SKILL.md"), []byte("---\nname: held\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.proj, "notes.txt"), []byte("notes"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"lnk-held": f.held, "lnk-away": filepath.Join(home, "elsewhere", "skills", "thing")} {
		if err := os.Symlink(target, filepath.Join(f.proj, name)); err != nil {
			t.Skipf("cannot create a link here: %v", err)
		}
	}
	return f
}

func hookFactsOf(t *testing.T, connector string, event map[string]any) assetfacts.Facts {
	t.Helper()
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	facts, _ := assetfacts.Decode(hookAssetFacts(connector, raw))
	return facts
}

// The folder a link ends in is protected whichever connector's call follows
// it: Codex reading a folder of the Claude Code skill root through a link, and
// OpenCode, which has no skill root list of its own, report where the link
// ends. A link that ends outside every skill root, and a call that reaches no
// skill folder, report nothing; a connector that only reports links sends no
// MCP server, skill text or skills selected by name.
func TestHookAssetFactsReportsALinkIntoAnotherConnectorsSkillRoot(t *testing.T) {
	f := newLinkReachFixture(t)
	for _, tc := range []struct {
		connector, tool, key string
	}{
		{"codex", "Read", "file_path"},
		{"opencode", "read", "filePath"},
		{"cursor", "read", "file_path"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			read := func(path string) assetfacts.Facts {
				return hookFactsOf(t, tc.connector, map[string]any{
					"tool_name": tc.tool, "cwd": f.proj, "tool_input": map[string]any{tc.key: path},
				})
			}
			for _, path := range []string{"lnk-held/SKILL.md", filepath.Join(f.proj, "lnk-held", "SKILL.md"), "lnk-held"} {
				if got := read(path); !slices.Equal(got.SkillLinks, []string{f.held}) {
					t.Errorf("%s %q: SkillLinks = %q, want [%s]", tc.connector, path, got.SkillLinks, f.held)
				}
			}
			for _, path := range []string{"lnk-away/SKILL.md", "notes.txt", filepath.Join(f.held, "SKILL.md")} {
				if got := read(path); len(got.SkillLinks) != 0 {
					t.Errorf("%s %q: SkillLinks = %q, want none", tc.connector, path, got.SkillLinks)
				}
			}
			if tc.connector != "codex" {
				if got := read("lnk-held/SKILL.md"); got.MCP != nil || len(got.Contents) != 0 || len(got.SkillDirs) != 0 {
					t.Errorf("%s reported more than the links: %+v", tc.connector, got)
				}
			}
		})
	}
}

// A word with no slash that names an existing entry of the working folder is a
// path: the link it names, or SKILL.md read from inside a skill folder, is
// reported as ./word would be. A word that names nothing there, and an
// ordinary file, report nothing.
func TestHookAssetFactsReportsASkillFolderAWordOfTheCallLeadsTo(t *testing.T) {
	f := newLinkReachFixture(t)
	for _, tc := range []struct {
		name, connector, tool string
		input                 map[string]any
		cwd                   string
		want                  bool
	}{
		{"ls the link", "claudecode", "Bash", map[string]any{"command": "ls lnk-held"}, f.proj, true},
		{"grep the link", "claudecode", "Grep", map[string]any{"path": "lnk-held", "pattern": "x"}, f.proj, true},
		{"glob the link", "claudecode", "Glob", map[string]any{"path": "lnk-held", "pattern": "*"}, f.proj, true},
		{"cd to the link", "codex", "Bash", map[string]any{"command": "cd lnk-held && ls"}, f.proj, true},
		{"opencode", "opencode", "bash", map[string]any{"command": "cat lnk-held"}, f.proj, true},
		{"manifest from inside", "claudecode", "Bash", map[string]any{"command": "cat SKILL.md"}, f.held, true},
		{"ordinary file", "claudecode", "Bash", map[string]any{"command": "cat notes.txt"}, f.proj, false},
		{"word that names nothing", "claudecode", "Bash", map[string]any{"command": "echo lnk-held-no ls"}, f.proj, false},
		{"link outside the roots", "claudecode", "Bash", map[string]any{"command": "ls lnk-away"}, f.proj, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := hookFactsOf(t, tc.connector, map[string]any{"tool_name": tc.tool, "cwd": tc.cwd, "tool_input": tc.input})
			if has := slices.Equal(got.SkillLinks, []string{f.held}); has != tc.want || (!tc.want && len(got.SkillLinks) != 0) {
				t.Fatalf("SkillLinks = %q, want the held folder reported: %t", got.SkillLinks, tc.want)
			}
		})
	}
}

// A path on a network share that does not answer is read by no part of the
// hook: not the declared name of a skill folder on it, not the folder it
// leads to after a leading cd, and the folder is not looked up to complete a
// claim. The share is asked once by the call (hookpaths), and what it did not
// answer is left unread.
func TestHookAssetFactsReadsNothingOnAShareThatDoesNotAnswer(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dead := filepath.Join(home, "dead-share")
	folder := filepath.Join(dead, "skills", "folder")
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "SKILL.md"), []byte("---\nname: declared-elsewhere\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	restore := hookpaths.OverrideNetworkSharesForTest(func(path string) string {
		if path == dead || strings.HasPrefix(path, dead+string(filepath.Separator)) {
			return dead
		}
		return ""
	}, func(string) { <-release })
	t.Cleanup(func() {
		close(release)
		restore()
	})
	for name, event := range map[string]map[string]any{
		"read":         {"tool_name": "Read", "cwd": home, "tool_input": map[string]any{"file_path": filepath.Join(folder, "SKILL.md")}},
		"shell":        {"tool_name": "Bash", "cwd": home, "tool_input": map[string]any{"command": "cat " + filepath.Join(folder, "SKILL.md")}},
		"cd":           {"tool_name": "Bash", "cwd": home, "tool_input": map[string]any{"command": "cd " + folder + " && cat SKILL.md"}},
		"cwd on share": {"tool_name": "Bash", "cwd": folder, "tool_input": map[string]any{"command": "cat SKILL.md"}},
		"skill name":   {"tool_name": "Skill", "cwd": folder, "tool_input": map[string]any{"skill": "folder"}},
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := assetfacts.Decode(hookAssetFacts("claudecode", raw))
			if len(got.Skills) != 0 || len(got.SkillDirs) != 0 {
				t.Fatalf("the hook read a skill folder on a share that did not answer: %+v", got)
			}
		})
	}
}

// A skill folder inside a skill root that is itself a link into a network
// share that has not answered is not read: the declared name, the folder and
// its files are read only once the share answers.
func TestHookAssetFactsSkipsALinkedSkillFolderOnAnUnansweredShare(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	share := filepath.Join(home, "unanswered-share")
	target := filepath.Join(share, "skills", "held")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("---\nname: other-name\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, ".claude", "skills")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(target, linked); err != nil {
		t.Skipf("cannot create a link here: %v", err)
	}
	read := func() assetfacts.Facts {
		raw, err := json.Marshal(map[string]any{
			"tool_name": "Read", "cwd": home,
			"tool_input": map[string]any{"file_path": filepath.Join(linked, "SKILL.md")},
		})
		if err != nil {
			t.Fatal(err)
		}
		facts, _ := assetfacts.Decode(hookAssetFacts("claudecode", raw))
		return facts
	}
	if facts := read(); len(facts.Skills) == 0 || facts.Skills[0].Declared != "other-name" {
		t.Fatalf("with no share in the way the hook reports the declared name: %+v", facts.Skills)
	}
	release := make(chan struct{})
	restore := hookpaths.OverrideNetworkSharesForTest(func(path string) string {
		if path == share || strings.HasPrefix(path, share+string(filepath.Separator)) {
			return share
		}
		return ""
	}, func(string) { <-release })
	t.Cleanup(func() { close(release); restore() })
	if facts := read(); len(facts.Skills) != 0 {
		t.Fatalf("the hook read the declared name through a local link onto an unanswered share: %+v", facts.Skills)
	}
}
