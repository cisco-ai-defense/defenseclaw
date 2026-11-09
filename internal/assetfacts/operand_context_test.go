// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func operandTree(t *testing.T, linkNames ...string) (home, held, proj string) {
	t.Helper()
	home, _, held = skillTree(t)
	proj = filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "notes.txt"), []byte("notes"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range linkNames {
		linkOrSkip(t, held, filepath.Join(proj, name))
	}
	return home, held, proj
}

func reaches(refs []FolderRef, dir string) bool {
	for _, ref := range refs {
		if ref.Dir == dir {
			return true
		}
	}
	return false
}

// The program a command runs, the pattern of a search and a text field are
// words that may equal the name of a link without reading it; the same word
// as a path operand is the link.
func TestBareWordIsAPathOnlyWhereTheCallUsesItAsOne(t *testing.T) {
	home, held, proj := operandTree(t, "echo", "needle", "grep", "ls", "sudo")
	type call struct {
		tool  string
		input any
	}
	for name, c := range map[string]call{
		"program":              {"Bash", map[string]any{"command": "echo hello"}},
		"program after pipe":   {"Bash", map[string]any{"command": "ls notes.txt | grep notes"}},
		"wrapped program":      {"Bash", map[string]any{"command": "sudo echo hello"}},
		"grep pattern":         {"Bash", map[string]any{"command": "grep needle notes.txt"}},
		"grep flags pattern":   {"Bash", map[string]any{"command": "grep -rn -A 3 needle notes.txt"}},
		"grep -e pattern":      {"Bash", map[string]any{"command": "grep -e needle notes.txt"}},
		"grep clustered -e":    {"Bash", map[string]any{"command": "grep -ne needle notes.txt"}},
		"rg pattern":           {"Bash", map[string]any{"command": "rg needle notes.txt"}},
		"piped grep pattern":   {"Bash", map[string]any{"command": "cat notes.txt | grep needle"}},
		"sed script":           {"Bash", map[string]any{"command": "sed -n needle notes.txt"}},
		"find name":            {"Bash", map[string]any{"command": "find notes.txt -name needle"}},
		"printed words":        {"Bash", map[string]any{"command": "echo needle grep ls"}},
		"argument vector":      {"Bash", map[string]any{"command": []any{"echo", "hello"}}},
		"vector grep":          {"Bash", map[string]any{"command": []any{"grep", "needle", "notes.txt"}}},
		"shell script":         {"Bash", map[string]any{"command": []any{"bash", "-lc", "echo hello"}}},
		"Grep pattern":         {"Grep", map[string]any{"path": "notes.txt", "pattern": "needle"}},
		"query":                {"Search", map[string]any{"query": "needle"}},
		"edit text":            {"Edit", map[string]any{"file_path": "notes.txt", "old_string": "needle", "new_string": "echo"}},
		"Grep include pattern": {"Grep", map[string]any{"path": "notes.txt", "pattern": "needle", "glob": "*.txt"}},
	} {
		t.Run("word "+name, func(t *testing.T) {
			if refs := SkillFolderRefs(c.tool, c.input, home, proj); len(refs) != 0 {
				t.Fatalf("%v: refs = %+v, want none", c.input, refs)
			}
		})
	}
	for name, c := range map[string]call{
		"cat operand":          {"Bash", map[string]any{"command": "cat echo"}},
		"ls operand":           {"Bash", map[string]any{"command": "ls needle"}},
		"grep file operand":    {"Bash", map[string]any{"command": "grep -r token needle"}},
		"grep -e file":         {"Bash", map[string]any{"command": "grep -e token needle"}},
		"rg file operand":      {"Bash", map[string]any{"command": "rg token needle"}},
		"find start":           {"Bash", map[string]any{"command": "find needle -name SKILL.md"}},
		"after pipe":           {"Bash", map[string]any{"command": "ls notes.txt | cat echo"}},
		"after wrapper":        {"Bash", map[string]any{"command": "sudo cat echo"}},
		"redirect":             {"Bash", map[string]any{"command": "echo hi > echo"}},
		"printed to a runner":  {"Bash", map[string]any{"command": "echo echo | xargs cat"}},
		"command substitution": {"Bash", map[string]any{"command": "echo $(cat needle)"}},
		"backquotes":           {"Bash", map[string]any{"command": "echo `cat needle`"}},
		"cd":                   {"Bash", map[string]any{"command": "cd needle && ls"}},
		"vector operand":       {"Bash", map[string]any{"command": []any{"cat", "echo"}}},
		"vector grep file":     {"Bash", map[string]any{"command": []any{"grep", "-r", "token", "needle"}}},
		"shell script operand": {"Bash", map[string]any{"command": []any{"bash", "-c", "cat echo"}}},
		"Read":                 {"Read", map[string]any{"file_path": "echo"}},
		"Grep path":            {"Grep", map[string]any{"path": "needle", "pattern": "x"}},
		"Glob pattern":         {"Glob", map[string]any{"pattern": "needle"}},
		"plain string":         {"", "cat echo"},
	} {
		t.Run("path "+name, func(t *testing.T) {
			if refs := SkillFolderRefs(c.tool, c.input, home, proj); !reaches(refs, held) {
				t.Fatalf("%v: refs = %+v, want one to %s", c.input, refs, held)
			}
		})
	}
}

// A search that names no place looks through the working folder, so a
// working folder in a skill folder, or a link to one, is what it reads.
func TestSearchWithoutAPlaceReadsTheWorkingFolder(t *testing.T) {
	home, held, proj := operandTree(t, "lnk-held")
	link := filepath.Join(proj, "lnk-held")
	for name, c := range map[string]struct {
		tool  string
		input map[string]any
		cwd   string
		want  bool
	}{
		"Glob in the folder":     {"Glob", map[string]any{"pattern": "*"}, held, true},
		"Glob in a link":         {"Glob", map[string]any{"pattern": "*"}, link, true},
		"Grep in the folder":     {"Grep", map[string]any{"pattern": "x"}, held, true},
		"Grep in a link":         {"Grep", map[string]any{"pattern": "x"}, link, true},
		"ls":                     {"Bash", map[string]any{"command": "ls -la"}, held, true},
		"ls in a link":           {"Bash", map[string]any{"command": "ls"}, link, true},
		"find":                   {"Bash", map[string]any{"command": "find -name x"}, held, true},
		"grep -r":                {"Bash", map[string]any{"command": "grep -rn token"}, held, true},
		"rg":                     {"Bash", map[string]any{"command": "rg token"}, link, true},
		"piped ls":               {"Bash", map[string]any{"command": "ls | wc -l"}, held, true},
		"Glob path elsewhere":    {"Glob", map[string]any{"pattern": "*", "path": proj}, held, false},
		"ls elsewhere":           {"Bash", map[string]any{"command": "ls " + proj}, held, false},
		"grep without -r":        {"Bash", map[string]any{"command": "grep token"}, held, false},
		"grep file":              {"Bash", map[string]any{"command": "grep -r token " + proj}, held, false},
		"find elsewhere":         {"Bash", map[string]any{"command": "find " + proj + " -name x"}, held, false},
		"Glob in a plain folder": {"Glob", map[string]any{"pattern": "*"}, proj, false},
		"ls in a plain folder":   {"Bash", map[string]any{"command": "ls"}, proj, false},
		"Read has no search":     {"Read", map[string]any{"limit": "5"}, held, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := reaches(SkillFolderRefs(c.tool, c.input, home, c.cwd), held); got != c.want {
				t.Fatalf("%s %v in %s: reaches the folder = %t, want %t", c.tool, c.input, c.cwd, got, c.want)
			}
		})
	}
}

// A typed path field is one path: a folder named with spaces or a tab is
// judged by its exact name, directly and through a link to it.
func TestTypedPathFieldKeepsSpacesAndTabsOfFolderNames(t *testing.T) {
	home, root, _ := skillTree(t)
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"  ", "folder\tname", "folder name", " lead", "trail "} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Skipf("folder name unavailable: %v", err)
		}
		link := filepath.Join(proj, "lnk "+strings.Repeat("x", i)+"\tlink")
		linkOrSkip(t, dir, link)
		for field, value := range map[string]string{
			"direct":       filepath.Join(dir, "SKILL.md"),
			"folder":       dir,
			"through link": filepath.Join(link, "SKILL.md"),
		} {
			t.Run(strings.ReplaceAll(name, " ", "_")+" "+field, func(t *testing.T) {
				refs := SkillFolderRefs("Read", map[string]any{"file_path": value}, home, proj)
				if !reaches(refs, dir) {
					t.Fatalf("file_path %q: refs = %+v, want one to %q", value, refs, dir)
				}
				for _, ref := range refs {
					if ref.Dir == dir && ref.Name != name {
						t.Fatalf("name = %q, want %q", ref.Name, name)
					}
				}
			})
		}
	}
	// The ordinary twin: a path with spaces outside any skill folder.
	if refs := SkillFolderRefs("Read", map[string]any{"file_path": filepath.Join(proj, "my notes", "a b.txt")}, home, proj); len(refs) != 0 {
		t.Fatalf("ordinary path with spaces: refs = %+v, want none", refs)
	}
}

func TestExtendedLengthPrefixIsSpelledTheUsualWay(t *testing.T) {
	for in, want := range map[string]string{
		"//?/C:/Users/u/.claude/skills/held": "C:/Users/u/.claude/skills/held",
		"//./C:/Users/u/skills/held":         "C:/Users/u/skills/held",
		"//?/UNC/host/share/skills/held":     "//host/share/skills/held",
		"//?/unc/host/share/skills/held":     "//host/share/skills/held",
		"//?/Volume{0000}/skills/held":       "//?/Volume{0000}/skills/held",
		"C:/Users/u/skills/held":             "C:/Users/u/skills/held",
		"//host/share/skills/held":           "//host/share/skills/held",
		"/home/u/skills/held":                "/home/u/skills/held",
		"skills/held":                        "skills/held",
	} {
		if got := trimExtendedPrefix(in); got != want {
			t.Errorf("trimExtendedPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}
