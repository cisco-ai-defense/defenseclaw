// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"os"
	"path/filepath"
	"runtime"
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

// A command line that holds the name of an entry that leads into a skill
// folder, and a word that reads, copies, writes or runs, reads that folder
// whatever the spelling around the name; the same name next to no such word is
// a word. A typed path is one path whatever spaces it holds.
func TestNameOfALinkIsAPathWhereTheLineReadsOrRuns(t *testing.T) {
	long := strings.Repeat("r", 70)
	home, held, proj := operandTree(t, "needle", "lnk,held", "lnk=held", "name with space", "Mixed")
	linkOrSkip(t, filepath.Join(held, "SKILL.md"), filepath.Join(proj, long))
	if err := os.MkdirAll(filepath.Join(proj, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	linkOrSkip(t, held, filepath.Join(proj, "sub", "inner"))
	if err := os.WriteFile(filepath.Join(proj, "needle notes.txt"), []byte("ordinary"), 0o644); err != nil {
		t.Fatal(err)
	}
	type call struct {
		tool  string
		input any
	}
	bash := func(command any) call { return call{"Bash", map[string]any{"command": command}} }
	for name, c := range map[string]call{
		"program":               bash("echo hello"),
		"program after pipe":    bash("ls notes.txt | grep notes"),
		"wrapped program":       bash("sudo echo hello"),
		"printed word":          bash("echo needle"),
		"printed words":         bash("echo hello needle world"),
		"sudo option value":     bash("sudo -u root echo hello"),
		"sudo long option":      bash("sudo --user root echo hello"),
		"env assignment":        bash("env LC_ALL=C echo hello"),
		"shell script echo":     bash("sh -c 'echo hello'"),
		"git word":              bash("git log needle"),
		"to the null device":    bash("echo needle > /dev/null 2>&1"),
		"typed path with blank": {"Read", map[string]any{"file_path": "needle notes.txt"}},
		"Grep path with blank":  {"Grep", map[string]any{"path": "needle notes.txt", "pattern": "x"}},
		"Glob exact filename":   {"Glob", map[string]any{"pattern": "needle notes.txt"}},
		"argument vector":       bash([]any{"echo", "hello"}),
		"printed by a vector":   bash([]any{"echo", "needle"}),
		"shell script vector":   bash([]any{"bash", "-lc", "echo hello"}),
		"Grep pattern":          {"Grep", map[string]any{"path": "notes.txt", "pattern": "needle"}},
		"query":                 {"Search", map[string]any{"query": "needle"}},
		"edit text":             {"Edit", map[string]any{"file_path": "notes.txt", "old_string": "needle", "new_string": "echo"}},
		"Grep include pattern":  {"Grep", map[string]any{"path": "notes.txt", "pattern": "needle", "glob": "*.txt"}},
	} {
		t.Run("word "+name, func(t *testing.T) {
			if refs := SkillFolderRefs(c.tool, c.input, home, proj); len(refs) != 0 {
				t.Fatalf("%v: refs = %+v, want none", c.input, refs)
			}
		})
	}
	for name, c := range map[string]call{
		"cat operand":               bash("cat needle"),
		"upper case":                bash("cat NEEDLE"),
		"link of another case":      bash("cat mixed"),
		"grep pattern":              bash("grep needle notes.txt"),
		"rg pattern":                bash("rg needle notes.txt"),
		"piped grep pattern":        bash("cat notes.txt | grep needle"),
		"find name value":           bash("find notes.txt -name needle"),
		"sudo option operand":       bash("sudo -u root cat needle"),
		"sudo attached user":        bash("sudo -uroot cat needle"),
		"sudo attached absolute":    bash("sudo -uroot /bin/cat needle"),
		"env attached unset":        bash("env -uAPP cat needle"),
		"escaped reader":            bash(`c\at needle`),
		"quoted reader":             bash(`'c'"a"t needle`),
		"quoted name":               bash("cat 'nee'dle"),
		"escaped name":              bash(`cat nee\dle`),
		"comma in name":             bash("cat lnk,held"),
		"quoted comma in name":      bash("cat 'lnk,held'"),
		"equals in name":            bash("cat lnk=held"),
		"name with spaces":          bash("cat name\\ with\\ space"),
		"quoted name with spaces":   bash(`cat "name with space"`),
		"long -f separated":         bash("grep -f " + long + " notes.txt"),
		"long -f attached":          bash("grep -f" + long + " notes.txt"),
		"long --file=":              bash("grep --file=" + long + " notes.txt"),
		"four eval":                 bash("eval eval eval eval cat needle"),
		"five eval":                 bash("eval eval eval eval eval cat needle"),
		"eval in a shell":           bash("bash -c 'eval eval eval eval eval cat needle'"),
		"printed to xargs":          bash("echo needle | xargs cat"),
		"printed to a runner":       bash("echo needle && sh -c true"),
		"printed beside readers":    bash("echo needle grep ls"),
		"shell script cat":          bash("sh -c 'cat needle'"),
		"shell script second":       bash("echo hi && bash -c 'cat needle'"),
		"eval":                      bash("eval cat needle"),
		"for list":                  bash("for f in needle; do ls $f; done"),
		"assignment":                bash("d=needle; ls $d"),
		"command prefix":            bash("command cat needle"),
		"windows shell":             bash("cmd /c type needle"),
		"ls operand":                bash("ls needle"),
		"grep file operand":         bash("grep -r token needle"),
		"find start":                bash("find needle -name SKILL.md"),
		"read redirect":             bash("wc -l < needle"),
		"read by the shell":         bash("echo $(<needle)"),
		"write redirect":            bash("echo hi > needle"),
		"command substitution":      bash("echo $(cat needle)"),
		"backquotes":                bash("echo `cat needle`"),
		"cd":                        bash("cd needle && ls"),
		"cd to a folder, then name": bash("(cd sub; cat inner)"),
		"folder named by a path":    bash("(cd ./sub; cat inner)"),
		"vector operand":            bash([]any{"cat", "needle"}),
		"vector name with spaces":   bash([]any{"cat", "name with space"}),
		"vector grep file":          bash([]any{"grep", "-r", "token", "needle"}),
		"shell script operand":      bash([]any{"bash", "-c", "cat needle"}),
		"Read":                      {"Read", map[string]any{"file_path": "needle"}},
		"Read with spaces":          {"Read", map[string]any{"file_path": "name with space"}},
		"Grep path":                 {"Grep", map[string]any{"path": "needle", "pattern": "x"}},
		"Glob pattern":              {"Glob", map[string]any{"pattern": "needle"}},
		"plain string":              {"", "cat needle"},
	} {
		t.Run("path "+name, func(t *testing.T) {
			if refs := SkillFolderRefs(c.tool, c.input, home, proj); !reaches(refs, held) {
				t.Fatalf("%v: refs = %+v, want one to %s", c.input, refs, held)
			}
		})
	}
}

// A path with a slash is a path whatever the program; a comma, an equals sign
// or an escape in it does not hide the folder.
func TestWordWithASlashIsAPathForAnyProgram(t *testing.T) {
	home, held, proj := operandTree(t)
	for name, command := range map[string]string{
		"echo":         "echo " + held,
		"git":          "git -C " + held + " log",
		"option value": "tool --file=" + filepath.Join(held, "SKILL.md"),
		"assignment":   "F=" + filepath.Join(held, "SKILL.md") + " tool",
		"quoted":       "cat '" + filepath.Join(held, "SKILL.md") + "'",
		"escaped":      "cat " + strings.Replace(held, "held", `he\ld`, 1) + "/SKILL.md",
		"sub shell":    "(cat " + held + "/SKILL.md)",
	} {
		t.Run(name, func(t *testing.T) {
			if name == "escaped" && runtime.GOOS == "windows" {
				t.Skip("a backslash is a path separator on Windows, not an escape")
			}
			if refs := SkillFolderRefs("Bash", map[string]any{"command": command}, home, proj); !reaches(refs, held) {
				t.Fatalf("%q: refs = %+v, want one to %s", command, refs, held)
			}
		})
	}
	// A vector element with a slash is one path, spaces and all.
	spaced := filepath.Join(filepath.Dir(held), "two words")
	if err := os.MkdirAll(spaced, 0o755); err != nil {
		t.Fatal(err)
	}
	if refs := SkillFolderRefs("Bash", map[string]any{"command": []any{"tool", filepath.Join(spaced, "SKILL.md")}}, home, proj); !reaches(refs, spaced) {
		t.Errorf("vector element with a space: refs = %+v, want one to %s", refs, spaced)
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
		"path then ls":           {"Bash", map[string]any{"command": "ls " + proj + "; ls"}, held, true},
		"null then ls":           {"Bash", map[string]any{"command": "ls /dev/null; ls"}, link, true},
		"null then find":         {"Bash", map[string]any{"command": "ls /dev/null; find -name x"}, held, true},
		"path then grep -r":      {"Bash", map[string]any{"command": "cat " + proj + "/a && grep -r x"}, held, true},
		"two commands, paths":    {"Bash", map[string]any{"command": "ls " + proj + "; ls " + proj}, held, false},
		"null then ls elsewhere": {"Bash", map[string]any{"command": "ls /dev/null; ls"}, proj, false},
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

// Every word of a program that reads files may name one, including the value
// of an option that takes a file; a program that does not read files names a
// path only by a slash in the strict tier excepted, which reads its slash-free
// words too.
func TestFileTakingOptionValueIsAPathOperand(t *testing.T) {
	home, held, proj := operandTree(t)
	linkOrSkip(t, filepath.Join(held, "SKILL.md"), filepath.Join(proj, "rules"))
	for name, command := range map[string]string{
		"cat":                 "cat rules",
		"grep -f":             "grep -f rules notes.txt",
		"grep --file":         "grep --file rules notes.txt",
		"grep --file=":        "grep --file=rules notes.txt",
		"grep attached -f":    "grep -frules notes.txt",
		"grep --exclude-from": "grep --exclude-from rules notes.txt",
		"rg -f":               "rg -f rules notes.txt",
		"rg --ignore-file":    "rg --ignore-file rules notes.txt",
		"sed -f":              "sed -f rules notes.txt",
		"awk -f":              "awk -f rules notes.txt",
		"behind sudo":         "sudo -u root sed -f rules notes.txt",
		"behind env":          "env LC_ALL=C grep -f rules notes.txt",
		"behind xargs":        "xargs -n1 cat rules",
		"behind sudo echo":    "sudo -u root echo rules",
	} {
		t.Run(name, func(t *testing.T) {
			if refs := SkillFolderRefs("Bash", map[string]any{"command": command}, home, proj); !reaches(refs, held) {
				t.Fatalf("%q: refs = %+v, want one to %s", command, refs, held)
			}
		})
	}
	for name, command := range map[string]string{
		"echo":     "echo rules",
		"printf":   "printf rules",
		"git":      "git log rules",
		"ordinary": "grep -f notes.txt notes.txt",
		"no entry": "grep -f nothing-here notes.txt",
	} {
		t.Run("twin "+name, func(t *testing.T) {
			if refs := SkillFolderRefs("Bash", map[string]any{"command": command}, home, proj); len(refs) != 0 {
				t.Fatalf("%q: refs = %+v, want none", command, refs)
			}
		})
	}
}

// The strict tier reads the slash-free word of any program that names an
// existing entry; the balanced tier does not.
func TestStrictTierReadsEveryWordThatNamesAnEntry(t *testing.T) {
	home, held, proj := operandTree(t, "needle")
	for _, command := range []string{"echo needle", "git log needle", "printf needle", "echo hi && git log needle"} {
		input := map[string]any{"command": command}
		if refs := SkillFolderRefs("Bash", input, home, proj); reaches(refs, held) {
			t.Errorf("%q: balanced reading reaches the folder: %+v", command, refs)
		}
		if refs := SkillFolderRefsStrict("Bash", input, home, proj); !reaches(refs, held) {
			t.Errorf("%q: strict reading refs = %+v, want one to %s", command, refs, held)
		}
	}
	// A word that names no entry stays a word in the strict tier too.
	if refs := SkillFolderRefsStrict("Bash", map[string]any{"command": "echo hello"}, home, proj); len(refs) != 0 {
		t.Errorf("strict reading of a word that names nothing: refs = %+v, want none", refs)
	}
	// Text and path fields do not change with the tier.
	if refs := SkillFolderRefsStrict("Grep", map[string]any{"path": "notes.txt", "pattern": "needle"}, home, proj); len(refs) != 0 {
		t.Errorf("strict reading of a search pattern: refs = %+v, want none", refs)
	}
}
