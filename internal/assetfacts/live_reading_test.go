// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// A call that only mentions the name of a link to a denied skill reads
// nothing through it: a lookup, quoted text, a search pattern and a function
// body nothing calls. The balanced tiers allow them; the strict tier keeps
// every word that names an entry. The twins below read through the link and
// stay refused in both.
func TestMentioningALinkNameWithoutReadingItIsNotARead(t *testing.T) {
	home, held, proj := operandTree(t, "needle")
	bash := func(command any) map[string]any { return map[string]any{"command": command} }
	mentions := map[string]any{
		"command -v":             bash("command -v needle"),
		"command -V":             bash("command -V needle"),
		"command -pv":            bash("command -pv needle"),
		"builtin command -v":     bash("builtin command -v needle"),
		"lookup then echo":       bash("command -v needle && echo ok"),
		"quoted text":            bash(`echo "cd needle && ls"`),
		"single quoted text":     bash(`echo 'cat needle'`),
		"printf quoted text":     bash(`printf '%s\n' "ls needle"`),
		"quoted text, no reader": bash(`echo "cd needle && ls" 2>&1`),
		"uncalled body":          bash("f() { cat needle; }"),
		"uncalled body, slash":   bash("f() { cat needle/SKILL.md; }; echo ok"),
		"uncalled function kw":   bash("function f { ls needle; }; echo ok"),
		"grep pattern":           bash("grep needle notes.txt"),
		"grep options, pattern":  bash("grep -rn -A 2 needle notes.txt"),
		"grep -i pattern":        bash("grep -i needle notes.txt"),
		"grep after --":          bash("grep -r -- needle notes.txt"),
		"grep -e pattern":        bash("grep -e needle notes.txt"),
		"grep attached -e":       bash("grep -eneedle notes.txt"),
		"grep --regexp":          bash("grep --regexp needle notes.txt"),
		"grep --regexp=":         bash("grep --regexp=needle notes.txt"),
		"egrep pattern":          bash("egrep needle notes.txt"),
		"rg pattern":             bash("rg -n needle notes.txt"),
		"rg -e pattern":          bash("rg -e needle notes.txt"),
		"piped grep":             bash("cat notes.txt | grep needle"),
		"behind sudo":            bash("sudo grep needle notes.txt"),
		"vector lookup":          bash([]any{"command", "-v", "needle"}),
		"vector quoted text":     bash([]any{"echo", "cd needle && ls"}),
		"vector grep pattern":    bash([]any{"grep", "needle", "notes.txt"}),
	}
	if runtime.GOOS != "windows" {
		mentions["type"] = bash("type needle")
		mentions["type a reader"] = bash("type cat needle")
	}
	for name, input := range mentions {
		t.Run("balanced allows "+name, func(t *testing.T) {
			if refs := SkillFolderRefs("Bash", input, home, proj); len(refs) != 0 {
				t.Fatalf("%v: refs = %+v, want none", input, refs)
			}
		})
	}
	// The strict tier keeps every word and the body of a function nothing
	// calls, with and without a reader.
	for name, input := range map[string]any{
		"quoted text":    bash(`echo "cd needle && ls"`),
		"lookup":         bash("command -v needle"),
		"uncalled body":  bash("f() { cat needle; }"),
		"uncalled slash": bash("f() { cat needle/SKILL.md; }; echo ok"),
		"grep pattern":   bash("grep needle notes.txt"),
	} {
		t.Run("strict reads "+name, func(t *testing.T) {
			if refs := SkillFolderRefsStrict("Bash", input, home, proj); !reaches(refs, held) {
				t.Fatalf("%v: strict refs = %+v, want one to %s", input, refs, held)
			}
		})
	}
	reads := map[string]any{
		"called function":          bash("f() { cat needle; }; f"),
		"called, slash":            bash("f() { cat needle/SKILL.md; }; f"),
		"function named by eval":   bash("f() { cat needle; }; eval f"),
		"lookup then read":         bash("command -v needle; cat needle"),
		"lookup holds a reader":    bash("command -v $(cat needle)"),
		"quoted text to a shell":   bash(`echo "cd needle && ls" | sh`),
		"quoted text to xargs":     bash(`echo "needle" | xargs cat`),
		"quoted text to a script":  bash(`echo "cd needle && ls" > run.sh; sh run.sh`),
		"quoted text, real reader": bash(`echo "x" && cat needle`),
		"grep file operand":        bash("grep -r token needle"),
		"grep pattern and file":    bash("grep needle needle"),
		"grep -e then file":        bash("grep -e token needle"),
		"grep file after pattern":  bash("grep token needle"),
		"grep -f patterns":         bash("grep -f needle notes.txt"),
		"grep attached -f":         bash("grep -fneedle notes.txt"),
		"grep --file":              bash("grep --file needle notes.txt"),
		"grep --file abbreviated":  bash("grep --fil needle notes.txt"),
		"grep operand first":       bash("grep notes.txt -e token needle"),
		"grep follows links":       bash("grep -R needle ."),
		"grep follows, long":       bash("grep --dereference-recursive needle ."),
		"rg follows links":         bash("rg -L needle ."),
		"grep with expansion":      bash("grep $pattern needle"),
		"grep expansion after":     bash("grep needle $more"),
		"grep value option":        bash("grep --exclude-from needle token notes.txt"),
		"pattern read elsewhere":   bash("grep needle notes.txt; cat needle"),
		"find name then exec":      bash("find -L . -name needle -exec cat {} +"),
		"vector file operand":      bash([]any{"grep", "-r", "token", "needle"}),
		"vector grep -e file":      bash([]any{"grep", "-e", "token", "needle"}),
		"write redirect":           bash("echo hi > needle"),
		"read redirect":            bash("wc -l < needle"),
		"dynamic program":          bash("$tool needle"),
	}
	if runtime.GOOS == "windows" {
		reads["type reads a file"] = bash("type needle")
	}
	for name, input := range reads {
		t.Run("reads "+name, func(t *testing.T) {
			if refs := SkillFolderRefs("Bash", input, home, proj); !reaches(refs, held) {
				t.Fatalf("%v: refs = %+v, want one to %s", input, refs, held)
			}
		})
	}
}

// The search pattern of grep and rg is found by the options that take a
// value; an option it does not know is a flag, so a word is never taken for a
// pattern unless the options before it are all known.
func TestSearchPatternOperandIsFoundFromTheOptions(t *testing.T) {
	line := func(text string) []int {
		file, ok := shellparseForTest(text)
		if !ok {
			t.Fatalf("%q does not parse", text)
		}
		return searchPatterns(file)
	}
	for text, want := range map[string]int{
		"grep needle notes.txt":              1,
		"grep -r needle .":                   2,
		"grep -A 2 needle notes.txt":         3,
		"grep -e needle notes.txt":           2,
		"grep -ie needle notes.txt":          2,
		"grep -- -needle notes.txt":          2,
		"sudo -u root grep needle notes.txt": 4,
		"rg -g '*.go' needle .":              3,
		"rg --regexp=needle .":               1,
	} {
		got := line(text)
		if len(got) != 1 || got[0] != want {
			t.Errorf("%q: pattern words = %v, want [%d]", text, got, want)
		}
	}
	for _, text := range []string{
		"grep -f rules notes.txt", "grep -R needle .", "rg --follow needle .", "grep --fil needle x", "grep $p needle",
		"echo needle", "cat needle", "grep", "grep -e",
	} {
		if got := line(text); len(got) != 0 {
			t.Errorf("%q: pattern words = %v, want none", text, got)
		}
	}
}

// shellparseForTest reads one simple command of a line as words.
func shellparseForTest(text string) ([]commandWord, bool) {
	file, ok := shellparse.Parse(text)
	if !ok || len(file.Stmts) != 1 {
		return nil, false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok {
		return nil, false
	}
	words := make([]commandWord, len(call.Args))
	for i, arg := range call.Args {
		words[i] = readCommandWord(arg)
	}
	return words, true
}
