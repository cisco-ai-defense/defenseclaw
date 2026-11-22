// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// inPlaceScreenSpellings are spellings of the in-place editors as program
// words: the split, quoted, escaped, GNU-prefixed and versioned words of
// GAP-0737, and more made from each name in code: every split point, every
// letter escaped or quoted, ANSI-C hex, upper case, a path, a tilde or
// $HOME path, a known $USER (the test home ends in "s") and prefix wrappers.
func inPlaceScreenSpellings() []string {
	words := []string{"sed", "s''ed", `"s"ed`, `s\ed`, "gsed", "gs''ed", "/usr/bin/s''ed",
		"perl", "p''erl", `"perl"`, "perl5.38.2", "p''erl5.38.2"}
	for _, name := range []string{"sed", "gsed", "perl", "perl5.38.2"} {
		words = append(words, strings.ToUpper(name), "/usr/bin/"+name, "~/bin/"+name, `"$HOME"/bin/`+name,
			"${HOME}/bin/"+name, "'"+name+"'", `"`+name+`"`, "env "+name, "command "+name, "nice -n 5 "+name,
			"env -- "+name)
		var hex strings.Builder
		for i := range len(name) {
			fmt.Fprintf(&hex, `\x%02x`, name[i])
			words = append(words,
				name[:i]+"''"+name[i:],
				name[:i]+`""`+name[i:],
				name[:i]+`\`+name[i:],
				name[:i]+"'"+name[i:i+1]+"'"+name[i+1:],
				name[:i]+`"`+name[i:i+1]+`"`+name[i+1:])
		}
		words = append(words, "$'"+hex.String()+"'")
	}
	// The home of the test is .../s, so the login it spells is s.
	words = append(words, "${USER}ed", `"$USER"ed`, "${LOGNAME}ed", "g${USER}ed")
	return words
}

// inPlaceScreenCommands puts each spelling in the statement shapes the
// readers place: alone, after a cd, in a list, a subshell, a group, an if,
// a pipeline, a substitution and after a binding of the login.
func inPlaceScreenCommands(word string) []string {
	sed := word + " -i s/a/b/ notes.txt"
	follow := word + " -i --follow-symlinks s/a/b/ notes.txt"
	perl := word + " -pi -e s/a/b/ notes.txt"
	var out []string
	for _, call := range []string{sed, follow, perl} {
		out = append(out, call,
			"cd sub && "+call,
			"echo a > x.txt; "+call+"; echo b",
			"( "+call+" )",
			"{ "+call+"; }",
			"if true; then "+call+"; fi",
			"cat x.txt | "+call,
			"echo $( "+call+" )",
			"USER=x; "+call,
			call+" && USER=x")
	}
	return out
}

// TestMayEditInPlaceIsASupersetOfTheReaders: the screen in front of the
// in-place state readers (GAP-0901) never skips a call that the readers find
// an editor operand in, for every spelling of GAP-0737 and the generated
// ones, under every statement placing and login reading the callers use.
func TestMayEditInPlaceIsASupersetOfTheReaders(t *testing.T) {
	home := filepath.Join(t.TempDir(), "s")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(cwd, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	read := func(command string) bool {
		if entries, _ := InPlaceEdits(command, cwd, home, KnownUser{}); len(entries) != 0 {
			return true
		}
		if len(inPlaceStateOperands(command, cwd, home, KnownUser{})) != 0 {
			return true
		}
		for _, statement := range PlacedOrWhole(command, cwd, home) {
			for _, user := range []KnownUser{statement.User, {Name: homeUser(home)}, {}} {
				if entries, _ := InPlaceEdits(statement.Command, statement.Dir, home, user); len(entries) != 0 {
					return true
				}
			}
		}
		return false
	}
	found, total := 0, 0
	for _, word := range inPlaceScreenSpellings() {
		for _, command := range inPlaceScreenCommands(word) {
			total++
			if !read(command) {
				continue
			}
			found++
			if !MayEditInPlace(command, home) {
				t.Errorf("MayEditInPlace skips %q, an in-place edit the readers find (rel-1-0-10:GAP-0737)", command)
			}
		}
	}
	// The readers find most of the spellings, so the check is not empty.
	if found*2 < total {
		t.Fatalf("the readers found an editor in %d of %d calls: the spellings no longer reach them", found, total)
	}
}

// TestMayEditInPlaceSkipsCallsWithNoEditor: the long benign lists of the
// GAP-0844 latency guard, and words that only hold sed or perl, are no
// in-place edit and skip the readers (GAP-0901).
func TestMayEditInPlaceSkipsCallsWithNoEditor(t *testing.T) {
	home := filepath.Join(t.TempDir(), "s")
	var chain, list []string
	for i := range 200 {
		chain = append(chain, fmt.Sprintf("grep -n pattern%d src/file%d.go", i, i))
		list = append(list, fmt.Sprintf("echo step%d > build/out%d.txt", i, i))
	}
	for _, command := range []string{
		"echo done > notes.txt", "git status", "cat README.md", strings.Join(chain, " && "), strings.Join(list, "; "),
		"grep -n parsed used.txt", "cat perlfile sed.txt", "echo 'quoted' > notes.txt", `grep "$PATTERN" based.go`,
		"cp ~/notes.txt sedimentary/", "ls closed/ pushed/",
	} {
		if MayEditInPlace(command, home) {
			t.Errorf("MayEditInPlace(%.60q) = true: no word of it is sed or perl", command)
		}
	}
}
