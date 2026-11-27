// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strconv"
	"strings"
	"testing"
)

// unknownFolderReadings are the readings of command (from project, home
// /home/alice) that name notes.txt.
func unknownFolderReadings(t *testing.T, command string) []SimpleCommand {
	t.Helper()
	input := Input{Tool: "Bash", Command: command, CWD: "/home/alice/proj", ActiveHome: "/home/alice"}
	var out []SimpleCommand
	for _, simple := range SimpleCommands(input, Analyze(input)) {
		if strings.Contains(simple.Text, "notes.txt") {
			out = append(out, simple)
		}
	}
	return out
}

// TestNestedBodyAndAssignmentKeepTheUnknownFolder is rel-1-0-10:GAP-1042:
// after a cd the walk cannot follow, a nested shell body starts in that
// unknown folder, and a variable assigned from a current-folder head there
// holds the operand in that folder. Each current-folder head (the heads of
// the GAP-1023 tests) is read as the plain operand, marked UnresolvedFolder,
// as on the top level. A later cd to a known folder forgets such a variable:
// its value names the file in the folder before that cd.
func TestNestedBodyAndAssignmentKeepTheUnknownFolder(t *testing.T) {
	param, subst := "$"+"PWD", "$("+"pwd)"
	heads := []string{param, "${" + "PWD}", subst, "`" + "pwd`", "~" + "+"}
	for _, cd := range []string{`cd "$UNSET_DIR"; `, `cd -- "$(mktemp -d)"; `} {
		for _, head := range heads {
			for _, form := range []string{`bash -c 'cat %s'`, `X=%s; cat "$X"`, `export X=%s; head "$X"`} {
				command := cd + strings.Replace(form, "%s", head+"/notes.txt", 1)
				found := false
				for _, simple := range unknownFolderReadings(t, command) {
					if simple.UnresolvedFolder && !strings.Contains(simple.Text, head) && !strings.Contains(simple.Text, "$X") {
						found = true
					}
				}
				if !found {
					t.Errorf("%q: no reading of notes.txt in the unknown folder: %+v", command, unknownFolderReadings(t, command))
				}
			}
		}
		// A known cd after the assignment: X names a file of the folder
		// before it, so the walk does not read it as notes.txt in /tmp.
		command := cd + "X=" + param + "/notes.txt; cd /tmp; cat \"$X\""
		for _, simple := range unknownFolderReadings(t, command) {
			if strings.HasPrefix(simple.Text, "cat") {
				t.Errorf("%q: the variable is read after the known cd: %+v", command, simple)
			}
		}
	}
	// In a folder the walk knows, nothing changes: the body and the variable
	// are read in that folder.
	for _, command := range []string{`bash -c 'cat notes.txt'`, `X=` + param + `/notes.txt; cat "$X"`} {
		for _, simple := range unknownFolderReadings(t, command) {
			if simple.UnresolvedFolder {
				t.Errorf("%q: %+v is read as an unknown folder", command, simple)
			}
		}
	}
}

// TestFindHandedReadings is rel-1-0-10:GAP-1048: a find hands its starting
// points to a program that reads or copies them, and each such program on
// one starting point is a reading of its own; a program that may change the
// entries, a find with no program and a starting point made at run time give
// none, and more readings than the walk's bound are truncated.
func TestFindHandedReadings(t *testing.T) {
	read := func(command string) ([]string, bool) {
		input := Input{Tool: "Bash", Command: command, CWD: "/home/alice/proj", ActiveHome: "/home/alice"}
		return FindHandedReadings(Analyze(input))
	}
	for command, want := range map[string]string{
		`find notes.txt -exec cp {} /tmp/n \;`:      "cp /home/alice/proj/notes.txt /tmp/n",
		`find ~/notes.txt -exec cat {} +`:           "cat /home/alice/notes.txt",
		`find /srv/a.log -execdir head -n1 {} \;`:   "head -n1 /srv/a.log",
		`find "my notes.txt" -exec cp {} /tmp/n \;`: "cp '/home/alice/proj/my notes.txt' /tmp/n",
		// a shell child whose body only reads is a reader (rel-1-0-10:GAP-1327)
		`find notes.txt -exec sh -c 'cat "$1"' _ {} \;`: `sh -c 'cat "$1"' _ /home/alice/proj/notes.txt`,
	} {
		got, truncated := read(command)
		if truncated || len(got) != 1 || got[0] != want {
			t.Errorf("%q: %q (truncated %v), want [%q]", command, got, truncated, want)
		}
	}
	for _, command := range []string{
		`find notes.txt -exec rm {} \;`, `find notes.txt -exec sh -c ': > "$1"' _ {} \;`,
		`find notes.txt -name x`, `find "$DIR" -exec cat {} \;`, `find notes.txt -exec echo done \;`,
	} {
		if got, _ := read(command); len(got) != 0 {
			t.Errorf("%q: %q, want no reading", command, got)
		}
	}
	// 40 starting points handed to 13 readers: 520 readings, past the bound.
	var many strings.Builder
	many.WriteString("find")
	for i := 0; i < 40; i++ {
		many.WriteString(" f" + strconv.Itoa(i))
	}
	many.WriteString(strings.Repeat(` -exec cat {} \;`, 13))
	if got, truncated := read(many.String()); !truncated || len(got) != maxSimpleEvaluations {
		t.Errorf("past the bound: %d readings, truncated %v; want %d, true", len(got), truncated, maxSimpleEvaluations)
	}
}
