// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"strings"
	"testing"
)

// currentFolderHeads are the spellings of the current folder before a slash
// (rel-1-0-10:GAP-1023, GAP-1024), built from their parts.
func currentFolderHeads() []string {
	param, subst := "$"+"PWD", "$("+"pwd)"
	return []string{param, "${" + "PWD}", `"` + param + `"`, subst, "`" + "pwd`", `"` + subst + `"`, "~" + "+"}
}

// currentFolderChild is the one statement of the walk of command that runs
// cat, cp, mv, rm or base64.
func currentFolderChild(t *testing.T, command, cwd, home string) SimpleCommand {
	t.Helper()
	input := Input{Tool: "shell", Command: command, CWD: cwd, ActiveHome: home, DialectHint: DialectPOSIX}
	var found []SimpleCommand
	for _, child := range SimpleCommands(input, Analyze(input)) {
		program, _, _ := strings.Cut(child.Text, " ")
		if slices.Contains([]string{"cat", "cp", "mv", "rm", "base64"}, program) {
			found = append(found, child)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%q: want one operand statement, got %#v", command, found)
	}
	return found[0]
}

// TestSimpleCommandsCurrentFolderHeadIsTheFolderTheWalkIsIn is
// rel-1-0-10:GAP-1023 and GAP-1024. After a cd the walk cannot follow, a
// current-folder head ($PWD/, ${PWD}/, "$PWD"/, $(pwd)/, `pwd`/, ~+/) is the
// current folder itself: the statement spells its operand alone, in
// an unresolved folder, so it takes the path of the plain spelling: the
// statement is the plain spelling itself. In a
// folder the walk knows, $(pwd)/ and `pwd`/ name the files $PWD/ names.
func TestSimpleCommandsCurrentFolderHeadIsTheFolderTheWalkIsIn(t *testing.T) {
	home := "/" + strings.Join([]string{"work", "alice"}, "/")
	project := home + "/proj"
	operands := []string{".ssh/id_rsa", ".aws/credentials", ".ssh/*", ".*/*", ".defenseclaw/config.yaml"}
	for _, cd := range []string{"cd \"$TD327_UNSET\" && ", "cd -- \"$(mktemp -d)\" && ", "cd \"$TD327_UNSET\"; "} {
		for _, operand := range operands {
			for _, verb := range []string{"cat %s", "mv %s /tmp/staged", "rm -f %s"} {
				plain := currentFolderChild(t, cd+strings.Replace(verb, "%s", operand, 1), project, home)
				if !plain.UnresolvedFolder {
					t.Fatalf("%q: the plain spelling is not in an unresolved folder: %#v", plain.Text, plain)
				}
				for _, head := range currentFolderHeads() {
					command := cd + strings.Replace(verb, "%s", head+"/"+operand, 1)
					got := currentFolderChild(t, command, project, home)
					if got != plain {
						t.Errorf("%q: statement %#v, want the plain spelling %#v", command, got, plain)
					}
				}
			}
		}
	}
	// The head stays "." where the rest alone would be another word: the
	// program word, and a rest that starts with - or /.
	for _, head := range currentFolderHeads() {
		cd := "cd \"$TD327_UNSET\" && "
		for rest, want := range map[string]string{"/-x": "cat ./-x", "//x": "cat .//x"} {
			command := cd + "cat " + head + rest
			if got := currentFolderChild(t, command, project, home); got.Text != want || !got.UnresolvedFolder {
				t.Errorf("%q: statement %#v, want %q", command, got, want)
			}
		}
		command := cd + head + "/run.sh"
		input := Input{Tool: "shell", Command: command, CWD: project, ActiveHome: home, DialectHint: DialectPOSIX}
		children := SimpleCommands(input, Analyze(input))
		if !slices.ContainsFunc(children, func(child SimpleCommand) bool { return child.Text == "./run.sh" }) {
			t.Errorf("%q: program statements %#v, want ./run.sh", command, children)
		}
	}
	// The head inside the quotes of the whole operand ("$PWD/x", "$(pwd)/x").
	for _, head := range []string{"$" + "PWD", "${" + "PWD}", "$(" + "pwd)"} {
		for _, operand := range operands[:2] {
			cd := "cd \"$TD327_UNSET\" && "
			plain := currentFolderChild(t, cd+"cat \""+operand+"\"", project, home)
			command := cd + "cat \"" + head + "/" + operand + "\""
			if got := currentFolderChild(t, command, project, home); got != plain {
				t.Errorf("%q: statement %#v, want the plain spelling %#v", command, got, plain)
			}
		}
	}
	// A folder the walk knows: $(pwd) and `pwd` name what $PWD names.
	paths := func(child SimpleCommand) []string {
		var out []string
		for _, fact := range Analyze(Input{Tool: "shell", Command: child.Text, CWD: child.CWD, ActiveHome: home, DialectHint: DialectPOSIX}).Paths {
			out = append(out, fact.Normalized)
		}
		return out
	}
	param := "$" + "PWD"
	for _, cd := range []string{"cd .. && ", "cd ~ && ", "cd ../proj && "} {
		for _, operand := range []string{".ssh/id_rsa", ".aws/credentials", ".defenseclaw/config.yaml"} {
			want := currentFolderChild(t, cd+"cat "+param+"/"+operand, project, home)
			for _, head := range currentFolderHeads()[3:6] {
				command := cd + "cat " + head + "/" + operand
				got := currentFolderChild(t, command, project, home)
				if !got.ResolvedVariable || got.CWD != want.CWD || !slices.Equal(paths(got), paths(want)) {
					t.Errorf("%q: statement %#v (paths %q), want the paths of %#v (%q)", command, got, paths(got), want, paths(want))
				}
			}
		}
	}
	// The value of an assignment keeps the folder the shell gave it.
	for _, head := range currentFolderHeads() {
		command := "cd \"$TD327_UNSET\" && F=" + head + "/.ssh/id_rsa && cat \"$F\""
		input := Input{Tool: "shell", Command: command, CWD: project, ActiveHome: home, DialectHint: DialectPOSIX}
		for _, child := range SimpleCommands(input, Analyze(input)) {
			if strings.Contains(child.Text, "F=./") {
				t.Errorf("%q: the assignment value was rewritten: %#v", command, child)
			}
		}
	}
}
