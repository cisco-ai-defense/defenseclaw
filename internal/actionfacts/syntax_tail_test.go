// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"slices"
	"testing"
)

// rel-1-0-10:GAP-0526: the per-command reading of a text with a plain syntax
// error holds its readable statements, each to be judged on its own, and
// ends with EvaluationFailureSyntax, at the top level, in an eval or bash -c
// body, and for a call that carries its command in the tool arguments.
func TestSimpleCommandsReadTheStatementsOfASyntaxError(t *testing.T) {
	args := func(command string) json.RawMessage {
		raw, _ := json.Marshal(map[string]string{"command": command})
		return raw
	}
	for _, tc := range []struct {
		name  string
		input Input
		want  []string
	}{
		{"top level", Input{Tool: "Bash", Command: "echo a\nfi", CWD: "/w"}, []string{"echo a"}},
		{"after the error", Input{Tool: "Bash", Command: "fi\necho b", CWD: "/w"}, []string{"echo b"}},
		{"eval body", Input{Tool: "Bash", Command: "eval 'echo a\nfi'", CWD: "/w"}, []string{"echo a"}},
		{"bash -c body", Input{Tool: "Bash", Command: "bash -c 'echo a\nfi'", CWD: "/w"}, []string{"echo a"}},
		{"tool arguments", Input{Tool: "Bash", Args: args("echo a\nfi"), CWD: "/w"}, []string{"echo a"}},
		{"shell tool arguments", Input{Tool: "shell", Args: args("bash -c 'echo a\nfi'"), CWD: "/w"}, []string{"echo a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			simples := SimpleCommands(tc.input, Analyze(tc.input))
			if !slices.ContainsFunc(simples, isSyntaxTailUnread) {
				t.Fatalf("no %q marker: %+v", EvaluationFailureSyntax, simples)
			}
			for _, want := range tc.want {
				if !slices.ContainsFunc(simples, func(simple SimpleCommand) bool {
					return simple.Text == want && simple.EvaluationFailure == ""
				}) {
					t.Errorf("no reading %q: %+v", want, simples)
				}
			}
		})
	}
}

// A text that parses keeps the reading it had: no marker.
func TestSimpleCommandsWithoutASyntaxErrorHaveNoMarker(t *testing.T) {
	for _, command := range []string{"echo a; echo b", "eval 'echo a'", "bash -c 'echo a; echo b'", "cat <(echo a)"} {
		input := Input{Tool: "Bash", Command: command, CWD: "/w"}
		if simples := SimpleCommands(input, Analyze(input)); slices.ContainsFunc(simples, isSyntaxTailUnread) {
			t.Errorf("%q: %+v has the syntax marker", command, simples)
		}
	}
}

// rel-1-0-10:GAP-0535: the -c option of a shell is the word the shell sees.
// Each spelling reads the body as the plain -c does; an option word the walk
// cannot resolve, with a body after it, is EvaluationFailureUnresolvedBody.
func TestSimpleCommandsReadTheShellOptionAsTheShellSeesIt(t *testing.T) {
	for _, command := range []string{
		"bash -c 'echo a; echo b'", "bash '-c' 'echo a; echo b'", `bash "-c" 'echo a; echo b'`,
		"bash $'-c' 'echo a; echo b'", "bash -'c' 'echo a; echo b'", `bash \-c 'echo a; echo b'`,
		"bash -lc 'echo a; echo b'", "sh '-ec' 'echo a; echo b'", "env bash '-c' 'echo a; echo b'",
		"nice -n 5 bash '-c' 'echo a; echo b'", "timeout 5 dash \"-c\" 'echo a; echo b'",
	} {
		input := Input{Tool: "Bash", Command: command, CWD: "/w"}
		simples := SimpleCommands(input, Analyze(input))
		for _, want := range []string{"echo a", "echo b"} {
			if !slices.ContainsFunc(simples, func(simple SimpleCommand) bool { return simple.Text == want }) {
				t.Errorf("%q: no reading %q: %+v", command, want, simples)
			}
		}
	}
	for _, command := range []string{`bash "$o" 'echo a'`, `bash -c "$(cat f)"`} {
		input := Input{Tool: "Bash", Command: command, CWD: "/w"}
		simples := SimpleCommands(input, Analyze(input))
		if !slices.ContainsFunc(simples, func(simple SimpleCommand) bool {
			return simple.EvaluationFailure == EvaluationFailureUnresolvedBody
		}) {
			t.Errorf("%q: %+v, want %q", command, simples, EvaluationFailureUnresolvedBody)
		}
	}
	// A script run with a dynamic path has no -c body.
	input := Input{Tool: "Bash", Command: `bash "$f"`, CWD: "/w"}
	if simples := SimpleCommands(input, Analyze(input)); slices.ContainsFunc(simples, func(simple SimpleCommand) bool {
		return simple.EvaluationFailure == EvaluationFailureUnresolvedBody
	}) {
		t.Errorf("a dynamic script path: %+v", simples)
	}
}

// rel-1-0-10:GAP-0876: the command of a quoted here-document decides what its
// body is: shell code only for a command that runs its standard input as
// code, data for any other, and unknown when the command is not known.
func TestSyntaxTailHereDocConsumer(t *testing.T) {
	for consumer, want := range map[string]hereDocConsumer{
		"cat > notes.txt":  hereDocData,
		"cat $f":           hereDocData,
		"tee -a log":       hereDocData,
		"python3 -":        hereDocData,
		"bash -c ls":       hereDocData,
		"bash":             hereDocRunsCode,
		"sh -s":            hereDocRunsCode,
		"/bin/zsh":         hereDocRunsCode,
		"env FOO=1 bash":   hereDocRunsCode,
		"sudo sh":          hereDocRunsCode,
		"cat | sh":         hereDocRunsCode,
		"$P":               hereDocUnknown,
		"sudo $X":          hereDocUnknown,
		"":                 hereDocUnknown,
		"cat > \"unclosed": hereDocUnknown,
	} {
		if got := syntaxTailHereDocConsumer(consumer); got != want {
			t.Errorf("%q: %d, want %d", consumer, got, want)
		}
	}
}

// The body of a quoted here-document after the error is read as statements
// only when its command is a shell; any other command's body is its input.
func TestSimpleCommandsReadAHereDocBodyOnlyForAShell(t *testing.T) {
	script := func(consumer string) string {
		return "tool '" + consumer + " <<'\"'\"'EOF'\"'\"'\nit's (x)\necho data\nEOF\n'"
	}
	read := func(command string) []SimpleCommand {
		input := Input{Tool: "Bash", Command: command, CWD: "/w"}
		return SimpleCommands(input, Analyze(input))
	}
	reads := func(simples []SimpleCommand) bool {
		return slices.ContainsFunc(simples, func(simple SimpleCommand) bool {
			return simple.Text == "echo data" && simple.EvaluationFailure == ""
		})
	}
	unknown := func(simples []SimpleCommand) bool {
		return slices.ContainsFunc(simples, func(simple SimpleCommand) bool {
			return simple.EvaluationFailure == EvaluationFailureUnresolvedBody
		})
	}
	if simples := read(script("cat > notes.txt")); reads(simples) || unknown(simples) || !slices.ContainsFunc(simples, isSyntaxTailUnread) {
		t.Errorf("cat: %+v, want the body unread and only the syntax marker", simples)
	}
	if simples := read(script("bash")); !reads(simples) {
		t.Errorf("bash: %+v, want the body read as statements", simples)
	}
	if simples := read(script("$P")); reads(simples) || !unknown(simples) {
		t.Errorf("$P: %+v, want the body unread and the unknown tier", simples)
	}
}
