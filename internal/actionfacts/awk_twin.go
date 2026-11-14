// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/awkprog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// MaxAwkNestedShellStrings is how many shell STRINGs deep an awk program is
// read (sh -c "sh -c 'awk ...'"); a program nested deeper is truncated (cap
// depth). It is the depth of the wrapper twin reading.
const MaxAwkNestedShellStrings = maxNestedShellStrings

// AwkTwin is the reading of a command in which the shell commands its awk
// programs start are written out (rel-1-0-10:GAP-0499).
type AwkTwin struct {
	// Text is the POSIX reading of the command in which every awk call whose
	// program starts a shell command through system(), print | or | getline,
	// with the command written as string literals, is written as the group
	// that runs those commands (an sh -c call behind a prefix wrapper or an
	// assignment; the command itself when the awk call is the whole command). Awk starts each command in a shell of its own, so the call
	// runs what the hook would run for that command directly; the awk call
	// itself, with its own file outputs, is judged as written. A prefix wrapper
	// (env, nohup, timeout, ...) stays in front of the sh call, and a shell
	// STRING (sh -c "awk ...") is read the same way. Empty when no call was
	// rewritten. A caller counts only a block proven on the reading.
	Text string
	// Bodies are the shell scripts the awk calls run, each as a plain command.
	Bodies []string
	// Truncated is the cap the reading hit: an awk program inside shell
	// STRINGs nested past maxNestedShellStrings is not read, so the call is
	// judged at least at the unknown tier of the pack (internal/guardrail/bounded).
	Truncated bounded.CapSet
}

// wholeCommand reports that call is the only statement of the command, with
// no redirection, background or negation around it.
func wholeCommand(file *syntax.File, call *syntax.CallExpr) bool {
	if len(file.Stmts) != 1 {
		return false
	}
	stmt := file.Stmts[0]
	return stmt.Cmd == syntax.Command(call) && len(stmt.Redirs) == 0 && !stmt.Background && !stmt.Negated && !stmt.Coprocess
}

// AwkCommandTwin reads the awk programs of a POSIX command. The zero AwkTwin
// means the command has none that start a command.
func AwkCommandTwin(command string) AwkTwin {
	var trunc bounded.Truncated
	text, bodies := awkCommandTwin(command, 0, &trunc)
	return AwkTwin{Text: text, Bodies: bodies, Truncated: trunc.Set()}
}

func awkCommandTwin(command string, depth int, trunc *bounded.Truncated) (twin string, bodies []string) {
	defer func() {
		if recover() != nil {
			twin, bodies = "", nil
		}
	}()
	if !strings.Contains(command, "awk") {
		return "", nil
	}
	file, parsed := shellparse.Parse(command)
	if !parsed {
		return "", nil
	}
	type edit struct {
		start, end int
		text       string
	}
	var edits []edit
	replace := func(from, to syntax.Pos, text string) {
		start, end := int(from.Offset()), int(to.Offset())
		if start >= 0 && end >= start && end <= len(command) {
			edits = append(edits, edit{start: start, end: end, text: text})
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		call, isCall := node.(*syntax.CallExpr)
		if !isCall || len(call.Args) == 0 {
			return true
		}
		words := make([]string, len(call.Args))
		static := make([]bool, len(call.Args))
		for i, arg := range call.Args {
			word := projectPOSIXWord(arg)
			words[i], static[i] = word.Value, !word.Expands
		}
		index := 0
		if run, wrapped := StaticPrefixWrapperChild(words, static); wrapped {
			index = run.Index
		}
		if index >= len(words) || !static[index] {
			return true
		}
		switch wrapperProgramName(words[index]) {
		case "awk", "gawk", "mawk", "nawk":
			argv := slices.Clone(words[index:])
			for i := range argv {
				if !static[index+i] {
					argv[i] = "" // an operand word is not program text
				}
			}
			if body, _ := awkprog.ArgvShell(argv); body != "" {
				// A bare awk call is the commands it starts written as the
				// group that runs them, the plain form the readers list the
				// targets of; with a prefix wrapper or an assignment in front
				// the commands run through sh -c, which keeps them.
				text := "sh -c " + posixSingleQuoted(body)
				switch {
				case index != 0 || len(call.Assigns) != 0:
				case wholeCommand(file, call) && !strings.Contains(body, "\n"):
					text = body // the command alone is the direct command itself
				default:
					text = "{ " + body + "\n}"
				}
				replace(call.Args[index].Pos(), call.Args[len(call.Args)-1].End(), text)
				bodies = append(bodies, body)
			}
		default:
			text, shell := shellOptionsString(call.Args, index)
			if !shell {
				var plain bool
				if text, plain = plainShellString(call.Args, index); !plain {
					return true
				}
			}
			value := projectPOSIXWord(call.Args[text])
			if value.Expands || !strings.Contains(value.Value, "awk") {
				return true
			}
			if !trunc.Within(bounded.Depth, depth+1, maxNestedShellStrings) {
				return true // an awk program in the string is not read
			}
			if inner, innerBodies := awkCommandTwin(value.Value, depth+1, trunc); inner != "" && inner != value.Value {
				replace(call.Args[text].Pos(), call.Args[text].End(), posixSingleQuoted(inner))
				bodies = append(bodies, innerBodies...)
			}
		}
		return true
	})
	if len(edits) == 0 {
		return "", nil
	}
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	var out strings.Builder
	last := 0
	for _, change := range edits {
		if change.start < last {
			return "", nil
		}
		out.WriteString(command[last:change.start])
		out.WriteString(change.text)
		last = change.end
	}
	out.WriteString(command[last:])
	return out.String(), bodies
}
