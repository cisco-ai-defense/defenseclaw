// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// WrapperUnwrapExactTwin returns the POSIX reading of command in which every
// call run through a chain of static prefix wrappers that hand the program
// its argv unchanged (taskset 1 sudo env LD_PRELOAD=x curl URL, chrt -i 0
// pkill -f defenseclaw), or timed by the time keyword, is written as the
// plain call (curl URL). It is the
// exact subset of WrapperUnwrapTwin: no leading word that may expand to
// nothing, no program word without a static spelling, no shell STRING
// (sh -c, flock -c), no wrapper that moves the folder (env -C, sudo -D,
// sudo -i) or changes how the program word is found (env PATH=...), and no
// command, builtin or exec, which change what the word names or the argv
// the program gets. The program's own rules may then judge the plain call
// (GAP-1461, GAP-1494; DET111 ruling 2026-11-24T21:35Z). ok is false when no
// call was rewritten.
func WrapperUnwrapExactTwin(command string) (twin string, ok bool) {
	defer func() {
		if recover() != nil {
			twin, ok = "", false
		}
	}()
	if !strings.ContainsAny(command, " \t") {
		return "", false
	}
	file, parsed := shellparse.Parse(command)
	if !parsed {
		return "", false
	}
	type edit struct{ start, end int }
	var edits []edit
	syntax.Walk(file, func(node syntax.Node) bool {
		if timed, isTime := node.(*syntax.TimeClause); isTime && timed.Stmt != nil {
			// The time keyword only times the pipeline it runs.
			start, end := int(timed.Pos().Offset()), int(timed.Stmt.Pos().Offset())
			if start >= 0 && end > start && end <= len(command) {
				edits = append(edits, edit{start: start, end: end})
			}
			return true
		}
		call, isCall := node.(*syntax.CallExpr)
		if !isCall {
			return true
		}
		index, exact := exactWrapperChild(call.Args)
		if !exact {
			return true
		}
		start, end := int(call.Args[0].Pos().Offset()), int(call.Args[index].Pos().Offset())
		if start >= 0 && end > start && end <= len(command) {
			edits = append(edits, edit{start: start, end: end})
		}
		return true
	})
	if len(edits) == 0 {
		return "", false
	}
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	var out strings.Builder
	last := 0
	for _, change := range edits {
		if change.start < last {
			return "", false
		}
		out.WriteString(command[last:change.start])
		last = change.end
	}
	out.WriteString(command[last:])
	return out.String(), true
}

// exactUnwrapExcluded are the prefix wrappers WrapperUnwrapExactTwin does
// not read through: command and builtin change what the program word names
// (a function of the call is skipped), and exec may rename argv[0]
// (exec -a). A flock that runs a shell STRING (flock FILE -c STRING) is
// refused by exactWrapperChild.
var exactUnwrapExcluded = map[string]bool{"command": true, "builtin": true, "exec": true}

// exactWrapperChild is the index of the program a chain of static prefix
// wrappers at the head of args runs with its argv unchanged, and whether
// the chain is such a chain (WrapperUnwrapExactTwin).
func exactWrapperChild(args []*syntax.Word) (int, bool) {
	if _, shell := flockShellString(args); shell {
		return 0, false
	}
	words := make([]string, len(args))
	static := make([]bool, len(args))
	for i, arg := range args {
		word := projectPOSIXWord(arg)
		words[i], static[i] = word.Value, !word.Expands
	}
	return exactWrapperChildIndex(words, static)
}

// ExactWrapperChild is the program, and its argv, that a chain of static
// prefix wrappers at the head of command runs with its argv unchanged
// (WrapperUnwrapExactTwin): taskset 1 sudo env LD_PRELOAD=x chmod u+s F
// runs chmod u+s F. ok is false when command is no such chain. A reader of
// a program's own words judges that program as it judges the plain call
// (GAP-1461, GAP-1494).
func ExactWrapperChild(command CommandFact) (program string, argv []string, ok bool) {
	if len(command.Arguments) != len(command.Argv) {
		return "", nil, false
	}
	static := make([]bool, len(command.Arguments))
	for i, argument := range command.Arguments {
		static[i] = !argument.Expands
	}
	for i, word := range command.Argv {
		if wrapperProgramName(word) == "flock" && slices.ContainsFunc(command.Argv[i+1:], func(arg string) bool {
			return arg == "-c" || arg == "--command" || strings.HasPrefix(arg, "--command=")
		}) {
			return "", nil, false
		}
	}
	index, exact := exactWrapperChildIndex(command.Argv, static)
	if !exact {
		return "", nil, false
	}
	return commandProgram(command.Argv[index]), cloneSlice(command.Argv[index:]), true
}

// exactWrapperChildIndex reads words (static[i] is false for a word the
// shell expands at run time) as the chain ExactWrapperChild and
// WrapperUnwrapExactTwin read.
func exactWrapperChildIndex(words []string, static []bool) (int, bool) {
	if len(words) != len(static) {
		return 0, false
	}
	value := func(at int) (string, bool) {
		if at >= len(words) {
			return "", false
		}
		return words[at], static[at]
	}
	var run PrefixWrapperRun
	index := 0
	for index < len(words) && run.ReadsMore() {
		word, isStatic := value(index)
		if !isStatic || word == "" || strings.HasPrefix(word, "-") {
			return 0, false
		}
		name := wrapperProgramName(word)
		if !prefixWrapperPrograms[name] {
			if index == 0 || wrappedShellPrograms[name] || run.Dir != "" || run.DirUnknown ||
				exactChainNamesOtherProgram(words[:index]) {
				return 0, false
			}
			return index, true
		}
		if exactUnwrapExcluded[name] {
			return 0, false
		}
		next, known := wrapperChildIndex(name, value, len(words), index, &run)
		if !known || next <= index {
			return 0, false
		}
		index = next
	}
	return 0, false
}

// exactChainNamesOtherProgram reports a NAME=value word of the wrapper
// chain (env NAME=value, sudo NAME=value) that changes which program the
// child word names or how the child's words are read: PATH, IFS, ENV,
// BASH_ENV. An LD_ or DYLD_ variable loads more code into the same program
// with the same argv, so the plain call's cell still holds; it only adds.
func exactChainNamesOtherProgram(words []string) bool {
	for _, word := range words {
		if strings.HasPrefix(word, "-") {
			continue
		}
		name, _, assigned := strings.Cut(word, "=")
		if !assigned || name == "" {
			continue
		}
		switch name {
		case "PATH", "IFS", "ENV", "BASH_ENV":
			return true
		}
	}
	return false
}
