// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// runTimeShellNames are the parameters that name the shell a call starts
// when the program word is written as their expansion, and the shell the
// reading writes in their place:
//
//   - SHELL is the login shell (set from the password database at login and
//     kept by every shell the user starts); "$SHELL" -c TEXT starts it.
//   - BASH is set by bash to the path of the running bash binary.
//   - ZSH_NAME is set by zsh to the name it was started as.
//
// A command substitution that looks a static shell name up on PATH
// ($(which sh), $(command -v bash); lookedUpShell) names that shell too.
//
// "0" (the positional parameter zero) is read as a shell only where it is
// one: in the agent's own command line, which the agent runs as SHELL -c
// TEXT, and in a -c STRING given no name operand. A script file or a
// STRING with a name operand sets it to that name, so there it is not read.
//
// No other parameter is read as a shell: a program word such as "$GREP",
// "$TOOL" or "$T" names a program the reading cannot know, and its -c
// cluster is an option of that program (a count, a config file), not a
// command STRING (rel-1-0-10:GAP-0981).
var runTimeShellNames = map[string]string{
	"SHELL":    "bash",
	"BASH":     "bash",
	"ZSH_NAME": "zsh",
}

// RunTimeShellWord reports whether word is the expansion of a parameter that
// names a shell (runTimeShellNames: $SHELL, "${SHELL}", ${SHELL:-sh},
// ${SHELL##*/}, $BASH, $ZSH_NAME, and $0 when zeroIsShell), and returns the
// static name of that shell. A default that is itself a shell name
// (${SHELL:-/bin/zsh}) gives that shell. Any other operator on the parameter
// (an alternate value, a replacement, a slice, a length) does not name the
// shell, and the word is not read.
func RunTimeShellWord(word *syntax.Word, zeroIsShell bool) (string, bool) {
	if word == nil || len(word.Parts) != 1 {
		return "", false
	}
	part := word.Parts[0]
	if quoted, ok := part.(*syntax.DblQuoted); ok {
		if len(quoted.Parts) != 1 {
			return "", false
		}
		part = quoted.Parts[0]
	}
	if substitution, ok := part.(*syntax.CmdSubst); ok {
		return lookedUpShell(substitution)
	}
	param, ok := part.(*syntax.ParamExp)
	if !ok || param.Param == nil || param.Excl || param.Length || param.Width || param.IsSet ||
		param.Flags != nil || param.NestedParam != nil || param.Index != nil || len(param.Modifiers) != 0 ||
		param.Slice != nil || param.Repl != nil || param.Names != 0 {
		return "", false
	}
	shell, named := runTimeShellNames[param.Param.Value]
	if !named {
		if param.Param.Value != "0" || !zeroIsShell {
			return "", false
		}
		shell = "bash"
	}
	if param.Exp == nil {
		return shell, true
	}
	switch param.Exp.Op {
	case syntax.DefaultUnset, syntax.DefaultUnsetOrNull, syntax.AssignUnset, syntax.AssignUnsetOrNull:
		if param.Exp.Word != nil {
			if fallback := projectPOSIXWord(param.Exp.Word); !fallback.Expands &&
				wrappedShellPrograms[wrapperProgramName(fallback.Value)] {
				return wrapperProgramName(fallback.Value), true
			}
		}
		return shell, true
	case syntax.RemSmallPrefix, syntax.RemLargePrefix:
		// ${SHELL##*/} is the base name of the shell.
		if param.Exp.Word != nil && len(param.Exp.Word.Parts) == 1 {
			if pattern, literal := param.Exp.Word.Parts[0].(*syntax.Lit); literal && pattern.Value == "*/" {
				return shell, true
			}
		}
	}
	return "", false
}

// lookedUpShell returns the shell a command substitution names when its one
// command looks a static shell name up on PATH: $(which sh), `which bash`,
// $(command -v bash), $(type -P zsh), $(whence -p zsh). The output of the
// lookup is the path of that shell, so the word names the shell.
func lookedUpShell(substitution *syntax.CmdSubst) (string, bool) {
	if len(substitution.Stmts) != 1 || substitution.Stmts[0].Negated || substitution.Stmts[0].Background {
		return "", false
	}
	call, ok := substitution.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) < 2 || len(call.Args) > 3 {
		return "", false
	}
	words := make([]string, len(call.Args))
	for index, arg := range call.Args {
		word := projectPOSIXWord(arg)
		if word.Expands {
			return "", false
		}
		words[index] = word.Value
	}
	lookup := strings.Join(words[:len(words)-1], " ")
	switch lookup {
	case "which", "command -v", "type -p", "type -P", "whence -p":
	default:
		return "", false
	}
	shell := wrapperProgramName(words[len(words)-1])
	if !wrappedShellPrograms[shell] {
		return "", false
	}
	return shell, true
}

// RunTimeShellTwin returns the POSIX reading of command in which the program
// word of every call that names its shell at run time ("$SHELL" -c TEXT,
// $BASH -ec TEXT, "${SHELL:-sh}" -o pipefail -c TEXT, env "$SHELL" -c
// TEXT, "$SHELL" <<< TEXT; RunTimeShellWord) is written as the shell it
// names, so the call is read exactly as the literal shell call: its TEXT is
// a script for every rule (state removal, a config, key or startup-file
// write, tamper), not data of a program of unknown role
// (rel-1-0-10:GAP-0980). The prefix wrappers in front of the program word
// stay as written: the caller reads them as it reads them in front of the
// literal shell. A static shell STRING (bash -c '"$SHELL" -c TEXT') is its
// own command line and is read the same way, up to maxNestedShellStrings.
//
// The reading is a twin of the call as written: a caller judges both and
// keeps the stricter verdict, so the reading only ever adds what the
// literal shell call proves. ok is false when no word was written.
func RunTimeShellTwin(command string) (twin string, ok bool) {
	return runTimeShellTwin(command, 0, true)
}

func runTimeShellTwin(command string, depth int, zeroIsShell bool) (twin string, ok bool) {
	defer func() {
		if recover() != nil {
			twin, ok = "", false
		}
	}()
	if !strings.ContainsAny(command, "$`") {
		return "", false
	}
	file, parsed := shellparse.Parse(command)
	if !parsed {
		return "", false
	}
	type edit struct {
		start, end int
		text       string
	}
	var edits []edit
	replace := func(word *syntax.Word, text string) {
		start, end := int(word.Pos().Offset()), int(word.End().Offset())
		if start >= 0 && end > start && end <= len(command) {
			edits = append(edits, edit{start: start, end: end, text: text})
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		call, isCall := node.(*syntax.CallExpr)
		if !isCall {
			return true
		}
		at, shell, found := shellCallProgram(call.Args, zeroIsShell)
		if !found {
			return true
		}
		if shell != "" {
			replace(call.Args[at], shell)
		}
		if depth >= maxNestedShellStrings {
			return true
		}
		text, isString := shellCommandStringIndex(call.Args, at)
		if !isString {
			return true
		}
		value := projectPOSIXWord(call.Args[text])
		if value.Expands {
			return true
		}
		// $0 of the STRING is its first operand after the STRING, if any.
		if body, changed := runTimeShellTwin(value.Value, depth+1, text+1 >= len(call.Args)); changed && body != value.Value {
			replace(call.Args[text], posixSingleQuoted(body))
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
		out.WriteString(change.text)
		last = change.end
	}
	out.WriteString(command[last:])
	return out.String(), true
}

// shellCallProgram returns the index of the program word of a shell that
// args start after words that may expand to nothing and static prefix
// wrappers (env, command, exec, nohup, nice, timeout, sudo, setsid, ...;
// wrapperChildIndex): a shell named at run time (RunTimeShellWord, whose
// static name is returned) or a static POSIX shell (an empty name).
func shellCallProgram(args []*syntax.Word, zeroIsShell bool) (int, string, bool) {
	// A wrapper reads the shell named at run time as the shell it names,
	// so its options end where they end before the literal shell.
	value := func(at int) (string, bool) {
		if at >= len(args) {
			return "", false
		}
		if shell, named := RunTimeShellWord(args[at], zeroIsShell); named {
			return shell, true
		}
		word := projectPOSIXWord(args[at])
		return word.Value, !word.Expands
	}
	var run PrefixWrapperRun
	index := 0
	for depth := 0; index < len(args) && depth < MaxPrefixWrapperChain; depth++ {
		if shell, named := RunTimeShellWord(args[index], zeroIsShell); named {
			return index, shell, true
		}
		word, static := value(index)
		if !static {
			if vanishingWord(args[index]) {
				index++
				continue
			}
			return 0, "", false
		}
		if word == "" {
			return 0, "", false
		}
		name := wrapperProgramName(word)
		if wrappedShellPrograms[name] {
			return index, "", true
		}
		next, known := wrapperChildIndex(name, value, len(args), index, &run)
		if !known {
			return 0, "", false
		}
		index = next
	}
	return 0, "", false
}

// shellCommandStringIndex returns the index of the -c STRING of the shell
// whose program word is args[at]: SHELL -c STRING, or the option forms
// shellOptionsAfter reads.
func shellCommandStringIndex(args []*syntax.Word, at int) (int, bool) {
	if at+2 < len(args) {
		if option := projectPOSIXWord(args[at+1]); !option.Expands && option.Value == "-c" {
			return at + 2, true
		}
	}
	return shellOptionsAfter(args, at)
}
