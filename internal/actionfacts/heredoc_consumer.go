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
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// hereDocConsumer is what the command of a quoted here-document does with
// its body (syntaxTailHereDocConsumer).
type hereDocConsumer uint8

const (
	// hereDocData: every command of the opener line is a known, trusted
	// program that is neither a shell nor a launcher; the body is its data.
	hereDocData hereDocConsumer = iota
	// hereDocUnknown: a command is not known (no command text, a text that
	// does not parse, a word made at run time, a launcher or option the
	// reading does not follow, an untrusted path, a variable that changes
	// which program a word names). The unknown tier of the pack.
	hereDocUnknown
	// hereDocRunsCode: a command runs its standard input as shell code: a
	// shell reading its script from stdin, through any chain of launchers
	// the shared resolution follows, source or . of the standard input, or
	// a privilege wrapper or scheduler that does (posixStdinCodeTarget).
	hereDocRunsCode
)

// syntaxTailHereDocConsumer reads the command of a quoted here-document
// (shellparse.SyntaxTailHereDoc.Consumer). Each simple command of the text is
// one that may get the body (cat <<'EOF' | sh pipes it on); the reading of
// the line is the strongest of its commands. Data is the narrow case: a
// command that the reading cannot place is the unknown tier, never data
// (rel-1-0-10:GAP-0876, GAP-0889).
func syntaxTailHereDocConsumer(consumer string) hereDocConsumer {
	return hereDocTextConsumer(consumer, 0)
}

func hereDocTextConsumer(consumer string, depth int) hereDocConsumer {
	if strings.TrimSpace(consumer) == "" || depth > maxControlNesting {
		return hereDocUnknown
	}
	file, ok := shellparse.Parse(consumer)
	if !ok || file == nil {
		return hereDocUnknown
	}
	verdict := hereDocData
	syntax.Walk(file, func(node syntax.Node) bool {
		call, isCall := node.(*syntax.CallExpr)
		if !isCall || len(call.Args) == 0 {
			return verdict != hereDocRunsCode
		}
		words := make([]string, len(call.Args))
		static := make([]bool, len(call.Args))
		for index, arg := range call.Args {
			words[index], static[index] = simpleStaticWord(arg, nil)
		}
		verdict = max(verdict, hereDocArgvConsumer(words, static, depth))
		return verdict != hereDocRunsCode
	})
	return verdict
}

// hereDocArgvConsumer reads one simple command (words, with static[i] false
// for a word the shell makes at run time) that gets a here-document body on
// its standard input. Launchers are followed with the shared resolution
// (StaticPrefixWrapperChild, then launcherInner); the program they reach
// decides.
func hereDocArgvConsumer(words []string, static []bool, depth int) hereDocConsumer {
	if depth > maxControlNesting {
		return hereDocUnknown
	}
	if len(words) == 0 || len(static) != len(words) || !static[0] || words[0] == "" {
		return hereDocUnknown
	}
	if allStatic(static) && posixStdinCodeTarget(words) {
		return hereDocRunsCode
	}
	if run, wrapped := StaticPrefixWrapperChild(words, static); wrapped {
		child := hereDocArgvConsumer(words[run.Index:], static[run.Index:], depth+1)
		if run.ChangesResolution && child == hereDocData {
			// env PATH=... cat: the word may name another program.
			return hereDocUnknown
		}
		return child
	}
	program, trusted := commandProgram(words[0]), true
	if program == "" {
		// A path outside the trusted directories (./bash, /usr/local/bin/bash)
		// is read by its name for code, and is never data.
		program, trusted = strings.ToLower(path.Base(strings.ReplaceAll(words[0], `\`, "/"))), false
	}
	verdict := hereDocProgramConsumer(program, words, static, depth)
	if !trusted && verdict == hereDocData {
		return hereDocUnknown
	}
	return verdict
}

// hereDocProgramConsumer reads the program word of one simple command after
// the static prefix wrappers.
func hereDocProgramConsumer(program string, words []string, static []bool, depth int) hereDocConsumer {
	switch {
	case program == "busybox":
		// busybox APPLET ...: the applet is the program.
		return hereDocArgvConsumer(words[1:], static[1:], depth+1)
	case posixShellProgram(program) || layoutShells[program]:
		return hereDocShellConsumer(words, static, depth)
	case program == "source" || program == ".":
		return hereDocSourceConsumer(words, static)
	case program == "eval":
		if !allStatic(static) {
			return hereDocUnknown
		}
		return hereDocTextConsumer(strings.Join(words[1:], " "), depth+1)
	}
	if inner := launcherInner(words); inner != nil {
		at := len(words) - len(inner)
		return hereDocArgvConsumer(words[at:], static[at:], depth+1)
	}
	if _, interpreter := inlineInterpreterRow(program); interpreter {
		// An interpreter (python3 -, perl) runs its standard input as its own
		// language, not as shell: the body is its data, which the strict and
		// managed raw scan still reads (GAP-0876 ruling).
		return hereDocData
	}
	if overLimitCodeProgram(program) || simpleNestedWrapper(program) || launcherWrapper(program) {
		// A launcher, a shell runner or an option layout the reading does not
		// follow to the program it starts.
		return hereDocUnknown
	}
	return hereDocData
}

// hereDocShellConsumer reads a shell's arguments as the shell does: options
// up to the first operand or --; -c (alone or in a group, -ec) makes the
// first operand the script, whose commands get the body; -s, or no operand,
// reads the script from the standard input (the body); any other operand is
// a script file whose reading of the body is not known.
func hereDocShellConsumer(words []string, static []bool, depth int) hereDocConsumer {
	script, stdin, operand := false, false, -1
options:
	for index := 1; index < len(words); index++ {
		if !static[index] {
			return hereDocUnknown
		}
		word := words[index]
		switch {
		case word == "--" || word == "-":
			if index+1 < len(words) {
				operand = index + 1
			}
			break options
		case word == "-o" || word == "+o" || word == "--rcfile" || word == "--init-file":
			index++
		case strings.HasPrefix(word, "--"):
		case len(word) > 1 && (word[0] == '-' || word[0] == '+'):
			if word[0] == '-' {
				script = script || strings.ContainsRune(word[1:], 'c')
				stdin = stdin || strings.ContainsRune(word[1:], 's')
			}
		default:
			operand = index
			break options
		}
	}
	switch {
	case script:
		if operand < 0 || !static[operand] {
			return hereDocUnknown
		}
		return hereDocTextConsumer(words[operand], depth+1)
	case stdin || operand < 0:
		return hereDocRunsCode
	default:
		return hereDocUnknown
	}
}

// hereDocSourceConsumer reads source FILE and . FILE: the standard input as
// the file runs the body in the shell; another file is not known.
func hereDocSourceConsumer(words []string, static []bool) hereDocConsumer {
	at := 1
	if at < len(words) && words[at] == "--" {
		at++
	}
	if at >= len(words) || !static[at] {
		return hereDocUnknown
	}
	if posixStdinFilePath(words[at]) {
		return hereDocRunsCode
	}
	return hereDocUnknown
}

// posixStdinFilePath reports a file name that is the standard input of the
// process that opens it.
func posixStdinFilePath(name string) bool {
	switch path.Clean(name) {
	case "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0":
		return true
	}
	return false
}

func allStatic(static []bool) bool {
	for _, known := range static {
		if !known {
			return false
		}
	}
	return true
}
