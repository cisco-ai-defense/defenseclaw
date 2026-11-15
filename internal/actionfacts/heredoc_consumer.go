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
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// hereDocConsumer is what the command of a quoted here-document does with
// its body (syntaxTailHereDocConsumer).
type hereDocConsumer uint8

const (
	// hereDocData: every command of the opener line is a program of
	// hereDocDataPrograms, a closed list of programs that never run their
	// standard input as code, named by a bare word with no PATH change and
	// no function, alias or hash entry of that name in the call, or by a
	// trusted path, after the full launcher unwrap. The body is its data.
	hereDocData hereDocConsumer = iota
	// hereDocUnknown: any other command. No command text, a text that does
	// not parse, a word made at run time, an interpreter (python3 -, perl,
	// awk, sed), a launcher, shell or program not on the list, an untrusted
	// path of the program or of a wrapper, a name spelled in another case,
	// an assignment that changes which program a word names (PATH=, env
	// PATH=, BASH_ENV=, LD_PRELOAD=), or a name the call may redefine. The
	// unknown tier of the pack (ONE BOUND rule).
	hereDocUnknown
	// hereDocRunsCode: a command runs its standard input as shell code: a
	// shell reading its script from stdin, through any chain of launchers
	// the shared resolution follows, source or . of the standard input, or
	// a privilege wrapper or scheduler that does (posixStdinCodeTarget).
	hereDocRunsCode
)

// hereDocDataPrograms are the programs whose standard input is data and is
// never run as code, whatever their options (except sort's compress program,
// hereDocDataOptions). Interpreters, pagers (less and more run commands and
// input preprocessors), stream editors with a command language (sed, awk),
// and every launcher or shell are not on it (rel-1-0-10:GAP-0902, the 1.0.10
// lead's ruling: data is a closed allowlist; everything else is unknown).
var hereDocDataPrograms = map[string]bool{
	"cat": true, "tac": true, "tee": true, "head": true, "tail": true, "wc": true,
	"sort": true, "uniq": true, "cut": true, "tr": true, "paste": true, "fold": true,
	"nl": true, "rev": true, "column": true, "expand": true, "unexpand": true,
	"grep": true, "egrep": true, "fgrep": true,
	"base64": true, "base32": true, "od": true, "xxd": true, "hexdump": true,
	"md5sum": true, "md5": true, "sha1sum": true, "sha224sum": true, "sha256sum": true,
	"sha384sum": true, "sha512sum": true, "b2sum": true, "shasum": true, "cksum": true, "sum": true,
	"diff": true, "cmp": true,
	// Builtins that never read their standard input as code.
	"read": true, "echo": true, "printf": true, "true": true, "false": true, ":": true,
}

// hereDocExtraShells are POSIX-family shells the shared shell sets
// (posixShellProgram, layoutShells, shellProgram) do not list. Each reads
// its script from the standard input when no script operand is given.
var hereDocExtraShells = map[string]bool{
	"yash": true, "posh": true, "oksh": true, "loksh": true, "lksh": true,
	"pdksh": true, "ksh93": true, "bosh": true,
}

// syntaxTailHereDocConsumer reads the command of a quoted here-document
// (shellparse.SyntaxTailHereDoc.Consumer). Each simple command of the text is
// one that may get the body (cat <<'EOF' | sh pipes it on, cat <<'EOF' > f &&
// sh f runs it); the reading of the line is the strongest of its commands.
// Data is the narrow case: a command that is not positively known to never
// run its input is the unknown tier, never data (rel-1-0-10:GAP-0876,
// GAP-0889, GAP-0902).
func syntaxTailHereDocConsumer(consumer string) hereDocConsumer {
	return syntaxTailHereDocConsumerIn(consumer, "")
}

// syntaxTailHereDocConsumerIn is syntaxTailHereDocConsumer for a consumer
// of the call text command: a bare data name the text may redefine (a
// function, alias or hash entry of that name, or any PATH assignment) is
// the unknown tier.
func syntaxTailHereDocConsumerIn(consumer, command string) hereDocConsumer {
	return hereDocTextConsumer(consumer, command, 0)
}

func hereDocTextConsumer(consumer, command string, depth int) hereDocConsumer {
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
		reading := hereDocArgvConsumer(words, static, command, depth)
		if reading == hereDocData {
			for _, assign := range call.Assigns {
				if assign.Name != nil && resolutionVariable(assign.Name.Value) {
					// PATH=/tmp/x cat, BASH_ENV=/tmp/x bash -c cat: another
					// program, or another file's code, may get the body.
					reading = hereDocUnknown
				}
			}
			if hereDocRedefined(command, words[0]) {
				reading = hereDocUnknown
			}
		}
		verdict = max(verdict, reading)
		return verdict != hereDocRunsCode
	})
	return verdict
}

// hereDocArgvConsumer reads one simple command (words, with static[i] false
// for a word the shell makes at run time) that gets a here-document body on
// its standard input. Launchers are followed with the shared resolution
// (StaticPrefixWrapperChild, then launcherInner); the program they reach
// decides.
func hereDocArgvConsumer(words []string, static []bool, command string, depth int) hereDocConsumer {
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
		child := hereDocArgvConsumer(words[run.Index:], static[run.Index:], command, depth+1)
		if child == hereDocData && (run.ChangesResolution || hereDocUntrustedPathWord(words[:run.Index])) {
			// env PATH=... cat, or /tmp/x/nohup cat: the program that runs
			// may not be the one the words name.
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
	verdict := hereDocProgramConsumer(program, words, static, command, depth)
	if !trusted && verdict == hereDocData {
		return hereDocUnknown
	}
	return verdict
}

// hereDocProgramConsumer reads the program word of one simple command after
// the static prefix wrappers.
func hereDocProgramConsumer(program string, words []string, static []bool, command string, depth int) hereDocConsumer {
	switch {
	case program == "busybox" || program == "toybox":
		// busybox APPLET ..., toybox APPLET ...: the applet is the program.
		return hereDocArgvConsumer(words[1:], static[1:], command, depth+1)
	case posixShellProgram(program) || layoutShells[program] || shellProgram(program) || hereDocExtraShells[program]:
		return hereDocShellConsumer(words, static, command, depth)
	case program == "source" || program == ".":
		return hereDocSourceConsumer(words, static)
	case program == "eval":
		if !allStatic(static) {
			return hereDocUnknown
		}
		return hereDocTextConsumer(strings.Join(words[1:], " "), command, depth+1)
	}
	if inner := launcherInner(words); inner != nil {
		at := len(words) - len(inner)
		return hereDocArgvConsumer(words[at:], static[at:], command, depth+1)
	}
	if hereDocDataPrograms[program] && path.Base(strings.ReplaceAll(words[0], `\`, "/")) == program && hereDocDataOptions(program, words) {
		// Named as it is installed: CAT is another file on a case-sensitive
		// disk.
		return hereDocData
	}
	// An interpreter, a launcher, a shell runner, an option layout the
	// reading does not follow, or a program not known to keep its input as
	// data.
	return hereDocUnknown
}

// hereDocDataOptions reports the options of a data program that keep its
// input data: sort --compress-program=PROG pipes the input through PROG (any
// --c... long option, which GNU getopt may expand to it, is not data).
func hereDocDataOptions(program string, words []string) bool {
	if program != "sort" {
		return true
	}
	for _, word := range words[1:] {
		if word == "--" {
			break
		}
		if strings.HasPrefix(word, "--c") {
			return false
		}
	}
	return true
}

// hereDocUntrustedPathWord reports a wrapper chain word with a path outside
// the trusted directories (commandProgram is empty for it): the wrapper
// that runs may not be the one its name says. An env assignment word
// (FOO=/x) names no program; PATH= is ChangesResolution.
func hereDocUntrustedPathWord(words []string) bool {
	for _, word := range words {
		if strings.ContainsAny(word, `/\`) && !strings.HasPrefix(word, "-") &&
			!hereDocAssignmentWord.MatchString(word) && commandProgram(word) == "" {
			return true
		}
	}
	return false
}

// hereDocAssignmentWord is an env assignment word NAME=value: its NAME is
// an identifier, so a path word (/tmp/a=b/nohup) never matches.
var hereDocAssignmentWord = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// hereDocPathAssignment matches a PATH (or zsh path array) assignment
// anywhere in a call text: it changes the program every bare name names.
var hereDocPathAssignment = regexp.MustCompile(`(?:^|[^\w])(?:PATH|path)\+?=`)

// hereDocRedefined reports a bare command word that the call text command
// may make name another program: a PATH assignment, or a function, alias or
// hash -p entry of that name. A word with a path is not looked up as a
// function, alias or hash entry.
func hereDocRedefined(command, word string) bool {
	if command == "" || word == "" || strings.ContainsAny(word, `/\`) {
		return false
	}
	if hereDocPathAssignment.MatchString(command) {
		return true
	}
	if !strings.Contains(command, word) {
		return false
	}
	name := regexp.QuoteMeta(word)
	start := `(?:^|[\s;&|(){}'"])`
	end := `(?:$|[\s;&|(){}'"])`
	pattern := start + `(?:` +
		`(?:function\s+)?` + name + `\s*\(\s*\)` + `|` +
		`function\s+` + name + end + `|` +
		`alias(?:\s[^\n;&|]*)?[\s'"]` + name + `=` + `|` +
		`hash\s[^\n;&|]*[\s'"]` + name + end +
		`)`
	matched, err := regexp.MatchString(pattern, command)
	return err != nil || matched
}

// hereDocShellConsumer reads a shell's arguments as the shell does: options
// up to the first operand or --; -c (alone or in a group, -ec) makes the
// first operand the script, whose commands get the body; -s, or no operand,
// reads the script from the standard input (the body); any other operand is
// a script file whose reading of the body is not known.
func hereDocShellConsumer(words []string, static []bool, command string, depth int) hereDocConsumer {
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
		return hereDocTextConsumer(words[operand], command, depth+1)
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
