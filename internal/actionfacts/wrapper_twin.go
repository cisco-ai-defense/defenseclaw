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
	"slices"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// WrapperUnwrapTwin returns the POSIX reading of command in which every cp,
// mv, install, ln, dd, tee, rsync or shell call run through static prefix
// wrappers (nohup, nice, time, timeout, env, command, builtin, sudo, doas,
// exec, setsid, stdbuf, ionice, taskset, chrt, flock, caffeinate with
// their known options), or after a leading word that may expand to nothing
// ($(true) cp ...), is written as the plain call (GAP-2512, GAP-2519,
// GAP-2477). A wrapper runs the call with the argv the caller shell
// expanded, so the call writes what the plain call writes, while the
// wrapped argv tied no write to it (nohup cp a.txt
// ~/.defenseclaw/config.yaml was allowed). A wrapper that runs the call in
// another directory (env -C dir) is written as ( cd dir && call ), so a
// relative operand is read where the call runs. ok is false when no call
// was rewritten. A caller counts only a block proven on the reading.
func WrapperUnwrapTwin(command string) (twin string, ok bool) {
	return wrapperUnwrapTwin(command, 0)
}

// maxNestedShellStrings bounds how deep wrapperUnwrapTwin reads shell
// STRINGs inside shell STRINGs.
const maxNestedShellStrings = 4

func wrapperUnwrapTwin(command string, depth int) (twin string, ok bool) {
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
	type edit struct {
		start, end int
		text       string
	}
	var edits []edit
	replace := func(from, to syntax.Pos, text string) {
		start, end := int(from.Offset()), int(to.Offset())
		if start >= 0 && end >= start && end <= len(command) && (end > start || text != "") {
			edits = append(edits, edit{start: start, end: end, text: text})
		}
	}
	// A static shell STRING is its own command line: a wrapper inside it
	// (sh -c "setsid sh -c 'cp ...'") is read the same way, and the STRING
	// word is written as the quoted reading (GAP-2519).
	nested := func(word *syntax.Word) {
		if depth >= maxNestedShellStrings {
			return
		}
		value := projectPOSIXWord(word)
		if value.Expands {
			return
		}
		if body, changed := wrapperUnwrapTwin(value.Value, depth+1); changed && body != value.Value {
			replace(word.Pos(), word.End(), posixSingleQuoted(body))
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch typed := node.(type) {
		case *syntax.TimeClause:
			if typed.Stmt == nil {
				return true
			}
			if call, isCall := typed.Stmt.Cmd.(*syntax.CallExpr); isCall {
				if _, writer := wrappedWriterRun(call.Args); writer {
					replace(typed.Pos(), typed.Stmt.Pos(), "")
				}
			}
		case *syntax.CallExpr:
			if command, ok := flockShellString(typed.Args); ok {
				// flock FILE -c STRING runs sh -c STRING under the lock.
				replace(typed.Args[0].Pos(), typed.Args[command].Pos(), "sh -c ")
				nested(typed.Args[command])
				return true
			}
			run, writer := wrappedWriterRun(typed.Args)
			if !writer {
				return true
			}
			// A shell started with other options before its STRING
			// (bash --norc -c, sh -c -- STRING, bash -euo pipefail -c)
			// runs what sh -c STRING runs (GAP-2527).
			text, shell := shellOptionsString(typed.Args, run.Index)
			if shell {
				nested(typed.Args[text])
			} else if body, plain := plainShellString(typed.Args, run.Index); plain {
				nested(typed.Args[body])
			}
			if run.Dir == "" && shell {
				replace(typed.Args[0].Pos(), typed.Args[text].Pos(), "sh -c ")
				return true
			}
			if run.Index == 0 {
				return true
			}
			if run.Dir == "" {
				replace(typed.Args[0].Pos(), typed.Args[run.Index].Pos(), "")
				return true
			}
			// A=1 env -C dir cp ... is ( cd dir && A=1 cp ... ): the
			// assignments stay in the child environment, and the subshell
			// opens before them so the twin parses.
			open := typed.Args[0].Pos()
			if len(typed.Assigns) > 0 {
				open = typed.Assigns[0].Pos()
				replace(open, open, "( cd "+wrapperDirWord(run.Dir)+" && ")
				replace(typed.Args[0].Pos(), typed.Args[run.Index].Pos(), "")
			} else {
				replace(open, typed.Args[run.Index].Pos(), "( cd "+wrapperDirWord(run.Dir)+" && ")
			}
			if shell {
				replace(typed.Args[run.Index].Pos(), typed.Args[text].Pos(), "sh -c ")
			}
			replace(typed.End(), typed.End(), " )")
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

// homeDirSentinel starts a wrapper directory spelled from the active home
// (env -C ~, env -C "$HOME"/dir, env --chdir="$HOME"): the caller shell
// expands the word before env runs, so the child runs in the home, while
// the twin wrote the literal word (cd '~') or gave no twin for "$HOME"
// (GAP-2519, checker r9i1 RV-r9-2). A shell word cannot hold NUL, so the
// marker never names a real directory.
const homeDirSentinel = "\x00home"

// wrapperDirWord writes the directory a wrapper runs its child in as a
// shell word for the cd of the twin; a home-spelled directory is written
// from "$HOME" again.
func wrapperDirWord(dir string) string {
	if rest, home := strings.CutPrefix(dir, homeDirSentinel); home {
		if rest == "" {
			return "\"$HOME\""
		}
		return "\"$HOME\"" + posixSingleQuoted(rest)
	}
	return posixSingleQuoted(dir)
}

// wrapperHomeDirWord returns the value of args[at] with homeDirSentinel in
// place of its home when the word is the directory of a -C or --chdir
// option (separate or glued) spelled from the active home. ok is false
// for every other word.
func wrapperHomeDirWord(args []*syntax.Word, at int) (string, bool) {
	if at > 0 {
		if option := projectPOSIXWord(args[at-1]); !option.Expands && (option.Value == "-C" || option.Value == "--chdir" ||
			envFlagClusterBefore(option.Value, 'C')) {
			if rest, home := homeSpelledDir(args[at], ""); home {
				return homeDirSentinel + rest, true
			}
		}
	}
	options := []string{"--chdir=", "-C"}
	if len(args[at].Parts) > 0 {
		// A bundled -iC"$HOME" names the home as -C"$HOME" does.
		if lit, isLit := args[at].Parts[0].(*syntax.Lit); isLit && envFlagClusterBefore(lit.Value, 'C') {
			options = append(options, lit.Value)
		}
	}
	for _, option := range options {
		if rest, home := homeSpelledDir(args[at], option); home {
			return option + homeDirSentinel + rest, true
		}
	}
	return "", false
}

// envFlagClusterBefore reports a bundled env short-option word such as
// -iC or -0vu: one or more value-less env flags (-i, -0, -v) followed by
// option last, so the next word (or the rest of the word) is its value.
// GNU env reads env -iC DIR as env -i -C DIR (GAP-2519, checker r10i2
// RV-r10-3).
func envFlagClusterBefore(word string, option byte) bool {
	if len(word) < 3 || word[0] != '-' || word[1] == '-' || word[len(word)-1] != option {
		return false
	}
	for _, flag := range word[1 : len(word)-1] {
		if flag != 'i' && flag != '0' && flag != 'v' {
			return false
		}
	}
	return true
}

// homeSpelledDir returns the static rest of word after option (the literal
// text that starts it) and a leading home spelling: an unquoted ~ or ~/ at
// the word start (no option), or a plain $HOME or ${HOME}, bare or first
// in double quotes. The rest is empty or starts with a slash; ok is false
// when any other part expands or the word names another directory.
func homeSpelledDir(word *syntax.Word, option string) (string, bool) {
	if word == nil || len(word.Parts) == 0 {
		return "", false
	}
	parts := word.Parts
	var rest strings.Builder
	lit, isLit := parts[0].(*syntax.Lit)
	if option == "" && isLit && (lit.Value == "~" || strings.HasPrefix(lit.Value, "~/")) {
		rest.WriteString(unquotePOSIXLiteral(lit.Value[1:], false))
		parts = parts[1:]
	} else {
		if option != "" {
			if !isLit || lit.Value != option || len(parts) < 2 {
				return "", false
			}
			parts = parts[1:]
		}
		switch typed := parts[0].(type) {
		case *syntax.ParamExp:
			if !plainHomeParameter(typed) {
				return "", false
			}
		case *syntax.DblQuoted:
			if typed.Dollar || len(typed.Parts) == 0 || !plainHomeParameter(typed.Parts[0]) {
				return "", false
			}
			for _, nested := range typed.Parts[1:] {
				value, expands := projectPOSIXDoubleQuotedPart(nested)
				if expands {
					return "", false
				}
				rest.WriteString(value)
			}
		default:
			return "", false
		}
		parts = parts[1:]
	}
	for _, part := range parts {
		value, _, expands := projectPOSIXWordPart(part)
		if expands {
			return "", false
		}
		rest.WriteString(value)
	}
	if text := rest.String(); text == "" || strings.HasPrefix(text, "/") {
		return text, true
	}
	return "", false
}

func posixSingleQuoted(value string) string {
	return "\x27" + strings.ReplaceAll(value, "\x27", "\x27\\\x27\x27") + "\x27"
}

// PrefixWrapperRun is where a chain of static prefix wrappers hands its
// argv on: Index is the word the last wrapper runs. Dir is the directory
// the child runs in when a wrapper sets one (env -C dir); DirUnknown is
// set when a wrapper moves it to a place the words do not name (sudo -i
// starts in the target user home). ChangesResolution is set when a
// wrapper assigns a variable that changes which program the child word
// names (env PATH=...).
type PrefixWrapperRun struct {
	Index             int
	Dir               string
	DirUnknown        bool
	ChangesResolution bool
}

// StaticPrefixWrapperChild reads words (the static values of the words of
// one simple command; static[i] is false for a word the shell expands at
// run time) as a chain of static prefix wrappers and returns where the
// chain runs its child. ok is false when words[0] is not such a wrapper,
// a wrapper word or option is not static or not known, or no child is
// left.
func StaticPrefixWrapperChild(words []string, static []bool) (PrefixWrapperRun, bool) {
	if len(words) == 0 || len(static) != len(words) {
		return PrefixWrapperRun{}, false
	}
	value := func(at int) (string, bool) {
		if at >= len(words) {
			return "", false
		}
		return words[at], static[at]
	}
	var run PrefixWrapperRun
	index := 0
	for depth := 0; depth < 8; depth++ {
		name, ok := value(index)
		if !ok || name == "" {
			break
		}
		next, known := wrapperChildIndex(wrapperProgramName(name), value, len(words), index, &run)
		if !known {
			break
		}
		index = next
	}
	if index == 0 {
		return PrefixWrapperRun{}, false
	}
	run.Index = index
	return run, true
}

func wrapperProgramName(word string) string {
	if slash := strings.LastIndexByte(word, 47); slash >= 0 {
		return word[slash+1:]
	}
	return word
}

// wrappedWriterRun returns where the program word of a file writer
// (dynamicOperandPrograms or rsync) or of a POSIX shell is that args run
// after leading words that may expand to nothing and static prefix
// wrappers. A shell is the stop too: setsid sh -c STRING runs what
// sh -c STRING runs (GAP-2519).
func wrappedWriterRun(args []*syntax.Word) (PrefixWrapperRun, bool) {
	index := 0
	for index < len(args) && vanishingWord(args[index]) {
		index++
	}
	value := func(at int) (string, bool) {
		if at >= len(args) {
			return "", false
		}
		if dir, home := wrapperHomeDirWord(args, at); home {
			return dir, true
		}
		word := projectPOSIXWord(args[at])
		return word.Value, !word.Expands
	}
	var run PrefixWrapperRun
	for depth := 0; index < len(args) && depth < 8; depth++ {
		word, static := value(index)
		if !static || word == "" {
			return PrefixWrapperRun{}, false
		}
		name := wrapperProgramName(word)
		if dynamicOperandPrograms[name] || name == "rsync" || wrappedShellPrograms[name] {
			run.Index = index
			return run, true
		}
		next, known := wrapperChildIndex(name, value, len(args), index, &run)
		if !known {
			return PrefixWrapperRun{}, false
		}
		index = next
	}
	return PrefixWrapperRun{}, false
}

// wrappedShellPrograms are the shells whose wrapped call is read as the
// plain call, so the plain reading of a -c STRING applies.
var wrappedShellPrograms = map[string]bool{"sh": true, "bash": true, "dash": true, "ksh": true, "zsh": true}

// shellOptionsString returns the index of the STRING a POSIX shell at
// args[at] runs when options other than the one -c stand before it: long
// startup options (--norc, --noprofile, --login, --posix, --rcfile FILE),
// short option clusters with their -o/-O values, and the -- or - that ends
// the options after -c. ok is false for the plain SHELL -c STRING, for a
// script or stdin shell, and for a word that is not static.
func shellOptionsString(args []*syntax.Word, at int) (int, bool) {
	static := func(i int) (string, bool) {
		if i >= len(args) {
			return "", false
		}
		word := projectPOSIXWord(args[i])
		return word.Value, !word.Expands
	}
	if name, ok := static(at); !ok || !wrappedShellPrograms[wrapperProgramName(name)] {
		return 0, false
	}
	command, noexec := false, false
	for i := at + 1; i < len(args); i++ {
		word, ok := static(i)
		if !ok {
			return 0, false
		}
		switch {
		case word == "--" || word == "-":
			if !command || i+1 >= len(args) {
				return 0, false
			}
			return i + 1, !noexec
		case word == "--rcfile" || word == "--init-file":
			i++
			if _, ok := static(i); !ok {
				return 0, false
			}
		case strings.HasPrefix(word, "--"):
			switch word {
			case "--login", "--noprofile", "--norc", "--posix", "--noediting", "--restricted", "--verbose":
			default:
				return 0, false
			}
		case len(word) > 1 && (word[0] == '-' || word[0] == '+'):
			// -n and -o noexec read the STRING and run nothing; +n and
			// +o noexec turn that off again (bash +n -c STRING runs it),
			// and the last setting wins.
			set := word[0] == '-'
			var values []rune
			for _, flag := range word[1:] {
				switch {
				case flag == 'c':
					if word[0] != '-' {
						return 0, false
					}
					command = true
				case flag == 'n':
					noexec = set
				case flag == 'o' || flag == 'O':
					values = append(values, flag)
				case flag >= 'a' && flag <= 'z' || flag >= 'A' && flag <= 'Z':
				default:
					return 0, false
				}
			}
			for _, flag := range values {
				i++
				value, ok := static(i)
				if !ok {
					return 0, false
				}
				if flag == 'o' && value == "noexec" {
					noexec = set
				}
			}
		default:
			if !command {
				return 0, false
			}
			if first, _ := static(at + 1); i == at+2 && first == "-c" {
				return 0, false
			}
			return i, !noexec
		}
	}
	return 0, false
}

// plainShellString returns the index of the STRING of a POSIX shell at
// args[at] started as SHELL -c STRING.
func plainShellString(args []*syntax.Word, at int) (int, bool) {
	if at+2 >= len(args) {
		return 0, false
	}
	name, option := projectPOSIXWord(args[at]), projectPOSIXWord(args[at+1])
	if name.Expands || option.Expands || option.Value != "-c" || !wrappedShellPrograms[wrapperProgramName(name.Value)] {
		return 0, false
	}
	return at + 2, true
}

// flockShellString returns the index of the STRING word of a
// flock FILE -c STRING (or --command STRING) call run after static prefix
// wrappers that keep the directory: flock runs sh -c STRING under the
// lock, so the call writes what sh -c STRING writes (GAP-2519).
func flockShellString(args []*syntax.Word) (int, bool) {
	value := func(at int) (string, bool) {
		if at >= len(args) {
			return "", false
		}
		word := projectPOSIXWord(args[at])
		return word.Value, !word.Expands
	}
	var run PrefixWrapperRun
	index := 0
	for depth := 0; index < len(args) && depth < 8; depth++ {
		word, static := value(index)
		if !static || word == "" {
			return 0, false
		}
		name := wrapperProgramName(word)
		next, known := wrapperChildIndex(name, value, len(args), index, &run)
		if !known || run.Dir != "" || run.DirUnknown {
			return 0, false
		}
		if name == "flock" {
			option, static := value(next)
			if static && (option == "-c" || option == "--command") && next+2 == len(args) {
				return next + 1, true
			}
			return 0, false
		}
		index = next
	}
	return 0, false
}

// wrapperChildIndex returns the index of the word a prefix wrapper at
// index runs. Every wrapper word must be static; an option that splits a
// string, starts a shell with no command, acts on a running process or is
// not known ends the reading. A directory the wrapper sets is recorded in
// run.
func wrapperChildIndex(name string, value func(int) (string, bool), count, index int, run *PrefixWrapperRun) (int, bool) {
	next := index + 1
	options := func(switches, valued, prefixes []string, assignments bool) bool {
		for {
			arg, static := value(next)
			if !static {
				return false
			}
			switch {
			case arg == "--":
				next++
				return true
			case slices.Contains(switches, arg), clusteredSwitches(arg, switches):
				next++
			case slices.Contains(valued, arg):
				if _, static := value(next + 1); !static {
					return false
				}
				next += 2
			case hasAnyPrefix(arg, prefixes):
				next++
			case strings.HasPrefix(arg, "-"):
				return false
			case assignments && strings.Contains(arg, "=") && !strings.HasPrefix(arg, "="):
				if variable, _, _ := strings.Cut(arg, "="); resolutionVariable(variable) {
					run.ChangesResolution = true
				}
				next++
			default:
				return true
			}
		}
	}
	// positional takes one static word that does not start with "-" and,
	// when digits is set, holds only digits (a priority).
	positional := func(digits bool) bool {
		arg, static := value(next)
		if !static || arg == "" || strings.HasPrefix(arg, "-") ||
			digits && strings.Trim(arg, "0123456789") != "" {
			return false
		}
		next++
		return true
	}
	var known bool
	switch name {
	case "nohup":
		known = options(nil, nil, nil, false)
	case "nice":
		known = options(nil, []string{"-n"}, []string{"--adjustment=", "-n"}, false)
		if !known {
			// nice -5 cp ...
			if arg, static := value(next); static && len(arg) > 1 && arg[0] == 45 &&
				strings.Trim(arg[1:], "0123456789") == "" {
				next++
				known = options(nil, []string{"-n"}, []string{"--adjustment="}, false)
			}
		}
	case "time":
		known = options([]string{"-p", "-v", "-a", "-q", "--portability", "--verbose", "--append", "--quiet"},
			[]string{"-f", "-o"}, []string{"--format=", "--output="}, false)
	case "timeout":
		known = options([]string{"--preserve-status", "--foreground", "-v", "--verbose"},
			[]string{"-s", "-k"}, []string{"--signal=", "--kill-after="}, false)
		if duration, static := value(next); !static || duration == "" || strings.HasPrefix(duration, "-") {
			return 0, false
		}
		next++
	case "env":
		known = envOptions(value, &next, run)
	case "command":
		known = options([]string{"-p"}, nil, nil, false)
	case "builtin":
		// builtin runs a shell builtin: only command and exec run a program.
		child, static := value(next)
		known = static && (child == "command" || child == "exec")
	case "sudo":
		before := next
		known = options(sudoSwitches,
			[]string{"-u", "-g", "-p", "-C", "-T", "-h"},
			[]string{"--user=", "--group=", "--prompt=", "--preserve-env=", "--host="}, true)
		for at := before; at < next; at++ {
			// sudo -i starts the command in the target user home.
			// (also as a letter of a switch cluster: sudo -Ei).
			if arg, _ := value(at); arg == "-i" || arg == "--login" ||
				clusteredSwitches(arg, sudoSwitches) && strings.ContainsRune(arg[1:], 'i') {
				run.DirUnknown = true
			}
		}
	case "doas":
		known = options([]string{"-n"}, []string{"-u"}, nil, false)
	case "exec":
		known = options([]string{"-c"}, []string{"-a"}, nil, false)
	case "setsid":
		known = options([]string{"-c", "-f", "-w", "--ctty", "--fork", "--wait"}, nil, nil, false)
	case "stdbuf":
		known = options(nil, []string{"-i", "-o", "-e"},
			[]string{"-i", "-o", "-e", "--input=", "--output=", "--error="}, false)
	case "ionice":
		known = options([]string{"-t", "--ignore"}, []string{"-c", "-n", "--class", "--classdata"},
			[]string{"-c", "-n", "--class=", "--classdata="}, false)
	case "taskset":
		known = options([]string{"-a", "-c", "--all-tasks", "--cpu-list"}, nil, nil, false) && positional(false)
	case "chrt":
		known = options([]string{"-a", "-b", "-d", "-f", "-i", "-o", "-r", "-R", "-v", "--all-tasks", "--batch",
			"--deadline", "--fifo", "--idle", "--other", "--rr", "--reset-on-fork", "--verbose"},
			[]string{"-T", "-P", "-D", "--sched-runtime", "--sched-period", "--sched-deadline"}, nil, false) &&
			positional(true)
	case "flock":
		known = options([]string{"-s", "-x", "-e", "-u", "-n", "-o", "-F", "--shared", "--exclusive", "--unlock",
			"--nonblock", "--nb", "--close", "--no-fork", "--verbose"},
			[]string{"-w", "-E", "--timeout", "--wait", "--conflict-exit-code"},
			[]string{"--timeout=", "--wait=", "--conflict-exit-code="}, false) && positional(false)
	case "caffeinate":
		known = options([]string{"-d", "-i", "-m", "-s", "-u"}, []string{"-t", "-w"}, nil, false)
	}
	if !known || next >= count {
		return 0, false
	}
	return next, true
}

// sudoSwitches are the sudo options that take no value.
var sudoSwitches = []string{"-E", "-H", "-n", "-P", "-S", "-b", "-k", "-i", "-s", "--preserve-env",
	"--set-home", "--non-interactive", "--stdin", "--background", "--login", "--shell"}

// clusteredSwitches reports whether arg is a cluster of two or more
// single-letter switches, each in switches (setsid -fw, caffeinate -di,
// flock -xn): the program reads it as those switches one by one. A
// cluster with any other letter (an option that takes a value) is not
// read.
func clusteredSwitches(arg string, switches []string) bool {
	if len(arg) < 3 || arg[0] != '-' || arg[1] == '-' {
		return false
	}
	for _, letter := range arg[1:] {
		if !slices.Contains(switches, "-"+string(letter)) {
			return false
		}
	}
	return true
}

// envOptions reads the options and NAME=value words of env from next on.
// -C dir and --chdir=dir set the directory the child runs in; -S splits a
// string and ends the reading.
func envOptions(value func(int) (string, bool), next *int, run *PrefixWrapperRun) bool {
	chdir := func(dir string) bool {
		if dir == "" {
			return false
		}
		if run.Dir != "" && !strings.HasPrefix(dir, "/") && !strings.HasPrefix(dir, homeDirSentinel) {
			dir = strings.TrimRight(run.Dir, "/") + "/" + dir
		}
		run.Dir = dir
		return true
	}
	for {
		arg, static := value(*next)
		if !static {
			return false
		}
		switch {
		case arg == "--":
			*next++
			return true
		case arg == "-i" || arg == "-" || arg == "--ignore-environment" || arg == "-0" || arg == "--null":
			*next++
		case arg == "-u" || arg == "--unset":
			if _, static := value(*next + 1); !static {
				return false
			}
			*next += 2
		case strings.HasPrefix(arg, "--unset=") || strings.HasPrefix(arg, "-u") && len(arg) > 2:
			*next++
		case arg == "-C" || arg == "--chdir":
			dir, static := value(*next + 1)
			if !static || !chdir(dir) {
				return false
			}
			*next += 2
		case strings.HasPrefix(arg, "--chdir="):
			if !chdir(strings.TrimPrefix(arg, "--chdir=")) {
				return false
			}
			*next++
		case strings.HasPrefix(arg, "-C") && len(arg) > 2:
			if !chdir(arg[2:]) {
				return false
			}
			*next++
		case arg == "-v" || arg == "--debug":
			*next++
		case len(arg) > 2 && arg[0] == '-' && arg[1] != '-':
			// A bundle of short options (-iC DIR, -i0, -vu NAME): the
			// value-less flags, then at most one -u or -C that takes the
			// rest of the word or the next word; -S and any other letter
			// end the reading.
			at := 1
			for at < len(arg) && (arg[at] == 'i' || arg[at] == '0' || arg[at] == 'v') {
				at++
			}
			if at == len(arg) {
				*next++
				continue
			}
			if at == 1 || arg[at] != 'u' && arg[at] != 'C' {
				return false
			}
			option, rest := arg[at], arg[at+1:]
			if rest == "" {
				var static bool
				if rest, static = value(*next + 1); !static {
					return false
				}
				*next++
			}
			if option == 'C' && !chdir(rest) {
				return false
			}
			*next++
		case strings.HasPrefix(arg, "-"):
			return false
		case strings.Contains(arg, "=") && !strings.HasPrefix(arg, "="):
			if variable, _, _ := strings.Cut(arg, "="); resolutionVariable(variable) {
				run.ChangesResolution = true
			}
			*next++
		default:
			return true
		}
	}
}

// resolutionVariable reports a variable that changes which program a
// word names or what a program loads.
func resolutionVariable(name string) bool {
	switch name {
	case "PATH", "IFS", "ENV", "BASH_ENV":
		return true
	}
	return strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_")
}

func hasAnyPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) && len(value) > len(prefix) {
			return true
		}
	}
	return false
}
