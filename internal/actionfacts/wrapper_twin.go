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
				return true
			}
			run, writer := wrappedWriterRun(typed.Args)
			if !writer || run.Index == 0 {
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
				replace(open, open, "( cd "+posixSingleQuoted(run.Dir)+" && ")
				replace(typed.Args[0].Pos(), typed.Args[run.Index].Pos(), "")
			} else {
				replace(open, typed.Args[run.Index].Pos(), "( cd "+posixSingleQuoted(run.Dir)+" && ")
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
			case slices.Contains(switches, arg):
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
		known = options([]string{"-E", "-H", "-n", "-P", "-S", "-b", "-k", "-i", "-s", "--preserve-env",
			"--set-home", "--non-interactive", "--stdin", "--background", "--login", "--shell"},
			[]string{"-u", "-g", "-p", "-C", "-T", "-h"},
			[]string{"--user=", "--group=", "--prompt=", "--preserve-env=", "--host="}, true)
		for at := before; at < next; at++ {
			// sudo -i starts the command in the target user home.
			if arg, _ := value(at); arg == "-i" || arg == "--login" {
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

// envOptions reads the options and NAME=value words of env from next on.
// -C dir and --chdir=dir set the directory the child runs in; -S splits a
// string and ends the reading.
func envOptions(value func(int) (string, bool), next *int, run *PrefixWrapperRun) bool {
	chdir := func(dir string) bool {
		if dir == "" {
			return false
		}
		if run.Dir != "" && !strings.HasPrefix(dir, "/") {
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
