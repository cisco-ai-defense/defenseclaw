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
// mv, install, ln, dd, tee or rsync call run through prefix wrappers
// (nohup, nice, time, timeout, env with options or NAME=value words,
// command -p, sudo with user options, exec), or after a leading word that
// may expand to nothing ($(true) cp ...), is written as the plain call
// (GAP-2512, GAP-2477). A wrapper runs the call with the argv the caller
// shell expanded, so the call writes what the plain call writes, while the
// wrapped argv tied no write to it (nohup cp a.txt
// ~/.defenseclaw/config.yaml was allowed). ok is false when no call was
// rewritten. A caller counts only a block proven on the reading.
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
	type edit struct{ start, end int }
	var edits []edit
	cut := func(from, to syntax.Pos) {
		start, end := int(from.Offset()), int(to.Offset())
		if start >= 0 && end > start && end <= len(command) {
			edits = append(edits, edit{start: start, end: end})
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch typed := node.(type) {
		case *syntax.TimeClause:
			if typed.Stmt == nil {
				return true
			}
			if call, isCall := typed.Stmt.Cmd.(*syntax.CallExpr); isCall {
				if _, writer := wrappedWriterIndex(call.Args); writer {
					cut(typed.Pos(), typed.Stmt.Pos())
				}
			}
		case *syntax.CallExpr:
			if first, writer := wrappedWriterIndex(typed.Args); writer && first > 0 {
				cut(typed.Args[0].Pos(), typed.Args[first].Pos())
			}
		}
		return true
	})
	if len(edits) == 0 {
		return "", false
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
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

// wrappedWriterIndex returns the index of the program word of a file
// writer (dynamicOperandPrograms or rsync) that args run after leading
// words that may expand to nothing and static prefix wrappers.
func wrappedWriterIndex(args []*syntax.Word) (int, bool) {
	index := 0
	for index < len(args) && vanishingWord(args[index]) {
		index++
	}
	for depth := 0; index < len(args) && depth < 8; depth++ {
		word := projectPOSIXWord(args[index])
		if word.Expands || word.Value == "" {
			return 0, false
		}
		name := word.Value
		if slash := strings.LastIndexByte(name, 47); slash >= 0 {
			name = name[slash+1:]
		}
		if dynamicOperandPrograms[name] || name == "rsync" {
			return index, true
		}
		next, known := wrapperChildIndex(name, args, index)
		if !known {
			return 0, false
		}
		index = next
	}
	return 0, false
}

// wrapperChildIndex returns the index of the word a prefix wrapper at
// index runs. Every wrapper word must be static; an option that changes
// the directory, splits a string, starts a login or a shell, or is not
// known ends the reading.
func wrapperChildIndex(name string, args []*syntax.Word, index int) (int, bool) {
	value := func(at int) (string, bool) {
		if at >= len(args) {
			return "", false
		}
		word := projectPOSIXWord(args[at])
		return word.Value, !word.Expands
	}
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
				next++
			default:
				return true
			}
		}
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
		known = options([]string{"-i", "-", "--ignore-environment"}, []string{"-u"}, []string{"--unset="}, true)
	case "command":
		known = options([]string{"-p"}, nil, nil, false)
	case "sudo":
		known = options([]string{"-E", "-H", "-n", "-P", "-S", "-b", "-k", "--preserve-env",
			"--set-home", "--non-interactive", "--stdin", "--background"},
			[]string{"-u", "-g", "-p", "-C", "-T", "-h"},
			[]string{"--user=", "--group=", "--prompt=", "--preserve-env=", "--host="}, true)
	case "exec":
		known = options([]string{"-c"}, []string{"-a"}, nil, false)
	}
	if !known || next >= len(args) {
		return 0, false
	}
	return next, true
}

func hasAnyPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) && len(value) > len(prefix) {
			return true
		}
	}
	return false
}
