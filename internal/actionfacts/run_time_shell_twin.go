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
	"errors"
	"io"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// The run-time shell reading is bounded (the one bound rule,
// internal/guardrail/bounded). A program word or text past a bound is
// TRUNCATED: the reading keeps what it read before the cap and reports the
// cap, and the gateway judges the call at the unknown tier of the pack at
// least (rel-1-0-10:GAP-1041).
const (
	// maxRunTimeShellWordDepth bounds the command substitutions nested in
	// one program word, $(which $(which ... sh)): the depth bound of the
	// POSIX analysis (maxPOSIXDepth). The analysis of the call itself stops
	// earlier (15 levels of $(which ...) pass its syntax depth), so such a
	// call is TRUNCATED already; this reading still names the shell up to
	// the bound, and the stricter of the two readings counts.
	maxRunTimeShellWordDepth = maxPOSIXDepth
	// maxRunTimeShellWords bounds the program words one reading expands,
	// its nested texts included: the syntax node bound of the analysis
	// (maxPOSIXNodes).
	maxRunTimeShellWords = maxPOSIXNodes
)

// shellWordReader reads the program words of one run-time shell reading.
// Each word is expanded once: its two expansions (with the shell's own
// parameters unset and set) share the reading of every word nested in it,
// so the cost grows with the word, not twofold per nested substitution
// (rel-1-0-10:GAP-1041).
type shellWordReader struct {
	trunc *bounded.Truncated
	words bounded.Counter
	memo  map[shellWordKey]shellWordValue
}

type shellWordKey struct {
	word        *syntax.Word
	zeroIsShell bool
	lastShell   string
}

type shellWordValue struct {
	shell string
	known bool
}

func newShellWordReader(trunc *bounded.Truncated) *shellWordReader {
	r := &shellWordReader{trunc: trunc, memo: map[shellWordKey]shellWordValue{}}
	r.words = bounded.NewCounter(trunc, bounded.Nodes, maxRunTimeShellWords)
	return r
}

// RunTimeShellWord projects the program word symbolically, using shell-owned
// parameter values and the shell expansion grammar. Quotes, concatenation and
// parameter operators therefore have one reading rather than a list of shapes.
// Unknown program variables stay unknown (GAP-0981), and so does a word past
// the reader's bounds. No command is executed.
func RunTimeShellWord(word *syntax.Word, zeroIsShell bool) (string, bool) {
	var trunc bounded.Truncated
	return newShellWordReader(&trunc).read(word, zeroIsShell, "", 0)
}

// read is the shell a program word names, read once per word. depth is the
// number of command substitutions the word is nested in.
func (r *shellWordReader) read(word *syntax.Word, zeroIsShell bool, lastShell string, depth int) (string, bool) {
	if word == nil {
		return "", false
	}
	key := shellWordKey{word: word, zeroIsShell: zeroIsShell, lastShell: lastShell}
	if value, seen := r.memo[key]; seen {
		return value.shell, value.known
	}
	shell, known := r.expand(word, zeroIsShell, lastShell, depth)
	r.memo[key] = shellWordValue{shell: shell, known: known}
	return shell, known
}

func (r *shellWordReader) expand(word *syntax.Word, zeroIsShell bool, lastShell string, depth int) (string, bool) {
	projected := projectPOSIXWord(word)
	if !projected.Expands && projected.Value != "/proc/self/exe" {
		return "", false
	}
	if !r.words.Take() {
		return "", false
	}
	safe := true
	syntax.Walk(word, func(n syntax.Node) bool {
		switch n.(type) {
		case *syntax.ArithmExp, *syntax.ProcSubst, *syntax.ExtGlob, *syntax.BraceExp:
			safe = false
		}
		return safe
	})
	if !safe {
		return "", false
	}
	// A runtime directory cannot change a final static /shell basename.
	// Flatten quote boundaries, resetting the suffix at every expansion.
	suffix := ""
	var tail func([]syntax.WordPart, bool)
	tail = func(parts []syntax.WordPart, quoted bool) {
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				suffix += unquotePOSIXLiteral(part.Value, quoted)
			case *syntax.SglQuoted:
				if part.Dollar {
					suffix = ""
				} else {
					suffix += part.Value
				}
			case *syntax.DblQuoted:
				tail(part.Parts, true)
			default:
				suffix = ""
			}
		}
	}
	tail(word.Parts, false)
	if strings.Contains(suffix, "/") {
		if name := wrapperProgramName(suffix); wrappedShellPrograms[name] {
			return name, true
		}
	}
	for _, populated := range []bool{false, true} {
		env := []string{"$=1"}
		if populated {
			env = append(env, "SHELL=/bin/bash", "BASH=/bin/bash", "BASH_ARGV0=/bin/bash", "ZSH_NAME=zsh")
			if zeroIsShell {
				env = append(env, "0=/bin/bash")
			}
			if lastShell != "" {
				env = append(env, "_="+lastShell)
			}
		}
		cfg := &expand.Config{Env: expand.ListEnviron(env...)}
		cfg.CmdSubst = func(w io.Writer, sub *syntax.CmdSubst) error {
			// A substitution nested past the bound is not read.
			if !r.trunc.Within(bounded.Depth, depth+1, maxRunTimeShellWordDepth) {
				return errors.New("unread command output")
			}
			shell, valid := "", true
			syntax.Walk(sub, func(n syntax.Node) bool {
				call, ok := n.(*syntax.CallExpr)
				if !ok {
					return true
				}
				if len(call.Args) == 0 || len(call.Assigns) != 0 {
					valid = false
					return false
				}
				program := wrapperProgramName(projectPOSIXWord(call.Args[0]).Value)
				// A stream selector preserves a shell path emitted upstream.
				if program == "head" && shell != "" {
					for _, arg := range call.Args[1:] {
						value := projectPOSIXWord(arg)
						option := strings.TrimLeft(value.Value, "-nc")
						if value.Expands || option != "" && strings.Trim(option, "0123456789") != "" {
							valid = false
						}
					}
					return false
				}
				switch program {
				case "which", "command", "type", "whence", "readlink", "realpath", "echo", "printf":
				default:
					valid = false
					return false
				}
				operands := 0
				lookup := program != "command" && program != "type" && program != "whence"
				for i, arg := range call.Args[1:] {
					value := projectPOSIXWord(arg)
					if !value.Expands && strings.HasPrefix(value.Value, "-") {
						if value.Value == "-V" {
							valid = false
						}
						if strings.ContainsAny(strings.TrimPrefix(value.Value, "-"), "vpP") {
							lookup = true
						}
						continue
					}
					if program == "printf" && i == 0 {
						if value.Expands || value.Value != "%s" && value.Value != "%s\\n" {
							valid = false
						}
						continue
					}
					name := wrapperProgramName(value.Value)
					if value.Expands {
						var known bool
						name, known = r.read(arg, zeroIsShell, lastShell, depth+1)
						if !known {
							valid = false
							continue
						}
					}
					if !wrappedShellPrograms[name] {
						valid = false
						continue
					}
					operands++
					if shell == "" {
						shell = name
					}
				}
				if operands != 1 || !lookup {
					valid = false
				}
				return false
			})
			if !valid || shell == "" {
				return errors.New("unknown command output")
			}
			_, err := io.WriteString(w, shell)
			return err
		}
		value, err := expand.Literal(cfg, word)
		if err != nil {
			continue
		}
		if value == "/proc/self/exe" || value == "/proc/1/exe" {
			return "bash", true
		}
		name := wrapperProgramName(value)
		if wrappedShellPrograms[name] {
			return name, true
		}
	}
	return "", false
}

// RunTimeShellTwin adds the literal-shell reading of every shell script
// source: a -c argument, static stdin, or a child command exposed by the
// existing wrapper and script readers. Program words use symbolic shell
// expansion, independent of their quote or parameter-operator shape.
// Generic runtime programs retain their unknown operand roles (GAP-0981).
// The gateway judges this reading beside the original and keeps the strictest
// verdict; the hook client resolves its targets using the same reading.
// truncated is the caps the reading hit (the one bound rule): such a call is
// TRUNCATED, and what the twin read before the cap is still judged.
func RunTimeShellTwin(command string) (twin string, ok bool, truncated bounded.CapSet) {
	var trunc bounded.Truncated
	reader := newShellWordReader(&trunc)
	twin, ok = runTimeShellTwin(command, 0, true, reader)
	return twin, ok, trunc.Set(&reader.words)
}

func runTimeShellTwin(command string, depth int, zeroIsShell bool, reader *shellWordReader) (twin string, ok bool) {
	defer func() {
		if recover() != nil {
			twin, ok = "", false
		}
	}()

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
	owners := map[*syntax.CallExpr]*syntax.Stmt{}
	inputs := map[*syntax.CallExpr]*syntax.Word{}
	syntax.Walk(file, func(node syntax.Node) bool {
		if stmt, ok := node.(*syntax.Stmt); ok {
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
				owners[call] = stmt
			}
		}
		if pipe, ok := node.(*syntax.BinaryCmd); ok && pipe.Op == syntax.Pipe {
			if call, ok := pipe.Y.Cmd.(*syntax.CallExpr); ok {
				inputs[call] = simpleEchoWord(pipe.X)
			}
		}
		return true
	})
	priorIndex, lastShell := 0, ""
	var visit func(syntax.Node) bool
	visit = func(node syntax.Node) bool {
		call, isCall := node.(*syntax.CallExpr)
		if !isCall {
			return true
		}
		if len(call.Args) == 0 {
			return true
		}
		// Advance once through preceding top-level calls for $_. Child
		// readers retain the same preceding context without a quadratic walk.
		for priorIndex < len(file.Stmts) && file.Stmts[priorIndex].End().Offset() < call.Pos().Offset() {
			prior, ok := file.Stmts[priorIndex].Cmd.(*syntax.CallExpr)
			priorIndex++
			if !ok || len(prior.Args) == 0 {
				continue
			}
			lastShell = ""
			last := projectPOSIXWord(prior.Args[len(prior.Args)-1])
			if !last.Expands && wrappedShellPrograms[wrapperProgramName(last.Value)] {
				lastShell = wrapperProgramName(last.Value)
			}
		}
		at, shell, found := shellCallProgram(reader, call.Args, zeroIsShell, lastShell)
		program := wrapperProgramName(projectPOSIXWord(call.Args[at]).Value)
		if program == "eval" {
			body, _, nested, static := simpleNestedScript(&syntax.CallExpr{Args: call.Args[at:]}, nil, nil, nil)
			if nested && static && depth < maxNestedShellStrings {
				if twin, changed := runTimeShellTwin(body, depth+1, zeroIsShell, reader); changed {
					start, end := int(call.Args[at].Pos().Offset()), int(call.End().Offset())
					edits = append(edits, edit{start, end, "eval " + posixSingleQuoted(twin)})
					return false
				}
			}
		}
		if program == "find" || program == "gfind" {
			argv := make([]string, len(call.Args)-at)
			for i, arg := range call.Args[at:] {
				argv[i] = projectPOSIXWord(arg).Value
			}
			for _, child := range findEmbeddedPrograms(argv) {
				if len(child.parent) == 0 {
					continue
				}
				start := at + child.parent[0]
				end := start + len(child.whole)
				if end <= len(call.Args) {
					visit(&syntax.CallExpr{Args: call.Args[start:end]})
				}
			}
			return true
		}
		if !found {
			return true
		}
		// Every shell script source is read through the same -c text parser.
		// A redirect supersedes pipeline stdin; opaque input is never invented.
		argv := []string{"bash"}
		staticArgs := true
		for _, arg := range call.Args[at+1:] {
			value := projectPOSIXWord(arg)
			if value.Expands {
				staticArgs = false
				break
			}
			argv = append(argv, value.Value)
		}
		invocation := parsePOSIXShellInvocation("bash", argv)
		if staticArgs && invocation.valid && !invocation.noExec && invocation.mode == posixShellModeStdin {
			bodyWord := inputs[call]
			body, known := "", false
			if bodyWord != nil {
				body, known = simpleStaticScriptWord(bodyWord, nil)
			}
			if stmt := owners[call]; stmt != nil {
				for _, redir := range stmt.Redirs {
					if redir.N != nil && redir.N.Value != "0" {
						continue
					}
					switch redir.Op {
					case syntax.WordHdoc:
						body, known = simpleStaticScriptWord(redir.Word, nil)
					case syntax.Hdoc, syntax.DashHdoc:
						body, known = literalPOSIXHeredocBody(redir.Hdoc)
					case syntax.RdrIn, syntax.RdrInOut, syntax.DplIn:
						body, known = "", false
					}
				}
			}
			if known {
				if depth < maxNestedShellStrings {
					if nested, changed := runTimeShellTwin(body, depth+1, true, reader); changed {
						body = nested
					}
				}
				edits = append(edits, edit{int(call.Args[at].Pos().Offset()), int(call.End().Offset()), "bash -c " + posixSingleQuoted(body)})
				return false
			}
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
		if body, changed := runTimeShellTwin(value.Value, depth+1, text+1 >= len(call.Args) || wrappedShellPrograms[wrapperProgramName(projectPOSIXWord(call.Args[text+1]).Value)], reader); changed && body != value.Value {
			replace(call.Args[text], posixSingleQuoted(body))
		}
		return true
	}
	syntax.Walk(file, visit)
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
func shellCallProgram(reader *shellWordReader, args []*syntax.Word, zeroIsShell bool, lastShell string) (int, string, bool) {
	// A wrapper reads the shell named at run time as the shell it names,
	// so its options end where they end before the literal shell.
	value := func(at int) (string, bool) {
		if at >= len(args) {
			return "", false
		}
		if shell, named := reader.read(args[at], zeroIsShell, lastShell, 0); named {
			return shell, true
		}
		word := projectPOSIXWord(args[at])
		return word.Value, !word.Expands
	}
	var run PrefixWrapperRun
	index := 0
	for depth := 0; index < len(args) && depth < MaxPrefixWrapperChain; depth++ {
		if shell, named := reader.read(args[index], zeroIsShell, lastShell, 0); named {
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
		if name == "xargs" {
			argv := make([]string, len(args)-index)
			for i := range argv {
				argv[i], _ = value(index + i)
			}
			if start, _, known := XargsProgram(argv); known && start > 0 {
				index += start
				continue
			}
			return 0, "", false
		}
		next, known := wrapperChildIndex(name, value, len(args), index, &run)
		if !known {
			return index, "", false
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
