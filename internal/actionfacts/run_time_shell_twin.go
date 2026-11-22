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
	// unread is set when a POSIX shell of the call (its nested texts
	// included) runs here-document or here-string text the reading cannot
	// know (rel-1-0-10:GAP-1147).
	unread bool
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
// TRUNCATED, and what the twin read before the cap is still judged. unread
// reports a shell that runs here-document or here-string text the reading
// cannot know (a body with a command substitution, a document reached
// through a command or a descriptor the reading does not follow): the
// gateway judges such a call at the unknown tier of the pack at least, with
// or without a twin (rel-1-0-10:GAP-1147).
func RunTimeShellTwin(command string) (twin string, ok bool, truncated bounded.CapSet, unread bool) {
	var trunc bounded.Truncated
	reader := newShellWordReader(&trunc)
	twin, ok = runTimeShellTwin(command, 0, true, reader)
	return twin, ok, trunc.Set(&reader.words), reader.unread
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
	// inputs is the text each stage of a pipeline reads from the stage
	// before it, when the reading knows it (pipeStageOutput); the first
	// command of a subshell or group stage reads it too. fed marks the
	// commands of a stage after one that holds here-document or here-string
	// text (rel-1-0-10:GAP-1147).
	inputs := map[*syntax.CallExpr]stageText{}
	fed := map[*syntax.CallExpr]bool{}
	flattened := map[*syntax.BinaryCmd]bool{}
	fileHereText := holdsHereText(file)
	// The holding shell has already evaluated assignments outside the document.
	// A receiving shell cannot be assumed to inherit their values.
	outerBound := map[string]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.Assign:
			if n.Name != nil {
				outerBound[n.Name.Value] = true
			}
		case *syntax.CallExpr:
			for _, arg := range n.Args {
				if value, static := simpleStaticWord(arg, nil); static {
					if name, _, assigned := strings.Cut(value, "="); assigned && simpleVariableName(name) {
						outerBound[name] = true
					}
				}
			}
		}
		return true
	})
	syntax.Walk(file, func(node syntax.Node) bool {
		if stmt, ok := node.(*syntax.Stmt); ok {
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
				owners[call] = stmt
			}
		}
		if pipe, ok := node.(*syntax.BinaryCmd); ok && pipelineOp(pipe.Op) && !flattened[pipe] {
			stages := pipelineStages(pipe, flattened)
			in, hereText := stageText{}, false
			for _, stage := range stages {
				if call := stageFirstCall(stage, 0); call != nil && in.known {
					inputs[call] = in
				}
				if hereText {
					syntax.Walk(stage, func(node syntax.Node) bool {
						if call, ok := node.(*syntax.CallExpr); ok {
							fed[call] = true
						}
						return true
					})
				}
				in.text, in.known = pipeStageOutput(stage, in, 0)
				in.parameters = in.parameters || heredocStageHasParameters(stage)
				hereText = hereText || holdsHereText(stage)
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
		// eval "$(cat <<EOF ... EOF)", source <(cat <<EOF ... EOF) and a shell
		// whose script file is such a process substitution run the text the
		// here-document carries (rel-1-0-10:GAP-1137, GAP-0788).
		script, known, sourced := substitutedScript(call.Args[at:], program, found)
		if known && depth < maxNestedShellStrings {
			if nested, changed := runTimeShellTwin(script, depth+1, true, reader); changed {
				script = nested
			}
			start, end := int(call.Args[at].Pos().Offset()), int(call.End().Offset())
			edits = append(edits, edit{start, end, "bash -c " + posixSingleQuoted(script)})
			return false
		}
		if !known && (sourced || program == "eval" && len(call.Args)-at == 2) && holdsHereText(call.Args[at+1]) {
			// source <(cat <<EOF ... EOF), sh <(...) or eval "$(cat <<EOF
			// ... EOF)" of a document the reading cannot know
			// (rel-1-0-10:GAP-1147, GAP-1193).
			reader.unread = true
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
			// hereText: the script comes from here-document or here-string
			// text, which the reading reads or reports as unread
			// (rel-1-0-10:GAP-1147).
			body, known, hereText := inputs[call].text, inputs[call].known, fed[call]
			// source is the here-string or here-document that supplied the
			// script: the twin hands that text to -c instead, so it is not
			// stdin of the twin any more and is left out of it (GAP-1088).
			// Kept, the twin would be judged as a stdin script call again,
			// which re-derives every reading of the call it was made from.
			var source *syntax.Redirect
			if stmt := owners[call]; stmt != nil {
				for _, redir := range stmt.Redirs {
					if redir.N != nil && redir.N.Value != "0" {
						continue
					}
					switch redir.Op {
					case syntax.WordHdoc:
						body, known = hereStringText(redir.Word)
						hereText = holdsHereText(redir.Word)
						source = redir
					case syntax.Hdoc, syntax.DashHdoc:
						body, known = heredocScriptText(redir)
						if known && heredocHasParameters(redir) &&
							(!heredocReadingShellKnown(program, shell) || heredocTextMentionsBoundName(body, outerBound) ||
								strings.Contains(command, "\\\n")) {
							known = false
						}
						hereText = true
						source = redir
					case syntax.RdrIn:
						// sh < <(cat <<EOF ... EOF) reads what the process
						// substitution writes.
						body, known = procSubstOutput(redir.Word)
						hereText = holdsHereText(redir.Word)
						// The text it writes is the -c STRING of the twin, so
						// the redirect is left out of it as a here-document
						// is: kept, the twin judged the same here-document
						// again as a child of its own, 10 dispatches per
						// hook call where the call alone takes 2
						// (rel-1-0-10:GAP-1593).
						source = nil
						if known {
							source = redir
						}
					case syntax.DplIn:
						// bash <&3 after exec 3<<EOF: the reading does not
						// follow descriptors.
						body, known, source = "", false, nil
						hereText = fileHereText
					case syntax.RdrInOut:
						body, known, hereText, source = "", false, false, nil
					}
				}
				if source != nil && stdinRedirectCount(stmt) != 1 {
					source = nil
				}
			}
			if known && inputs[call].parameters &&
				(!heredocReadingShellKnown(program, shell) || heredocTextMentionsBoundName(body, outerBound) ||
					strings.Contains(command, "\\\n")) {
				known = false
			}
			if !known && hereText {
				reader.unread = true
			}
			if known {
				if depth < maxNestedShellStrings {
					if nested, changed := runTimeShellTwin(body, depth+1, true, reader); changed {
						body = nested
					}
				}
				edits = append(edits, edit{int(call.Args[at].Pos().Offset()), int(call.End().Offset()), "bash -c " + posixSingleQuoted(body)})
				if source != nil {
					if start, end, ok := stdinSourceSpan(command, source); ok {
						edits = append(edits, edit{start: start, end: end, text: ""})
					}
				}
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
			// -c "$(cat <<EOF ... EOF)": the STRING is what the substitution
			// writes (rel-1-0-10:GAP-1137).
			if script, known := substitutionOutput(call.Args[text]); known {
				if nested, changed := runTimeShellTwin(script, depth+1, true, reader); changed {
					script = nested
				}
				replace(call.Args[text], posixSingleQuoted(script))
			} else if holdsHereText(call.Args[text]) {
				// A STRING of here-document text the reading cannot know
				// (rel-1-0-10:GAP-1147, GAP-1193).
				reader.unread = true
			}
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
	for index < len(args) && run.ReadsMore() {
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

// stageText is the text one pipeline stage reads or writes, when it is known.
type stageText struct {
	text       string
	known      bool
	parameters bool
}

// maxStageNesting bounds the subshells, groups and pipelines nested in one
// stage that pipeStageOutput reads: the depth bound of the POSIX analysis.
const maxStageNesting = maxPOSIXDepth

func pipelineOp(op syntax.BinCmdOperator) bool { return op == syntax.Pipe || op == syntax.PipeAll }

// pipelineStages returns the stages of the pipeline pipe heads, in order,
// whatever way the parse nests them, and marks every pipe of it as read.
func pipelineStages(pipe *syntax.BinaryCmd, flattened map[*syntax.BinaryCmd]bool) []*syntax.Stmt {
	flattened[pipe] = true
	var stages []*syntax.Stmt
	for _, side := range []*syntax.Stmt{pipe.X, pipe.Y} {
		if inner, ok := side.Cmd.(*syntax.BinaryCmd); ok && pipelineOp(inner.Op) &&
			len(side.Redirs) == 0 && !side.Negated && !side.Background {
			stages = append(stages, pipelineStages(inner, flattened)...)
			continue
		}
		stages = append(stages, side)
	}
	return stages
}

// pipeStageOutput returns the text a pipeline stage writes to its standard
// output when the reading can know it, given the text in that it reads: a
// static echo or printf word, or a cat or tee that passes on what it reads,
// a literal here-document or here-string of its own or the known text of
// the stage before it; also inside a subshell, a group or a nested pipeline.
// A shell that reads that text runs it as its script (rel-1-0-10:GAP-1137,
// GAP-0788: cat <<EOF | sh, tee f <<EOF | sh, ( cat <<EOF ) | sh). A stage
// that writes anything else, or sends its standard output elsewhere, has no
// known output, and nothing is invented for it.
func pipeStageOutput(stmt *syntax.Stmt, in stageText, depth int) (string, bool) {
	if stmt == nil || stmt.Negated || stmt.Background || stmt.Cmd == nil || depth > maxStageNesting {
		return "", false
	}
	if word := simpleEchoWord(stmt); word != nil {
		// echo and printf '%s\n' end what they write with a newline, so the
		// next statement of a group starts a line of its own
		// (rel-1-0-10:GAP-1146).
		text, known := simpleStaticScriptWord(word, nil)
		return text + echoLineEnd(stmt), known
	}
	for _, redir := range stmt.Redirs {
		fd := ""
		if redir.N != nil {
			fd = redir.N.Value
		}
		switch redir.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			if fd == "" || fd == "0" {
				in.text, in.known = heredocScriptText(redir)
			}
		case syntax.WordHdoc:
			if fd == "" || fd == "0" {
				in.text, in.known = hereStringText(redir.Word)
				in.text += "\n"
			}
		case syntax.RdrIn, syntax.RdrInOut, syntax.DplIn:
			if fd == "" || fd == "0" {
				in = stageText{}
			}
		case syntax.RdrAll, syntax.AppAll:
			return "", false
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.DplOut:
			if fd == "" || fd == "1" {
				return "", false
			}
		}
	}
	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if len(cmd.Args) == 0 {
			return "", false
		}
		program, static := simpleStaticWord(cmd.Args[0], nil)
		if !static {
			return "", false
		}
		switch wrapperProgramName(program) {
		case "cat":
			// cat with no operand, or only - (standard input) and -u, passes
			// its input on unchanged; any other option or a file changes it.
			stdin := 0
			for _, arg := range cmd.Args[1:] {
				word, static := simpleStaticWord(arg, nil)
				switch {
				case !static:
					return "", false
				case word == "-":
					stdin++
				case word == "-u" || word == "--":
				default:
					return "", false
				}
			}
			if stdin > 1 {
				return "", false
			}
			return in.text, in.known
		case "tee":
			// tee writes what it reads to standard output too; its file
			// operands are writes the call is judged on as written.
			return in.text, in.known
		}
		return "", false
	case *syntax.Subshell:
		return stmtsOutput(cmd.Stmts, in, depth+1)
	case *syntax.Block:
		return stmtsOutput(cmd.Stmts, in, depth+1)
	case *syntax.BinaryCmd:
		if !pipelineOp(cmd.Op) {
			return "", false
		}
		mid, known := pipeStageOutput(cmd.X, in, depth+1)
		return pipeStageOutput(cmd.Y, stageText{text: mid, known: known}, depth+1)
	}
	return "", false
}

// stmtsOutput is the output of a list of statements run in order: what each
// writes, joined. The first one may read the input of the list; a later one
// reads what the first left of it, which the reading does not know.
func stmtsOutput(stmts []*syntax.Stmt, in stageText, depth int) (string, bool) {
	if len(stmts) == 0 {
		return "", false
	}
	var out strings.Builder
	for index, stmt := range stmts {
		if index > 0 {
			in = stageText{}
		}
		text, known := pipeStageOutput(stmt, in, depth)
		if !known {
			return "", false
		}
		out.WriteString(text)
	}
	return out.String(), true
}

// substitutionOutput returns what a word that is one command substitution,
// quoted ("$(cat <<EOF ... EOF)") or not, expands to when the reading knows
// what its statements write. The shell strips the trailing newlines.
func substitutionOutput(word *syntax.Word) (string, bool) {
	if word == nil || len(word.Parts) != 1 {
		return "", false
	}
	part := word.Parts[0]
	if quoted, ok := part.(*syntax.DblQuoted); ok {
		if quoted.Dollar || len(quoted.Parts) != 1 {
			return "", false
		}
		part = quoted.Parts[0]
	}
	sub, ok := part.(*syntax.CmdSubst)
	if !ok || sub.Backquotes || sub.TempFile || sub.ReplyVar {
		return "", false
	}
	text, known := stmtsOutput(sub.Stmts, stageText{}, 0)
	return strings.TrimRight(text, "\n"), known
}

// substitutedScript returns the script a call runs from a substitution whose
// output the reading knows: eval "$(...)" (one operand), source <(...) or
// . <(...), and a POSIX shell (shell: found by shellCallProgram) whose only
// operand is a process substitution, its script file. sourced reports a call
// of the last two shapes, whose script is its one operand.
func substitutedScript(args []*syntax.Word, program string, shell bool) (script string, known, sourced bool) {
	if len(args) != 2 {
		return "", false, false
	}
	switch {
	case program == "eval":
		script, known = substitutionOutput(args[1])
		return script, known, false
	case program == "source" || program == ".", shell && wrappedShellPrograms[program]:
		script, known = procSubstOutput(args[1])
		return script, known, true
	}
	return "", false, false
}

// procSubstOutput returns what a word that is one input process
// substitution, <(...), writes when the reading knows it.
func procSubstOutput(word *syntax.Word) (string, bool) {
	if word == nil || len(word.Parts) != 1 {
		return "", false
	}
	sub, ok := word.Parts[0].(*syntax.ProcSubst)
	if !ok || sub.Op != syntax.CmdIn {
		return "", false
	}
	return stmtsOutput(sub.Stmts, stageText{}, 0)
}

// hereStringText is the text of a here-string word: a static word, or one
// command substitution whose output the reading knows
// (bash <<< "$(cat <<EOF ... EOF)"). The shell adds the line end.
func hereStringText(word *syntax.Word) (string, bool) {
	if text, known := simpleStaticScriptWord(word, nil); known {
		return text, true
	}
	return substitutionOutput(word)
}

// echoLineEnd is the line end a stage simpleEchoWord reads writes after its
// word: echo and printf '%s\n' write one, printf '%s' none.
func echoLineEnd(stmt *syntax.Stmt) string {
	call := stmt.Cmd.(*syntax.CallExpr)
	if program, _ := simpleStaticWord(call.Args[0], nil); program == "printf" {
		if format, _ := simpleStaticWord(call.Args[1], nil); format == "%s" {
			return ""
		}
	}
	return "\n"
}

// stageFirstCall is the command of a pipeline stage that reads its input
// first: the stage itself, or the first command of a subshell or group stage
// (cat <<EOF | (sh), cat <<EOF | { bash; }).
func stageFirstCall(stmt *syntax.Stmt, depth int) *syntax.CallExpr {
	if stmt == nil || depth > maxStageNesting {
		return nil
	}
	var stmts []*syntax.Stmt
	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		return cmd
	case *syntax.Subshell:
		stmts = cmd.Stmts
	case *syntax.Block:
		stmts = cmd.Stmts
	}
	if len(stmts) == 0 || len(stmt.Redirs) != 0 {
		return nil
	}
	return stageFirstCall(stmts[0], depth+1)
}

// holdsHereText reports a node that holds a here-document or a here-string
// anywhere in it, also in a substitution (rel-1-0-10:GAP-1147).
func holdsHereText(node syntax.Node) bool {
	if node == nil {
		return false
	}
	found := false
	syntax.Walk(node, func(node syntax.Node) bool {
		if redir, ok := node.(*syntax.Redirect); ok {
			switch redir.Op {
			case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
				found = true
			}
		}
		return !found
	})
	return found
}

// heredocScriptText is the text of a here-document body as the shell that
// runs it reads it: the literal body of a quoted delimiter, or, for an
// unquoted delimiter whose body expands only parameters
// (posixHeredocBodyRunsNothing), the body with the backslash escapes the
// holding shell undoes (\$, \`, \\ and a backslash line end;
// rel-1-0-10:GAP-1148) undone and its parameters as written. The holding
// shell expands those parameters before the shell that runs the text parses
// it, so the text as written is that script only where the running shell
// expands each parameter the same way (heredocParamsExpandAsWritten): rm -rf
// $HOME/* is the same delete in both. A body that runs a command
// substitution or arithmetic, or whose parameters the running shell would
// read otherwise (inside single quotes, after an escaped backslash, a name
// the body binds, a positional or special parameter; rel-1-0-10:GAP-1193),
// is not known: a shell that runs it is unread (rel-1-0-10:GAP-1147).
func heredocScriptText(redir *syntax.Redirect) (string, bool) {
	body := redir.Hdoc
	if posixHeredocDelimiterQuoted(redir.Word) {
		return literalPOSIXHeredocBody(body)
	}
	if body == nil || !posixHeredocBodyRunsNothing(body) {
		return "", false
	}
	var out strings.Builder
	params := map[int]int{}
	names := map[string]bool{}
	printer := syntax.NewPrinter()
	for _, part := range body.Parts {
		switch typed := part.(type) {
		case *syntax.Lit:
			out.WriteString(unescapeHeredocLiteral(typed.Value))
			continue
		case *syntax.ParamExp:
			if !heredocParamNames(typed, names) {
				return "", false
			}
			start := out.Len()
			if err := printer.Print(&out, &syntax.Word{Parts: []syntax.WordPart{part}}); err != nil {
				return "", false
			}
			params[start] = out.Len()
			continue
		default:
			return "", false
		}
	}
	text := out.String()
	if len(params) != 0 && !heredocParamsExpandAsWritten(text, params, names) {
		return "", false
	}
	return text, true
}

func heredocWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

// heredocParamNames adds to names every parameter a parameter expansion of an
// unquoted here-document body reads, and reports whether each is a variable
// both shells hold alike: a positional or special parameter ($1, $@, $?, $$,
// $0, ...) is the holding shell's own, and ${NAME=word} or ${NAME:=word}
// assigns it there (rel-1-0-10:GAP-1193).
func heredocParamNames(param *syntax.ParamExp, names map[string]bool) bool {
	if param.Param == nil || !simpleVariableName(param.Param.Value) ||
		param.Excl || param.Index != nil || param.Slice != nil || param.Repl != nil ||
		param.Names != 0 || param.Width || param.IsSet || param.Flags != nil ||
		len(param.Modifiers) != 0 || param.NestedParam != nil || param.Exp != nil {
		return false
	}
	name := param.Param.Value
	if heredocShellOwnedName(name) {
		return false
	}
	names[name] = true
	return true
}

func heredocReadingShellKnown(program, resolved string) bool {
	if resolved != "" {
		return resolved == "bash" || resolved == "sh"
	}
	return program == "bash" || program == "sh"
}

func heredocHasParameters(redir *syntax.Redirect) bool {
	if redir == nil || redir.Hdoc == nil || posixHeredocDelimiterQuoted(redir.Word) {
		return false
	}
	for _, part := range redir.Hdoc.Parts {
		if _, ok := part.(*syntax.ParamExp); ok {
			return true
		}
	}
	return false
}

func heredocStageHasParameters(stage *syntax.Stmt) bool {
	found := false
	syntax.Walk(stage, func(node syntax.Node) bool {
		if redir, ok := node.(*syntax.Redirect); ok && heredocHasParameters(redir) {
			found = true
		}
		return !found
	})
	return found
}

func heredocTextMentionsBoundName(text string, bound map[string]bool) bool {
	for name := range bound {
		if strings.Contains(text, "${"+name+"}") || strings.Contains(text, "${#"+name+"}") {
			return true
		}
		bare := "$" + name
		for from := 0; from < len(text); {
			at := strings.Index(text[from:], bare)
			if at < 0 {
				break
			}
			end := from + at + len(bare)
			if end == len(text) || !heredocWordByte(text[end]) {
				return true
			}
			from = end
		}
	}
	return false
}

// These values are initialized or changed independently by each shell.
func heredocShellOwnedName(name string) bool {
	// A named coprocess can also be started by the holding shell before the
	// here-document. Bash does not export its generated NAME_PID value to the
	// receiving shell, so no NAME_PID expansion is provably shared.
	if strings.HasSuffix(name, "_PID") {
		return true
	}
	switch name {
	case "_", "PWD", "OLDPWD", "SHLVL", "LINENO", "RANDOM", "SRANDOM", "SECONDS",
		"PPID", "BASHPID", "UID", "EUID", "GROUPS", "HOSTNAME", "HOSTTYPE",
		"OSTYPE", "MACHTYPE", "SHELLOPTS", "BASHOPTS", "PIPESTATUS", "OPTIND",
		"OPTARG", "REPLY", "MAPFILE", "COPROC", "DIRSTACK", "IFS":
		return true
	}
	for _, prefix := range []string{"PS", "HIST", "OPT", "BASH_", "EPOCH", "COMP_", "ZSH_", "KSH_"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// heredocParamsExpandAsWritten reports a here-document text, its parameters
// printed as written at the offsets at, that the shell running it reads as
// the holding shell left it: each of those parameters is a parameter
// expansion of the running shell too (not inside single quotes or after an
// escaping backslash), or sits in a comment, and the text binds none of the
// names they read (NAME=, for NAME, read NAME, ((NAME++)), ...), which the
// holding shell expands before the text runs (rel-1-0-10:GAP-1193).
func heredocParamsExpandAsWritten(text string, at map[int]int, names map[string]bool) bool {
	file, ok := shellparse.ParseWithComments(text)
	if !ok {
		return false
	}
	expanded := map[int]int{}
	var comments [][2]int
	bound := false
	bind := func(name string) {
		// An indexed destination (printf -v NAME[i], read NAME[i]) binds
		// NAME, and its subscript is arithmetic that can bind any name.
		if names[name] || strings.Contains(name, "[") {
			bound = true
		}
	}
	bindAll := func() { bound = true }
	syntax.Walk(file, func(node syntax.Node) bool {
		switch typed := node.(type) {
		case *syntax.ParamExp:
			expanded[int(typed.Pos().Offset())] = int(typed.End().Offset())
			if typed.Param != nil && typed.Exp != nil &&
				(typed.Exp.Op == syntax.AssignUnset || typed.Exp.Op == syntax.AssignUnsetOrNull) {
				bind(typed.Param.Value)
			}
		case *syntax.Comment:
			comments = append(comments, [2]int{int(typed.Pos().Offset()), int(typed.End().Offset())})
		case *syntax.Assign:
			if typed.Name != nil {
				bind(typed.Name.Value)
			}
		case *syntax.DeclClause:
			// A declaration can carry a dynamic option or a name reference.
			bindAll()
		case *syntax.LetClause:
			bindAll()
		case *syntax.TestClause:
			// Arithmetic in [[ ]] can bind a name while testing it. A string,
			// file or pattern test binds nothing (=~ sets BASH_REMATCH, a
			// name each shell keeps for itself: heredocShellOwnedName).
			if heredocTestMayAssign(typed.X) {
				bindAll()
			}
		case *syntax.CoprocClause:
			// Bash creates both an array of descriptors and a PID variable.
			// An unnamed coprocess uses COPROC and COPROC_PID. The holding
			// shell expands these before the receiving shell runs this body.
			if typed.Name == nil {
				bind("COPROC")
				bind("COPROC_PID")
			} else if name, known := simpleStaticWord(typed.Name, nil); known && simpleVariableName(name) {
				bind(name)
				bind(name + "_PID")
			} else {
				bindAll()
			}
		case *syntax.Redirect:
			if typed.N != nil {
				bind(strings.Trim(typed.N.Value, "{}"))
			}
		case *syntax.ForClause:
			if iter, ok := typed.Loop.(*syntax.WordIter); ok && iter.Name != nil {
				bind(iter.Name.Value)
			}
		case *syntax.BinaryArithm:
			if heredocArithmAssigns(typed.Op) {
				if name := arithmWordName(typed.X); name != "" {
					bind(name)
				} else {
					bindAll()
				}
			}
		case *syntax.UnaryArithm:
			if typed.Op == syntax.Inc || typed.Op == syntax.Dec {
				if name := arithmWordName(typed.X); name != "" {
					bind(name)
				} else {
					bindAll()
				}
			}
		case *syntax.CallExpr:
			heredocCallBinds(typed, bind, bindAll)
		}
		return !bound
	})
	if bound {
		return false
	}
	for offset, end := range at {
		if end < len(text) && (text[end] == '{' || text[end] == '[' ||
			text[end] == '_' || text[end] >= '0' && text[end] <= '9' ||
			text[end] >= 'A' && text[end] <= 'Z' || text[end] >= 'a' && text[end] <= 'z') {
			return false
		}
		if expanded[offset] == end {
			continue
		}
		inComment := false
		for _, span := range comments {
			if offset > span[0] && offset < span[1] {
				inComment = true
				break
			}
		}
		if !inComment {
			return false
		}
	}
	return true
}

// heredocTestMayAssign reports a [[ ]] expression with an arithmetic
// comparison (-eq, -ne, -lt, -le, -gt, -ge) whose operand may assign a name
// when the shell evaluates it: anything but a decimal number, a length
// expansion or a special parameter ($#, $?, $$, $!) that always expands to
// one. A word that spells an assignment ([[ D=1 ]]) keeps the reading of
// review round c (row A01): the test is not read as proof that it binds
// nothing.
func heredocTestMayAssign(expr syntax.TestExpr) bool {
	assigns := false
	syntax.Walk(expr, func(node syntax.Node) bool {
		if word, isWord := node.(*syntax.Word); isWord && strings.Contains(word.Lit(), "=") {
			assigns = true
		}
		test, isBinary := node.(*syntax.BinaryTest)
		if !isBinary || assigns {
			return !assigns
		}
		switch test.Op {
		case syntax.TsEql, syntax.TsNeq, syntax.TsLeq, syntax.TsGeq, syntax.TsLss, syntax.TsGtr:
			assigns = !heredocNumericOperand(test.X) || !heredocNumericOperand(test.Y)
		}
		return !assigns
	})
	return assigns
}

func heredocNumericOperand(expr syntax.TestExpr) bool {
	word, isWord := expr.(*syntax.Word)
	if !isWord || len(word.Parts) != 1 {
		return false
	}
	if text, static := simpleStaticWord(word, nil); static {
		digits := strings.TrimPrefix(text, "-")
		return digits != "" && strings.Trim(digits, "0123456789") == ""
	}
	param, isParam := word.Parts[0].(*syntax.ParamExp)
	if !isParam || param.Param == nil || param.Exp != nil || param.Repl != nil || param.Slice != nil {
		return false
	}
	if param.Length {
		return true
	}
	switch param.Param.Value {
	case "#", "?", "$", "!":
		return param.Index == nil && !param.Excl
	}
	return false
}

// heredocArithmAssigns reports an arithmetic operator that assigns its left
// operand.
func heredocArithmAssigns(op syntax.BinAritOperator) bool {
	switch op {
	case syntax.Assgn, syntax.AddAssgn, syntax.SubAssgn, syntax.MulAssgn, syntax.QuoAssgn,
		syntax.RemAssgn, syntax.AndAssgn, syntax.OrAssgn, syntax.XorAssgn, syntax.ShlAssgn,
		syntax.ShrAssgn, syntax.AndBoolAssgn, syntax.OrBoolAssgn, syntax.XorBoolAssgn, syntax.PowAssgn:
		return true
	}
	return false
}

// arithmWordName is the variable an arithmetic operand names, including an
// indexed assignment such as NAME[0]=value.
func arithmWordName(expr syntax.ArithmExpr) string {
	word, ok := expr.(*syntax.Word)
	if !ok || len(word.Parts) != 1 {
		return ""
	}
	if lit, ok := word.Parts[0].(*syntax.Lit); ok {
		name, _, _ := strings.Cut(lit.Value, "[")
		if simpleVariableName(name) {
			return name
		}
	}
	return ""
}

// heredocCallBinds marks names that a command can change in the receiving
// shell. A static command outside the proven non-binding set can change any
// name, including through a builtin, alias or shell function.
func heredocCallBinds(call *syntax.CallExpr, bind func(string), bindAll func()) {
	if len(call.Args) == 0 {
		return
	}
	program, static := simpleStaticWord(call.Args[0], nil)
	if !static {
		// A computed command with no fixed path may name a builtin or
		// function that changes any variable.
		if !strings.Contains(call.Args[0].Lit(), "/") {
			bindAll()
		}
		return
	}
	switch program {
	case "cd", "pushd", "popd":
		bind("PWD")
	case "read", "getopts", "mapfile", "readarray", "unset", "wait":
		if program == "mapfile" || program == "readarray" {
			for _, arg := range call.Args[1:] {
				if word, known := simpleStaticWord(arg, nil); !known || strings.HasPrefix(word, "-") && strings.ContainsRune(word, 'C') {
					// A callback (-C) runs code that can bind any name.
					bindAll()
					return
				}
			}
		}
		for _, arg := range call.Args[1:] {
			name, known := simpleStaticWord(arg, nil)
			if !known {
				bindAll()
				continue
			}
			bind(name)
			// An option can carry its destination in the same word.
			if len(name) > 2 && name[0] == '-' {
				for i := 2; i < len(name); i++ {
					bind(name[i:])
				}
			}
		}
	case "printf":
		for index := 1; index < len(call.Args); index++ {
			flag, known := simpleStaticWord(call.Args[index], nil)
			if !known {
				// Before the format, this could expand to -v.
				bindAll()
				break
			}
			switch {
			case flag == "-v" && index+1 < len(call.Args):
				if name, known := simpleStaticWord(call.Args[index+1], nil); known {
					bind(name)
				} else {
					bindAll()
				}
				index++
			case strings.HasPrefix(flag, "-v") && len(flag) > 2:
				bind(flag[2:])
			case strings.HasPrefix(flag, "-"):
				continue
			default:
				// Arguments after the format are data, not options.
				return
			}
		}
	case ":", "true", "false", "echo", "test", "[", "[[", "pwd", "times",
		"type", "hash", "umask", "ulimit", "jobs", "dirs",
		"rm", "ls", "cat", "tee", "make", "grep", "sed", "git", "curl",
		"chmod", "sleep", "date", "jq", "mysql", "python3", "ssh",
		"sh", "bash", "zsh", "env", "sudo":
		// These commands do not assign a parameter in the calling shell.
	default:
		bindAll()
	}
}

// unescapeHeredocLiteral undoes the escapes of the literal text of an
// unquoted here-document body: a backslash before $, a backquote or another
// backslash is dropped, a backslash line end joins the lines, and any other
// backslash stays (posixHeredocLiteralEscapes).
func unescapeHeredocLiteral(text string) string {
	if !strings.Contains(text, "\\") {
		return text
	}
	var out strings.Builder
	for index := 0; index < len(text); index++ {
		if text[index] == '\\' && index+1 < len(text) {
			switch text[index+1] {
			case '$', '`', '\\':
				out.WriteByte(text[index+1])
				index++
				continue
			case '\n':
				index++
				continue
			}
		}
		out.WriteByte(text[index])
	}
	return out.String()
}

// stdinRedirectCount is the number of here-strings, here-documents and
// redirects from one process substitution (< <(...)) of stmt.
func stdinRedirectCount(stmt *syntax.Stmt) int {
	count := 0
	for _, redir := range stmt.Redirs {
		if redir.Op == syntax.WordHdoc || redir.Op == syntax.Hdoc || redir.Op == syntax.DashHdoc ||
			redir.Op == syntax.RdrIn && procSubstWord(redir.Word) {
			count++
		}
	}
	return count
}

// procSubstWord reports a word that is one process substitution.
func procSubstWord(word *syntax.Word) bool {
	if word == nil || len(word.Parts) != 1 {
		return false
	}
	_, ok := word.Parts[0].(*syntax.ProcSubst)
	return ok
}

// stdinSourceSpan returns the bytes of command to remove to leave out the
// here-string or here-document redirect: the redirect, the white space before
// it and, for a here-document, its body and delimiter line. ok is false when
// the span is not exactly that (text after the operator on its line, a
// delimiter line that is not found): the redirect is then kept as written.
func stdinSourceSpan(command string, redir *syntax.Redirect) (start, end int, ok bool) {
	start, end = int(redir.Pos().Offset()), int(redir.End().Offset())
	if redir.Op == syntax.Hdoc || redir.Op == syntax.DashHdoc {
		// The operator and its delimiter word end the first line; the body
		// and the delimiter line follow it.
		if redir.Word == nil {
			return 0, 0, false
		}
		end = int(redir.Word.End().Offset())
	}
	if start < 0 || end <= start || end > len(command) {
		return 0, 0, false
	}
	if redir.Op == syntax.Hdoc || redir.Op == syntax.DashHdoc {
		rest := command[end:]
		newline := strings.IndexByte(rest, 10)
		if newline < 0 || strings.Trim(rest[:newline], " 	") != "" {
			return 0, 0, false
		}
		delimiter := projectPOSIXWord(redir.Word)
		if delimiter.Expands || delimiter.Value == "" {
			return 0, 0, false
		}
		at := end + newline + 1
		found := false
		for at <= len(command) {
			line := command[at:]
			next := strings.IndexByte(line, 10)
			if next >= 0 {
				line = line[:next]
			}
			if redir.Op == syntax.DashHdoc {
				line = strings.TrimLeft(line, "	")
			}
			if line == delimiter.Value {
				end, found = indexLineEnd(command, at), true
				break
			}
			if next < 0 {
				break
			}
			at += next + 1
		}
		if !found {
			return 0, 0, false
		}
	}
	for start > 0 && (command[start-1] == 32 || command[start-1] == 9) {
		start--
	}
	return start, end, true
}

// indexLineEnd is the offset of the end of the line of command that starts at
// at (before its newline, or the end of command).
func indexLineEnd(command string, at int) int {
	if next := strings.IndexByte(command[at:], 10); next >= 0 {
		return at + next
	}
	return len(command)
}
