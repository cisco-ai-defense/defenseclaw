// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
	"path"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// loopWriterMaxValues bounds the fixed words of a for list that are read one
// by one; a longer list is read as a list of unknown words.
const loopWriterMaxValues = 32

// LoopWriterReachesState reports a for loop whose body writes (cp, mv,
// install, ln, tee, sed -i, perl -i or a redirect) a path that some value of
// the loop variable, or of a variable the walk cannot read at that point,
// makes a file or tree of the active DefenseClaw state. The writer target is
// judged, not the list: a variable the walk cannot read stands for any one
// path segment, and the target is matched against the state paths (a
// segment of the target that holds it matches any name). A fixed list is
// read word by word, so a loop over other names stays allowed. What ran
// before the loop (a sourced file, eval, an assignment) leaves no variable
// known unless the walk proves its value (rel-1-0-6:GAP-0880).
func LoopWriterReachesState(command, cwd, home string) bool {
	if len(command) > MaxPayloadBytes || !strings.Contains(command, "for") || !strings.ContainsAny(command, "$`") ||
		!strings.HasPrefix(cwd, "/") || !strings.HasPrefix(home, "/") {
		return false
	}
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	scan := loopWriterScan{home: path.Clean(home), elsewhere: loopWriterReadNames(file, home)}
	scan.roots = []string{scan.home}
	if resolved, ok := ResolveWriteTarget(home); ok && path.Clean(resolved) != scan.home {
		scan.roots = append(scan.roots, path.Clean(resolved))
	}
	values := actionValues{"HOME": scan.home, "PWD": cwd}
	var stack []string
	for _, top := range file.Stmts {
		values["PWD"] = cwd
		scan.statement(top, values, cwd)
		if scan.found {
			return true
		}
		if call, ok := top.Cmd.(*syntax.CallExpr); ok {
			if scan.opaque(call) {
				clear(values)
				values["HOME"] = scan.home
			}
			actionPosixAdvanceDirectory(call, values, scan.home, &cwd, &stack)
		}
		actionUpdateValues(top, values, cwd, scan.home)
	}
	return false
}

type loopWriterScan struct {
	home  string
	roots []string
	// elsewhere holds the names a read, mapfile or printf -v binds, and the
	// names a function body assigns: the login-loop readings follow those
	// bindings (a here-string, a call, declare -g), so a word spelled through
	// one is not read here as an unknown segment.
	elsewhere []string
	// bound holds the variables of the for loops being read.
	bound []string
	found bool
}

// loopWriterReadNames returns the names that read, mapfile, readarray and
// printf -v bind anywhere in the command, and the names a function assigns.
func loopWriterReadNames(file *syntax.File, home string) []string {
	var names []string
	add := func(word *syntax.Word) {
		if text, whole := wordLiteralPrefix(word); whole && actionEvalAssignmentName(text) {
			names = append(names, text)
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if function, ok := node.(*syntax.FuncDecl); ok {
			syntax.Walk(function.Body, func(inner syntax.Node) bool {
				if assign, ok := inner.(*syntax.Assign); ok && assign.Name != nil {
					names = append(names, assign.Name.Value)
				}
				return true
			})
			return true
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		program, fixed := staticProgramWord(call.Args[0], home)
		if !fixed {
			return true
		}
		args := call.Args[1:]
		switch programBase(program) {
		case "printf":
			for i := 0; i+1 < len(args); i++ {
				if text, whole := wordLiteralPrefix(args[i]); whole && text == "-v" {
					add(args[i+1])
				}
			}
		case "read", "mapfile", "readarray":
			// Options come first; these take the next word as their value.
			valued := "ptnNdui"
			if programBase(program) != "read" {
				valued = "dnOsuCc"
			}
			for i := 0; i < len(args); i++ {
				text, whole := wordLiteralPrefix(args[i])
				if !strings.HasPrefix(text, "-") || len(text) == 1 {
					for _, name := range args[i:] {
						add(name)
					}
					break
				}
				if whole && len(text) == 2 && strings.Contains(valued, text[1:]) {
					i++
				}
			}
		}
		return true
	})
	return names
}

// opaque reports a call that can bind any variable: a sourced file, eval, or
// a program the walk cannot name.
func (s *loopWriterScan) opaque(call *syntax.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}
	program, fixed := staticProgramWord(call.Args[0], s.home)
	if !fixed {
		return true
	}
	switch programBase(program) {
	case "source", ".", "eval":
		return true
	}
	return false
}

// statement judges every for loop in one statement with the values the walk
// holds where the statement starts.
func (s *loopWriterScan) statement(stmt *syntax.Stmt, values actionValues, cwd string) {
	syntax.Walk(stmt, func(node syntax.Node) bool {
		if s.found {
			return false
		}
		if loop, ok := node.(*syntax.ForClause); ok {
			s.loop(loop, values, cwd)
			return false
		}
		return true
	})
}

// loop reads the body once for each fixed word of the list and once more
// with the variable unknown when any word of the list is not fixed.
func (s *loopWriterScan) loop(loop *syntax.ForClause, values actionValues, cwd string) {
	iter, ok := loop.Loop.(*syntax.WordIter)
	if !ok || iter.Name == nil {
		return
	}
	name := iter.Name.Value
	s.bound = append(s.bound, name)
	defer func() { s.bound = s.bound[:len(s.bound)-1] }()
	var fixed []string
	unknown := len(iter.Items) == 0
	for _, item := range iter.Items {
		if s.tracked(item) {
			continue
		}
		value, known := actionWordValue(item, values, cwd, s.home)
		if !known || value == "" || strings.ContainsAny(value, " \t\n*?[") {
			unknown = true
			continue
		}
		fixed = append(fixed, value)
	}
	if len(fixed) > loopWriterMaxValues {
		fixed, unknown = fixed[:loopWriterMaxValues], true
	}
	for _, value := range fixed {
		bound := maps.Clone(values)
		bound[name] = value
		s.body(loop.Do, bound, cwd)
	}
	if unknown && !s.found {
		bound := maps.Clone(values)
		delete(bound, name)
		s.body(loop.Do, bound, cwd)
	}
}

func (s *loopWriterScan) body(stmts []*syntax.Stmt, values actionValues, cwd string) {
	var stack []string
	for _, stmt := range stmts {
		syntax.Walk(stmt, func(node syntax.Node) bool {
			if s.found {
				return false
			}
			switch node := node.(type) {
			case *syntax.ForClause:
				s.loop(node, values, cwd)
				return false
			case *syntax.Stmt:
				for _, redir := range node.Redirs {
					if redir.Word != nil && actionOutputRedirect(redir.Op) {
						s.judge(redir.Word, values, cwd)
					}
				}
			case *syntax.CallExpr:
				for _, word := range loopWriterOperands(node, s.home) {
					s.judge(word, values, cwd)
				}
				actionPosixAdvanceDirectory(node, values, s.home, &cwd, &stack)
			}
			return !s.found
		})
	}
}

// tracked reports a word spelled through a variable that other readings
// follow (elsewhere) and that no loop being read binds.
func (s *loopWriterScan) tracked(word *syntax.Word) bool {
	for _, name := range s.elsewhere {
		if !slices.Contains(s.bound, name) && actionClientWordNamesVariable(word, name) {
			return true
		}
	}
	return false
}

func (s *loopWriterScan) judge(word *syntax.Word, values actionValues, cwd string) {
	if s.tracked(word) {
		return
	}
	if pattern := loopWriterPattern(word, values, cwd, s.home); pattern != "" && loopPatternReachesState(pattern, s.roots) {
		s.found = true
	}
}

// loopWriterOperands returns the words a writer call may write: the
// destinations of cp, mv, install, ln and tee, and the file operands of an
// in-place sed or perl (the script word is one too; it names no state path).
func loopWriterOperands(call *syntax.CallExpr, home string) []*syntax.Word {
	if words := actionClientLoopWriterDestinations(call, home); len(words) != 0 {
		return words
	}
	program, words, fixed := actionClientLoopCallProgram(call, home)
	if !fixed {
		return nil
	}
	switch programBase(program) {
	case "sed", "gsed", "perl":
	default:
		return nil
	}
	inPlace := false
	var operands []*syntax.Word
	for _, word := range words[1:] {
		text, _ := wordLiteralPrefix(word)
		switch {
		case strings.HasPrefix(text, "--"):
			inPlace = inPlace || strings.HasPrefix(text, "--in-place")
		case strings.HasPrefix(text, "-") && len(text) > 1:
			inPlace = inPlace || strings.Contains(text[1:], "i")
		default:
			operands = append(operands, word)
		}
	}
	if !inPlace {
		return nil
	}
	return operands
}

// loopWriterPattern renders word as an absolute glob pattern: a part whose
// value the walk knows is its text, any other part (a variable, a command
// substitution) is one unknown path segment text (*). Empty when the word
// has no usable text.
func loopWriterPattern(word *syntax.Word, values actionValues, cwd, home string) string {
	var out strings.Builder
	var walk func(parts []syntax.WordPart, first bool)
	walk = func(parts []syntax.WordPart, first bool) {
		for i, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				text := unescapedLiteral(part.Value)
				if first && i == 0 && (text == "~" || strings.HasPrefix(text, "~/")) {
					text = home + text[1:]
				}
				out.WriteString(loopPatternEscape(text))
			case *syntax.SglQuoted:
				out.WriteString(loopPatternEscape(part.Value))
			case *syntax.DblQuoted:
				walk(part.Parts, false)
			default:
				if value, known := actionWordValue(&syntax.Word{Parts: []syntax.WordPart{part}}, values, cwd, home); known {
					out.WriteString(loopPatternEscape(value))
				} else {
					out.WriteString("*")
				}
			}
		}
	}
	walk(word.Parts, true)
	text := out.String()
	if text == "" {
		return ""
	}
	if !strings.HasPrefix(text, "/") {
		text = cwd + "/" + text
	}
	return path.Clean(text)
}

func loopPatternEscape(text string) string {
	if !strings.ContainsAny(text, `*?[\`) {
		return text
	}
	var out strings.Builder
	for i := 0; i < len(text); i++ {
		if strings.IndexByte(`*?[\`, text[i]) >= 0 {
			out.WriteByte(0x5c)
		}
		out.WriteByte(text[i])
	}
	return out.String()
}

// loopPatternReachesState reports a pattern (an absolute glob, one segment
// per slash) that matches a file or tree of the active state under one of
// the homes: the files directly under .defenseclaw and every entry of its
// trees (activeStateFiles, activeStateTrees).
func loopPatternReachesState(pattern string, roots []string) bool {
	segments := strings.Split(strings.Trim(pattern, "/"), "/")
	match := func(segment, name string) bool {
		matched, err := path.Match(segment, name)
		return err == nil && matched
	}
	for _, root := range roots {
		rootSegments := strings.Split(strings.Trim(root, "/"), "/")
		if len(segments) < len(rootSegments)+2 {
			continue
		}
		within := true
		for i, name := range rootSegments {
			if !match(segments[i], name) {
				within = false
				break
			}
		}
		rest := segments[len(rootSegments):]
		if !within || !match(rest[0], ".defenseclaw") {
			continue
		}
		state := rest[1:]
		if len(state) == 1 {
			for _, file := range activeStateFiles {
				if match(state[0], file) {
					return true
				}
			}
		}
		for _, tree := range activeStateTrees {
			names := strings.Split(tree, "/")
			if len(state) <= len(names) {
				continue
			}
			inside := true
			for i, name := range names {
				if !match(state[i], name) {
					inside = false
					break
				}
			}
			if inside {
				return true
			}
		}
	}
	return false
}
