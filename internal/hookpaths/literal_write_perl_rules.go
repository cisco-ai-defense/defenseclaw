// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"sort"
	"strings"
)

func perlArgumentLiteral(tokens []perlToken, arg [2]int) (string, bool) {
	return perlFixedPath(tokens, arg[0], arg[1])
}

func perlThreeArgWriteMode(mode string) bool {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		return false
	}
	var prefix string
	for _, candidate := range []string{"+>>", "+>", "+<", ">>", ">"} {
		if strings.HasPrefix(mode, candidate) {
			prefix = candidate
			break
		}
	}
	if prefix == "" {
		return false
	}
	tail := mode[len(prefix):]
	return tail == "" || strings.HasPrefix(tail, ":")
}

func perlTwoArgWritePath(spec string) (string, bool) {
	spec = strings.TrimLeft(spec, " \t\r\n")
	if spec == "" || spec[0] == '|' || spec[len(spec)-1] == '|' ||
		strings.HasPrefix(spec, ">&") || strings.HasPrefix(spec, "<&") {
		return "", false
	}
	for _, prefix := range []string{"+>>", "+>", "+<", ">>", ">"} {
		if strings.HasPrefix(spec, prefix) {
			path := strings.TrimSpace(spec[len(prefix):])
			return path, path != ""
		}
	}
	return "", false
}

// perlScalarName finds the argument's first token by its start (tokens are
// in source order): the walk from the program's first token per argument
// grew with the square of dense code (rel-1-0-10:GAP-2230).
func perlScalarName(tokens []perlToken, arg [2]int) string {
	first := sort.Search(len(tokens), func(i int) bool { return tokens[i].start >= arg[0] })
	if first == len(tokens) || tokens[first].end > arg[1] {
		first = -1
	}
	if first >= 0 && first+1 < len(tokens) && tokens[first].text == "$" &&
		tokens[first+1].kind == 'w' && tokens[first+1].end == arg[1] {
		return tokens[first+1].text
	}
	return ""
}

// perlDirectScalarMode accepts a straight-line S1 assignment from the call's
// block or an enclosing block, excluding sub and loop boundaries.
func perlScalarAt(tokens []perlToken, at int) (string, int) {
	if at >= len(tokens) || tokens[at].text != "$" {
		return "", at
	}
	if at+1 < len(tokens) && tokens[at+1].kind == 'w' {
		return tokens[at+1].text, at + 2
	}
	if at+3 < len(tokens) && tokens[at+1].text == "{" &&
		tokens[at+2].kind == 'w' && tokens[at+3].text == "}" {
		return tokens[at+2].text, at + 4
	}
	return "", at
}

func perlOpaqueAt(tokens []perlToken, at int) bool {
	if at+1 >= len(tokens) {
		return false
	}
	switch tokens[at].text {
	case "eval", "do":
		return tokens[at+1].text != "{"
	case "require":
		return tokens[at+1].kind != 'w'
	case "$", "*", "&":
		return at+3 < len(tokens) && tokens[at+1].text == "{" &&
			tokens[at+2].kind == 's' && tokens[at+3].text == "}"
	}
	return false
}

// perlS1ValueSpan is the span of the value of the last straight-line S1
// assignment "$name = VALUE" before call that encloses it (no sub or loop
// boundary and no closing brace between them, not escaped, not under a
// statement modifier loop or a conditional), when nothing between the value
// and the call uses $name again or runs code the reading cannot see
// (perlOpaqueAt). Every question is answered from the program's index
// (perlS1Index): the reading of the whole token prefix per question grew
// with the square of dense code (rel-1-0-10:GAP-2230).
func perlS1ValueSpan(s1 *perlS1Lazy, tokens []perlToken, call perlCall, name string) ([2]int, bool) {
	index := s1.of(tokens)
	callAt, found := index.at[call.start]
	if !found {
		return [2]int{}, false
	}
	assignment, valueStart := -1, -1
	assigns := index.assigns[name]
	for k := sort.SearchInts(assigns, callAt) - 1; k >= 0; k-- {
		i := assigns[k]
		if _, next := perlScalarAt(tokens, i); next < callAt && index.encloses(i, callAt) {
			assignment, valueStart = i, next+1
			break
		}
	}
	if assignment < 0 {
		return [2]int{}, false
	}
	if perlIndexWithin(index.uses[name], valueStart, callAt) || perlIndexWithin(index.opaque, valueStart, callAt) {
		return [2]int{}, false
	}
	valueEnd := min(index.term[valueStart], callAt)
	if valueEnd == valueStart {
		return [2]int{}, false
	}
	return [2]int{tokens[valueStart].start, tokens[valueEnd-1].end}, true
}

func perlDirectScalarMode(s1 *perlS1Lazy, tokens []perlToken, call perlCall, name string) (string, bool) {
	span, proven := perlS1ValueSpan(s1, tokens, call, name)
	if !proven {
		return "", false
	}
	return perlFixedPath(tokens, span[0], span[1])
}

func perlResolveDirectWrites(s1 *perlS1Lazy, tokens []perlToken, calls []perlCall, skip map[int]bool) []string {
	var paths []string
	add := func(value string) {
		if value == "" {
			return
		}
		for _, path := range paths {
			if path == value {
				return
			}
		}
		paths = append(paths, value)
	}
	pathAt := func(call perlCall, index int) (string, bool) {
		if index >= call.argc {
			return "", false
		}
		return perlArgumentLiteral(tokens, call.args[index])
	}
	for _, call := range calls {
		if skip[call.start] {
			continue
		}
		switch call.name {
		case "unlink":
			for i := 0; i < call.argc; i++ {
				if path, ok := pathAt(call, i); ok {
					add(path)
				}
			}
		case "rename":
			if call.argc != 2 {
				continue
			}
			for i := 0; i < 2; i++ {
				if path, ok := pathAt(call, i); ok {
					add(path)
				}
			}
		case "link", "symlink":
			if call.argc != 2 {
				continue
			}
			if path, ok := pathAt(call, 1); ok {
				add(path)
			}
		case "truncate":
			if call.argc != 2 {
				continue
			}
			if path, ok := pathAt(call, 0); ok {
				add(path)
			}
		case "open":
			if call.argc >= 3 {
				mode, known := pathAt(call, 1)
				if known && perlThreeArgWriteMode(mode) {
					if path, fixed := pathAt(call, 2); fixed {
						add(path)
					}
					continue
				}
				if !known {
					if name := perlScalarName(tokens, call.args[1]); name != "" {
						if mode, proven := perlDirectScalarMode(s1, tokens, call, name); proven && perlThreeArgWriteMode(mode) {
							if path, fixed := pathAt(call, 2); fixed {
								add(path)
							}
						}
					}
				}
			} else if call.argc == 2 {
				if spec, fixed := pathAt(call, 1); fixed {
					if path, write := perlTwoArgWritePath(spec); write {
						add(path)
					}
				}
				if path, proven := perlInterpolatedOpenPath(s1, tokens, call); proven {
					add(path)
				}
			}
		}
	}
	return paths
}

func perlInterpolatedOpenPath(s1 *perlS1Lazy, tokens []perlToken, call perlCall) (string, bool) {
	if call.argc != 2 {
		return "", false
	}
	expr := perlFlagTokens(tokens, call.args[1])
	if len(expr) != 1 || expr[0].kind != 's' || len(expr[0].text) < 4 ||
		expr[0].text[0] != '"' {
		return "", false
	}
	inner := expr[0].text[1 : len(expr[0].text)-1]
	if len(inner) < 3 || inner[0] != '$' {
		return "", false
	}
	end := 1
	for end < len(inner) && perlIdent(inner[end]) {
		end++
	}
	if end == 1 || end == len(inner) || strings.ContainsAny(inner[end:], "$@\\") {
		return "", false
	}
	mode, proven := perlDirectScalarMode(s1, tokens, call, inner[1:end])
	if !proven || !perlThreeArgWriteMode(mode) {
		return "", false
	}
	return perlTwoArgWritePath(mode + inner[end:])
}
