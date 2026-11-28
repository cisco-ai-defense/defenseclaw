// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"sort"
	"strconv"
	"strings"
)

type perlFlagConstant struct {
	name  string
	value uint64
}

var perlCommonFlags = [...]perlFlagConstant{
	{"O_RDONLY", uint64(os.O_RDONLY)},
	{"O_WRONLY", uint64(os.O_WRONLY)},
	{"O_RDWR", uint64(os.O_RDWR)},
	{"O_CREAT", uint64(os.O_CREATE)},
	{"O_TRUNC", uint64(os.O_TRUNC)},
	{"O_APPEND", uint64(os.O_APPEND)},
}

func perlFlagNumber(name string) (uint64, bool) {
	for _, item := range perlCommonFlags {
		if item.name == name {
			return item.value, true
		}
	}
	for _, item := range perlPlatformFlags {
		if item.name == name {
			return item.value, true
		}
	}
	return 0, false
}

func perlFlagTokens(tokens []perlToken, span [2]int) []perlToken {
	lo, hi := 0, len(tokens)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if tokens[mid].start < span[0] {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	start := lo
	for lo < len(tokens) && tokens[lo].end <= span[1] {
		lo++
	}
	return tokens[start:lo]
}

type perlFlagVisibility struct {
	imported [3]bool
	loaded   [2]bool
	runtime  [2]bool
}

func perlFlagModule(name string) int {
	switch name {
	case "Fcntl":
		return 0
	case "POSIX":
		return 1
	case "IO::File":
		return 2
	}
	return -1
}

func perlImportHasName(tokens []perlToken, start, end int, name string) bool {
	if start >= end {
		return true
	}
	if tokens[start].text == "(" && start+1 < end && tokens[start+1].text == ")" {
		return false
	}
	for i := start; i < end; i++ {
		word := tokens[i].text
		if word == name || word == ":DEFAULT" || word == "':DEFAULT'" || word == "\":DEFAULT\"" {
			return true
		}
		if tokens[i].kind == 's' {
			if imported, fixed := literalString(word); fixed && (imported == name || imported == ":DEFAULT") {
				return true
			}
		}
		if strings.HasPrefix(word, "qw") {
			inner := strings.Trim(word[2:], "(){}[]<>/'\"")
			for _, item := range strings.Fields(inner) {
				if item == name || item == ":DEFAULT" {
					return true
				}
			}
		}
	}
	return false
}

// perlVisibilityAt is what a call sees of the flag modules and of name: a
// use of the module before the call (loaded, and imported when its import
// list names name), a require of the module in a BEGIN-like block other than
// the call's (loaded), and a straight-line require in the call's own block
// after its last branch word (runtime). Each question read the whole token
// prefix of the call, the square of dense code (rel-1-0-10:GAP-2230); it is
// now answered from the program's index (perlVisIndex).
func perlVisibilityAt(s1 *perlS1Lazy, tokens []perlToken, call perlCall, name string) perlFlagVisibility {
	return s1.visibility(tokens).at(tokens, call, name)
}

// perlVisIndex holds what perlVisibilityAt needs of one program, from one
// pass over its tokens.
type perlVisIndex struct {
	// branches are the ascending indexes of sub and the loop and
	// conditional words.
	branches []int
	// uses are the use statements of a flag module, in source order; end is
	// the first ; at or after the import list (len(tokens) when none), so
	// ends only grow.
	uses []perlVisUse
	// loadedUse[m] is the first use of Fcntl (0) or POSIX (1),
	// len(tokens) when none.
	loadedUse [2]int
	// begin[m] are the first require of module m in a BEGIN-like block and
	// the first one after it in another block.
	begin [2][]perlVisRequire
	// requires maps a block and a module to the ascending indexes of the
	// module's requires in that block when it is not a sub or loop block.
	requires map[[2]int][]int
	// imports maps a name to, per module, the first use (an index of uses)
	// whose whole import list names it; len(uses) when none.
	imports map[string][3]int
}

type perlVisUse struct{ at, module, end int }

type perlVisRequire struct{ at, block int }

func (lazy *perlS1Lazy) visibility(tokens []perlToken) *perlVisIndex {
	if lazy == nil {
		return newPerlVisIndex(tokens)
	}
	if lazy.vis == nil {
		lazy.vis = newPerlVisIndex(tokens)
	}
	return lazy.vis
}

func newPerlVisIndex(tokens []perlToken) *perlVisIndex {
	n := len(tokens)
	index := &perlVisIndex{loadedUse: [2]int{n, n}, requires: map[[2]int][]int{}, imports: map[string][3]int{}}
	nextSemi := make([]int, n+1)
	nextSemi[n] = n
	for i := n - 1; i >= 0; i-- {
		nextSemi[i] = nextSemi[i+1]
		if tokens[i].text == ";" {
			nextSemi[i] = i
		}
	}
	for i := range tokens {
		switch tokens[i].text {
		case "sub", "for", "foreach", "while", "until", "if", "unless":
			index.branches = append(index.branches, i)
		}
		if i+1 >= n {
			continue
		}
		module := perlFlagModule(tokens[i+1].text)
		if module < 0 {
			continue
		}
		switch tokens[i].text {
		case "use":
			if module < 2 && index.loadedUse[module] == n {
				index.loadedUse[module] = i
			}
			index.uses = append(index.uses, perlVisUse{at: i, module: module, end: nextSemi[i+2]})
		case "require":
			if module >= 2 {
				continue
			}
			block, kind := tokens[i].block, tokens[i].blockKind
			if kind != "sub" && kind != "loop" {
				key := [2]int{block, module}
				index.requires[key] = append(index.requires[key], i)
			}
			if kind == "BEGIN" || kind == "UNITCHECK" || kind == "CHECK" || kind == "INIT" {
				if first := index.begin[module]; len(first) == 0 || len(first) == 1 && first[0].block != block {
					index.begin[module] = append(first, perlVisRequire{at: i, block: block})
				}
			}
		}
	}
	return index
}

func (index *perlVisIndex) at(tokens []perlToken, call perlCall, name string) perlFlagVisibility {
	var visibility perlFlagVisibility
	callAt := sort.Search(len(tokens), func(i int) bool { return tokens[i].start >= call.start })
	lastBranch := -1
	if k := sort.SearchInts(index.branches, callAt) - 1; k >= 0 {
		lastBranch = index.branches[k]
	}
	for module := range 2 {
		loaded := index.loadedUse[module] < callAt
		if first := index.begin[module]; !loaded && len(first) > 0 {
			if first[0].block != call.block {
				loaded = first[0].at < callAt
			} else if len(first) > 1 {
				loaded = first[1].at < callAt
			}
		}
		visibility.loaded[module] = loaded
		requires := index.requires[[2]int{call.block, module}]
		k := sort.SearchInts(requires, lastBranch-1)
		visibility.runtime[module] = k < len(requires) && requires[k] < callAt
	}
	// The uses before the call whose statement ends after it read their
	// import list only up to the call; they are the last uses before it
	// (ends only grow). The others read their whole list.
	before := sort.Search(len(index.uses), func(k int) bool { return index.uses[k].at >= callAt })
	whole := before
	for whole > 0 && index.uses[whole-1].end > callAt {
		whole--
	}
	imports := index.importsOf(tokens, name)
	for module := range 3 {
		visibility.imported[module] = imports[module] < whole
	}
	for _, use := range index.uses[whole:before] {
		if !visibility.imported[use.module] &&
			perlImportHasName(tokens, use.at+2, max(use.at+2, min(use.end, callAt)), name) {
			visibility.imported[use.module] = true
		}
	}
	return visibility
}

func (index *perlVisIndex) importsOf(tokens []perlToken, name string) [3]int {
	if first, known := index.imports[name]; known {
		return first
	}
	none := len(index.uses)
	first := [3]int{none, none, none}
	for k, use := range index.uses {
		if first[use.module] == none && perlImportHasName(tokens, use.at+2, use.end, name) {
			first[use.module] = k
		}
	}
	index.imports[name] = first
	return first
}

func perlFlagVisible(s1 *perlS1Lazy, tokens []perlToken, call perlCall, spelling string, callForm bool) (string, bool) {
	module := -1
	name := spelling
	if strings.HasPrefix(spelling, "Fcntl::") {
		module = 0
		name = strings.TrimPrefix(spelling, "Fcntl::")
	} else if strings.HasPrefix(spelling, "POSIX::") {
		module = 1
		name = strings.TrimPrefix(spelling, "POSIX::")
	} else if strings.Contains(spelling, "::") {
		return "", false
	}
	if _, known := perlFlagNumber(name); !known {
		return "", false
	}
	v := perlVisibilityAt(s1, tokens, call, name)
	if module < 0 {
		return name, v.imported[0] || v.imported[1] || v.imported[2]
	}
	return name, v.loaded[module] || callForm && v.runtime[module]
}

func perlFlagExpression(s1 *perlS1Lazy, tokens []perlToken, call perlCall, span [2]int, defs map[string]perlDef) (uint64, bool) {
	return perlFlagExpressionDepth(s1, tokens, call, span, defs, 0)
}

func perlFlagExpressionDepth(s1 *perlS1Lazy, tokens []perlToken, call perlCall, span [2]int, defs map[string]perlDef, depth int) (uint64, bool) {
	if depth > 1 {
		return 0, false
	}
	expr := perlFlagTokens(tokens, span)
	if len(expr) == 0 {
		return 0, false
	}
	at := 0
	var parseExpr func() (uint64, bool)
	parseTerm := func() (uint64, bool) {
		if at >= len(expr) {
			return 0, false
		}
		tok := expr[at]
		if tok.text == "$" {
			if depth >= 1 {
				return 0, false
			}
			name, next := perlScalarAt(expr, at)
			if name == "" {
				return 0, false
			}
			at = next
			valueSpan, proven := perlS1ValueSpan(s1, tokens, call, name)
			if !proven {
				return 0, false
			}
			source := perlCall{start: valueSpan[0], block: call.block}
			return perlFlagExpressionDepth(s1, tokens, source, valueSpan, defs, depth+1)
		}
		if tok.text == "(" {
			at++
			value, ok := parseExpr()
			if !ok || at >= len(expr) || expr[at].text != ")" {
				return 0, false
			}
			at++
			return value, true
		}
		if tok.text == "&" {
			at++
			if at >= len(expr) {
				return 0, false
			}
			tok = expr[at]
		}
		if tok.kind == 'n' {
			at++
			value, err := strconv.ParseUint(tok.text, 0, 64)
			return value, err == nil
		}
		if tok.kind != 'w' {
			return 0, false
		}
		at++
		callForm := at > 1 && expr[at-2].text == "&"
		if at+1 < len(expr) && expr[at].text == "(" && expr[at+1].text == ")" {
			at += 2
			callForm = true
		}
		if def, exists := defs[perlDefName(tok.text)]; exists && def.at < call.start {
			if !def.runtime || callForm {
				return def.value, def.known
			}
		}
		name, visible := perlFlagVisible(s1, tokens, call, tok.text, callForm)
		if !visible {
			return 0, false
		}
		return perlFlagNumber(name)
	}
	parseExpr = func() (uint64, bool) {
		value, ok := parseTerm()
		if !ok {
			return 0, false
		}
		for at < len(expr) && (expr[at].text == "|" || expr[at].text == "+") {
			op := expr[at].text
			at++
			right, known := parseTerm()
			if !known {
				return 0, false
			}
			if op == "|" {
				value |= right
			} else {
				if value+right < value {
					return 0, false
				}
				value += right
			}
		}
		return value, true
	}
	value, ok := parseExpr()
	return value, ok && at == len(expr)
}

func perlSysopenWrites(s1 *perlS1Lazy, tokens []perlToken, calls []perlCall, definitions []perlDef, skip map[int]bool) []string {
	var paths []string
	defs := make(map[string]perlDef)
	next := 0
	for _, call := range calls {
		if skip[call.start] {
			continue
		}
		for next < len(definitions) && definitions[next].at < call.start {
			def := definitions[next]
			if previous, exists := defs[def.name]; exists &&
				(previous.block != 0 || def.block != 0 || previous.runtime || def.runtime) {
				def.known = false
			}
			defs[def.name] = def
			next++
		}
		if call.name != "sysopen" || call.argc < 3 || call.argc > 4 {
			continue
		}
		path, fixed := perlArgumentLiteral(tokens, call.args[1])
		if !fixed {
			continue
		}
		flags, known := perlFlagExpression(s1, tokens, call, call.args[2], defs)
		if !known {
			continue
		}
		if perlFlagsWrite(flags, perlPlatformWriteBits) {
			paths = append(paths, path)
		}
	}
	return paths
}

// perlFlagsWrite reports whether sysopen flags ask for a change to the path:
// an access mode other than read only, or one of the write bits of the
// platform (perlPlatformWriteBits).
func perlFlagsWrite(flags, writeBits uint64) bool {
	return flags&3 != 0 || flags&writeBits != 0
}
