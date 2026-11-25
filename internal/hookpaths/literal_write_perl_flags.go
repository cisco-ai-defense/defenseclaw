// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
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

func perlVisibilityAt(tokens []perlToken, call perlCall, name string) perlFlagVisibility {
	var visibility perlFlagVisibility
	for i := 0; i+1 < len(tokens) && tokens[i].start < call.start; i++ {
		word := tokens[i].text
		module := perlFlagModule(tokens[i+1].text)
		if module < 0 {
			continue
		}
		if word == "use" {
			if module < 2 {
				visibility.loaded[module] = true
			}
			end := i + 2
			for end < len(tokens) && tokens[end].text != ";" && tokens[end].start < call.start {
				end++
			}
			if perlImportHasName(tokens, i+2, end, name) {
				visibility.imported[module] = true
			}
		}
		if word == "require" && module < 2 {
			if tokens[i].block == call.block && tokens[i].blockKind != "sub" &&
				tokens[i].blockKind != "loop" {
				straight := true
				for j := i + 2; j < len(tokens) && tokens[j].start < call.start; j++ {
					switch tokens[j].text {
					case "sub", "for", "foreach", "while", "until", "if", "unless":
						straight = false
					}
				}
				if straight {
					visibility.runtime[module] = true
				}
			} else if tokens[i].blockKind == "BEGIN" || tokens[i].blockKind == "UNITCHECK" ||
				tokens[i].blockKind == "CHECK" || tokens[i].blockKind == "INIT" {
				visibility.loaded[module] = true
			}
		}
	}
	return visibility
}

func perlFlagVisible(tokens []perlToken, call perlCall, spelling string, callForm bool) (string, bool) {
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
	v := perlVisibilityAt(tokens, call, name)
	if module < 0 {
		return name, v.imported[0] || v.imported[1] || v.imported[2]
	}
	return name, v.loaded[module] || callForm && v.runtime[module]
}

func perlFlagExpression(tokens []perlToken, call perlCall, span [2]int, defs map[string]perlDef) (uint64, bool) {
	return perlFlagExpressionDepth(tokens, call, span, defs, 0)
}

func perlFlagExpressionDepth(tokens []perlToken, call perlCall, span [2]int, defs map[string]perlDef, depth int) (uint64, bool) {
	if depth > 1 {
		return 0, false
	}
	expr := perlFlagTokens(tokens, span)
	if len(expr) == 0 {
		return 0, false
	}
	at := 0
	var parseExpr func() (uint64, bool)
	var parseTerm func() (uint64, bool)
	parseTerm = func() (uint64, bool) {
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
			valueSpan, proven := perlS1ValueSpan(tokens, call, name)
			if !proven {
				return 0, false
			}
			source := perlCall{start: valueSpan[0], block: call.block}
			return perlFlagExpressionDepth(tokens, source, valueSpan, defs, depth+1)
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
		name, visible := perlFlagVisible(tokens, call, tok.text, callForm)
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

func perlSysopenWrites(tokens []perlToken, calls []perlCall, definitions []perlDef, skip map[int]bool) []string {
	var paths []string
	defs := make(map[string]perlDef)
	next := 0
	const accmode = 3
	for _, call := range calls {
		if skip[call.start] {
			continue
		}
		for next < len(definitions) && definitions[next].at < call.start {
			def := definitions[next]
			if previous, exists := defs[def.name]; exists &&
				!(previous.block == 0 && def.block == 0 && !previous.runtime && !def.runtime) {
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
		flags, known := perlFlagExpression(tokens, call, call.args[2], defs)
		if !known {
			continue
		}
		if flags&accmode != 0 || flags&uint64(os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0 {
			paths = append(paths, path)
		}
	}
	return paths
}
