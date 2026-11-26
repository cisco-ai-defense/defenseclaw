// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "strings"

type perlOverrideDef struct {
	name                      string
	start, bodyStart, bodyEnd int
	global                    bool
}

type perlSubsImport struct {
	name string
	at   int
}

type perlOverrideResult struct {
	skip  map[int]bool
	paths []string
}

func perlOverrideNames(tokens []perlToken, start, end int) []string {
	var names []string
	for i := start; i < end; i++ {
		text := tokens[i].text
		if tokens[i].kind == 's' {
			if value, ok := literalString(text); ok {
				names = append(names, value)
			} else if strings.HasPrefix(text, "qw") {
				inner := strings.Trim(text[2:], "(){}[]<>/'\"")
				names = append(names, strings.Fields(inner)...)
			}
		}
	}
	return names
}

func perlUseSubs(tokens []perlToken) []perlSubsImport {
	var imports []perlSubsImport
	for i := 0; i+2 < len(tokens); i++ {
		if tokens[i].text != "use" || tokens[i+1].text != "subs" {
			continue
		}
		end := i + 2
		for end < len(tokens) && tokens[end].text != ";" {
			end++
		}
		for _, name := range perlOverrideNames(tokens, i+2, end) {
			imports = append(imports, perlSubsImport{name: name, at: tokens[i].start})
		}
	}
	return imports
}

func perlOverrideBody(tokens []perlToken, at int) (perlOverrideDef, bool) {
	if at >= len(tokens) {
		return perlOverrideDef{}, false
	}
	nameAt, body := -1, -1
	global := false
	switch tokens[at].text {
	case "sub":
		if at+1 < len(tokens) {
			nameAt, body = at+1, at+2
		}
	case "*":
		if at+3 < len(tokens) && tokens[at+2].text == "=" && tokens[at+3].text == "sub" {
			nameAt, body = at+1, at+4
		}
	}
	if nameAt < 0 || nameAt >= len(tokens) || tokens[nameAt].kind != 'w' {
		return perlOverrideDef{}, false
	}
	name := tokens[nameAt].text
	if strings.HasPrefix(name, "CORE::GLOBAL::") {
		global = true
		name = strings.TrimPrefix(name, "CORE::GLOBAL::")
	}
	switch name {
	case "open", "sysopen", "unlink", "rename", "link", "symlink", "truncate":
	default:
		return perlOverrideDef{}, false
	}
	if global && tokens[at].blockKind != "BEGIN" && tokens[at].blockKind != "UNITCHECK" &&
		tokens[at].blockKind != "CHECK" && tokens[at].blockKind != "INIT" {
		return perlOverrideDef{}, false
	}
	if body < len(tokens) && tokens[body].text == "(" {
		depth := 1
		body++
		for body < len(tokens) && depth > 0 {
			if tokens[body].text == "(" {
				depth++
			}
			if tokens[body].text == ")" {
				depth--
			}
			body++
		}
	}
	if body >= len(tokens) || tokens[body].text != "{" {
		return perlOverrideDef{}, false
	}
	start := body + 1
	end := start
	depth := 1
	for end < len(tokens) {
		if tokens[end].text == "{" {
			depth++
		}
		if tokens[end].text == "}" {
			depth--
		}
		if depth == 0 {
			break
		}
		end++
	}
	if end >= len(tokens) {
		return perlOverrideDef{}, false
	}
	return perlOverrideDef{name: name, start: tokens[at].start,
		bodyStart: tokens[start].start, bodyEnd: tokens[end].start, global: global}, true
}

func perlOverrideDefinitions(tokens []perlToken) []perlOverrideDef {
	var defs []perlOverrideDef
	for i := range tokens {
		if tokens[i].text == "sub" || tokens[i].text == "*" {
			if def, ok := perlOverrideBody(tokens, i); ok {
				defs = append(defs, def)
			}
		}
	}
	return defs
}

func perlArgumentSyntax(tokens []perlToken, span [2]int) string {
	var out strings.Builder
	for _, tok := range perlFlagTokens(tokens, span) {
		out.WriteString(tok.text)
	}
	return out.String()
}

func perlOverrideBodyPaths(s1 *perlS1Lazy, tokens []perlToken, body perlOverrideDef, caller perlCall, calls []perlCall) []string {
	var paths []string
	pathAt := func(index int) (string, bool) {
		if index >= caller.argc {
			return "", false
		}
		return perlArgumentLiteral(tokens, caller.args[index])
	}
	for _, inner := range calls {
		if inner.start < body.bodyStart || inner.start >= body.bodyEnd {
			continue
		}
		pos := -1
		for i := range tokens {
			if tokens[i].start == inner.start {
				pos = i
				break
			}
		}
		if pos < 0 || !strings.HasPrefix(tokens[pos].text, "CORE::") {
			continue
		}
		switch inner.name {
		case "open":
			if inner.argc < 3 {
				continue
			}
			mode, known := perlArgumentLiteral(tokens, inner.args[1])
			if !known || !perlThreeArgWriteMode(mode) {
				continue
			}
			switch perlArgumentSyntax(tokens, inner.args[2]) {
			case "$_[2]":
				if path, fixed := pathAt(2); fixed {
					paths = append(paths, path)
				}
			case "substr($_[1],1)":
				if caller.argc == 2 {
					if spec, fixed := pathAt(1); fixed && strings.HasPrefix(spec, "<") {
						paths = append(paths, strings.TrimPrefix(spec, "<"))
					}
				}
			}
		case "sysopen":
			if inner.argc < 3 || perlArgumentSyntax(tokens, inner.args[1]) != "$_[1]" {
				continue
			}
			flags, known := perlFlagExpression(s1, tokens, inner, inner.args[2], nil)
			if known && (flags&3 != 0 || flags&uint64(perlCommonFlags[3].value|perlCommonFlags[4].value|perlCommonFlags[5].value) != 0) {
				if path, fixed := pathAt(1); fixed {
					paths = append(paths, path)
				}
			}
		case "unlink":
			if perlArgumentSyntax(tokens, inner.args[0]) == "@_" {
				for i := 0; i < caller.argc; i++ {
					if path, fixed := pathAt(i); fixed {
						paths = append(paths, path)
					}
				}
			}
		case "rename", "truncate", "link", "symlink":
			if caller.argc == 0 {
				continue
			}
			switch inner.name {
			case "rename":
				if caller.argc == 2 {
					if path, fixed := pathAt(0); fixed {
						paths = append(paths, path)
					}
					if path, fixed := pathAt(1); fixed {
						paths = append(paths, path)
					}
				}
			case "truncate":
				if path, fixed := pathAt(0); fixed {
					paths = append(paths, path)
				}
			case "link", "symlink":
				if caller.argc == 2 {
					if path, fixed := pathAt(1); fixed {
						paths = append(paths, path)
					}
				}
			}
		}
	}
	return paths
}

func perlResolveOverrides(s1 *perlS1Lazy, tokens []perlToken, calls []perlCall) perlOverrideResult {
	imports := perlUseSubs(tokens)
	defs := perlOverrideDefinitions(tokens)
	result := perlOverrideResult{skip: make(map[int]bool)}
	for _, call := range calls {
		var matched *perlOverrideDef
		maybe := false
		for _, imp := range imports {
			if imp.name == call.name && imp.at < call.start {
				maybe = true
			}
		}
		for i := range defs {
			def := &defs[i]
			if def.name != call.name {
				continue
			}
			if def.global && def.start < call.start {
				matched, maybe = def, true
			}
			if maybe && !def.global {
				matched = def
			}
		}
		if !maybe {
			continue
		}
		result.skip[call.start] = true
		if matched != nil {
			result.paths = append(result.paths, perlOverrideBodyPaths(s1, tokens, *matched, call, calls)...)
		}
	}
	return result
}
