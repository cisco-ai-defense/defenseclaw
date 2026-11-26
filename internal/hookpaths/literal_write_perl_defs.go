// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "strings"

type perlDef struct {
	name    string
	value   uint64
	known   bool
	runtime bool
	at      int
	block   int
}

func perlDefName(name string) string {
	if strings.HasPrefix(name, "main::") {
		return strings.TrimPrefix(name, "main::")
	}
	if strings.HasPrefix(name, "::") {
		return strings.TrimPrefix(name, "::")
	}
	return name
}

func perlDefinitionValue(tokens []perlToken, from, to int, defs map[string]perlDef) (uint64, bool) {
	if from >= to {
		return 0, false
	}
	call := perlCall{start: tokens[from].start, block: tokens[from].block}
	return perlFlagExpression(tokens, call, [2]int{tokens[from].start, tokens[to-1].end}, defs)
}

func perlNamedDefinitions(tokens []perlToken) []perlDef {
	var result []perlDef
	defs := make(map[string]perlDef)
	for i := 0; i+2 < len(tokens); i++ {
		if tokens[i].text == "*" {
			if def, parsed := perlGlobDefinition(tokens, i, defs); parsed {
				result = append(result, def)
				defs[def.name] = def
			}
		}
		if tokens[i].text == "sub" {
			if def, parsed := perlSubDefinition(tokens, i, defs); parsed {
				result = append(result, def)
				defs[def.name] = def
			}
		}
		if tokens[i].text != "use" || tokens[i+1].text != "constant" {
			continue
		}
		j := i + 2
		if tokens[j].text == "{" {
			j++
			for j+2 < len(tokens) && tokens[j].text != "}" {
				if tokens[j].kind != 'w' || tokens[j+1].text != "=>" {
					break
				}
				name := perlDefName(tokens[j].text)
				start := j + 2
				k := start
				depth := 0
				for k < len(tokens) {
					switch tokens[k].text {
					case "(":
						depth++
					case ")":
						depth--
					case ",", "}":
						if depth == 0 {
							goto hashEnd
						}
					}
					k++
				}
			hashEnd:
				value, known := perlDefinitionValue(tokens, start, k, defs)
				def := perlDef{name: name, value: value, known: known, at: tokens[j].start, block: tokens[j].block}
				result = append(result, def)
				defs[name] = def
				if k >= len(tokens) || tokens[k].text == "}" {
					break
				}
				j = k + 1
			}
		} else if j+2 < len(tokens) && tokens[j].kind == 'w' && tokens[j+1].text == "=>" {
			name := perlDefName(tokens[j].text)
			start := j + 2
			k := start
			for k < len(tokens) && tokens[k].text != ";" {
				k++
			}
			value, known := perlDefinitionValue(tokens, start, k, defs)
			def := perlDef{name: name, value: value, known: known, at: tokens[j].start, block: tokens[j].block}
			result = append(result, def)
			defs[name] = def
		}
	}
	return result
}

func perlSubDefinition(tokens []perlToken, at int, defs map[string]perlDef) (perlDef, bool) {
	if at+2 >= len(tokens) || tokens[at].text != "sub" {
		return perlDef{}, false
	}
	nameAt := at + 1
	if tokens[nameAt].text == "::" {
		nameAt++
	}
	if nameAt >= len(tokens) || tokens[nameAt].kind != 'w' {
		return perlDef{}, false
	}
	name := perlDefName(tokens[nameAt].text)
	body := nameAt + 1
	if body+1 < len(tokens) && tokens[body].text == "(" && tokens[body+1].text == ")" {
		body += 2
	}
	if body >= len(tokens) || tokens[body].text != "{" {
		return perlDef{}, false
	}
	start := body + 1
	end := start
	depth := 1
	for end < len(tokens) {
		switch tokens[end].text {
		case "{":
			depth++
		case "}":
			depth--
		}
		if depth == 0 {
			break
		}
		end++
	}
	if end >= len(tokens) {
		return perlDef{}, false
	}
	if start < end && tokens[start].text == "return" {
		start++
	}
	if end > start && tokens[end-1].text == ";" {
		end--
	}
	value, known := perlDefinitionValue(tokens, start, end, defs)
	return perlDef{name: name, value: value, known: known, at: tokens[at].start, block: tokens[at].block}, true
}

func perlGlobDefinition(tokens []perlToken, at int, defs map[string]perlDef) (perlDef, bool) {
	if tokens[at].text != "*" || at+4 >= len(tokens) {
		return perlDef{}, false
	}
	nameAt := at + 1
	if tokens[nameAt].text == "::" {
		nameAt++
	}
	if nameAt+2 >= len(tokens) || tokens[nameAt].kind != 'w' ||
		tokens[nameAt+1].text != "=" || tokens[nameAt+2].text != "sub" {
		return perlDef{}, false
	}
	name := perlDefName(tokens[nameAt].text)
	body := nameAt + 3
	if body+1 < len(tokens) && tokens[body].text == "(" && tokens[body+1].text == ")" {
		body += 2
	}
	if body >= len(tokens) || tokens[body].text != "{" {
		return perlDef{}, false
	}
	start := body + 1
	end := start
	depth := 1
	for end < len(tokens) {
		switch tokens[end].text {
		case "{":
			depth++
		case "}":
			depth--
		}
		if depth == 0 {
			break
		}
		end++
	}
	if end >= len(tokens) {
		return perlDef{}, false
	}
	if start < end && tokens[start].text == "return" {
		start++
	}
	if end > start && tokens[end-1].text == ";" {
		end--
	}
	value, known := perlDefinitionValue(tokens, start, end, defs)
	compileTime := tokens[at].blockKind == "BEGIN" || tokens[at].blockKind == "UNITCHECK" ||
		tokens[at].blockKind == "CHECK" || tokens[at].blockKind == "INIT"
	return perlDef{name: name, value: value, known: known, runtime: !compileTime,
		at: tokens[at].start, block: tokens[at].block}, true
}
