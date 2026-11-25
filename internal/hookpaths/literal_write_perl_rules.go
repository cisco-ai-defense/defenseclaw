// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "strings"

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

func perlScalarName(tokens []perlToken, arg [2]int) string {
	first := -1
	for i := range tokens {
		if tokens[i].start < arg[0] {
			continue
		}
		if tokens[i].end > arg[1] {
			break
		}
		if first < 0 {
			first = i
		}
	}
	if first >= 0 && first+1 < len(tokens) && tokens[first].text == "$" &&
		tokens[first+1].kind == 'w' && tokens[first+1].end == arg[1] {
		return tokens[first+1].text
	}
	return ""
}

// perlDirectScalarMode proves the small straight-line S1 case. It requires
// one assignment in the same block and no intervening use or redeclaration.
// The remaining S1/S2 forms are added in stage four.
func perlDirectScalarMode(tokens []perlToken, call perlCall, name string) (string, bool) {
	callAt := -1
	for i := range tokens {
		if tokens[i].start == call.start {
			callAt = i
			break
		}
	}
	if callAt < 0 {
		return "", false
	}
	assignment := -1
	for i := 0; i+3 < callAt; i++ {
		if tokens[i].text != "$" || tokens[i+1].text != name ||
			tokens[i+2].text != "=" || tokens[i].block != call.block ||
			tokens[i].modifierLoop {
			continue
		}
		if i > 0 && tokens[i-1].text == "\\" {
			continue
		}
		conditional := false
		for j := i - 1; j >= 0 && tokens[j].text != ";" && tokens[j].text != "{" && tokens[j].text != "}"; j-- {
			switch tokens[j].text {
			case "if", "unless", "while", "until", "for", "foreach":
				conditional = true
			}
		}
		if conditional {
			continue
		}
		assignment = i
	}
	if assignment < 0 {
		return "", false
	}
	for i := assignment + 2; i+1 < callAt; i++ {
		if tokens[i].text == "$" && tokens[i+1].text == name {
			return "", false
		}
		if tokens[i].text == "eval" || tokens[i].text == "do" ||
			tokens[i].text == "require" {
			return "", false
		}
	}
	valueStart := assignment + 3
	if valueStart >= len(tokens) {
		return "", false
	}
	valueEnd := valueStart
	for valueEnd < callAt && tokens[valueEnd].text != ";" &&
		tokens[valueEnd].text != "," && tokens[valueEnd].text != ")" {
		valueEnd++
	}
	if valueEnd == valueStart {
		return "", false
	}
	return perlFixedPath(tokens, tokens[valueStart].start, tokens[valueEnd-1].end)
}

func perlResolveDirectWrites(tokens []perlToken, calls []perlCall) []string {
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
						if mode, proven := perlDirectScalarMode(tokens, call, name); proven && perlThreeArgWriteMode(mode) {
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
			}
		}
	}
	return paths
}
