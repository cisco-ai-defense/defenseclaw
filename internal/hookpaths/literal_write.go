// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

var (
	literalOpenCall    = regexp.MustCompile(`\b(?:open|File\.open|fs\.openSync|os\.open)\s*\(`)
	literalWriteCall   = regexp.MustCompile(`\b(?:appendFileSync|writeFileSync|File\.write|File\.binwrite)\s*\(`)
	literalPathWrite   = regexp.MustCompile(`\b(?:pathlib\.)?Path\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\.write_(?:text|bytes)\s*\(`)
	literalPerlOpen    = regexp.MustCompile(`\bopen\s+\w+\s*,\s*['"](?:>>|>)['"]\s*,\s*['"]([^'"]+)['"]`)
	literalAwkRedirect = regexp.MustCompile(`(?:>>|>)\s*['"]([^'"]+)['"]`)
)

// LiteralWriteOperands lists fixed write paths inside a directly invoked
// interpreter, awk program, or sed in-place command. The shell and gateway
// call this same extractor before resolving each operand through links.
func LiteralWriteOperands(command, cwd, home string) (operands []string) {
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	add := func(name string) {
		if name == "" || strings.ContainsAny(name, "\x00\r\n") {
			return
		}
		if !filepath.IsAbs(name) {
			if !filepath.IsAbs(cwd) {
				return
			}
			name = filepath.Join(cwd, name)
		}
		operands = append(operands, filepath.Clean(name))
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := make([]string, len(call.Args))
		for i, arg := range call.Args {
			var static bool
			words[i], static = StaticWord(arg, home)
			if !static {
				return true
			}
		}
		switch programBase(words[0]) {
		case "python", "python3", "perl", "ruby", "node":
			if len(words) == 3 && (words[1] == "-c" || words[1] == "-e") {
				for _, name := range literalInterpreterWrites(words[2]) {
					add(name)
				}
			}
		case "awk", "gawk", "mawk", "nawk":
			for _, arg := range words[1:] {
				if strings.Contains(arg, "{") {
					for _, match := range literalAwkRedirect.FindAllStringSubmatch(arg, -1) {
						add(match[1])
					}
				}
			}
		case "sed", "gsed":
			if sedFollowsInPlaceLinks(words) {
				for _, name := range sedInPlaceFiles(words) {
					add(name)
				}
			}
		}
		return true
	})
	return operands
}

// SedReplacedOperands names sed -i operands whose directory entry is
// replaced, so a pre-existing link at that entry is not a target write.
func SedReplacedOperands(command, cwd, home string) map[string]bool {
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	replaced := map[string]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := make([]string, len(call.Args))
		for i, arg := range call.Args {
			var static bool
			words[i], static = StaticWord(arg, home)
			if !static {
				return true
			}
		}
		if (programBase(words[0]) == "sed" || programBase(words[0]) == "gsed") &&
			!sedFollowsInPlaceLinks(words) {
			for _, name := range sedInPlaceFiles(words) {
				if !filepath.IsAbs(name) {
					if !filepath.IsAbs(cwd) {
						continue
					}
					name = filepath.Join(cwd, name)
				}
				replaced[filepath.Clean(name)] = true
			}
		}
		return true
	})
	return replaced
}

func sedFollowsInPlaceLinks(words []string) bool {
	for _, word := range words[1:] {
		if word == "--follow-symlinks" {
			return true
		}
	}
	return false
}

func sedInPlaceFiles(words []string) []string {
	inPlace, script := false, false
	var files []string
	for i := 1; i < len(words); i++ {
		word := words[i]
		switch {
		case word == "-i" || word == "--in-place" || strings.HasPrefix(word, "--in-place=") ||
			strings.HasPrefix(word, "-i") && len(word) > 2:
			inPlace = true
		case word == "-e" || word == "--expression":
			i++
			script = true
		case strings.HasPrefix(word, "-e") && len(word) > 2 || strings.HasPrefix(word, "--expression="):
			script = true
		case strings.HasPrefix(word, "-"):
			continue
		case !script:
			script = true
		default:
			files = append(files, word)
		}
	}
	if !inPlace {
		return nil
	}
	return files
}

func literalInterpreterWrites(code string) []string {
	if len(code) > 16<<10 {
		return nil
	}
	var paths []string
	for _, loc := range literalOpenCall.FindAllStringIndex(code, -1) {
		if !literalCodePosition(code, loc[0]) {
			continue
		}
		call, ok := literalBoundedCall(code, loc[1]-1)
		if !ok {
			continue
		}
		args := literalCallArgs(call)
		name := strings.TrimSpace(code[loc[0] : loc[1]-1])
		switch {
		case name == "os.open" && len(args) >= 2 && literalOSWriteFlags(args[1]):
			if path, ok := literalString(args[0]); ok {
				paths = append(paths, path)
			}
		case name == "open" && len(args) >= 3:
			if mode, ok := literalString(args[1]); ok && (mode == ">" || mode == ">>") {
				if path, ok := literalString(args[2]); ok {
					paths = append(paths, path)
				}
			}
		case len(args) >= 2:
			if mode, ok := literalString(args[1]); ok && literalWriteMode(mode) {
				if path, ok := literalString(args[0]); ok {
					paths = append(paths, path)
				}
			}
		}
	}
	for _, loc := range literalWriteCall.FindAllStringIndex(code, -1) {
		if !literalCodePosition(code, loc[0]) {
			continue
		}
		if call, ok := literalBoundedCall(code, loc[1]-1); ok {
			args := literalCallArgs(call)
			if len(args) > 0 {
				if path, ok := literalString(args[0]); ok {
					paths = append(paths, path)
				}
			}
		}
	}
	for _, match := range literalPathWrite.FindAllStringSubmatchIndex(code, -1) {
		if literalCodePosition(code, match[0]) {
			paths = append(paths, code[match[2]:match[3]])
		}
	}
	for _, match := range literalPerlOpen.FindAllStringSubmatchIndex(code, -1) {
		if literalCodePosition(code, match[0]) {
			paths = append(paths, code[match[2]:match[3]])
		}
	}
	return paths
}

func literalWriteMode(mode string) bool {
	return strings.ContainsAny(mode, "wax+") || mode == ">" || mode == ">>"
}

func literalOSWriteFlags(flags string) bool {
	for _, flag := range []string{"O_WRONLY", "O_RDWR", "O_APPEND", "O_TRUNC", "O_CREAT"} {
		if strings.Contains(flags, flag) {
			return true
		}
	}
	return false
}

func literalString(arg string) (string, bool) {
	arg = strings.TrimSpace(arg)
	if len(arg) < 2 || arg[0] != arg[len(arg)-1] || arg[0] != '\'' && arg[0] != '"' {
		return "", false
	}
	value := arg[1 : len(arg)-1]
	if strings.Contains(value, "\\") {
		return "", false
	}
	return value, true
}

func literalBoundedCall(code string, open int) (string, bool) {
	depth := 0
	var quote byte
	for i := open; i < len(code); i++ {
		c := code[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return code[open : i+1], true
			}
		}
	}
	return "", false
}

func literalCallArgs(call string) []string {
	open := strings.IndexByte(call, '(')
	if open < 0 || !strings.HasSuffix(call, ")") {
		return nil
	}
	var args []string
	start, depth := open+1, 0
	var quote byte
	for i := start; i < len(call)-1; i++ {
		c := call[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(call[start:i]))
				start = i + 1
			}
		}
	}
	return append(args, strings.TrimSpace(call[start:len(call)-1]))
}

func literalCodePosition(code string, position int) bool {
	var quote byte
	for i := 0; i < position; i++ {
		c := code[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		} else if c == '\'' || c == '"' {
			quote = c
		}
	}
	return quote == 0
}
