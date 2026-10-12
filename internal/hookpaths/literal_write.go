// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

var (
	literalOpenCall    = regexp.MustCompile(`\b(?:open|File\.open|fs\.openSync|os\.open)\s*\(`)
	literalWriteCall   = regexp.MustCompile(`\b(?:appendFileSync|writeFileSync|createWriteStream|File\.write|File\.binwrite)\s*\(`)
	literalPathWrite   = regexp.MustCompile(`\b(?:pathlib\.)?Path\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\.write_(?:text|bytes)\s*\(`)
	literalPathOpen    = regexp.MustCompile(`\b(?:pathlib\.)?Path\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\.open\s*\(`)
	literalPerlOpen    = regexp.MustCompile(`\bopen\s*(?:\(\s*)?(?:my\s+)?\$?\w+\s*,\s*['"](?:>>|>)['"]\s*,\s*['"]([^'"]+)['"]`)
	literalPerlOpen2   = regexp.MustCompile(`\bopen\s*(?:\(\s*)?(?:my\s+)?\$?\w+\s*,\s*['"](?:>>|>)([^'"]+)['"]`)
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
	add := func(name, base string) {
		if name == "" || strings.ContainsAny(name, "\x00\r\n") {
			return
		}
		if !filepath.IsAbs(name) && !filepath.IsAbs(base) {
			return
		}
		operands = append(operands, OperandPath(name, base))
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if pipe, ok := node.(*syntax.BinaryCmd); ok && pipe.Op == syntax.Pipe {
			cmdCWD, code, ok := literalPipelineInterpreterInput(pipe, command, cwd, home)
			if ok {
				for _, name := range literalInterpreterWrites(code) {
					add(name, cmdCWD)
				}
			}
			return true
		}
		if stmt, ok := node.(*syntax.Stmt); ok {
			call, ok := stmt.Cmd.(*syntax.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			cmdCWD, programWords, ok := literalProgramWords(call, cwd, home)
			if !ok || len(programWords) == 0 {
				return true
			}
			program := programBase(programWords[0])
			if !literalInterpreterProgram(program) || !literalReadsStdin(programWords) {
				return true
			}
			for _, redirect := range stmt.Redirs {
				if (redirect.Op != syntax.Hdoc && redirect.Op != syntax.DashHdoc) || redirect.Hdoc == nil {
					continue
				}
				start, end := int(redirect.Hdoc.Pos().Offset()), int(redirect.Hdoc.End().Offset())
				if start < 0 || end > len(command) || end <= start {
					continue
				}
				for _, name := range literalInterpreterWrites(command[start:end]) {
					add(name, cmdCWD)
				}
			}
			for _, redirect := range stmt.Redirs {
				if redirect.Op != syntax.WordHdoc || redirect.Word == nil {
					continue
				}
				code, static := staticShellWordWithVars(redirect.Word, home, nil, shellVariablePoison{})
				if !static {
					continue
				}
				for _, name := range literalInterpreterWrites(code) {
					add(name, cmdCWD)
				}
			}
			return true
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		cmdCWD, programWords, ok := literalProgramWords(call, cwd, home)
		if !ok || len(programWords) == 0 {
			return true
		}
		program := programBase(programWords[0])
		switch {
		case literalInterpreterProgram(program):
			for i := 1; i+1 < len(programWords); i++ {
				if programWords[i] == "-c" || programWords[i] == "-e" {
					for _, name := range literalInterpreterWrites(programWords[i+1]) {
						add(name, cmdCWD)
					}
					break
				}
			}
		case program == "awk" || program == "gawk" || program == "mawk" || program == "nawk":
			for _, arg := range programWords[1:] {
				if strings.Contains(arg, "{") {
					for _, match := range literalAwkRedirect.FindAllStringSubmatch(arg, -1) {
						add(match[1], cmdCWD)
					}
				}
			}
		case program == "sed" || program == "gsed":
			for _, name := range sedInPlaceFiles(programWords) {
				if sedFollowsInPlaceLinks(programWords) || sedParentProtected(name, cmdCWD, home) {
					add(name, cmdCWD)
				}
			}
		}
		return true
	})
	return operands
}

func literalProgramWords(call *syntax.CallExpr, cwd, home string) (string, []string, bool) {
	words := make([]string, len(call.Args))
	for i, arg := range call.Args {
		var static bool
		words[i], static = staticShellWordWithVars(arg, home, nil, shellVariablePoison{})
		if !static {
			return cwd, nil, false
		}
	}
	cmdCWD, words, ok := envCommandWords(words, cwd)
	if !ok {
		return cwd, nil, false
	}
	for len(words) > 1 && (programBase(words[0]) == "busybox" || programBase(words[0]) == "toybox") {
		words = words[1:]
	}
	return cmdCWD, words, true
}

func literalInterpreterProgram(program string) bool {
	return program == "python" || strings.HasPrefix(program, "python3") ||
		program == "perl" || program == "ruby" || program == "node"
}

func literalReadsStdin(words []string) bool {
	sawOperand := false
	for _, word := range words[1:] {
		if word == "-c" || word == "-e" {
			return false
		}
		if word == "-" {
			return true
		}
		if word == "--" {
			sawOperand = true
			continue
		}
		if strings.HasPrefix(word, "-") && word != "-" {
			if word == "-m" || word == "-S" || word == "-x" || word == "-I" {
				continue
			}
			continue
		}
		sawOperand = true
	}
	return !sawOperand
}

func literalPipelineInterpreterInput(
	pipe *syntax.BinaryCmd, command, cwd, home string,
) (string, string, bool) {
	if pipe == nil || pipe.X == nil || pipe.Y == nil {
		return "", "", false
	}
	call, ok := pipe.Y.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return "", "", false
	}
	cmdCWD, programWords, ok := literalProgramWords(call, cwd, home)
	if !ok || len(programWords) == 0 || !literalInterpreterProgram(programBase(programWords[0])) ||
		!literalReadsStdin(programWords) {
		return "", "", false
	}
	code, ok := literalProducerCode(pipe.X, command, home)
	return cmdCWD, code, ok
}

func literalProducerCode(stmt *syntax.Stmt, command, home string) (string, bool) {
	if stmt == nil {
		return "", false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return "", false
	}
	_, words, ok := literalProgramWords(call, "", home)
	if !ok || len(words) == 0 {
		return "", false
	}
	switch programBase(words[0]) {
	case "echo":
		return strings.Join(words[1:], " ") + "\n", true
	case "printf":
		if len(words) < 2 || strings.Contains(words[1], "%") {
			return "", false
		}
		return words[1], true
	case "cat":
		for _, redirect := range stmt.Redirs {
			if (redirect.Op != syntax.Hdoc && redirect.Op != syntax.DashHdoc) || redirect.Hdoc == nil {
				continue
			}
			start, end := int(redirect.Hdoc.Pos().Offset()), int(redirect.Hdoc.End().Offset())
			if start >= 0 && end <= len(command) && end > start {
				return command[start:end], true
			}
		}
	}
	return "", false
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
					name = OperandPath(name, cwd)
				}
				parent, ok := ResolveWriteTarget(rawParent(name))
				if !ok {
					continue
				}
				entry := filepath.Join(parent, filepath.Base(name))
				protected := false
				for _, path := range ProtectedAuthorizedKeysPaths(home) {
					if samePathName(entry, path) {
						protected = true
						break
					}
				}
				if !protected {
					replaced[name] = true
					if link, err := os.Readlink(name); err == nil &&
						(strings.Contains(filepath.ToSlash(link), "/../") || strings.HasSuffix(filepath.ToSlash(link), "/..")) {
						replaced[name] = false
					}
				}
			}
		}
		return true
	})
	return replaced
}

func sedParentProtected(name, cwd, home string) bool {
	parent, ok := ResolveWriteTarget(rawParent(OperandPath(name, cwd)))
	if !ok {
		return true
	}
	entry := filepath.Join(parent, filepath.Base(name))
	for _, path := range ProtectedAuthorizedKeysPaths(home) {
		if samePathName(entry, path) {
			return true
		}
	}
	return false
}

func rawParent(path string) string {
	index := strings.LastIndexAny(path, `/\`)
	if index < 0 {
		return "."
	}
	if index == 0 {
		return path[:1]
	}
	return path[:index]
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
		case name == "open" && len(args) >= 3 && perlRedirectMode(args[1]):
			if mode, ok := literalString(args[1]); ok && (mode == ">" || mode == ">>") {
				if path, ok := literalString(args[2]); ok {
					paths = append(paths, path)
				}
			}
		case len(args) >= 1:
			modeArg := ""
			if len(args) >= 2 {
				modeArg = args[1]
			}
			for _, arg := range args[1:] {
				if strings.HasPrefix(strings.TrimSpace(arg), "mode=") {
					modeArg = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(arg), "mode="))
				}
			}
			if mode, ok := literalString(modeArg); ok && literalWriteMode(mode) {
				if path, ok := literalString(args[0]); ok {
					paths = append(paths, path)
				}
			}
		}
	}
	for _, match := range literalPathOpen.FindAllStringSubmatchIndex(code, -1) {
		if !literalCodePosition(code, match[0]) {
			continue
		}
		call, ok := literalBoundedCall(code, match[1]-1)
		if !ok {
			continue
		}
		args := literalCallArgs(call)
		modeArg := ""
		if len(args) >= 1 {
			modeArg = args[0]
		}
		for _, arg := range args {
			if strings.HasPrefix(strings.TrimSpace(arg), "mode=") {
				modeArg = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(arg), "mode="))
			}
		}
		if mode, ok := literalString(modeArg); ok && literalWriteMode(mode) {
			paths = append(paths, code[match[2]:match[3]])
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
	for _, match := range literalPerlOpen2.FindAllStringSubmatchIndex(code, -1) {
		if literalCodePosition(code, match[0]) {
			paths = append(paths, code[match[2]:match[3]])
		}
	}
	return paths
}

func perlRedirectMode(arg string) bool {
	mode, ok := literalString(arg)
	return ok && (mode == ">" || mode == ">>")
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
