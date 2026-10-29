// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

var (
	literalOpenCall         = regexp.MustCompile(`\b(?:open|File\.open|fs\.openSync|os\.open|(?:io\.)?FileIO)\s*\(`)
	literalWriteCall        = regexp.MustCompile(`\b(?:appendFileSync|writeFileSync|File\.write|File\.binwrite)\s*\(`)
	literalNodeStream       = regexp.MustCompile(`\brequire\s*\(\s*['"]fs['"]\s*\)\s*\.createWriteStream\s*\(`)
	literalPathWrite        = regexp.MustCompile(`\b(?:pathlib\.)?Path\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\.write_(?:text|bytes)\s*\(`)
	literalPathOpen         = regexp.MustCompile(`\b(?:pathlib\.)?Path\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\.open\s*\(\s*['"]([waxr][waxr+bt]*)['"]\s*\)`)
	literalPythonPathCall   = regexp.MustCompile(`\b(?:pathlib\.)?Path\s*\(`)
	literalPerlOpen         = regexp.MustCompile(`\bopen\s+(?:my\s+)?(?:\$?\w+)\s*,\s*['"](?:>>|>)['"]\s*,\s*['"]([^'"]+)['"]`)
	literalCopyCall         = regexp.MustCompile(`\b(?:shutil\.(?:copyfile|copy|copy2)|copyFileSync|copyFile|copyfile|copy2|(?:File::Copy::)?copy)\s*\(`)
	literalPythonCopyImport = regexp.MustCompile(`\bfrom\s+shutil\s+import\s+copyfile\b`)
	literalPerlCopy         = regexp.MustCompile(`\b(?:File::Copy::)?copy\s+['"][^'"]+['"]\s*,\s*(['"][^'"]+['"])`)
	literalPerlImport       = regexp.MustCompile(`\buse\s+File::Copy\b`)
)

// LiteralWriteOperands lists fixed write paths inside a directly invoked
// interpreter, awk program, or sed in-place command. The shell and gateway
// call this same extractor before resolving each operand through links.
func LiteralWriteOperands(command, cwd, home string) (operands []string) {
	return literalWriteOperandsDepth(command, cwd, home, 0)
}

func literalWriteOperandsDepth(command, cwd, home string, depth int) (operands []string) {
	if depth > 4 {
		return nil
	}
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	add := func(name string) {
		if name == "" || strings.ContainsAny(name, "\x00\r\n") {
			return
		}
		if !filepath.IsAbs(name) && !filepath.IsAbs(cwd) {
			return
		}
		operands = append(operands, OperandPath(name, cwd))
	}
	boundName, boundValue := boundedProgramAssignment(file, home)
	// The values the command assigns before each top-level statement, so an
	// awk word built from them is read as the shell expands it (GAP-2197,
	// GAP-0509): out=alias; awk "BEGIN {print 1 >> \"$out\"}".
	before := make([]actionValues, len(file.Stmts))
	values := actionValues{"HOME": home, "PWD": cwd}
	for i, stmt := range file.Stmts {
		before[i] = maps.Clone(values)
		actionUpdateValues(stmt, values, cwd, home)
	}
	valuesAt := func(node syntax.Node) actionValues {
		for i, stmt := range file.Stmts {
			if node.Pos().Offset() >= stmt.Pos().Offset() && node.End().Offset() <= stmt.End().Offset() {
				return before[i]
			}
		}
		return nil
	}
	// A definition runs nothing. A body is read once, where it is defined,
	// when the command may call it, so an uncalled body stays inert.
	called := calledFunctions(file, home)
	syntax.Walk(file, func(node syntax.Node) bool {
		if declaration, isFunction := node.(*syntax.FuncDecl); isFunction {
			return declaration.Name != nil && called[declaration.Name.Value]
		}
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := make([]string, len(call.Args))
		for i, arg := range call.Args {
			var static bool
			words[i], static = StaticWord(arg, home)
			if i == 0 && !static && simpleShellParameter(arg) == boundName {
				words[i], static = boundValue, true
			}
			if !static && i > 0 && (awkProgramName(words[0]) || programBase(words[0]) == "tee" && wordExpandsParameter(arg)) {
				// An awk word the command assigned (GAP-2197), or a tee
				// operand named by an assigned variable or a ${f:-default}
				// the shell expands to its default (GAP-2514). A generated
				// basename has no fixed spelling and stays dynamic.
				if known := valuesAt(stmt); known != nil {
					if value, fixed := actionWordValue(shellUnescapedWord(arg), known, cwd, home); fixed &&
						!strings.Contains(value, actionGeneratedMarker) {
						words[i], static = value, true
					}
				}
			}
			if !static {
				// Interpreter arguments after fixed code do not change that
				// code. Keep its write operands even though argv is dynamic.
				if i > 0 && fixedInterpreterCodePrefix(words[:i]) {
					for _, name := range literalProgramOperands(words[:i], stmt, cwd, home, depth, len(file.Stmts) == 1) {
						add(name)
					}
				} else if i > 0 && awkProgramName(words[0]) {
					// A double-quoted awk program with an expansion: its
					// literal print targets stay targets (GAP-2197).
					if text, rendered := awkRenderedProgram(arg); rendered {
						prefix := append(append([]string(nil), words[:i]...), text)
						for _, name := range literalProgramOperands(prefix, stmt, cwd, home, depth, len(file.Stmts) == 1) {
							add(name)
						}
					}
				}
				return true
			}
		}
		for _, name := range literalProgramOperands(words, stmt, cwd, home, depth, len(file.Stmts) == 1) {
			add(name)
		}
		return true
	})
	operands = append(operands, literalPipelineOperands(file, called, cwd, home, depth)...)
	operands = append(operands, literalGeneratedScriptOperands(file, cwd, home, depth)...)
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

// InPlaceEditOperands lists the files a sed -i or perl -i call of the
// command edits in place, as absolute paths read in cwd, whatever their
// parent directory. The editor replaces the directory entry; a caller that
// follows the name through a link the same command makes to a directory
// reads the file the edit replaces (GAP-2522).
func InPlaceEditOperands(command, cwd, home string) (operands []string) {
	file, ok := parseShell(command)
	if !ok || !filepath.IsAbs(cwd) {
		return nil
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := make([]string, len(call.Args))
		static := make([]bool, len(call.Args))
		for i, arg := range call.Args {
			words[i], static[i] = StaticWord(arg, home)
		}
		if index, wrapped := plainWrappedChild(words, static); wrapped {
			words, static = words[index:], static[index:]
		}
		if slices.Contains(static, false) {
			return true
		}
		var files []string
		switch programBase(words[0]) {
		case "sed", "gsed":
			files = sedInPlaceFiles(words)
		case "perl":
			files = perlInPlaceFiles(words)
		}
		for _, name := range files {
			if name != "" && !strings.ContainsAny(name, "\x00\r\n") {
				operands = append(operands, OperandPath(name, cwd))
			}
		}
		return true
	})
	return operands
}

// perlInPlaceFiles lists the file operands of perl -i (-pi -e CODE FILE,
// -i.bak -ne CODE FILE). Without -e the first operand is the script.
func perlInPlaceFiles(words []string) []string {
	inPlace, script := false, false
	var files []string
	for i := 1; i < len(words); i++ {
		word := words[i]
		switch {
		case word == "--":
			files = append(files, words[i+1:]...)
			i = len(words)
		case strings.HasPrefix(word, "-") && len(word) > 1 && !strings.HasPrefix(word, "--"):
			cluster := word[1:]
			for j := 0; j < len(cluster); j++ {
				switch string(cluster[j]) {
				case "i":
					inPlace = true
					j = len(cluster) // the rest is the backup suffix
				case "e", "E":
					script = true
					if j == len(cluster)-1 {
						i++
					}
					j = len(cluster)
				case "I", "M", "m", "x", "C", "d", "D", "F", "0":
					j = len(cluster) // takes the rest of the word
				}
			}
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

func literalInterpreterWrites(code, language, cwd, home string) []string {
	if len(code) > 16<<10 {
		return nil
	}
	pathString := literalString
	if language == "python" || strings.HasPrefix(language, "python3") {
		pathString = literalPythonString
	}
	var paths []string
	for _, loc := range literalOpenCall.FindAllStringIndex(code, -1) {
		if !literalCodePosition(code, loc[0], language) {
			continue
		}
		call, ok := literalBoundedCall(code, loc[1]-1)
		if !ok {
			continue
		}
		args := literalCallArgs(call)
		name := strings.TrimSpace(code[loc[0] : loc[1]-1])
		if (name == "FileIO" || name == "io.FileIO") && language != "python" {
			continue
		}
		switch {
		case name == "os.open" && len(args) >= 2 && literalOSWriteFlags(args[1]):
			if path, ok := pathString(args[0]); ok {
				paths = append(paths, path)
			}
		case name == "open" && len(args) >= 3 && perlRedirectMode(args[1]):
			if mode, ok := literalString(args[1]); ok && (mode == ">" || mode == ">>") {
				if path, ok := pathString(args[2]); ok {
					paths = append(paths, path)
				}
			}
		case len(args) >= 1:
			pathArg := args[0]
			if language == "python" {
				pathArg = literalCallArgument(args, 0, "file")
			}
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
				if path, ok := pathString(pathArg); ok {
					paths = append(paths, path)
				}
			}
		}
	}
	for _, loc := range literalWriteCall.FindAllStringIndex(code, -1) {
		if !literalCodePosition(code, loc[0], language) {
			continue
		}
		if call, ok := literalBoundedCall(code, loc[1]-1); ok {
			args := literalCallArgs(call)
			if len(args) > 0 {
				if path, ok := pathString(args[0]); ok {
					paths = append(paths, path)
				}
			}
		}
	}
	for _, loc := range literalNodeStream.FindAllStringIndex(code, -1) {
		if !literalCodePosition(code, loc[0], language) {
			continue
		}
		if call, ok := literalBoundedCall(code, loc[1]-1); ok {
			args := literalCallArgs(call)
			if len(args) > 0 {
				if path, ok := pathString(args[0]); ok {
					paths = append(paths, path)
				}
			}
		}
	}
	perlCopyImported := false
	pythonCopyfileImported := false
	if language == "python" {
		for _, loc := range literalPythonCopyImport.FindAllStringIndex(code, -1) {
			if literalCodePosition(code, loc[0], language) {
				pythonCopyfileImported = true
				break
			}
		}
	}
	if language == "perl" {
		for _, loc := range literalPerlImport.FindAllStringIndex(code, -1) {
			if literalCodePosition(code, loc[0], language) {
				perlCopyImported = true
				break
			}
		}
	}
	for _, loc := range literalCopyCall.FindAllStringIndex(code, -1) {
		if !literalCodePosition(code, loc[0], language) {
			continue
		}
		name := strings.TrimSpace(code[loc[0] : loc[1]-1])
		if !literalCopyAPI(language, name, perlCopyImported) &&
			(language != "python" || name != "copyfile" || !pythonCopyfileImported) {
			continue
		}
		if call, ok := literalBoundedCall(code, loc[1]-1); ok {
			args := literalCallArgs(call)
			if len(args) >= 2 {
				destination := args[1]
				if language == "python" {
					destination = literalCallArgument(args, 1, "dst")
				}
				if path, ok := pathString(destination); ok {
					paths = append(paths, path)
					if language == "python" && (name == "shutil.copy" || name == "shutil.copy2") {
						source := literalCallArgument(args, 0, "src")
						if sourcePath, fixed := pathString(source); fixed {
							if info, err := os.Stat(OperandPath(path, cwd)); err == nil && info.IsDir() {
								paths = append(paths, filepath.Join(path, filepath.Base(sourcePath)))
							}
						}
					}
				}
			}
		}
	}
	if language == "perl" {
		for _, match := range literalPerlCopy.FindAllStringSubmatchIndex(code, -1) {
			name := "copy"
			if strings.HasPrefix(code[match[0]:match[1]], "File::Copy::copy") {
				name = "File::Copy::copy"
			}
			if literalCodePosition(code, match[0], language) &&
				literalCopyAPI(language, name, perlCopyImported) {
				if path, ok := pathString(code[match[2]:match[3]]); ok {
					paths = append(paths, path)
				}
			}
		}
	}
	for _, match := range literalPathWrite.FindAllStringSubmatchIndex(code, -1) {
		if literalCodePosition(code, match[0], language) {
			paths = append(paths, code[match[2]:match[3]])
		}
	}
	for _, match := range literalPathOpen.FindAllStringSubmatchIndex(code, -1) {
		if literalCodePosition(code, match[0], language) &&
			(strings.HasPrefix(code[match[0]:match[1]], "pathlib.") ||
				strings.Contains(code[:match[0]], "from pathlib import Path")) &&
			validPythonWriteMode(code[match[4]:match[5]]) {
			paths = append(paths, code[match[2]:match[3]])
		}
	}
	if language == "python" || strings.HasPrefix(language, "python3") {
		for _, loc := range unprovenWriter.FindAllStringIndex(code, -1) {
			name := strings.TrimSpace(code[loc[0] : loc[1]-1])
			if (name != "write_text" && name != "write_bytes") || !pythonExecutableCodePosition(code, loc[0]) {
				continue
			}
			if destination, fixed := pythonReboundReceiver(code, loc[1], home); fixed {
				paths = append(paths, destination)
			}
		}
		for _, match := range literalPathHomeJoinOpen.FindAllStringSubmatchIndex(code, -1) {
			if !pythonExecutableCodePosition(code, match[0]) {
				continue
			}
			call, fixed := literalBoundedCall(code, match[1]-1)
			if !fixed {
				continue
			}
			args := literalCallArgs(call)
			if len(args) == 0 {
				continue
			}
			if mode, fixed := literalString(args[0]); fixed && literalWriteMode(mode) {
				paths = append(paths, filepath.Join(home, code[match[2]:match[3]]))
			}
		}
		for _, loc := range literalPythonPathCall.FindAllStringIndex(code, -1) {
			if !pythonExecutableCodePosition(code, loc[0]) {
				continue
			}
			call, fixed := literalBoundedCall(code, loc[1]-1)
			if !fixed {
				continue
			}
			end := loc[1] - 1 + len(call)
			if end > len(code) {
				continue
			}
			suffix := code[end:]
			if !strings.HasPrefix(suffix, ".write_text(") && !strings.HasPrefix(suffix, ".write_bytes(") &&
				!strings.HasPrefix(suffix, ".open(") {
				continue
			}
			args := literalCallArgs(call)
			if len(args) != 1 {
				continue
			}
			path, fixed := literalPythonString(args[0])
			if !fixed {
				continue
			}
			if strings.HasPrefix(suffix, ".open(") {
				open, known := literalBoundedCall(suffix, len(".open"))
				if !known {
					continue
				}
				arguments := literalCallArgs(open)
				if len(arguments) == 0 {
					continue
				}
				mode, known := literalString(arguments[0])
				if !known || !literalWriteMode(mode) {
					continue
				}
			}
			paths = append(paths, path)
		}
	}
	for _, match := range literalPerlOpen.FindAllStringSubmatchIndex(code, -1) {
		if literalCodePosition(code, match[0], language) {
			paths = append(paths, code[match[2]:match[3]])
		}
	}
	return paths
}

func literalCallArgument(args []string, position int, keyword string) string {
	for _, arg := range args {
		name, value, found := strings.Cut(strings.TrimSpace(arg), "=")
		if found && strings.TrimSpace(name) == keyword {
			return strings.TrimSpace(value)
		}
	}
	if position < len(args) {
		return args[position]
	}
	return ""
}

func literalCopyAPI(language, name string, perlImported bool) bool {
	switch language {
	case "python":
		return strings.HasPrefix(name, "shutil.")
	case "node":
		return name == "copyFileSync" || name == "copyFile"
	case "perl":
		return name == "File::Copy::copy" || name == "copy" && perlImported
	}
	return false
}

func perlRedirectMode(arg string) bool {
	mode, ok := literalString(arg)
	return ok && (mode == ">" || mode == ">>")
}

func literalWriteMode(mode string) bool {
	return strings.ContainsAny(mode, "wax+") || mode == ">" || mode == ">>"
}

func validPythonWriteMode(mode string) bool {
	if mode == "" || !strings.ContainsRune("waxr", rune(mode[0])) {
		return false
	}
	plus, binary, text := 0, 0, 0
	for _, flag := range mode[1:] {
		switch flag {
		case '+':
			plus++
		case 'b':
			binary++
		case 't':
			text++
		default:
			return false
		}
	}
	return plus <= 1 && binary+text <= 1 && (mode[0] != 'r' || plus == 1)
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
	if strings.Contains(value, "\\") || strings.ContainsRune(value, rune(arg[0])) {
		return "", false
	}
	return value, true
}

// Python folds adjacent literal strings and literal + literal at compile
// time. Accept only those bounded forms when proving a path argument.
func literalPythonString(arg string) (string, bool) {
	if value, ok := literalString(arg); ok {
		return value, true
	}
	arg = strings.TrimSpace(arg)
	if len(arg) > MaxWriteTargetPathBytes || len(arg) < 4 {
		return "", false
	}
	var out strings.Builder
	segments := 0
	for pos := 0; pos < len(arg); {
		quote := arg[pos]
		if quote != '\'' && quote != '"' {
			return "", false
		}
		pos++
		start := pos
		for pos < len(arg) && arg[pos] != quote {
			if arg[pos] == '\\' {
				return "", false
			}
			pos++
		}
		if pos == len(arg) {
			return "", false
		}
		out.WriteString(arg[start:pos])
		segments++
		pos++
		for pos < len(arg) && (arg[pos] == ' ' || arg[pos] == '\t') {
			pos++
		}
		if pos < len(arg) && arg[pos] == '+' {
			pos++
			for pos < len(arg) && (arg[pos] == ' ' || arg[pos] == '\t') {
				pos++
			}
			if pos == len(arg) {
				return "", false
			}
		}
	}
	return out.String(), segments > 1
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

func literalCodePosition(code string, position int, language string) bool {
	var quote byte
	comment := false
	perlHashDelimiters := 0
	for i := 0; i < position; i++ {
		c := code[i]
		if comment {
			if c == '\n' {
				comment = false
			}
			continue
		}
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		} else if c == '\'' || c == '"' {
			quote = c
		} else if c == '#' {
			if language == "perl" && perlHashDelimiters > 0 {
				perlHashDelimiters--
			} else if language == "perl" && perlHashRegexpStart(code, i) > 0 {
				perlHashDelimiters = perlHashRegexpStart(code, i)
			} else if literalCommentStart(code, i, language) {
				comment = true
			}
		}
	}
	return quote == 0 && !comment
}

func perlHashRegexpStart(code string, i int) int {
	for _, operator := range []string{"s", "m", "qr", "tr", "y"} {
		start := i - len(operator)
		if start < 0 || code[start:i] != operator ||
			start > 0 && !strings.ContainsRune(" \t\n;=~(", rune(code[start-1])) {
			continue
		}
		if operator == "m" || operator == "qr" {
			return 1
		}
		return 2
	}
	return 0
}

func literalCommentStart(code string, i int, language string) bool {
	switch language {
	case "python", "ruby":
		return true
	case "perl":
		// Perl's $#name is an array index, not a comment.
		return i == 0 || code[i-1] != '$'
	default:
		// JavaScript uses # in private names, not for comments.
		return false
	}
}

// shellUnescapedWord is word with the backslashes the shell removes taken
// out of its literal parts: any escaped byte outside quotes, and an escaped
// $, `, ", \ or newline inside double quotes. Single-quoted text is kept.
// The word itself is not changed.
func shellUnescapedWord(word *syntax.Word) *syntax.Word {
	if word == nil {
		return nil
	}
	var convert func(parts []syntax.WordPart, quoted bool) []syntax.WordPart
	convert = func(parts []syntax.WordPart, quoted bool) []syntax.WordPart {
		out := make([]syntax.WordPart, 0, len(parts))
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				if !strings.Contains(part.Value, "\\") {
					out = append(out, part)
					continue
				}
				var value strings.Builder
				for i := 0; i < len(part.Value); i++ {
					c := part.Value[i]
					if c == '\\' && i+1 < len(part.Value) && (!quoted || strings.IndexByte("$`\"\\\n", part.Value[i+1]) >= 0) {
						i++
						if part.Value[i] == '\n' {
							continue // a line continuation
						}
						c = part.Value[i]
					}
					value.WriteByte(c)
				}
				copied := *part
				copied.Value = value.String()
				out = append(out, &copied)
			case *syntax.DblQuoted:
				copied := *part
				copied.Parts = convert(part.Parts, true)
				out = append(out, &copied)
			default:
				out = append(out, part)
			}
		}
		return out
	}
	copied := *word
	copied.Parts = convert(word.Parts, false)
	return &copied
}

func awkProgramName(word string) bool {
	switch programBase(word) {
	case "awk", "gawk", "mawk", "nawk":
		return true
	}
	return false
}

// wordExpandsParameter reports a word that contains a parameter expansion.
func wordExpandsParameter(word *syntax.Word) bool {
	found := false
	syntax.Walk(word, func(node syntax.Node) bool {
		if _, ok := node.(*syntax.ParamExp); ok {
			found = true
		}
		return !found
	})
	return found
}
