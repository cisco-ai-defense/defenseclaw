// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// actionRecursiveKeyDirectoryRead reports a content reader that walks the
// SSH key directory: grep -r . ~/.ssh, rg . ~/.ssh, cd ~/.ssh && grep -r . .
// It prints every private key the directory holds, as cat of each key does.
// A named file operand is decided by the operand readers, so grep -r Host
// ~/.ssh/config and grep -r marker ~/.ssh/authorized_keys stay plain reads
// (GAP-2168 ruling); only a directory operand is a key read here (RV22-1,
// GAP-0281).
func actionRecursiveKeyDirectoryRead(words []string, cwd, home string, windows bool) bool {
	if len(words) == 0 {
		return false
	}
	program := strings.TrimSuffix(strings.ToLower(programBase(words[0])), ".exe")
	var valueLetters string
	recursive := false
	switch program {
	case "grep", "egrep", "fgrep":
		valueLetters = "efmABCdD"
	case "rg":
		// ripgrep walks a directory operand by default; its -r is --replace.
		valueLetters = "efgtTmABCjMErd"
		recursive = true
	default:
		return false
	}
	var operands []string
	explicitPattern := false
	for i := 1; i < len(words); i++ {
		word := words[i]
		if word == "--" {
			operands = append(operands, words[i+1:]...)
			break
		}
		if strings.HasPrefix(word, "--") {
			name, value, hasValue := strings.Cut(word[2:], "=")
			takesValue := false
			switch name {
			case "recursive", "dereference-recursive":
				recursive = true
			case "regexp", "file":
				explicitPattern, takesValue = true, true
			case "directories":
				takesValue = true
			case "max-count", "after-context", "before-context", "context", "devices", "include",
				"exclude", "exclude-dir", "exclude-from", "label", "binary-files", "glob", "iglob",
				"type", "type-not", "max-depth", "threads", "sort", "sortr", "encoding", "replace",
				"max-filesize", "engine", "path-separator", "ignore-file", "pre", "pre-glob":
				takesValue = true
			}
			if takesValue && !hasValue && i+1 < len(words) {
				i++
				value = words[i]
			}
			if name == "directories" && value == "recurse" {
				recursive = true
			}
			continue
		}
		if len(word) < 2 || word[0] != '-' {
			operands = append(operands, word)
			continue
		}
		for j := 1; j < len(word); j++ {
			letter := word[j]
			if program != "rg" && (letter == 'r' || letter == 'R') {
				recursive = true
			}
			if !strings.ContainsRune(valueLetters, rune(letter)) {
				continue
			}
			value := word[j+1:]
			if value == "" && i+1 < len(words) {
				i++
				value = words[i]
			}
			if letter == 'e' || letter == 'f' {
				explicitPattern = true
			}
			if letter == 'd' && program != "rg" && value == "recurse" {
				recursive = true
			}
			break
		}
	}
	if !recursive {
		return false
	}
	if !explicitPattern && len(operands) != 0 {
		operands = operands[1:]
	}
	if len(operands) == 0 {
		operands = []string{"."}
	}
	for _, operand := range operands {
		if actionKeyDirectory(operand, cwd, home, windows) {
			return true
		}
	}
	return false
}

// actionKeyDirectory reports the SSH key directory, or a directory inside
// it, in any alias the resolver follows.
func actionKeyDirectory(value, cwd, home string, windows bool) bool {
	if value == "" {
		return false
	}
	if windows {
		resolved, ok := actionWindowsPath(value, cwd, home)
		if !ok {
			return false
		}
		root, ok := actionWindowsPath(home, cwd, home)
		if !ok {
			return false
		}
		if resolved == root+"/.ssh" {
			return true
		}
		if !strings.HasPrefix(resolved, root+"/.ssh/") {
			return false
		}
		info, err := os.Stat(resolved)
		return err == nil && info.IsDir()
	}
	ssh, ok := ResolveWriteTarget(filepath.Join(home, ".ssh"))
	if !ok {
		// A managed gateway behind ProtectHome (or the macOS service
		// account, which may name the home but not search it) cannot walk
		// the caller's SSH directory. The directory spelled as itself is
		// still the key directory: a recursive reader of ~/.ssh prints every
		// key there, as it does for the per-user gateway (GAP-2565). A name
		// below it is not read as a directory here, since only a walk could
		// tell a file from one.
		return filepath.IsAbs(home) &&
			samePathName(filepath.Clean(OperandPath(value, cwd)), filepath.Join(filepath.Clean(home), ".ssh"))
	}
	resolved, ok := ResolveWriteTarget(OperandPath(value, cwd))
	if !ok {
		return false
	}
	if samePathName(resolved, ssh) {
		return true
	}
	if !strings.HasPrefix(resolved, ssh+string(filepath.Separator)) {
		return false
	}
	info, err := os.Stat(resolved)
	return err == nil && info.IsDir()
}

// actionWindowsPipedKeyDirectoryRead reports a PowerShell pipeline whose
// head lists the SSH key directory (Get-ChildItem $HOME\.ssh, -Recurse or
// not) and whose stage reads each listed file's content (Select-String,
// Get-Content): Get-ChildItem $HOME\.ssh | Select-String . prints every key
// (RV22-1, GAP-0281).
//
// A content reader given its own path operand (Get-Content -Raw -Path
// notes.txt, Get-Content notes.txt) reads that file, not the piped items, and
// in a POSIX shell cat and type read the listing text on stdin (the GAP-2400
// reader rules, actionIndirectBarePSReader).
func actionWindowsPipedKeyDirectoryRead(head, reader []string, cwd, home string, posix bool) bool {
	if len(head) == 0 || len(reader) == 0 {
		return false
	}
	base := func(word string) string {
		return strings.TrimSuffix(strings.ToLower(programBase(strings.ReplaceAll(word, `\`, "/"))), ".exe")
	}
	switch base(reader[0]) {
	case "select-string", "sls", "format-hex", "fhx":
	case "cat", "type":
		if posix || !actionIndirectBarePSReader(reader) {
			return false
		}
	case "get-content", "gc":
		if !actionIndirectBarePSReader(reader) {
			return false
		}
	default:
		return false
	}
	switch base(head[0]) {
	case "get-childitem", "gci", "dir", "ls", "get-item", "gi":
	default:
		return false
	}
	var paths []string
	publicOnly := false
	for i := 1; i < len(head); i++ {
		word := strings.ToLower(head[i])
		if !strings.HasPrefix(word, "-") {
			paths = append(paths, head[i])
			continue
		}
		switch word {
		case "-path", "-literalpath", "-lp", "-pspath":
			if i+1 < len(head) {
				i++
				paths = append(paths, head[i])
			}
		case "-filter", "-include", "-exclude", "-depth", "-attributes":
			if i+1 < len(head) {
				i++
				if word != "-exclude" && word != "-depth" && word != "-attributes" &&
					strings.HasSuffix(strings.ToLower(strings.Trim(head[i], `'"`)), ".pub") {
					publicOnly = true
				}
			}
		}
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	for _, value := range paths {
		value = strings.Trim(value, `'"`)
		if strings.HasSuffix(strings.ToLower(value), ".pub") {
			continue
		}
		if protected, _ := actionWindowsProtected(value, cwd, home, true); protected {
			return true
		}
		if publicOnly {
			continue
		}
		directory := strings.ReplaceAll(value, `\`, "/")
		if strings.ContainsAny(path.Base(directory), "*?[") {
			directory = path.Dir(directory)
		}
		if actionKeyDirectory(directory, cwd, home, true) {
			return true
		}
	}
	return false
}

// actionCertainDirectoryCalls maps each call that runs only after a cd or
// pushd to one absolute directory succeeded to that cd call: in cd /proj &&
// grep -rn TODO . the grep runs in /proj and in no directory an earlier cd
// named (GAP-2421). Only the statement just before && counts, so a relative
// directory (CDPATH), cd -, a directory set by another program (source,
// eval, a function) and a cd in a subshell or group keep every candidate.
// A right side that may change the directory again (cd -, popd, cd ~-,
// cd "$OLDPWD", a nested shell that does so) keeps every candidate for all
// its calls (RV26-1), and a command with a function, an alias, a trap, eval
// or source keeps them all.
func actionCertainDirectoryCalls(file *syntax.File, home string) map[*syntax.CallExpr]*syntax.CallExpr {
	certain := make(map[*syntax.CallExpr]*syntax.CallExpr)
	opaque := false
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.FuncDecl:
			opaque = true
		case *syntax.CallExpr:
			if len(node.Args) == 0 {
				break
			}
			program, static := StaticWord(node.Args[0], home)
			switch program {
			case "eval", "source", ".", "trap", "alias", "builtin", "command":
				opaque = true
			}
			opaque = opaque || !static
		}
		return !opaque
	})
	if opaque {
		return certain
	}
	// syntax.Walk visits an outer && before the ones inside its right side,
	// so the innermost cd a call depends on is the one kept.
	syntax.Walk(file, func(node syntax.Node) bool {
		binary, ok := node.(*syntax.BinaryCmd)
		if !ok || binary.Op != syntax.AndStmt {
			return true
		}
		last := binary.X
		for {
			inner, ok := last.Cmd.(*syntax.BinaryCmd)
			if !ok || inner.Op != syntax.AndStmt {
				break
			}
			last = inner.Y
		}
		cd, ok := last.Cmd.(*syntax.CallExpr)
		if !ok || last.Negated || last.Background || last.Coprocess || len(last.Redirs) != 0 ||
			len(cd.Assigns) != 0 || len(cd.Args) != 2 {
			return true
		}
		program, programStatic := StaticWord(cd.Args[0], home)
		target, targetStatic := StaticWord(cd.Args[1], home)
		if !programStatic || !targetStatic || program != "cd" && program != "pushd" || !filepath.IsAbs(target) {
			return true
		}
		if actionMayChangeDirectory(binary.Y, home) {
			return true
		}
		syntax.Walk(binary.Y, func(inner syntax.Node) bool {
			if call, ok := inner.(*syntax.CallExpr); ok {
				certain[call] = cd
			}
			return true
		})
		return true
	})
	return certain
}

// actionMayChangeDirectory reports a command that names a directory change
// anywhere in its text, quoted shell bodies included: cd, pushd, popd,
// Set-Location and its aliases, ~- or OLDPWD (RV26-1). Any such mention may
// take a later reader back to an earlier directory, so it is never certain.
// Each whole word is judged, both as the shell expands it and as its literal
// text with quotes, backslashes and brace punctuation removed, so a program
// split across parts (c\d, "c"d, c'd', an empty quote pair inside cd or
// popd) or a nested body that does so (bash -c 'c""d -') still counts
// (RV-it2-1).
func actionMayChangeDirectory(node syntax.Node, home string) bool {
	inToken := func(r rune) bool {
		return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '~' || r == '-'
	}
	mentionsText := func(text string) bool {
		for _, token := range strings.FieldsFunc(text, func(r rune) bool { return !inToken(r) }) {
			switch strings.ToLower(token) {
			case "cd", "chdir", "pushd", "popd", "sl", "set-location", "push-location", "pop-location", "~-", "oldpwd":
				return true
			}
		}
		return false
	}
	joined := strings.NewReplacer(`'`, "", `"`, "", `\`, "", "{", "", "}", "", ",", "", "`", "")
	mentions := func(text string) bool {
		return mentionsText(text) || mentionsText(joined.Replace(text))
	}
	found := false
	syntax.Walk(node, func(inner syntax.Node) bool {
		switch inner := inner.(type) {
		case *syntax.Word:
			if value, static := StaticWord(inner, home); static && mentions(value) {
				found = true
			} else if mentions(actionWordLiteralText(inner)) {
				found = true
			}
		case *syntax.ParamExp:
			found = found || inner.Param != nil && mentions(inner.Param.Value)
		}
		return !found
	})
	return found
}

// actionWordLiteralText is the literal text of a word with its quoting
// taken off: the parts of c\d, "c"d and c'd' joined as cd. An expansion
// adds nothing.
func actionWordLiteralText(word *syntax.Word) string {
	var text strings.Builder
	var add func(parts []syntax.WordPart)
	add = func(parts []syntax.WordPart) {
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				text.WriteString(part.Value)
			case *syntax.SglQuoted:
				text.WriteString(part.Value)
			case *syntax.DblQuoted:
				add(part.Parts)
			}
		}
	}
	add(word.Parts)
	return text.String()
}

// actionWindowsCertainLocation reports a location statement whose success
// a following && statement needs to place it in next and nowhere earlier
// (GAP-2421). cmd's cd and chdir without /d change the directory of the
// named drive only, so they are certain only when every earlier candidate
// is on that drive; cd - and cd + return to an earlier directory.
func actionWindowsCertainLocation(statement []string, next string, earlier []string) bool {
	if operand := strings.TrimSpace(statement[1]); operand == "-" || operand == "+" || strings.HasPrefix(operand, "-") {
		return false
	}
	switch strings.TrimSuffix(strings.ToLower(programBase(strings.ReplaceAll(statement[0], `\`, "/"))), ".exe") {
	case "sl", "set-location", "pushd", "push-location":
		return true
	case "cd", "chdir":
		drive := actionWindowsDrive(next)
		if drive == "" {
			return false
		}
		for _, dir := range earlier {
			if actionWindowsDrive(dir) != drive {
				return false
			}
		}
		return true
	}
	return false
}

// actionWindowsStatementNamesLocation reports a flat Windows statement with
// a location program in any word, a leading ( { or & taken off: ( cd -,
// (Set-Location -), (popd (RV26-1).
func actionWindowsStatementNamesLocation(statement []string) bool {
	for _, word := range statement {
		if actionWindowsLocationProgram(strings.TrimLeft(word, "({&")) {
			return true
		}
	}
	return false
}

// actionWindowsUngroupedStatement is a flat Windows statement without the
// grouping around it: (grep -r . .) reads as grep -r . . (RV26-1).
func actionWindowsUngroupedStatement(statement []string) []string {
	if len(statement) == 0 {
		return statement
	}
	words := append([]string(nil), statement...)
	if first := strings.TrimLeft(words[0], "({"); first == "" {
		words = words[1:]
	} else {
		words[0] = first
	}
	if len(words) == 0 {
		return words
	}
	if last := strings.TrimRight(words[len(words)-1], ")}"); last == "" {
		words = words[:len(words)-1]
	} else {
		words[len(words)-1] = last
	}
	return words
}

// actionWindowsDrive is the lower-case drive letter of an absolute Windows
// path (C:\x, C:/x), or "" for any other spelling.
func actionWindowsDrive(dir string) string {
	if len(dir) >= 3 && asciiLetter(dir[0]) && dir[1] == ':' && (dir[2] == '\\' || dir[2] == '/') {
		return strings.ToLower(dir[:1])
	}
	return ""
}
