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
		return false
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
func actionWindowsPipedKeyDirectoryRead(head, reader []string, cwd, home string) bool {
	if len(head) == 0 || len(reader) == 0 {
		return false
	}
	base := func(word string) string {
		return strings.TrimSuffix(strings.ToLower(programBase(strings.ReplaceAll(word, `\`, "/"))), ".exe")
	}
	switch base(reader[0]) {
	case "select-string", "sls", "get-content", "gc", "cat", "type", "format-hex", "fhx":
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
// A command that defines its own cd or pushd keeps them all too.
func actionCertainDirectoryCalls(file *syntax.File, home string) map[*syntax.CallExpr]*syntax.CallExpr {
	certain := make(map[*syntax.CallExpr]*syntax.CallExpr)
	redefined := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if decl, ok := node.(*syntax.FuncDecl); ok && decl.Name != nil {
			if name := decl.Name.Value; name == "cd" || name == "pushd" {
				redefined = true
			}
		}
		return !redefined
	})
	if redefined {
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

// actionWindowsDrive is the lower-case drive letter of an absolute Windows
// path (C:\x, C:/x), or "" for any other spelling.
func actionWindowsDrive(dir string) string {
	if len(dir) >= 3 && asciiLetter(dir[0]) && dir[1] == ':' && (dir[2] == '\\' || dir[2] == '/') {
		return strings.ToLower(dir[:1])
	}
	return ""
}
