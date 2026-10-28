// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path"
	"path/filepath"
	"strings"
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
