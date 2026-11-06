// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"io"
	"path/filepath"
	"runtime"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// plainTouchMissingLeaves proves that a long, literal touch call creates
// ordinary names in one directory. An existing entry needs the usual path
// walk because it may be a link or a second name of a protected file.
func plainTouchMissingLeaves(command, cwd, home string, memo *TargetMemo) ([]string, bool) {
	if runtime.GOOS != "linux" || !filepath.IsAbs(cwd) || !filepath.IsAbs(home) ||
		len(command) > MaxPayloadBytes || strings.ContainsAny(command, "\r\n") {
		return nil, false
	}
	words, literal := plainTouchWords(command, cwd, home)
	if !literal {
		return nil, false
	}
	if len(words) < 129 || words[0] != "touch" {
		return nil, false
	}
	// This proof only handles options that never name another path. A
	// reference or unfamiliar option takes the full path reader.
	names := make([]string, 0, len(words)-1)
	endOptions := false
	for i := 1; i < len(words); i++ {
		word := words[i]
		if !endOptions && word == "--" {
			endOptions = true
			continue
		}
		if !endOptions && (word == "--no-create" || word == "--time=access" ||
			word == "--time=modify" || word == "--time=atime" || word == "--time=mtime" ||
			word == "--no-dereference") {
			continue
		}
		if !endOptions && (word == "-d" || word == "--date") {
			i++
			if i == len(words) || words[i] == "" {
				return nil, false
			}
			continue
		}
		if !endOptions && (strings.HasPrefix(word, "--date=") && len(word) > len("--date=") ||
			strings.HasPrefix(word, "-d") && len(word) > 2) {
			continue
		}
		if !endOptions && word == "-t" {
			i++
			if i == len(words) || !plainTouchTimestamp(words[i]) {
				return nil, false
			}
			continue
		}
		if !endOptions && strings.HasPrefix(word, "-t") && plainTouchTimestamp(word[2:]) {
			continue
		}
		if !endOptions && len(word) > 1 && word[0] == '-' && word[1] != '-' &&
			strings.Trim(word[1:], "amcfh") == "" {
			continue
		}
		if !endOptions && strings.HasPrefix(word, "-") {
			return nil, false
		}
		// Both relative and absolute words must name one leaf of the same
		// proved directory. Other paths keep the full link-aware reader.
		if filepath.IsAbs(word) {
			prefix := filepath.Clean(cwd)
			if prefix != string(filepath.Separator) {
				prefix += string(filepath.Separator)
			}
			if !strings.HasPrefix(word, prefix) {
				return nil, false
			}
			word = strings.TrimPrefix(word, prefix)
		}
		for strings.HasPrefix(word, "./") {
			word = word[2:]
		}
		if word == "" || word == "." || word == ".." || strings.ContainsAny(word, "/\x00") {
			return nil, false
		}
		names = append(names, word)
	}
	if len(names) < 128 {
		return nil, false
	}
	if memo == nil {
		memo = NewTargetMemo()
	}
	parent, ok := memo.resolveWriteTarget(cwd)
	if !ok {
		return nil, false
	}
	for _, root := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw")} {
		resolved, ok := memo.resolveWriteTarget(root)
		if !ok {
			return nil, false
		}
		if rel, err := filepath.Rel(resolved, parent); err != nil ||
			rel == "." || rel == ".." || !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, false
		}
	}
	dir, err := pathOpen(parent)
	if err != nil {
		return nil, false
	}
	entries, readErr := dir.ReadDir(4097)
	closeErr := dir.Close()
	if len(entries) > 4096 || readErr != nil && readErr != io.EOF || closeErr != nil {
		return nil, false
	}
	present := make(map[string]bool, len(entries))
	for _, entry := range entries {
		present[entry.Name()] = true
	}
	protected := memo.protectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	for _, word := range names {
		if present[word] {
			return nil, false
		}
		target := filepath.Join(parent, word)
		if protected.has(target) || samePathName(target, ssh) {
			return nil, false
		}
	}
	return names, true
}

// The fast spelling remains allocation-light. Other shell spellings resolve
// bounded literal and known HOME/PWD words; unknown values and extra
// statements cannot acquire a missing-leaf proof.
func plainTouchWords(command, cwd, home string) ([]string, bool) {
	if !strings.ContainsAny(command, "'\"\\;|&<>(){}$`*?[]#") {
		return strings.Fields(command), true
	}
	file, ok := parseShell(command)
	if !ok || len(file.Stmts) != 1 {
		return nil, false
	}
	stmt := file.Stmts[0]
	if stmt.Negated || stmt.Background || stmt.Coprocess || len(stmt.Redirs) != 0 {
		return nil, false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 {
		return nil, false
	}
	words := make([]string, 0, len(call.Args))
	for _, arg := range call.Args {
		if !lateKnownWordParts(arg) || actionWordHasUnquotedGlob(arg, command) {
			return nil, false
		}
		value, ok := lateKnownWord(arg, cwd, home)
		if !ok {
			return nil, false
		}
		words = append(words, value)
	}
	return words, true
}

func plainTouchTimestamp(value string) bool {
	if len(value) != 8 && len(value) != 10 && len(value) != 12 &&
		len(value) != 11 && len(value) != 13 && len(value) != 15 {
		return false
	}
	for i, c := range value {
		if c == '.' && i == len(value)-3 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// OrdinaryLongTouchMissingLeaves proves the bounded long-touch case for a
// local no-answer decision. The same proof is used by the path resolver.
func OrdinaryLongTouchMissingLeaves(command, cwd, home string) bool {
	_, ok := plainTouchMissingLeaves(command, cwd, home, NewTargetMemo())
	return ok
}
