// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"io"
	"path/filepath"
	"runtime"
	"strings"
)

// plainTouchMissingLeaves proves that a long, literal touch call creates
// ordinary names in one directory. An existing entry needs the usual path
// walk because it may be a link or a second name of a protected file.
func plainTouchMissingLeaves(command, cwd, home string, memo *TargetMemo) ([]string, bool) {
	if runtime.GOOS != "linux" || !filepath.IsAbs(cwd) || !filepath.IsAbs(home) ||
		len(command) > MaxPayloadBytes {
		return nil, false
	}
	words := strings.Fields(command)
	if len(words) < 129 || words[0] != "touch" {
		return nil, false
	}
	for _, word := range words[1:] {
		if len(word) == 0 || !plainTouchNameStart(word[0]) {
			return nil, false
		}
		for i := 1; i < len(word); i++ {
			if !plainTouchNamePart(word[i]) {
				return nil, false
			}
		}
	}
	if memo == nil {
		memo = NewTargetMemo()
	}
	parent, ok := memo.resolveWriteTarget(cwd)
	if !ok || !samePathName(parent, filepath.Clean(cwd)) {
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
	for _, word := range words[1:] {
		if present[word] {
			return nil, false
		}
		target := filepath.Join(parent, word)
		if protected.has(target) || samePathName(target, ssh) {
			return nil, false
		}
	}
	return words[1:], true
}

// OrdinaryLongTouchMissingLeaves proves the bounded long-touch case for a
// local no-answer decision. The same proof is used by the path resolver.
func OrdinaryLongTouchMissingLeaves(command, cwd, home string) bool {
	_, ok := plainTouchMissingLeaves(command, cwd, home, NewTargetMemo())
	return ok
}

func plainTouchNameStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func plainTouchNamePart(c byte) bool {
	return plainTouchNameStart(c) || c == '_' || c == '-' || c == '.'
}
