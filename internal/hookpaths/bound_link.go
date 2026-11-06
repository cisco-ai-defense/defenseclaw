// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
)

// maxBoundLinkWords is the number of distinct words of one call that
// BoundCallReachesProtectedLink looks up. A call with more is not looked up:
// it counts as reaching a protected file, because a reading that stops
// early lets a long run of words push the one that matters out of it.
const maxBoundLinkWords = 4096

// BoundCallReachesProtectedLink reports whether a word of a command the
// readers did not finish (BoundCallMayNameProtected: past the reading
// bounds, or a recovered parse the unproven-write reader stopped at) is a
// file or folder that a link, or a second name of the same file, makes a
// protected target: a link in the project that points at the keys file,
// an agent settings file or the DefenseClaw state, named directly or through
// a value the command assigns. The text of the command does not show it,
// so every word that can be a path is looked up as the user, without
// reading any file. It runs only for a call past a reading bound, and
// costs at most maxBoundLinkWords lookups. The hook client calls it as the
// user, and sends the answer (ActionDecisionKey), because a gateway behind
// ProtectHome cannot see the links.
func BoundCallReachesProtectedLink(command, cwd, home string) bool {
	if home == "" || !filepath.IsAbs(home) || !filepath.IsAbs(cwd) {
		return false
	}
	separators := ""
	if runtime.GOOS == "windows" {
		separators = "/"
	}
	text := strings.NewReplacer("\x27", "", "\"", "", "`", "", "\\", separators,
		"${HOME}", home, "$HOME", home, "${env:HOME}", home, "$env:HOME", home,
		"${env:USERPROFILE}", home, "$env:USERPROFILE", home, "%USERPROFILE%", home).Replace(command)
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	seen := map[string]bool{}
	for _, word := range strings.FieldsFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune(";|&()<>=,{}", r) || r == 0x3a && runtime.GOOS != "windows"
	}) {
		if seen[word] || len(word) > MaxWriteTargetPathBytes ||
			strings.ContainsAny(word, "*?[]$\x00") || strings.HasPrefix(word, "-") && !strings.Contains(word, "/") {
			continue
		}
		if seen[word] = true; len(seen) > maxBoundLinkWords {
			return true
		}
		path := word
		switch {
		case word == "~":
			continue
		case strings.HasPrefix(word, "~/"):
			path = filepath.Join(home, word[2:])
		case strings.HasPrefix(word, "~"):
			continue
		}
		path = OperandPath(path, cwd)
		resolved, ok := ResolveWriteTarget(path)
		if !ok {
			continue
		}
		if protected.has(resolved) || samePathName(resolved, ssh) {
			return true
		}
		if mapped, ok := protected.target(resolved); ok && protected.has(mapped) {
			return true
		}
		if !samePathName(resolved, path) && BoundCallMayNameProtected(resolved, cwd, home) {
			return true
		}
	}
	return false
}
