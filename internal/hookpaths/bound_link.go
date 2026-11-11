// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"regexp"
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
	words := strings.FieldsFunc(text, boundLinkWordSeparator)
	if strings.Contains(text, "$") {
		// A word the call builds from values is looked up as the text
		// shows it built too (GAP-0677 review 6).
		words = append(words, strings.FieldsFunc(boundKnownValuesText(text, cwd, home), boundLinkWordSeparator)...)
	}
	for _, word := range words {
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

func boundLinkWordSeparator(r rune) bool {
	return unicode.IsSpace(r) || strings.ContainsRune(";|&()<>=,{}", r) || r == 0x3a && runtime.GOOS != "windows"
}

// boundValueReference is a value the shell or PowerShell expands: ${name},
// $(command), $name.
var boundValueReference = regexp.MustCompile(`\$\{[^{}]*\}|\$\([^()]*\)|\$[A-Za-z_][A-Za-z0-9_:]*`)

// boundAssignment is an assignment the text makes: name=value or
// name+=value, and the PowerShell $name = value (quotes already removed).
var boundAssignment = regexp.MustCompile(`(?:^|[\s;&|(])\$?([A-Za-z_][A-Za-z0-9_]*)\s*(\+?)=\s*([^\s;&|()<>]*)`)

// boundKnownValuesText is text with each value reference replaced by what the
// text shows of it: the value the assignments give it (an appended value
// joined), the working directory for PWD and the home folder for HOME. Any
// other reference (a command substitution, a value the text does not set)
// is left out, as an empty value would be. Names are read in lower case, so
// a PowerShell and a shell spelling meet. It is one pass over the text for
// the assignments and one for the references.
func boundKnownValuesText(text, cwd, home string) string {
	values := map[string]string{"pwd": cwd, "home": home}
	expand := func(value string) string {
		return boundValueReference.ReplaceAllStringFunc(value, func(reference string) string {
			name := strings.ToLower(strings.Trim(reference, "${}"))
			return values[strings.TrimPrefix(name, "env:")]
		})
	}
	for _, assignment := range boundAssignment.FindAllStringSubmatch(text, -1) {
		name, value := strings.ToLower(assignment[1]), expand(assignment[3])
		if assignment[2] == "+" {
			value = values[name] + value
		}
		values[name] = value
	}
	return expand(text)
}
