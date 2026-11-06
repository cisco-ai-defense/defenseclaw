// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strings"
	"unicode"
)

// boundProtectedNames are the protected names, in lower case, that
// BoundCallMayNameProtected looks for as a whole path component: the SSH
// folder and keys, the hook settings and configuration folders of the
// supported agents, agent instruction files, shell startup profiles,
// sudoers and Git hooks. A component is a run of letters, digits, "-", "_"
// and "." between any other characters, so settings.json is named by
// ~/.claude/settings.json and by settings.json alone, and is not named by
// notes-settings.json, hooks.log or .config-cache (GAP-0534 review 3). The
// DefenseClaw state is looked for by MayNameState.
var boundProtectedNames = map[string]bool{
	".ssh": true, "authorized_keys": true,
	".claude": true, ".codex": true, ".copilot": true, ".cursor": true, ".config": true, ".gemini": true,
	".hermes": true, ".kiro": true, ".devin": true, "appdata": true,
	"claude.md": true, "agents.md": true, "hooks": true, "hooks.json": true, "core.hookspath": true,
	"settings.json": true, "settings.local.json": true,
	".bashrc": true, "bash.bashrc": true, ".zshrc": true, ".zshenv": true, ".bash_login": true, ".profile": true,
	".bash_profile": true, "zprofile": true, ".zprofile": true, "profile.ps1": true,
	"sudoers": true, "sudoers.d": true,
}

// boundNameMayBeProtected reports a path component that is a protected
// name, or a PowerShell host profile (Microsoft.PowerShell_profile.ps1).
func boundNameMayBeProtected(component string) bool {
	return boundProtectedNames[component] || strings.HasSuffix(component, "_profile.ps1")
}

// boundUnquoteKeepEscapes removes quotes and backticks and keeps backslashes,
// which boundTextNamesProtected reads both ways.
var boundUnquoteKeepEscapes = strings.NewReplacer("\x27", "", "\"", "", "`", "")

func boundNameSeparator(r rune) bool {
	return !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("-_.", r))
}

// boundTextNamesProtected reports whether a path component of text (in
// lower case, quotes removed) is a protected name, with its backslashes
// removed (a POSIX escape) and again with them as separators (a Windows
// path).
func boundTextNamesProtected(text string) bool {
	for _, variant := range []string{
		strings.NewReplacer("\\", "").Replace(text),
		strings.NewReplacer("\\", "/").Replace(text),
	} {
		if slices.ContainsFunc(strings.FieldsFunc(variant, boundNameSeparator), boundNameMayBeProtected) {
			return true
		}
	}
	return false
}

// boundHomeSpellings are the spellings of the home folder, in lower case,
// that BoundCallMayNameProtected reads at the start of a word, besides ~
// and the home path itself.
var boundHomeSpellings = []string{
	"${home}", "$home", "${env:home}", "$env:home", "${env:userprofile}", "$env:userprofile",
	"%userprofile%", "%homepath%", "$env:homepath",
}

// BoundCallMayNameProtected reports whether a command the readers did not
// finish (past the reading bounds, or a recovered parse the unproven-write
// reader stopped at, shell-parse-bound) may name a protected target in its
// text, however it is quoted or escaped: the DefenseClaw state
// (MayNameState), a protected name (boundProtectedNames), or the home folder
// itself, an ancestor of it, or a part of it the text builds at run time or
// matches with a pattern (~, ~user, $HOME, %USERPROFILE%, the home path,
// alone or followed by $, a glob or .., and a relative word that starts
// with ..). An assignment counts like its
// value, so a target reached through a known value is named too. It never
// parses and reads no file, so it costs one pass over the text whatever its
// size. Over-matching only keeps the over-limit block; an ordinary command
// that names none of these gets the evaluation-limit finding the profile
// decides (GAP-0534 and GAP-0677).
func BoundCallMayNameProtected(command, cwd, home string) bool {
	if MayNameState(command) {
		return true
	}
	unquote := strings.NewReplacer("'", "", "\"", "", "\\", "", "`", "")
	text := strings.ToLower(unquote.Replace(command))
	if boundTextNamesProtected(strings.ToLower(boundUnquoteKeepEscapes.Replace(command))) {
		return true
	}
	homeText := strings.TrimRight(strings.ToLower(unquote.Replace(home)), "/")
	cwdText := strings.TrimRight(strings.ToLower(unquote.Replace(cwd)), "/")
	atHome := homeText != "" && cwdText == homeText
	for _, word := range strings.FieldsFunc(text, boundWordSeparator) {
		if boundWordMayReachHome(word, homeText, atHome) {
			return true
		}
	}
	return false
}

func boundWordSeparator(r rune) bool {
	return unicode.IsSpace(r) || strings.ContainsRune(";|&()<>=,", r)
}

// boundWordMayReachHome reports a word that is the home folder, an ancestor
// of it, or a part of it built at run time or matched by a pattern.
func boundWordMayReachHome(word, home string, atHome bool) bool {
	if atHome && boundRestMayReach(word) || strings.HasPrefix(word, "..") {
		// At home any relative word may reach it; anywhere a word that
		// starts with a parent folder may.
		return true
	}
	if word == "/" || home != "" && strings.HasPrefix(word, "/") && strings.HasPrefix(home+"/", strings.TrimRight(word, "/")+"/") {
		return true
	}
	rest, ok := "", false
	switch {
	case strings.HasPrefix(word, "~"):
		// ~ or ~user, then the rest of the path.
		ok = true
		if _, tail, found := strings.Cut(word[1:], "/"); found {
			rest = tail
		}
	case home != "" && strings.HasPrefix(word, home):
		rest, ok = strings.TrimPrefix(word, home), true
		if rest != "" && rest[0] != '/' {
			return false
		}
	default:
		for _, spelling := range boundHomeSpellings {
			if strings.HasPrefix(word, spelling) {
				rest, ok = strings.TrimPrefix(word, spelling), true
				break
			}
		}
	}
	return ok && boundRestMayReach(rest)
}

// boundRestMayReach reports the rest of a home-relative word that leaves
// the home folder itself, its parent, or a part known only at run time. A
// closing brace ends a word of JSON or PowerShell text (a script block),
// not a path.
func boundRestMayReach(rest string) bool {
	rest = strings.Trim(strings.TrimRight(rest, "}"), "/")
	return rest == "" || rest == "." || strings.Contains(rest, "..") || strings.ContainsAny(rest, "$*?[{")
}
