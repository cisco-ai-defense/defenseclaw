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
// and "." between any other characters, so .bashrc is named by ~/.bashrc
// and by .bashrc alone, and is not named by my_profile.txt or .config-cache
// (GAP-0534 review 3). The hook settings names (boundFolderNames) count
// only in an agent folder. The DefenseClaw state is looked for by
// MayNameState.
var boundProtectedNames = map[string]bool{
	".ssh": true, "authorized_keys": true,
	".claude": true, ".codex": true, ".copilot": true, ".cursor": true, ".config": true, ".gemini": true,
	".hermes": true, ".kiro": true, ".devin": true, "appdata": true,
	"claude.md": true, "agents.md": true, "core.hookspath": true,
	".bashrc": true, "bash.bashrc": true, ".zshrc": true, ".zshenv": true, ".bash_login": true, ".profile": true,
	".bash_profile": true, "zprofile": true, ".zprofile": true, "profile.ps1": true,
	"sudoers": true, "sudoers.d": true,
}

// boundFolderNames are the protected names, in lower case, that are agent
// hook settings or Git hooks only inside a folder of boundAgentFolders: a
// project document called settings.json or hooks.json, or a project folder
// called hooks, is an ordinary target (GAP-0534 review 6).
var boundFolderNames = map[string]bool{
	"hooks": true, "hooks.json": true, "settings.json": true, "settings.local.json": true,
}

// boundAgentFolders are the folders, in lower case, whose boundFolderNames
// are protected: the agent configuration folders and the Git folder.
var boundAgentFolders = map[string]bool{
	".claude": true, ".codex": true, ".copilot": true, ".cursor": true, ".config": true, ".gemini": true,
	".hermes": true, ".kiro": true, ".devin": true, "appdata": true, ".git": true,
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
	return !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("-_.", r)
}

// boundTextNamesProtected reports whether a path component of text (in
// lower case, quotes removed) is a protected name, with its backslashes
// removed (a POSIX escape) and again with them as separators (a Windows
// path). A name of boundFolderNames counts when its folder may be an agent
// folder: the folder the word gives is built at run time, matched by a
// pattern or reached through .., or the word gives none and the working
// directory cwd (lower case, / separators) is in an agent folder or unknown,
// or the folder the word gives, or cwd, is in an agent folder, or the text
// names a variable that moves an agent folder (CLAUDE_CONFIG_DIR,
// CODEX_HOME).
func boundTextNamesProtected(text, cwd string) bool {
	anyFolder := cwd == "" || strings.Contains(text, "config_dir") || strings.Contains(text, "codex_home") ||
		boundInAgentFolder(cwd)
	for _, variant := range []string{
		strings.NewReplacer("\\", "").Replace(text),
		strings.NewReplacer("\\", "/").Replace(text),
	} {
		for _, word := range strings.FieldsFunc(variant, boundWordSeparator) {
			// The folder the word gives so far: whether it has an agent
			// folder, and whether it is built at run time.
			agentFolder, unknownFolder := false, false
			for _, segment := range strings.Split(word, "/") {
				for _, component := range strings.FieldsFunc(segment, boundNameSeparator) {
					if boundNameMayBeProtected(component) {
						return true
					}
					if !boundFolderNames[component] {
						continue
					}
					before, _, _ := strings.Cut(segment, component)
					if anyFolder || agentFolder || unknownFolder || boundFolderUnknown(before) {
						return true
					}
				}
				agentFolder = agentFolder || boundAgentFolders[segment]
				unknownFolder = unknownFolder || boundFolderUnknown(segment)
			}
		}
	}
	return false
}

// boundInAgentFolder reports a folder (lower case, / separators) with a
// component of boundAgentFolders.
func boundInAgentFolder(folder string) bool {
	return slices.ContainsFunc(strings.Split(folder, "/"), func(component string) bool { return boundAgentFolders[component] })
}

// boundFolderUnknown reports a folder part of a word that is built at run
// time, matched by a pattern or reached through .., so it may be an agent
// folder.
func boundFolderUnknown(folder string) bool {
	return strings.ContainsAny(folder, "$%*?[{`") || strings.Contains(folder, "..")
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
// size. The gateway adds the evaluation-limit finding, which the profile
// decides, to a call of the nested-body proof band whose text may name one
// of these; over-matching only adds that finding (GAP-0677).
func BoundCallMayNameProtected(command, cwd, home string) bool {
	if MayNameState(command) {
		return true
	}
	unquote := strings.NewReplacer("'", "", "\"", "", "\\", "", "`", "")
	text := strings.ToLower(unquote.Replace(command))
	folderCWD := ""
	if cwd != "" {
		folderCWD = strings.ToLower(strings.ReplaceAll(cwd, "\\", "/"))
	}
	if boundTextNamesProtected(strings.ToLower(boundUnquoteKeepEscapes.Replace(command)), folderCWD) {
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
