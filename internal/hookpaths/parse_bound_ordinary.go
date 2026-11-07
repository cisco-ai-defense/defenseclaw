// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// ParseBoundOrdinaryKey carries the hook reading of a command whose parse
// exceeded the proof bound ("shell-parse-bound"): "1" when every word of the
// bounded text, read as a path in the file system view of the user, reaches no
// protected or owned place (BoundedTextOrdinary). A gateway behind ProtectHome
// cannot repeat that walk of the links of the user, so it reads this fact as a
// per-user gateway reads its own walk. It is positive evidence only: its
// absence changes nothing, and no value can make a call less restricted.
const ParseBoundOrdinaryKey = "\x00parse-bound-ordinary"

const (
	// boundedTextWordsMax bounds the words, and boundedTextGlobMax the
	// matches of a pattern, the reading examines; more is unproven.
	boundedTextWordsMax = 512
	boundedTextGlobMax  = 64
)

var (
	// boundedTextHomeComputed finds a word that computes a place from the
	// user (a home or user variable, a directory change, a user lookup): the
	// text then holds no path that tells where a write lands.
	boundedTextHomeComputed = lazyregexp.New(`(?i)((\$\{?|env:|%)(home|user|username|logname|userprofile|homepath|homedrive|appdata|localappdata)\b|(^|[\s;&|(` + "`" + `])(cd|pushd|popd|chdir|set-location|getent|whoami|logname)([\s;&|)]|$))`)

	// agentConfigFolders are the folders in which an agent, its hooks or the
	// version control of a project keep settings that can change what runs.
	// A dot-folder of another name is an ordinary one.
	agentConfigFolders = []string{
		".git", ".claude", ".codex", ".cursor", ".gemini", ".opencode", ".kiro", ".github", ".vscode",
		".windsurf", ".amp", ".devin", ".openclaw", ".hermes", ".antigravity", ".copilot", ".config", ".defenseclaw", ".ssh",
	}
)

// BoundedTextOrdinary reports a command, whose parse exceeded the proof
// bound, that provably reaches no protected or owned place: the words of its
// text are bounded in number and none of them (also through a pattern it
// names) is, or sits below, a link on disk, a protected file or folder (the
// authorized-keys files, the SSH folder, a shell startup profile, a Git hook
// or the DefenseClaw state), a folder of an agent or of version control, the
// home itself or one of its dot-entries, or a dot-name that is not an
// existing entry (the part of a name a shell assembles). The hook client
// sends the answer as ParseBoundOrdinaryKey because it alone can read the
// links of the user; false keeps the block the call had.
func BoundedTextOrdinary(command, cwd, home string) bool {
	if command == "" || home == "" || !filepath.IsAbs(cwd) || !filepath.IsAbs(home) || len(command) > MaxPayloadBytes ||
		boundedTextHomeComputed.MatchString(command) || protectedReachFromText(command, cwd, home) {
		return false
	}
	home, cwd = filepath.Clean(home), filepath.Clean(cwd)
	if samePathName(cwd, home) || strings.HasPrefix(strings.ToLower(home), strings.ToLower(cwd)+string(filepath.Separator)) {
		return false
	}
	text := strings.ReplaceAll(strings.ReplaceAll(command, "${HOME}/", home+"/"), "$HOME/", home+"/")
	words := unprovenPathToken.FindAllString(text, boundedTextWordsMax+1)
	for _, quoted := range unprovenQuotedPath {
		for _, match := range quoted.FindAllStringSubmatch(text, boundedTextWordsMax+1) {
			words = append(words, match[1])
		}
	}
	if len(words) > 2*boundedTextWordsMax {
		return false
	}
	roots := boundedTextRoots(home, cwd)
	seen := map[string]bool{}
	for _, word := range words {
		if seen[word] || len(word) > MaxWriteTargetPathBytes || word == "." || word == ".." {
			continue
		}
		seen[word] = true
		if word == "~" || strings.HasPrefix(word, "~/") {
			word = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(word, "~"), "/"))
		}
		path := OperandPath(word, cwd)
		if !strings.ContainsAny(path, "*?[]") {
			if !boundedTextPathOrdinary(path, home, roots) {
				return false
			}
			continue
		}
		// A pattern names what it matches; its folder part has no pattern.
		if strings.ContainsAny(filepath.Dir(path), "*?[]") {
			return false
		}
		matches, err := filepath.Glob(path)
		if err != nil {
			continue // Not a pattern (an incomplete bracket): no path.
		}
		if len(matches) > boundedTextGlobMax {
			return false
		}
		for _, match := range matches {
			if !boundedTextPathOrdinary(match, home, roots) {
				return false
			}
		}
	}
	return true
}

// boundedTextRoots pairs the home and the working directory with their
// physical spellings, so a path below them without a link is told from a path
// through one.
func boundedTextRoots(home, cwd string) [][2]string {
	var roots [][2]string
	for _, root := range []string{cwd, home} {
		if resolved, ok := ResolveWriteTarget(root); ok {
			roots = append(roots, [2]string{root, resolved})
		}
	}
	return roots
}

// boundedTextPathOrdinary reports one absolute path of the bounded text that
// reaches no protected or owned place (BoundedTextOrdinary).
func boundedTextPathOrdinary(path, home string, roots [][2]string) bool {
	path = filepath.Clean(path)
	resolved, ok := ResolveWriteTarget(path)
	if !ok {
		return false
	}
	physical := path
	for _, root := range roots {
		if samePathName(path, root[0]) || strings.HasPrefix(strings.ToLower(path), strings.ToLower(root[0])+string(filepath.Separator)) {
			physical = root[1] + path[len(root[0]):]
			break
		}
	}
	if !samePathName(resolved, physical) || ProtectedOperandName(path, true) || ProtectedOperandName(resolved, true) {
		return false
	}
	// A dot-entry of the home is a profile or the folder of an agent or tool.
	if rel, err := filepath.Rel(home, path); err == nil && rel != "." && !strings.HasPrefix(rel, "..") && strings.HasPrefix(rel, ".") {
		return false
	}
	current := filepath.VolumeName(path)
	for _, part := range strings.Split(filepath.ToSlash(strings.TrimPrefix(path, current)), "/") {
		if part == "" {
			continue
		}
		current = filepath.Join(current+string(filepath.Separator), part)
		if !strings.HasPrefix(part, ".") || part == "." || part == ".." {
			continue
		}
		if slices.Contains(agentConfigFolders, strings.ToLower(part)) {
			return false
		}
		if _, err := os.Lstat(current); err != nil {
			return false // A dot-name the shell may assemble.
		}
	}
	return true
}
