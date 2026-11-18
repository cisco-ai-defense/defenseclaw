// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A write cmdlet's -Path (or -FilePath, -Destination, positional path) is a
// wildcard pattern, and -Include and -Filter narrow the items it reaches:
// the cmdlet writes every item the pattern matches. The reading of the
// statement as written names the pattern, which is no protected file, so a
// Remove-Item or Set-Content of <hook folder>/* or <state folder>/* proved
// no protected write and was allowed (rel-1-0-10:GAP-1272). Each protected
// file such a pattern can match is read as the write of that file at the
// unknown tier (alert by default, block in strict), the reading of a .NET
// write of a folder's children (psFolderTwin, rel-1-0-10:GAP-1257); a pattern
// that can match no protected file adds nothing. -LiteralPath (and its
// aliases) is no pattern and keeps its literal reading.

// psWildcardRole is what a write cmdlet does to the items a pattern matches.
type psWildcardRole int

const (
	// psWildcardNone: the items are only read (the Copy-Item source).
	psWildcardNone psWildcardRole = iota
	// psWildcardWrite: each item is written in place (Set-Content).
	psWildcardWrite
	// psWildcardRemove: each item is removed, moved, renamed or copied
	// over, with every file a folder among them holds.
	psWildcardRemove
)

// psWildcardSlot is a positional parameter of a write cmdlet: its name
// (path for -Path, -FilePath and -LiteralPath) and the role of its items.
type psWildcardSlot struct {
	param string
	role  psWildcardRole
}

// psWildcardRoles returns, for a mutator cmdlet (psMutatorCmdlet), its
// positional parameters in order and the role of each positional word past
// them. A parameter bound by name takes no positional word: the next one
// binds the next slot, as PowerShell binds them.
func psWildcardRoles(cmdlet string) (slots []psWildcardSlot, rest psWildcardRole) {
	switch strings.ToLower(cmdlet) {
	case "remove-item", "ri", "rm", "rmdir", "rd", "del", "erase":
		// A native rm of pwsh on Linux and macOS takes every operand, and
		// pwsh expands its patterns.
		return []psWildcardSlot{{"path", psWildcardRemove}}, psWildcardRemove
	case "rename-item", "rni", "ren":
		return []psWildcardSlot{{"path", psWildcardRemove}, {"newname", psWildcardNone}}, psWildcardNone
	case "move-item", "mi", "mv", "move":
		return []psWildcardSlot{{"path", psWildcardRemove}, {"destination", psWildcardRemove}}, psWildcardRemove
	case "copy-item", "cpi", "cp", "copy":
		return []psWildcardSlot{{"path", psWildcardNone}, {"destination", psWildcardRemove}}, psWildcardRemove
	case "set-content", "sc", "add-content", "ac", "clear-content", "clc", "out-file",
		"new-item", "ni", "clear-item", "cli", "set-item", "si", "tee-object", "tee":
		// The next positional word is the value, encoding or name.
		return []psWildcardSlot{{"path", psWildcardWrite}}, psWildcardNone
	}
	return nil, psWildcardNone
}

// psWildcardSlotRole is the role of the slot param of slots.
func psWildcardSlotRole(slots []psWildcardSlot, param string) psWildcardRole {
	for _, slot := range slots {
		if slot.param == param {
			return slot.role
		}
	}
	return psWildcardNone
}

// psResolveParameter returns the full name of a parameter (without its
// dash) as PowerShell binds it: the known parameter it spells or the only
// one it is a prefix of (psKnownParameters); matches counts the known
// parameters it may be (1 when it is one).
func psResolveParameter(name string) (full string, matches int) {
	for _, known := range psKnownParameters {
		if strings.EqualFold(known, name) {
			return known, 1
		}
		if len(name) <= len(known) && strings.EqualFold(known[:len(name)], name) {
			full = known
			matches++
		}
	}
	return full, matches
}

// psWildcardPath is one path value of a write cmdlet and its role.
type psWildcardPath struct {
	word string
	role psWildcardRole
}

// psWildcardWriteTwins returns the unknown-tier twins of the protected files
// the path patterns of a write cmdlet statement may write: one
// Set-Content -LiteralPath <file> -Value x for an item written in place, one
// Remove-Item -LiteralPath <item> -Recurse -Force for an item removed, moved
// or copied over (and every file it holds). A pattern whose folder the
// reading cannot place is read as the removal of that folder (psFolderTwin).
func psWildcardWriteTwins(statement string, reading psReading, budget *psBudget) []string {
	if !strings.ContainsAny(statement, "*?[") || reading.protected.empty() {
		return nil
	}
	words := psJoinListWords(psWords(statement, budget), budget)
	if budget.over || len(words) < 2 || !psMutatorCmdlet(words[0].text) {
		return nil
	}
	slots, rest := psWildcardRoles(words[0].text)
	var paths []psWildcardPath
	var positional, filters []string
	bound := map[string]bool{}
	recurse := false
	for k := 1; k < len(words); k++ {
		word := words[k]
		if word.quoted || len(word.text) < 2 || word.text[0] != '-' || !unicode.IsLetter(rune(word.text[1])) {
			positional = append(positional, word.text)
			continue
		}
		name, value, joined := strings.Cut(word.text[1:], ":")
		full, matches := psResolveParameter(name)
		if matches != 1 {
			// An unknown parameter: PowerShell refuses the statement.
			continue
		}
		if !joined && !psSwitchParameter(full) && k+1 < len(words) {
			k++
			value = words[k].text
		}
		switch param := strings.ToLower(full); param {
		case "path", "filepath":
			bound["path"] = true
			paths = append(paths, psWildcardPath{value, psWildcardSlotRole(slots, "path")})
		case "literalpath", "pspath", "lp":
			// The item as written: no pattern.
			bound["path"] = true
		case "destination":
			bound[param] = true
			paths = append(paths, psWildcardPath{value, psWildcardSlotRole(slots, param)})
		case "include", "filter":
			for _, filter := range psSplitArgumentTexts(value, budget) {
				filter = psUnquote(filter, budget)
				if cut := strings.LastIndexAny(filter, `/\`); cut >= 0 {
					filter = filter[cut+1:]
				}
				if filter != "" {
					filters = append(filters, filter)
				}
			}
		case "recurse":
			recurse = true
		default:
			bound[param] = true
		}
	}
	free := slices.DeleteFunc(slices.Clone(slots), func(slot psWildcardSlot) bool { return bound[slot.param] })
	for k, word := range positional {
		role := rest
		if k < len(free) {
			role = free[k].role
		}
		paths = append(paths, psWildcardPath{word, role})
	}
	var twins []string
	for _, path := range paths {
		if path.role == psWildcardNone {
			continue
		}
		for _, element := range psSplitArgumentTexts(path.word, budget) {
			twins = append(twins, psWildcardElementTwins(element, path.role, filters, recurse, reading, budget)...)
		}
	}
	return twins
}

// psWildcardElementTwins returns the twins of one path element (a word or
// one item of a comma list) of role. When the hook client placed the element
// (the pattern as written, links walked as the user), each twin's file is
// recorded in reading.placed at the folder the client walked to: a managed
// gateway proves a write only of a path the client placed.
func psWildcardElementTwins(element string, role psWildcardRole, filters []string, recurse bool, reading psReading, budget *psBudget) []string {
	home := reading.merge.home
	inner := psUnquote(element, budget)
	wild := strings.ContainsAny(inner, "*?[")
	if !wild && len(filters) == 0 || strings.ContainsAny(inner, "()") {
		return nil
	}
	folder, pattern, rest, placed := psWildcardFolder(inner, home, reading.merge.cwd)
	if !placed {
		// Where the pattern lies is known only at run time: every file
		// the folder before its first wildcard holds may be written.
		if twin := psFolderTwin("-Path "+element, home); twin != "" {
			return []string{twin}
		}
		return nil
	}
	// -Include and -Filter keep the items whose name one of them matches,
	// and reach the children of a folder the path names.
	type psWildcardPattern struct {
		components []string
		filtered   bool
	}
	var patterns []psWildcardPattern
	if len(pattern) > 0 {
		patterns = append(patterns, psWildcardPattern{pattern, len(filters) > 0})
	}
	for _, filter := range filters {
		patterns = append(patterns, psWildcardPattern{append(slices.Clone(pattern), filter), false})
	}
	physical := ""
	if value, ok := reading.targets[inner]; ok && (strings.HasPrefix(value, "/") || psDriveComponent(psFirst(value))) {
		physical = value
		if rest != "" {
			physical = ""
			if strings.HasSuffix(value, rest) && len(value) > len(rest)+1 {
				physical = value[:len(value)-len(rest)-1]
			}
		}
	}
	var twins []string
	for _, pattern := range patterns {
		for _, rel := range reading.protected.matches(folder, pattern.components, recurse, role == psWildcardRemove) {
			if pattern.filtered && !slices.ContainsFunc(filters, func(filter string) bool { return psWildcardMatch(filter, rel[len(rel)-1]) }) {
				continue
			}
			path := psComponentsPath(append(slices.Clone(folder), rel...))
			if physical != "" && reading.placed != nil {
				reading.placed[path] = psComponentsPath(append(psPathComponents(physical, true), rel...))
			}
			file := managed.PowerShellLiteral(path)
			// The write of the item: under a Linux or macOS home only a
			// Set-Content twin is read as the file write it is
			// (psPOSIXWriteTwin).
			twins = append(twins, "Set-Content -LiteralPath "+file+" -Value x")
			if role == psWildcardRemove {
				twins = append(twins, "Remove-Item -LiteralPath "+file+" -Recurse -Force")
			}
		}
	}
	return twins
}

// psFirst is the first component of a path.
func psFirst(path string) string {
	if components := psPathComponents(path, false); len(components) > 0 {
		return components[0]
	}
	return ""
}

// psWildcardHomeAnchors are the spellings of the user home that start a
// path the reading places (PowerShell's ~ and $HOME, and the profile
// variables).
var psWildcardHomeAnchors = []string{"~", "${home}", "$home", "${env:userprofile}", "$env:userprofile", "${env:home}", "$env:home"}

// psWildcardFolder splits a path value at the last separator before its
// first wildcard: folder is the part before it as the components of an
// absolute path (a home spelling written as home, a relative one read in
// cwd), pattern the components after it, rest their text. A value with no
// wildcard is all folder. placed is false when the folder spells a value
// known only at run time, or the home or working directory it needs is not
// known.
func psWildcardFolder(inner, home, cwd string) (folder, pattern []string, rest string, placed bool) {
	text := inner
	if wild := strings.IndexAny(inner, "*?["); wild >= 0 {
		cut := strings.LastIndexAny(inner[:wild], `/\`)
		text, rest = "", inner
		if cut >= 0 {
			text, rest = inner[:cut], inner[cut+1:]
			if cut == 0 {
				text = inner[:1]
			}
		}
	}
	lower := strings.ToLower(text)
	for _, anchor := range psWildcardHomeAnchors {
		if lower == anchor || strings.HasPrefix(lower, anchor+"/") || strings.HasPrefix(lower, anchor+`\`) {
			if home == "" {
				return nil, nil, "", false
			}
			text = strings.TrimRight(home, `/\`) + text[len(anchor):]
			break
		}
	}
	if strings.ContainsAny(text, "$`{}@") || strings.HasPrefix(text, `\\`) || strings.HasPrefix(text, "//") {
		return nil, nil, "", false
	}
	switch {
	case len(text) >= 2 && text[1] == ':':
	case strings.HasPrefix(text, "/") || strings.HasPrefix(text, `\`):
		if len(home) >= 2 && home[1] == ':' {
			// The root of the drive of the home.
			text = home[:2] + text
		}
	case cwd == "":
		return nil, nil, "", false
	default:
		text = cwd + "/" + text
	}
	folder = psPathComponents(text, true)
	for _, component := range psPathComponents(rest, false) {
		if component == ".." {
			return nil, nil, "", false
		}
		pattern = append(pattern, component)
	}
	return folder, pattern, rest, true
}

// psPathComponents splits a path at its separators, without empty and .
// components; steps resolves .. (else it is kept).
func psPathComponents(path string, steps bool) []string {
	var out []string
	for _, component := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		switch {
		case component == ".":
		case component == ".." && steps:
			if len(out) > 0 && !(len(out) == 1 && psDriveComponent(out[0])) {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, component)
		}
	}
	return out
}

// psDriveComponent reports a drive component (C:).
func psDriveComponent(component string) bool {
	return len(component) == 2 && component[1] == ':'
}

// psComponentsPath joins the components of an absolute path: a drive path
// with backslashes, any other with slashes from the root.
func psComponentsPath(components []string) string {
	if len(components) > 0 && psDriveComponent(components[0]) {
		if len(components) == 1 {
			return components[0] + `\`
		}
		return strings.Join(components, `\`)
	}
	return "/" + strings.Join(components, "/")
}

// psProtectedPaths are the protected files a wildcard pattern may match:
// anchored are absolute paths, as components; floating are the trailing
// components of a protected file in any folder (a project's
// .claude/settings.json, a state file in a .defenseclaw folder).
type psProtectedPaths struct {
	anchored, floating [][]string
}

// newPSProtectedPaths returns the protected paths of anchored absolute
// paths and floating suffixes, each once.
func newPSProtectedPaths(anchored, floating []string) psProtectedPaths {
	var out psProtectedPaths
	seen := map[string]bool{}
	add := func(list *[][]string, path string, steps bool) {
		components := psPathComponents(path, steps)
		key := strings.ToLower(strings.Join(components, "/"))
		if len(components) == 0 || seen[key] {
			return
		}
		seen[key] = true
		*list = append(*list, components)
	}
	for _, path := range anchored {
		add(&out.anchored, path, true)
	}
	for _, path := range floating {
		add(&out.floating, path, false)
	}
	return out
}

func (p psProtectedPaths) empty() bool { return len(p.anchored) == 0 && len(p.floating) == 0 }

// matches returns, as components under folder, each item the pattern
// (components under folder) may match that is a protected file or, when
// ancestors is set, a folder that holds one. recurse lets the last
// component of the pattern match at any depth below the others (-Recurse).
// A folder that is a protected folder or lies in one (a state tree) is
// matched as the pattern itself: whatever it matches there is protected.
func (p psProtectedPaths) matches(folder, pattern []string, recurse, ancestors bool) [][]string {
	var out [][]string
	seen := map[string]bool{}
	add := func(rel []string) {
		key := strings.ToLower(strings.Join(rel, "/"))
		if !seen[key] {
			seen[key] = true
			out = append(out, rel)
		}
	}
	try := func(rel []string) {
		if len(rel) == 0 {
			// The folder is the protected item or lies in it.
			add(pattern)
			return
		}
		for _, n := range psWildcardWindow(rel, pattern, recurse) {
			if ancestors || n == len(rel) {
				add(rel[:n])
			}
		}
	}
	for _, path := range p.anchored {
		switch {
		case len(path) > len(folder) && psComponentsEqual(path[:len(folder)], folder):
			try(path[len(folder):])
		case len(path) <= len(folder) && psComponentsEqual(folder[:len(path)], path):
			try(nil)
		}
	}
	for _, path := range p.floating {
		// The folder is or lies in the folder of the protected path: its
		// last j components are the first j of the path (j > 0). A
		// pattern in another folder (.codex/sessions/*) would reach a
		// protected file only through a .codex folder below it, which no
		// hook client reads.
		for j := 1; j <= len(path) && j <= len(folder); j++ {
			if psComponentsEqual(path[:j], folder[len(folder)-j:]) {
				try(path[j:])
			}
		}
	}
	return out
}

// psComponentsEqual reports two component lists equal but for case.
func psComponentsEqual(a, b []string) bool {
	return slices.EqualFunc(a, b, strings.EqualFold)
}

// psWildcardWindow returns the lengths n for which rel[:n] matches pattern:
// component i of the pattern matches rel[i], and with recurse its last one
// may match any component at or below its place.
func psWildcardWindow(rel, pattern []string, recurse bool) []int {
	k := len(pattern)
	if k == 0 || len(rel) < k {
		return nil
	}
	for i := 0; i < k-1; i++ {
		if !psWildcardMatch(pattern[i], rel[i]) {
			return nil
		}
	}
	var out []int
	for e := k - 1; e < len(rel); e++ {
		if psWildcardMatch(pattern[k-1], rel[e]) {
			out = append(out, e+1)
		}
		if !recurse {
			break
		}
	}
	return out
}

// psWildcardToken is one element of a PowerShell wildcard pattern.
type psWildcardToken struct {
	star, any bool
	set       []rune // a [..] set, with a-b ranges
	literal   rune
}

// psWildcardMatch reports whether a PowerShell wildcard pattern matches
// name, ignoring case: * is any run of characters, ? one character, [..] one
// of a set or range, and ` quotes the next character. A [ with no closing ]
// matches any one character (an over-match, as the protected reading wants).
// It runs in time linear in the product of the lengths.
func psWildcardMatch(pattern, name string) bool {
	var tokens []psWildcardToken
	p := []rune(strings.ToLower(pattern))
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '*':
			if len(tokens) == 0 || !tokens[len(tokens)-1].star {
				tokens = append(tokens, psWildcardToken{star: true})
			}
		case '?':
			tokens = append(tokens, psWildcardToken{any: true})
		case '[':
			end := slices.Index(p[i+1:], ']')
			if end <= 0 {
				tokens = append(tokens, psWildcardToken{any: true})
				continue
			}
			tokens = append(tokens, psWildcardToken{set: p[i+1 : i+1+end]})
			i += end + 1
		case '`':
			if i+1 < len(p) {
				i++
			}
			tokens = append(tokens, psWildcardToken{literal: p[i]})
		default:
			tokens = append(tokens, psWildcardToken{literal: p[i]})
		}
	}
	n := []rune(strings.ToLower(name))
	one := func(token psWildcardToken, r rune) bool {
		switch {
		case token.any:
			return true
		case token.set != nil:
			for k := 0; k < len(token.set); k++ {
				if k+2 < len(token.set) && token.set[k+1] == '-' {
					if token.set[k] <= r && r <= token.set[k+2] {
						return true
					}
					k += 2
					continue
				}
				if token.set[k] == r {
					return true
				}
			}
			return false
		}
		return token.literal == r
	}
	// The classic one-star backtrack: on a mismatch, the last * takes one
	// more character.
	ti, ni, star, mark := 0, 0, -1, 0
	for ni < len(n) {
		switch {
		case ti < len(tokens) && tokens[ti].star:
			star, mark = ti, ni
			ti++
		case ti < len(tokens) && one(tokens[ti], n[ni]):
			ti++
			ni++
		case star >= 0:
			mark++
			ti, ni = star+1, mark
		default:
			return false
		}
	}
	for ti < len(tokens) && tokens[ti].star {
		ti++
	}
	return ti == len(tokens)
}

// psStateProtectedPaths are the DefenseClaw state files and trees a wildcard
// pattern may match (activeDefenseClawStateNames): in the .defenseclaw
// folder of home, and in any .defenseclaw folder the pattern's folder is.
func psStateProtectedPaths(home string) psProtectedPaths {
	var anchored, floating []string
	for _, name := range activeDefenseClawStateNames {
		floating = append(floating, ".defenseclaw/"+name)
		if home != "" {
			anchored = append(anchored, strings.TrimRight(home, `/\`)+"/.defenseclaw/"+name)
		}
	}
	return newPSProtectedPaths(anchored, floating)
}

// psProtectedPaths are the hook files of the guard a wildcard pattern may
// match: every registered and home hook file, the DefenseClaw hook programs,
// and the project hook files of any folder (agentHookConfigProjectFiles).
func (g *agentHookConfigGuard) psProtectedPaths() psProtectedPaths {
	anchored := make([]string, 0, len(g.files)+2)
	for _, file := range g.files {
		anchored = append(anchored, file.Path)
	}
	if g.home != "" {
		for _, name := range []string{"defenseclaw-hook-user", "defenseclaw-hook-post"} {
			anchored = append(anchored, filepath.Join(g.home, ".local", "bin", name))
		}
	}
	floating := make([]string, 0, len(agentHookConfigProjectFiles))
	for _, file := range agentHookConfigProjectFiles {
		floating = append(floating, file.suffix)
	}
	return newPSProtectedPaths(anchored, floating)
}
