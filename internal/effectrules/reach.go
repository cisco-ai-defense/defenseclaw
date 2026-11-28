// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// Reach reasons (DET111 PLAN 5.3): the closed list of reasons an unknown
// effect may reach the unknown tier. An unknown with none stays allow, as in
// 1.0.10. Each reason is counted on its own so the bar can hold its benign
// alert rate at or below 1.0.10. The names are decide's (the proof's Reach).
const (
	// ReachName: a word of the call, after resolution, names a protected set
	// member (the GAP-0843 rule).
	ReachName = decide.ReachName
	// ReachGlob: an unquoted glob can match a protected path (pattern
	// intersection, no disk walk).
	ReachGlob = decide.ReachGlob
	// ReachCWD: the working folder is unknown and a relative operand would
	// land in a protected set from a folder the call could be in.
	ReachCWD = decide.ReachCwd
	// ReachRole: the table says the program writes or sends its operand and
	// the operand is unknown (dd of=$X).
	ReachRole = decide.ReachRole
	// ReachCode: opaque code that names a protected set member as a literal.
	ReachCode = decide.ReachCode
	// ReachFS: the path is lexically known but its link reading could not
	// complete (an unverified path).
	ReachFS = decide.ReachFS
)

// ReasonLinkExact is the match basis of a member the resolver reached
// through a link and found to be an exact member of the set (the link names
// the member itself, not a file under its folder). It reads as "link"
// everywhere, except that a write which opens the path it names takes the
// member's own cell through it (DET111 ruling R2).
const ReasonLinkExact = "link_exact"

// ReachReasons is every reach reason, in report order.
var ReachReasons = []string{ReachName, ReachGlob, ReachCWD, ReachRole, ReachCode, ReachFS}

// ReachForMatch is the reach reason of an unknown effect whose target the
// protected-set grade matched with basis matchReason (Project's
// ProtectedMatch.Reason); effectReasons are the effect's own reason codes.
func ReachForMatch(matchReason string, effectReasons []string) string {
	switch matchReason {
	case "glob":
		return ReachGlob
	case "link", ReasonLinkExact, "unresolved":
		return ReachFS
	case "dynamic":
		for _, r := range effectReasons {
			if r == string(effects.ReasonDynamicCWD) {
				return ReachCWD
			}
		}
	}
	// exact, tree, dir, protected_dir, wrong_dir, dynamic: the spelling names
	// a member or a protected location.
	return ReachName
}

// textReachSets are the sets a bare mention reaches for a call that is not
// fully read: the persistence targets of the 1.0.10 GAP-0843 rule (the keys
// file and the shell startup files). A mention of a hook config, a
// credential or the state folder beside an unread program is common in
// benign calls (jq . ~/.claude/settings.json) and is left to the readers.
var textReachSets = []string{SetSSHAuthorizedKeys, SetShellRC}

// TextNamesProtected reports the first word of text (a shell command or a
// code body) that names a member of a text-reach set, skipping the words in
// accounted (paths a known effect of the call already reads or writes, so
// the readers judge them). It returns the set name. The scan is lexical: no
// file is read.
func TextNamesProtected(text, home string, flavor effects.Flavor, accounted map[string]bool) (string, bool) {
	if text == "" {
		return "", false
	}
	if flavor == "" {
		flavor = effects.FlavorPOSIX
	}
	sets := buildSets(home, flavor)
	// The caller bounds the text (the effect lane reads at most 64 KiB), so
	// every word is read. Quotes split words here; the same text with its
	// quotes removed is scanned too, so ~/.ssh/"authorized_keys" is one word.
	unquoted := strings.NewReplacer("'", "", `"`, "", `\`, "").Replace(text)
	split := func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ';', '|', '&', '<', '>', '(', ')', '\'', '"', '`', '$', '=', ',', '{', '}':
			return true
		}
		return false
	}
	words := strings.FieldsFunc(text, split)
	if unquoted != text {
		words = append(words, strings.FieldsFunc(unquoted, split)...)
	}
	for _, w := range words {
		path := w
		if home != "" && (w == "~" || strings.HasPrefix(w, "~/") || strings.HasPrefix(w, `~\`)) {
			path = home + w[1:]
		}
		if accounted[path] || accounted[w] {
			continue
		}
		t := effects.Target{Type: effects.TargetPath, Spelling: "x/" + w}
		if isAbs(path, flavor) {
			t.Path = path
		}
		for _, name := range textReachSets {
			set := sets[name]
			if t.Path != "" && (memberExact(t.Path, set, flavor) || underTree(t.Path, set, flavor)) {
				return name, true
			}
			if suspiciousShape(t, set, flavor) {
				return name, true
			}
		}
	}
	return "", false
}

func isAbs(p string, flavor effects.Flavor) bool {
	if strings.HasPrefix(p, "/") {
		return true
	}
	if flavor == effects.FlavorWindows {
		return len(p) > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') || strings.HasPrefix(p, `\\`)
	}
	return false
}

// GlobReaches reports whether glob, an absolute unquoted pattern, can select
// a member of the set name, an ancestor of one, or a path at or under one of
// its protected folders and trees. It compares component by component, with
// no disk walk. With dotRule (a POSIX shell reading with no dotglob or
// globdots in the call) a component that does not start with a dot never
// matches a dot name, as the shell does by default, so ~/* does not reach
// ~/.ssh or ~/.bashrc while ~/.* does. It fails closed: a ** component, or a
// component this matcher does not model as the shell does (brackets,
// escapes, braces, extglob and zsh qualifiers in parentheses), reaches. It
// is the R-GLOB rule; the classifier's own glob grade (maybe) is wider and
// only records the set.
//
// del is a delete: it does not reach the project instruction files at the
// home root (CLAUDE.md, AGENTS.md), whose risk is their content (an injected
// instruction); removing one adds none (rel-1-0-10 GAP-0594 g594-x04,
// rm -ri ~/*).
func GlobReaches(glob, home string, flavor effects.Flavor, dotRule, del bool, name string) bool {
	if glob == "" {
		return false
	}
	if flavor == "" {
		flavor = effects.FlavorPOSIX
	}
	set, ok := buildSets(home, flavor)[name]
	if !ok {
		return false
	}
	g := pathComponents(glob, flavor)
	for _, c := range g {
		if c == "**" {
			return true
		}
	}
	targets := append(append(append([]string(nil), set.files...), set.dirs...), set.trees...)
	for i, t := range targets {
		if del && i < len(set.files) && instructionFile(t, home, flavor) {
			continue
		}
		x := pathComponents(t, flavor)
		// A member file is selected itself or through an ancestor (rm -r
		// ~/.s*); a protected folder or tree also through a path under it.
		if i < len(set.files) && len(g) > len(x) {
			continue
		}
		k := min(len(g), len(x))
		if componentsMatch(g[:k], x[:k], dotRule) {
			return true
		}
	}
	return false
}

// KnownPathReaches reports whether a known path the classifier placed only
// beside the set's members (basis "dir": a child of a protected folder) can
// touch one: it is a member, an ancestor of one, or at or above a protected
// tree. A file beside the members (~/.ssh/known_hosts.d) is not: the words of
// the call name no member, so R-NAME does not hold. (The ssh folder's active
// files, authorized_keys*, rc, environment and config, are members.)
func KnownPathReaches(p, home string, flavor effects.Flavor, name string) bool {
	if p == "" {
		return false
	}
	if flavor == "" {
		flavor = effects.FlavorPOSIX
	}
	set, ok := buildSets(home, flavor)[name]
	if !ok {
		return false
	}
	cp := canon(p, flavor)
	for _, f := range set.files {
		if atOrUnder(canon(f, flavor), cp) {
			return true
		}
	}
	for _, t := range set.trees {
		ct := canon(t, flavor)
		if atOrUnder(cp, ct) || atOrUnder(ct, cp) {
			return true
		}
	}
	return false
}

func pathComponents(p string, flavor effects.Flavor) []string {
	var out []string
	for _, c := range strings.Split(toSlash(canon(p, flavor)), "/") {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

// globUnmodeled marks a component path.Match does not read as the shell
// does: brackets ([!x] is negation in the shell), escapes, braces, extglob
// and zsh qualifiers in parentheses.
const globUnmodeled = "[\\{("

// componentsMatch matches glob components g against path components x of the
// same length, failing closed on what it does not model.
func componentsMatch(g, x []string, dotRule bool) bool {
	if len(g) != len(x) {
		return false
	}
	for i := range g {
		if g[i] == x[i] {
			continue
		}
		if strings.ContainsAny(g[i], globUnmodeled) {
			continue
		}
		if dotRule && strings.HasPrefix(x[i], ".") && !strings.HasPrefix(g[i], ".") {
			return false
		}
		if ok, err := path.Match(g[i], x[i]); err == nil && !ok {
			return false
		}
	}
	return true
}

// instructionFiles are the project instruction files of the agent hook
// config set at the home root.
var instructionFiles = []string{"CLAUDE.md", "AGENTS.md"}

func instructionFile(member, home string, flavor effects.Flavor) bool {
	for _, n := range instructionFiles {
		if canon(member, flavor) == canon(joinFlavor(flavor, home, n), flavor) {
			return true
		}
	}
	return false
}
