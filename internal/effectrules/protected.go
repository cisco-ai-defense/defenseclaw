// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// Grade is the protected-set answer for one target: known (a member),
// unknown (it may be one), or no (it cannot be one).
type setGrade string

const (
	gradeKnown   setGrade = "known"
	gradeUnknown setGrade = "unknown"
	gradeNo      setGrade = "no"
)

// resolver follows one lexical absolute write path through links, as the hook
// client does. ok is false when it could not be trusted. A nil resolver on the
// env falls back to hookpaths.ResolveWriteTarget, which reads the file system
// the way a gateway running as the user does.
type resolver func(path string) (string, bool)

// gradeTarget grades one effect target against one protected set. A target
// that cannot be a member returns gradeNo; a target whose link reading could
// not complete, or whose spelling is a glob or dynamic, never returns gradeNo
// for a set it could reach.
func gradeTarget(t effects.Target, state effects.TargetState, set protectedSet, flavor effects.Flavor, res resolver) setGrade {
	// A glob could expand to a member; it is a pattern, not a literal file.
	if t.Glob != "" {
		if globReachesSet(t.Glob, set, flavor) {
			return gradeUnknown
		}
		return gradeNo
	}
	// No lexical path: the spelling is fully dynamic, with no information at
	// all. It is not claimed as a member of any NAMED set (that would make a
	// benign dynamic read look like a credential read); a dynamic MUTATION is
	// still caught away-from-home by the outside_home signal in the projector.
	if t.Path == "" {
		return gradeNo
	}
	// A concrete lexical name that is a member is authoritative even before
	// its physical path is read (writing the name ~/.ssh/authorized_keys is a
	// known protected write whether or not the file exists yet).
	if memberExact(t.Path, set, flavor) {
		return gradeKnown
	}
	if underTree(t.Path, set, flavor) {
		return gradeKnown
	}
	underDir := underProtectedDir(t.Path, set, flavor)

	// Follow links. A target that resolves to a member (or under a protected
	// tree) is a known write through a link; a target the resolver could not
	// follow is unknown.
	resolved, ok := res(t.Path)
	if ok && resolved != "" && resolved != t.Path {
		if memberExact(resolved, set, flavor) || underTree(resolved, set, flavor) {
			return gradeKnown
		}
		if underProtectedDir(resolved, set, flavor) {
			return gradeUnknown
		}
	}
	if !ok {
		// The link reading could not complete: the write may still reach a
		// member. Never "no" for an unchecked link.
		return gradeUnknown
	}
	if underDir {
		// A new child of a protected directory (a control file we do not
		// list, or a link placed there) stays suspect.
		return gradeUnknown
	}
	if suspiciousShape(t.Path, set, flavor) {
		// A canonical path whose basename/shape is a protected file's but in an
		// unexpected directory (a CDPATH / reassigned-HOME resolution that came
		// out canonical but wrong): unknown, not clean (rule c).
		return gradeUnknown
	}
	// The resolver trusted the path and it is neither a member nor under a
	// protected location of this set. A lexically unresolved target_state is
	// not, by itself, a match for a named set; the away-from-home signal
	// (outside_home) covers an unresolved mutation whose destination we
	// cannot vouch for.
	return gradeNo
}

func memberExact(p string, set protectedSet, flavor effects.Flavor) bool {
	key := canon(p, flavor)
	for _, m := range set.files {
		if canon(m, flavor) == key {
			return true
		}
	}
	return false
}

func underTree(p string, set protectedSet, flavor effects.Flavor) bool {
	key := canon(p, flavor)
	for _, tree := range set.trees {
		if atOrUnder(key, canon(tree, flavor)) {
			return true
		}
	}
	return false
}

func underProtectedDir(p string, set protectedSet, flavor effects.Flavor) bool {
	parent := canon(parentOf(p, flavor), flavor)
	for _, d := range set.dirs {
		if parent == canon(d, flavor) {
			return true
		}
	}
	return false
}

// globReachesSet reports whether an unquoted glob pattern could select a
// member of the set, or sits in a protected directory or tree.
func globReachesSet(glob string, set protectedSet, flavor effects.Flavor) bool {
	g := canon(glob, flavor)
	gdir := canon(parentOf(glob, flavor), flavor)
	match := func(member string) bool {
		m := canon(member, flavor)
		if ok, _ := path.Match(toSlash(g), toSlash(m)); ok {
			return true
		}
		// A glob whose directory is the member's directory can select it.
		return gdir == canon(parentOf(member, flavor), flavor)
	}
	for _, m := range set.files {
		if match(m) {
			return true
		}
	}
	for _, d := range set.dirs {
		cd := canon(d, flavor)
		if gdir == cd || atOrUnder(gdir, cd) {
			return true
		}
	}
	for _, tree := range set.trees {
		ct := canon(tree, flavor)
		if atOrUnder(gdir, ct) || atOrUnder(ct, gdir) {
			return true
		}
	}
	return false
}

// canon folds a path to its comparison key the way effects.Target.Key does:
// backslash and lower case for Windows, clean slashes for POSIX.
func canon(p string, flavor effects.Flavor) string {
	if p == "" {
		return ""
	}
	if flavor == effects.FlavorWindows {
		return strings.ToLower(strings.ReplaceAll(cleanSlashes(p, "/"), "/", `\`))
	}
	return cleanSlashes(p, "/")
}

func cleanSlashes(p, sep string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	p = path.Clean(p)
	if sep != "/" {
		p = strings.ReplaceAll(p, "/", sep)
	}
	return p
}

func toSlash(p string) string { return strings.ReplaceAll(p, `\`, "/") }

func parentOf(p string, flavor effects.Flavor) string {
	s := toSlash(p)
	i := strings.LastIndex(s, "/")
	if i <= 0 {
		return s
	}
	return s[:i]
}

// atOrUnder reports whether child is base or a descendant of base. Both are
// already canonicalized to the same flavor.
func atOrUnder(child, base string) bool {
	if child == base {
		return true
	}
	cs, bs := toSlash(child), toSlash(base)
	return strings.HasPrefix(cs, strings.TrimRight(bs, "/")+"/")
}

// defaultResolver reads the file system through the hook's bounded reader.
func defaultResolver(p string) (string, bool) {
	return hookpaths.ResolveWriteTarget(p)
}

// matchBasis names why a target matched a set, so the restricted tier can
// require an exact canonical member. For a known grade it is exact, tree or
// link; for unknown it is glob, dir, dynamic or unresolved.
func matchBasis(t effects.Target, grade setGrade, set protectedSet, flavor effects.Flavor) string {
	if grade == gradeKnown {
		switch {
		case memberExact(t.Path, set, flavor):
			return "exact"
		case underTree(t.Path, set, flavor):
			return "tree"
		default:
			return "link"
		}
	}
	switch {
	case t.Glob != "":
		return "glob"
	case t.Path == "":
		return "dynamic"
	case underProtectedDir(t.Path, set, flavor):
		return "dir"
	case suspiciousShape(t.Path, set, flavor):
		return "wrong_dir"
	default:
		return "unresolved"
	}
}

// dirExact reports that a path is exactly one of the set's protected
// directories (the directory itself, not a child).
func dirExact(p string, set protectedSet, flavor effects.Flavor) bool {
	if p == "" {
		return false
	}
	key := canon(p, flavor)
	for _, d := range set.dirs {
		if canon(d, flavor) == key {
			return true
		}
	}
	return false
}

// suspiciousShape reports a concrete path whose home-relative shape matches
// one of the set's protected file tails (for example .../.ssh/authorized_keys
// or .../.bashrc) but which is not an exact member -- a protected basename in
// an unexpected directory. memberExact has already been checked by the
// caller, so any tail hit here is a wrong-directory match.
func suspiciousShape(p string, set protectedSet, flavor effects.Flavor) bool {
	if p == "" {
		return false
	}
	key := canon(p, flavor)
	for _, tail := range set.tails {
		if tail == "" {
			continue
		}
		// tail begins with a separator; match it at a component boundary.
		if hasSuffixSep(key, canon(tail, flavor)) {
			return true
		}
	}
	return false
}

// hasSuffixSep reports whether key ends with suffix, where suffix already
// starts with a separator so the match lands on a path-component boundary.
func hasSuffixSep(key, suffix string) bool {
	return len(key) > len(suffix) && strings.HasSuffix(key, suffix)
}

// canonFlavor is canon for a path that may be empty.
func canonFlavor(p string, flavor effects.Flavor) string {
	if p == "" {
		return ""
	}
	return canon(p, flavor)
}

// hasPrefixSep reports whether child is under base at a component boundary.
func hasPrefixSep(child, base string) bool {
	return atOrUnder(child, base) && child != base
}
