// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"path"
	"runtime"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
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
func gradeTarget(t effects.Target, state effects.TargetState, kind effects.Kind, set protectedSet, flavor effects.Flavor, res resolver) setGrade {
	// A glob could expand to a member; it is a pattern, not a literal file. It
	// is intersected with the set as a pattern, placed where the walk placed it
	// (Lexical), never by reading the disk (DET111 D3).
	if t.Glob != "" {
		pat := t.Glob
		if t.Lexical != "" {
			pat = t.Lexical
		}
		if globReachesSet(pat, set, flavor) || patternReachesSet(pat, set, flavor) {
			return gradeUnknown
		}
		if t.Lexical == "" && cwdReach(t.Glob, kind, set, flavor) {
			return gradeUnknown
		}
		return gradeNo
	}
	// A spelling that is not canonical (a .. after a folder that may be a link,
	// an 8.3-looking name) is a member only when the resolver walked it
	// physically to one; otherwise its lexical candidate is a pattern (F1).
	if t.Path == "" && t.Lexical != "" {
		if resolved, ok := res(t.Lexical); ok && resolved != "" && resolved != t.Lexical {
			if knownProtectedHomeTail(resolved, set, flavor) {
				return gradeKnown
			}
			if memberExact(resolved, set, flavor) || underTree(resolved, set, flavor) ||
				(t.Subtree && treeHoldsSet(resolved, set, flavor)) {
				return gradeKnown
			}
			if underProtectedDir(resolved, set, flavor) {
				return gradeUnknown
			}
		}
		if lexicalReachesSet(t.Lexical, set, flavor) {
			return gradeUnknown
		}
		if t.Subtree {
			if segs := patternSegs(t.Lexical, flavor); len(segs) == 0 || segs[0] == "**" ||
				treeHoldsSet(joinFlavor(flavor, rootOf(flavor), strings.Join(segs, "/")), set, flavor) {
				return gradeUnknown
			}
		}
	}
	// No lexical path: the spelling is fully dynamic. A relative spelling can
	// still name a protected file (a dynamic cwd plus ../.ssh/authorized_keys),
	// so check the shape; otherwise it carries no protected signal and is not
	// claimed as a member of any named set (which would make a benign dynamic
	// read look like a credential read).
	if t.Path == "" {
		if strings.HasPrefix(t.Spelling, "$?") {
			// Only the literal tail of an unread word ($(f)/.ssh/id_rsa): a
			// mutation of a protected name, or a read of a credential, reaches
			// the set (R-NAME). A read of another protected name behind an unread
			// prefix ("$X/.ssh/config", "$d/AGENTS.md" in a loop) stays out: it is
			// common in benign traces (FPR rule).
			if (mutatingKind(kind) || set.readReach) && suspiciousShape(t, set, flavor) {
				return gradeUnknown
			}
			return gradeNo
		}
		if suspiciousShape(t, set, flavor) {
			return gradeUnknown
		}
		if t.Lexical == "" && cwdReach(t.Spelling, kind, set, flavor) {
			return gradeUnknown
		}
		return gradeNo
	}
	// A tree effect (a find -delete root, a clone into a folder) reaches every
	// member below its folder.
	if t.Subtree && t.Lexical != "" {
		// a tree effect that selects by a name pattern (find -name x -delete):
		// the pattern below the root is what it reaches.
		if patternReachesSet(t.Lexical, set, flavor) {
			return gradeUnknown
		}
	} else if t.Subtree && treeHoldsSet(t.Path, set, flavor) {
		if state == effects.TargetStateKnown {
			return gradeKnown
		}
		return gradeUnknown
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
	if knownProtectedHomeTail(t.Path, set, flavor) {
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
	// A target at or below a link an earlier command of this call created
	// lands on that link's target (effects fills Physical). The link is not on
	// disk at hook time, so not every component is resolved: maybe, never
	// known (DET111 F1, rel-1-0-10:GAP-1573c).
	if callLinkReaches(t, set, flavor) {
		return gradeUnknown
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
	if suspiciousShape(t, set, flavor) {
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

// knownProtectedHomeTail recognizes one exact protected tail beneath a
// passwd home or a conventional home root. It is a resolver fact: a basename
// that merely resembles a credential in a project or arbitrary folder remains
// a Maybe match.
func knownProtectedHomeTail(p string, set protectedSet, flavor effects.Flavor) bool {
	if p == "" {
		return false
	}
	roots := append([]string(nil), set.homeRoots...)
	if root := shapedHomeRoot(p, flavor); root != "" {
		roots = append(roots, root)
	}
	child := canon(p, flavor)
	for _, root := range roots {
		base := canon(root, flavor)
		if child == base || !atOrUnder(child, base) {
			continue
		}
		childSlash, baseSlash := toSlash(child), strings.TrimRight(toSlash(base), "/")
		tail := strings.TrimPrefix(childSlash, baseSlash)
		if tail == "" || !strings.HasPrefix(tail, "/") {
			continue
		}
		for _, protectedTail := range set.tails {
			if canon(protectedTail, flavor) == canon(tail, flavor) {
				return true
			}
		}
	}
	return false
}

// AccountHomeCandidates are the folders that would be another account's home
// for the placed POSIX targets of res: a target less one credential tail
// (/mnt/home/bob for /mnt/home/bob/.ssh/id_rsa), outside the active home and
// outside the home roots the classifier places by shape (/home/<u>,
// /Users/<u>, /root). A candidate is only a question for the passwd lookup:
// it is an account home when the lookup of its last name returns that folder
// (rel-1-0-10:GAP-0899), never by its shape.
func AccountHomeCandidates(res effects.Result, home string) []string {
	const posix = effects.FlavorPOSIX
	tailHome := home
	if tailHome == "" {
		tailHome = "/home/u" // the tails are home-relative
	}
	tails := buildSets(tailHome, posix)[SetCredentials].tails
	active := canon(home, posix)
	var out []string
	for i := range res.Effects {
		p := canon(res.Effects[i].Target.Path, posix)
		if !strings.HasPrefix(p, "/") || (active != "" && atOrUnder(p, active)) || shapedHomeRoot(p, posix) != "" {
			continue
		}
		for _, tail := range tails {
			if len(p) <= len(tail) || !strings.HasSuffix(p, tail) {
				continue
			}
			if root := p[:len(p)-len(tail)]; root != "" && !slices.Contains(out, root) {
				out = append(out, root)
			}
		}
	}
	return out
}

func shapedHomeRoot(p string, flavor effects.Flavor) string {
	if flavor == effects.FlavorWindows {
		sep := string([]byte{92})
		clean := strings.ToLower(strings.ReplaceAll(p, "/", sep))
		parts := strings.Split(clean, sep)
		if len(parts) >= 4 && len(parts[0]) == 2 && parts[0][1] == ':' && parts[1] == "users" && parts[2] != "" {
			return strings.Join(parts[:3], sep)
		}
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		return ""
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) >= 3 && (parts[0] == "home" || parts[0] == "Users") && parts[1] != "" {
		return "/" + parts[0] + "/" + parts[1]
	}
	if len(parts) >= 2 && parts[0] == "root" {
		return "/root"
	}
	return ""
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

// hostGOOS is the system whose file system the resolver reads; a test pins it.
var hostGOOS = runtime.GOOS

// resolverFor is the link resolver of a call's path flavor: the hook's file
// system reader for the host's own flavor, else the placed path itself. A
// Windows path judged on a POSIX host (or a POSIX path on Windows) names no
// file of this file system, so there is no link to follow: its placed path is
// the whole answer, a member or not by name, never an unresolved target that
// reaches every set (DET111 D3; it graded every Windows home write the
// unknown tier).
func resolverFor(flavor effects.Flavor) resolver {
	if (flavor == effects.FlavorWindows) != (hostGOOS == "windows") {
		return func(p string) (string, bool) { return p, true }
	}
	return defaultResolver
}

// matchBasis names why a target matched a set, so the restricted tier can
// require an exact canonical member. For a known grade it is exact, tree or
// link; for unknown it is glob, dir, dynamic or unresolved.
func matchBasis(t effects.Target, grade setGrade, set protectedSet, flavor effects.Flavor) string {
	if grade == gradeKnown {
		switch {
		case t.Path == "":
			return "link" // a non-canonical spelling the resolver walked to a member
		case memberExact(t.Path, set, flavor):
			return "exact"
		case knownProtectedHomeTail(t.Path, set, flavor):
			return "other_home"
		case underTree(t.Path, set, flavor):
			return "tree"
		case t.Subtree && treeHoldsSet(t.Path, set, flavor):
			return "subtree"
		default:
			return "link"
		}
	}
	switch {
	case t.Glob != "" && dotDotAfterWildcard(t.Glob):
		// u*/../x: the .. climbs from whatever the wildcard matched, which
		// may be a link; where it lands is a file-system answer, not a
		// pattern one (rel-1-0-10:GAP-0443).
		return "unresolved"
	case t.Glob != "":
		return "glob"
	case t.Path == "" && t.Lexical != "" && lexicalReachesSet(t.Lexical, set, flavor):
		return "lexical"
	case t.Path == "" && t.Lexical == "" && !suspiciousShape(t, set, flavor) && t.Spelling != "":
		return "cwd"
	case t.Path == "":
		return "dynamic"
	case callLinkReaches(t, set, flavor):
		return "call_link"
	case t.Subtree && treeHoldsSet(t.Path, set, flavor):
		return "subtree"
	case underProtectedDir(t.Path, set, flavor):
		return "dir"
	case suspiciousShape(t, set, flavor):
		return "wrong_dir"
	default:
		return "unresolved"
	}
}

// dotDotAfterWildcard reports a .. component after a component with a
// pattern character.
func dotDotAfterWildcard(glob string) bool {
	wild := false
	for _, seg := range strings.FieldsFunc(glob, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." && wild {
			return true
		}
		if strings.ContainsAny(seg, "*?[") {
			wild = true
		}
	}
	return false
}

// callLinkReaches reports that a target's in-call link landing (Physical, set
// by effects for a path at or below a link this call created) is a member, is
// under a protected tree or folder, or, for a tree effect, holds the set.
func callLinkReaches(t effects.Target, set protectedSet, flavor effects.Flavor) bool {
	ph := t.Physical
	if ph == "" || t.Path == "" || ph == t.Path {
		return false
	}
	if t.Subtree && t.Lexical != "" {
		// a walk that selects by name below the link (find d/ -name x):
		// effects joined the pattern on the landing; that pattern decided.
		return false
	}
	return memberExact(ph, set, flavor) || underTree(ph, set, flavor) || underProtectedDir(ph, set, flavor) ||
		(t.Subtree && treeHoldsSet(ph, set, flavor))
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
func suspiciousShape(t effects.Target, set protectedSet, flavor effects.Flavor) bool {
	// Match the resolved path and the as-written spelling: a dynamic cwd that
	// left the path empty can still carry a relative spelling whose tail is a
	// protected file (../.ssh/authorized_keys, ~/.bashrc).
	for _, cand := range []string{t.Path, t.Spelling} {
		if cand == "" {
			continue
		}
		key := canon(cand, flavor)
		for _, tail := range set.tails {
			if tail == "" {
				continue
			}
			// tail begins with a separator; match at a component boundary.
			if hasSuffixSep(key, canon(tail, flavor)) {
				return true
			}
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

// treeHoldsSet reports a folder at or above a member, a protected folder or a
// protected tree of the set: an effect on every file below it reaches them.
func treeHoldsSet(dir string, set protectedSet, flavor effects.Flavor) bool {
	d := canon(dir, flavor)
	for _, group := range [][]string{set.files, set.dirs, set.trees} {
		for _, m := range group {
			if atOrUnder(canon(m, flavor), d) {
				return true
			}
		}
	}
	return false
}

// lexicalReachesSet reads a non-canonical lexical candidate as a pattern: its
// lexically cleaned form is a member or in a protected folder, an 8.3-looking
// component can be the short name of a member's component, or a .. after a
// wildcard leaves only the member's base name to match (rel-1-0-10:GAP-1677,
// GAP-1648, GAP-1553, GAP-0443).
func lexicalReachesSet(lex string, set protectedSet, flavor effects.Flavor) bool {
	if lex == "" {
		return false
	}
	if memberExact(lex, set, flavor) || underTree(lex, set, flavor) || underProtectedDir(lex, set, flavor) {
		return true
	}
	return patternReachesSet(lex, set, flavor)
}

// patternReachesSet intersects a placed pattern with the set's member files by
// components:
// each component is a glob (path.Match), ** is any run of components, an
// 8.3-looking Windows component matches the long names it can be the short
// name of, and a .. after a wildcard component (whose folder may be a link
// anywhere) leaves only the components after it, matched at any depth.
func patternReachesSet(pat string, set protectedSet, flavor effects.Flavor) bool {
	segs := patternSegs(pat, flavor)
	if len(segs) == 0 {
		return false
	}
	// Only the member files: a pattern that selects some new child of a
	// protected folder or tree (find ~ -name '*.pyc' -delete) is not read as
	// reaching the set, so a benign clean-up stays allowed (FPR rule).
	for _, m := range set.files {
		if segsMatch(segs, strings.Split(strings.Trim(toSlash(canon(m, flavor)), "/"), "/"), flavor) {
			return true
		}
	}
	return false
}

// patternSegs splits a placed pattern into components, collapsing a .. after a
// literal component by name (the lexical reading of 1.0.10). A .. after a
// wildcard or 8.3 component climbs from a folder the walk cannot place, so the
// pattern becomes ** and the last name (rel-1-0-10:GAP-0443).
func patternSegs(pat string, flavor effects.Flavor) []string {
	p := toSlash(pat)
	if flavor == effects.FlavorWindows {
		p = strings.ToLower(p)
	}
	var out []string
	reset := false
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			switch n := len(out); {
			case n == 0:
				// the parent of the root is the root
			case out[n-1] != "**" && !strings.ContainsAny(out[n-1], "*?[") && !isShortNameSeg(out[n-1]):
				out = out[:n-1]
			default:
				out = []string{"**"}
				reset = true
			}
			continue
		}
		out = append(out, seg)
	}
	if reset && len(out) > 1 {
		// After a .. from a folder the walk cannot place, every later folder may
		// be a link anywhere too: only the last name is known.
		out = []string{"**", out[len(out)-1]}
	}
	return out
}

// segsMatch matches pattern components against a member's components.
func segsMatch(pat, name []string, flavor effects.Flavor) bool {
	if len(pat) == 0 {
		return len(name) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(name); i++ {
			if segsMatch(pat[1:], name[i:], flavor) {
				return true
			}
		}
		return false
	}
	if len(name) == 0 {
		return false
	}
	if !segMatch(pat[0], name[0], flavor) {
		return false
	}
	return segsMatch(pat[1:], name[1:], flavor)
}

func segMatch(p, n string, flavor effects.Flavor) bool {
	if ok, err := path.Match(p, n); ok && err == nil {
		return true
	}
	if flavor == effects.FlavorWindows && isShortNameSeg(p) {
		return shortNameMatches(p, n)
	}
	return false
}

// isShortNameSeg reports a Windows 8.3-looking component: NAME~N or NAME~N.EXT.
func isShortNameSeg(s string) bool {
	i := strings.IndexByte(s, '~')
	return i > 0 && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9'
}

// shortNameMatches reports whether the 8.3 name short (lower case) can be the
// short name Windows makes for long: the first characters of the long name
// with dots, spaces and leading dots removed, then ~N, then the first three
// characters of its last extension. The hashed form Windows uses after four
// collisions keeps only the first two characters, so a two-character prefix
// match is enough when the short base is longer than that.
func shortNameMatches(short, long string) bool {
	short, long = strings.ToLower(short), strings.ToLower(long)
	tilde := strings.IndexByte(short, '~')
	base := short[:tilde]
	ext := ""
	if dot := strings.LastIndexByte(short, '.'); dot > tilde {
		ext = short[dot+1:]
	}
	lbase, lext := strings.TrimLeft(long, ". "), ""
	if dot := strings.LastIndexByte(lbase, '.'); dot > 0 {
		lbase, lext = lbase[:dot], lbase[dot+1:]
	}
	lbase = strings.NewReplacer(".", "", " ", "").Replace(lbase)
	if (ext == "") != (lext == "") || !strings.HasPrefix(lext, ext) {
		return false
	}
	if strings.HasPrefix(lbase, base) {
		return true
	}
	return len(base) > 2 && strings.HasPrefix(lbase, base[:2])
}

// cwdReach reports a relative mutation spelling under an unknown working
// folder that lands on a member from a folder the call may be in: the home or
// a protected folder of the set (the R-CWD reach of PLAN 5.3,
// rel-1-0-10:GAP-1556). Reads are left out: their benign rate is not measured
// for this reach yet.
func cwdReach(spelling string, kind effects.Kind, set protectedSet, flavor effects.Flavor) bool {
	if spelling == "" || !mutatingKind(kind) {
		return false
	}
	sl := toSlash(spelling)
	if strings.HasPrefix(sl, "/") || strings.HasPrefix(sl, "~") || strings.Contains(sl, "$") ||
		(len(sl) >= 2 && sl[1] == ':') {
		return false
	}
	for _, base := range set.bases {
		cand := joinFlavor(flavor, base, spelling)
		if memberExact(cand, set, flavor) || underTree(cand, set, flavor) ||
			(strings.ContainsAny(spelling, "*?[") && patternReachesSet(cand, set, flavor)) {
			return true
		}
	}
	return false
}

func rootOf(flavor effects.Flavor) string {
	if flavor == effects.FlavorWindows {
		return ""
	}
	return "/"
}

// Protection is the protected-set classifier's answer for one set of one
// target, in the terms of the one decision function (DET111 D3/D4): the target
// class, yes (known) or maybe, and for maybe the reach reason (PLAN 5.3).
type Protection struct {
	Set string
	// Class: authorized_keys, autostart, credential, other_home_credential,
	// hook_config or state.
	Class string
	// Certainty: known (yes) or maybe.
	Certainty string
	// Reach, for maybe only: R-NAME (a word names a member), R-GLOB (a pattern
	// can match one), R-CWD (a relative name under an unknown folder lands on
	// one) or R-FS (a path the resolver could not verify).
	Reach string
	// Basis is the classifier's match basis (exact, tree, link, inode,
	// subtree, glob, inode_glob, lexical, cwd, dir, protected_dir, wrong_dir,
	// dynamic, call_link, unresolved).
	Basis string
}

var setClass = map[string]string{
	SetSSHAuthorizedKeys: "authorized_keys",
	SetShellRC:           "autostart",
	SetCredentials:       "credential",
	SetAgentHookConfig:   "hook_config",
	SetSelfProtection:    "state",
}

// Protected is protected(target) -> yes | no | maybe(reason) for one graded
// target of Project: one Protection per set it may be in (none: no). Every
// route reads the classifier through this one function.
func Protected(pt *semanticpb.EffectTarget) []Protection {
	if pt == nil {
		return nil
	}
	out := make([]Protection, 0, len(pt.Protected))
	for _, m := range pt.Protected {
		p := Protection{Set: m.Set, Class: setClass[m.Set], Basis: m.Reason}
		if p.Class == "" {
			continue
		}
		if m.State == string(gradeKnown) {
			p.Certainty = "known"
			if m.Set == SetCredentials && m.Reason == "other_home" {
				p.Class = "other_home_credential"
			}
		} else {
			p.Certainty = "maybe"
			switch m.Reason {
			case "glob", "subtree":
				p.Reach = "R-GLOB"
			case "cwd":
				p.Reach = "R-CWD"
			case "lexical", "unresolved":
				p.Reach = "R-FS"
			case "inode_glob":
				// a glob's literal word that is a hard link of a member
				p.Reach = "R-NAME"
			default: // dir, protected_dir, wrong_dir, dynamic
				p.Reach = "R-NAME"
			}
			if m.Set == SetCredentials && m.Reason == "wrong_dir" {
				// a credential file's shape outside the active home: another
				// account's credential (rel-1-0-10:GAP-0899, GAP-0898)
				p.Class = "other_home_credential"
			}
		}
		out = append(out, p)
	}
	return out
}
