// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// policyHoldWalkLimit bounds the ancestors compared for one path.
const policyHoldWalkLimit = 64

// policyHoldLinkLimit bounds the links followed when a path is named.
const policyHoldLinkLimit = 40

// policyHoldFileLimit bounds the entries of a held folder compared by file
// identity with a file outside it.
const policyHoldFileLimit = 20000

// PolicyHoldScope says what the held copies of a policy hold show about the
// paths of one call.
type PolicyHoldScope struct {
	// Ignored are the fields of the hold that do not cover the paths: the
	// hold was written for copies of the asset that are still in their
	// folders, and every path is shown to lie outside all of them. A journal
	// row is keyed by the asset name, so without this a hold on one denied
	// copy also blocks another copy of the same name that an allow rule
	// admitted. Nothing is ignored, so the hold stands, when the entry carries
	// no hold, no path is given, a path is relative, carries a parent element
	// or cannot be resolved, a path is a held copy or lies inside one, or no
	// held copy is left to compare with.
	Ignored []string
	// Unknown are the held copies this process could not inspect, or could
	// not compare in full (present, but not readable here, for example below
	// a private home folder, or a folder with too many entries). They are not
	// absent and not proven to hold the paths: only what could be compared
	// was, so the caller decides by profile whether to run the call.
	Unknown []string
}

// PolicyHoldIgnoredFields compares paths with the copies the hold on entry
// was written for. A path lies inside a held copy when any name it takes on
// the way to its target (the path as given, and every link it passes through)
// is below the copy, so a link that sits in a held copy is protected whatever
// it points to; when the resolved path or any ancestor of it is that copy by
// file identity (device and inode), or is below it by name; or when the
// resolved path is a file with the identity of a file in a held folder, which
// is how a hard link to a held file looks.
func PolicyHoldIgnoredFields(entry *audit.ActionEntry, paths []string) PolicyHoldScope {
	if entry == nil {
		return PolicyHoldScope{}
	}
	fields, copies := parsePolicyHold(entry.Reason)
	if len(fields) == 0 || len(copies) == 0 {
		return PolicyHoldScope{}
	}
	held := heldPolicyCopies(copies)
	if len(held) == 0 {
		return PolicyHoldScope{}
	}
	proven := 0
	unsure := make([]bool, len(held))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) || hasParentElement(path) {
			return PolicyHoldScope{}
		}
		resolved, exact := resolveHoldPath(path)
		if !exact {
			return PolicyHoldScope{}
		}
		trail := holdPathTrail(path)
		for i := range held {
			inside, complete := held[i].contains(resolved, trail)
			if inside {
				return PolicyHoldScope{}
			}
			if !complete {
				unsure[i] = true
			}
		}
		proven++
	}
	if proven == 0 {
		return PolicyHoldScope{}
	}
	scope := PolicyHoldScope{Ignored: fields}
	for i, copy := range held {
		if copy.info == nil || unsure[i] {
			scope.Unknown = append(scope.Unknown, copy.recorded)
		}
	}
	return scope
}

// PolicyHoldStrict reports whether connector runs the strict tier or the
// managed enterprise deployment, which keep a policy hold on a copy they
// cannot inspect, and on a root owner that allows a copy another connector
// denies. Balanced and permissive run the ordinary call and say so.
func PolicyHoldStrict(cfg *config.Config, connector string) bool {
	return cfg != nil && (managed.IsManagedEnterprise(cfg.DeploymentMode) ||
		cfg.HookPolicyTierForConnector(connector) == config.HookPolicyTierStrict)
}

// heldPolicyCopy is one copy a policy hold was written for.
type heldPolicyCopy struct {
	recorded string      // the path in the hold tag
	resolved string      // the path with every link followed as far as it could be
	info     os.FileInfo // its identity; nil when it cannot be inspected here

	files     []os.FileInfo // identities of the files and links in a held folder
	filesDone bool          // files was read
	filesFull bool          // files lists every entry of the folder
}

// heldPolicyCopies are the copies of a hold tag that are not absent. A copy
// that cannot be inspected is kept, with no identity: it is present, unknown.
func heldPolicyCopies(copies []string) []heldPolicyCopy {
	var out []heldPolicyCopy
	for _, key := range livePolicyCopies(copies, "") {
		raw, err := base64.RawURLEncoding.DecodeString(key)
		if err != nil {
			continue
		}
		resolved, _ := resolveHoldPath(string(raw))
		info, err := os.Stat(resolved)
		if err != nil && pathAbsent(err) {
			continue
		}
		out = append(out, heldPolicyCopy{recorded: string(raw), resolved: resolved, info: info})
	}
	return out
}

// contains reports whether a path is the held copy or inside it, and whether
// the comparison could be made in full. resolved is the target of the path and
// trail the names and links on the way to it: any name below the copy counts,
// as does the resolved path below it, the identity of the resolved path or of
// one of its ancestors, and the identity of a file or link in a held folder
// (a hard link to it has the same device and inode, whatever the link points
// to). A folder that cannot be read through, or is too large to compare, does
// not prove that the path lies inside it: the answer is outside and
// incomplete, and the caller decides by profile. A lookup that fails on the
// path itself counts as inside.
func (h *heldPolicyCopy) contains(resolved string, trail holdTrail) (inside, complete bool) {
	for _, name := range append([]string{resolved}, trail.names...) {
		if pathWithinRoot(name, h.resolved) || pathWithinRoot(name, h.recorded) {
			return true, true
		}
	}
	if h.info == nil {
		return false, true
	}
	links := trail.links
	for p, depth := resolved, 0; ; depth++ {
		if depth >= policyHoldWalkLimit {
			return true, true
		}
		info, err := os.Stat(p)
		switch {
		case err == nil:
			if os.SameFile(info, h.info) {
				return true, true
			}
			if depth == 0 && info.Mode().IsRegular() {
				links = append(links[:len(links):len(links)], info)
			}
		case !pathAbsent(err):
			return true, true
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	if !h.info.IsDir() || len(links) == 0 {
		return false, true
	}
	found, full := h.holdsAny(links)
	return found, full
}

// holdsAny reports whether any of infos is the identity of a file or link in
// the held folder, and whether the whole folder was compared. The folder is
// read once per call.
func (h *heldPolicyCopy) holdsAny(infos []os.FileInfo) (found, complete bool) {
	if !h.filesDone {
		h.filesDone = true
		h.filesFull = true
		seen := 0
		_ = filepath.WalkDir(h.resolved, func(_ string, d fs.DirEntry, err error) error {
			if err != nil {
				h.filesFull = false
				return nil
			}
			if seen++; seen > policyHoldFileLimit {
				h.filesFull = false
				return fs.SkipAll
			}
			if d.Type().IsRegular() || d.Type()&fs.ModeSymlink != 0 {
				if entry, ierr := d.Info(); ierr == nil {
					h.files = append(h.files, entry)
				} else {
					h.filesFull = false
				}
			}
			return nil
		})
	}
	for _, entry := range h.files {
		for _, info := range infos {
			if os.SameFile(entry, info) {
				return true, true
			}
		}
	}
	return false, h.filesFull
}

// holdTrail is how a path reaches its target: the names it takes, and the
// identity of every link it passes through.
type holdTrail struct {
	names []string
	links []os.FileInfo
}

// holdPathTrail follows path the way the system does and records the names it
// takes: each prefix of the path that is still on the way to the target and,
// for every link on it, the link itself and each prefix of its target in turn.
// A folder that a parent element steps out of again is not on the way (an
// alias spelled held/../admitted/x is the admitted file), but a link is named
// whatever follows it. A link that cannot be read ends the trail.
func holdPathTrail(path string) holdTrail {
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	cur := volume + string(filepath.Separator)
	queue := strings.Split(filepath.ToSlash(strings.TrimPrefix(path, cur)), "/")
	var trail holdTrail
	var chain []string
	for links := 0; len(queue) > 0 && len(trail.names)+len(chain) < policyHoldWalkLimit*policyHoldLinkLimit; {
		name := queue[0]
		queue = queue[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			if len(chain) > 0 {
				chain = chain[:len(chain)-1]
			}
			continue
		}
		cur = filepath.Join(cur, name)
		info, err := os.Lstat(cur)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			chain = append(chain, cur)
			continue
		}
		trail.names = append(trail.names, cur)
		trail.links = append(trail.links, info)
		target, err := os.Readlink(cur)
		if links++; err != nil || links > policyHoldLinkLimit {
			break
		}
		cur = filepath.Dir(cur)
		if filepath.IsAbs(target) {
			cur = filepath.VolumeName(target) + string(filepath.Separator)
			target = strings.TrimPrefix(target, cur)
			chain = chain[:0]
		}
		queue = append(strings.Split(filepath.ToSlash(target), "/"), queue...)
	}
	trail.names = append(trail.names, chain...)
	return trail
}

// resolveHoldPath is path with every link followed. A path that does not
// exist is resolved through its longest existing ancestor and the missing
// names are appended; the result is exact only when nothing along the way was
// unreadable, a loop or a link to nowhere.
func resolveHoldPath(path string) (string, bool) {
	path = filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, true
	}
	parent := filepath.Dir(path)
	if parent == path {
		return path, false
	}
	dir, exact := resolveHoldPath(parent)
	if _, lerr := os.Lstat(path); lerr == nil || !pathAbsent(err) {
		exact = false
	}
	return filepath.Join(dir, filepath.Base(path)), exact
}

// pathAbsent reports a lookup error that proves the path is not there (the
// name is missing, or a parent is not a folder), as opposed to one that only
// says this process could not look.
func pathAbsent(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// hasParentElement reports whether path has a parent element, which would
// make a comparison by name unreliable.
func hasParentElement(path string) bool {
	for _, element := range strings.FieldsFunc(path, func(r rune) bool { return r == os.PathSeparator || r == '/' }) {
		if element == ".." {
			return true
		}
	}
	return false
}
