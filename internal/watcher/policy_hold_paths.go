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
	// Unknown are the held copies this process could not inspect (present,
	// but not readable here, for example below a private home folder). They
	// are not absent: only the names of the paths were compared with them,
	// so the caller decides by profile whether to run the call.
	Unknown []string
}

// PolicyHoldIgnoredFields compares paths with the copies the hold on entry
// was written for. Each path is resolved first (every link on it followed),
// and it lies inside a held copy when the resolved path or any ancestor of it
// is that copy by file identity (device and inode), or is below it by name.
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
		for _, copy := range held {
			if copy.contains(resolved) {
				return PolicyHoldScope{}
			}
		}
		proven++
	}
	if proven == 0 {
		return PolicyHoldScope{}
	}
	scope := PolicyHoldScope{Ignored: fields}
	for _, copy := range held {
		if copy.info == nil {
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

// contains reports whether the resolved path is the held copy or below it:
// by name, or by the identity of the path or of one of its ancestors. A
// comparison that cannot be made counts as inside.
func (h heldPolicyCopy) contains(resolved string) bool {
	if pathWithinRoot(resolved, h.resolved) {
		return true
	}
	if h.info == nil {
		return false
	}
	for p, depth := resolved, 0; depth < policyHoldWalkLimit; depth++ {
		info, err := os.Stat(p)
		switch {
		case err == nil:
			if os.SameFile(info, h.info) {
				return true
			}
		case !pathAbsent(err):
			return true
		}
		parent := filepath.Dir(p)
		if parent == p {
			return false
		}
		p = parent
	}
	return true
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
