// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// policyHoldWalkLimit bounds the ancestors compared for one path.
const policyHoldWalkLimit = 64

// PolicyHoldIgnoredFields are the fields of the policy hold on entry (a
// journal row journalPolicyDenied wrote) that do not cover paths: the hold
// was written for copies of the asset that are still in their folders, and
// every path is shown to lie outside all of them. A journal row is keyed by
// the asset name, so without this a hold on one denied copy also blocks
// another copy of the same name that an allow rule admitted. Nothing is
// ignored, so the hold stands, when entry carries no hold, no path is given,
// a path is relative, carries a parent element or cannot be compared, or no
// held copy is left to compare with.
func PolicyHoldIgnoredFields(entry *audit.ActionEntry, paths []string) []string {
	if entry == nil {
		return nil
	}
	fields, copies := parsePolicyHold(entry.Reason)
	if len(fields) == 0 || len(copies) == 0 {
		return nil
	}
	held := livePolicyCopyPaths(copies)
	if len(held) == 0 {
		return nil
	}
	proven := 0
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) || hasParentElement(path) {
			return nil
		}
		for _, copy := range held {
			if pathInsideHeldCopy(path, copy) {
				return nil
			}
		}
		proven++
	}
	if proven == 0 {
		return nil
	}
	return fields
}

// PolicyHoldIgnores reports whether field of the hold on entry is one that
// PolicyHoldIgnoredFields shows does not cover paths.
func PolicyHoldIgnores(entry *audit.ActionEntry, field string, paths []string) bool {
	return slices.Contains(PolicyHoldIgnoredFields(entry, paths), field)
}

// livePolicyCopyPaths are the paths of the copies of a hold tag whose folder
// is still there.
func livePolicyCopyPaths(copies []string) []string {
	var out []string
	for _, key := range livePolicyCopies(copies, "") {
		if raw, err := base64.RawURLEncoding.DecodeString(key); err == nil {
			out = append(out, string(raw))
		}
	}
	return out
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

// pathInsideHeldCopy reports whether path is the held copy or below it, by
// name or, through links, by identity of the copy folder and each ancestor of
// path. A comparison that cannot be made counts as inside.
func pathInsideHeldCopy(path, held string) bool {
	if pathWithinRoot(path, held) {
		return true
	}
	heldInfo, err := os.Stat(held)
	if err != nil {
		return true
	}
	for p, depth := path, 0; depth < policyHoldWalkLimit; depth++ {
		if info, err := os.Stat(p); err == nil && os.SameFile(info, heldInfo) {
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
