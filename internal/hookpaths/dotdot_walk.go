// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// DotDotWalkUnresolvedKey carries the hook client's finding that a write
// operand with a .. component could not be walked as the kernel walks it
// (DotDotWalkUnresolved), for a gateway that does not open the user home.
// The value is "1".
const DotDotWalkUnresolvedKey = "\x00dotdot-walk-unresolved"

// maxDotDotWalkParts bounds the components one unresolved operand is walked
// by, prefix by prefix, to tell a missing folder from a link the walk cannot
// follow. A longer operand is past the bound: TRUNCATED (the one bound rule).
const maxDotDotWalkParts = 256

// DotDotWalkUnresolved reports a write or append operand of facts with a ..
// component whose walk cannot be resolved, on every system and in every tier
// (rel-1-0-10:GAP-1007). A .. after a link or junction ascends from the
// link's target, so only the walk (RawDotDotOperand, the spelling the client
// keys and the gateway asks by) tells which file the call writes; its
// lexical spelling proves nothing. When the walk fails at a name that exists
// (a link loop, a chain past the link limit, a reparse point the walk cannot
// read, a folder closed to the user) or the operand is past the walk bound,
// the target is unknown: the gateway judges the call at least in the unknown
// tier of the pack, never an allow. A walk that fails only because a folder
// before a .. does not exist yet is not unknown: no link can be on the way,
// and the lexical spelling is the file.
func DotDotWalkUnresolved(facts actionfacts.Facts, cwd string) bool {
	for _, candidate := range facts.Paths {
		if candidate.Access != actionfacts.PathAccessWrite && candidate.Access != actionfacts.PathAccessAppend {
			continue
		}
		raw, ok := RawDotDotOperand(candidate.Value, cwd)
		if ok && dotDotWalkUnresolved(raw) {
			return true
		}
	}
	return false
}

// dotDotWalkUnresolved reports a raw .. spelling whose walk fails at an
// existing name, or one past maxDotDotWalkParts.
func dotDotWalkUnresolved(raw string) bool {
	if _, ok := ResolveWriteTarget(raw); ok {
		return false
	}
	volume := filepath.VolumeName(raw)
	parts := strings.Split(filepath.ToSlash(strings.TrimPrefix(raw, volume)), "/")
	if len(parts) > maxDotDotWalkParts {
		return true
	}
	parent := ""
	for index, part := range parts {
		if part == "" || part == "." {
			continue
		}
		prefix := volume + strings.Join(parts[:index+1], "/")
		resolved, ok := ResolveWriteTarget(prefix)
		if ok {
			parent = resolved
			continue
		}
		if parent == "" {
			return true
		}
		// The walk refuses a step over a name that does not exist (it may
		// become a link before the command runs); the kernel refuses it
		// too, and Win32 cleans it lexically, so the lexical reading stands.
		_, err := pathLstat(parent)
		return !os.IsNotExist(err)
	}
	return true
}
