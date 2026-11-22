// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A write operand with a .. component names the file the kernel reaches by
// walking it: a .. after a link or a Windows junction ascends from the
// link's target, so with jx a junction to ~/.defenseclaw the operand
// project/jx/../.defenseclaw/config.yaml is the DefenseClaw config, while
// its lexically cleaned spelling, project/.defenseclaw/config.yaml, is an
// ordinary project file. The protected-path check judges the walk spelling
// before the lexical one, on the same path in every tier: a per-user
// gateway walks it on the local file system, a managed one asks the hook
// client's map by the key the client walked (hookpaths.RawDotDotOperand),
// and a walk that cannot be resolved is an unknown target, at least the
// unknown tier of the pack (rel-1-0-10:GAP-1007; GAP-2047 is the POSIX
// spelling on Linux and macOS).

// dotDotWalkSpelling is the walk spelling of a write operand with a ..
// component, as the hook client keys it on every system: the operand when
// it is absolute, else the operand joined to the call's directory, uncleaned.
// ok is false for any other operand, and for a relative one whose join does
// not clean to the path fact's resolved path (an operand placed after a cd
// keeps its lexical reading), as for stateWalkSpelling.
func dotDotWalkSpelling(candidate actionfacts.PathFact, request trustedActionRequest) (string, bool) {
	raw, ok := hookpaths.RawDotDotOperand(candidate.Value, dotDotWalkCWD(request))
	if !ok {
		return "", false
	}
	if raw == candidate.Value && filepath.IsAbs(raw) {
		return raw, true
	}
	if candidate.Resolved == "" || !sameCleanPath(raw, candidate.Resolved) {
		return "", false
	}
	return raw, true
}

// dotDotWalkCWD is the directory the hook client keyed the call's operands
// in: the call's cwd, else the directory a static cd placed a simple command
// in, else the client's own cwd from its map.
func dotDotWalkCWD(request trustedActionRequest) string {
	if filepath.IsAbs(request.Input.CWD) {
		return request.Input.CWD
	}
	if filepath.IsAbs(request.evidenceCWD) {
		return request.evidenceCWD
	}
	if cwd := request.ResolvedWriteTargets[hookpaths.CWDKey]; filepath.IsAbs(cwd) {
		return filepath.Clean(cwd)
	}
	return ""
}

// trustedDotDotWalkUnresolved reports a write operand with a .. component
// whose walk cannot be resolved (hookpaths.DotDotWalkUnresolved). The hook
// client's fact answers for a managed gateway, which does not open the user
// home; a per-user gateway walks the operands itself. A call with no .. in
// its text has no such operand and costs no walk.
func trustedDotDotWalkUnresolved(request trustedActionRequest, facts actionfacts.Facts) bool {
	if fact := request.ResolvedWriteTargets[hookpaths.DotDotWalkUnresolvedKey]; fact != "" || request.ProtectedHomeHook {
		return fact == "1"
	}
	if request.SkipLocalFilesystemResolution {
		return false
	}
	if command, ok := trustedBashCommandInput(request.Input); !ok || !strings.Contains(command, "..") {
		return false
	}
	return hookpaths.DotDotWalkUnresolved(facts, dotDotWalkCWD(request))
}
