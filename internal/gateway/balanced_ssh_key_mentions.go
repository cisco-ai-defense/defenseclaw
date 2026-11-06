// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// sshKeyShellGrade keeps uncertainty from an unselected shell reading in
// strict policy, while only a target named by the selected shell is Named.
// The selected reader already combines the grammars that may execute there.
func sshKeyShellGrade(memo *hookpaths.TargetMemo, input actionfacts.Input, home string, globFacts map[string]string, posixShell bool) hookpaths.Grade {
	unknown := memo.ActionCommandGradeWithDialectAndGlobFacts(input.Command, input.CWD, home, "", globFacts)
	if input.DialectHint == "" {
		if posixShell {
			unknown = unknown.Max(memo.ActionCommandGradeInShell(input.Command, input.CWD, home, globFacts, true))
		}
		return unknown
	}
	hinted := memo.ActionCommandGradeWithDialectAndGlobFacts(input.Command, input.CWD, home, input.DialectHint, globFacts)
	if unknown != hookpaths.GradeNone {
		hinted = hinted.Max(hookpaths.GradePossible)
	}
	return hinted
}

// A confirmed target from the client is stronger than an uncertain shell
// reading. The gateway also checks concrete paths resolved on the user's host.
func sshKeyMentionGrade(request trustedActionRequest) hookpaths.Grade {
	input := request.Input
	if len(input.ActiveHome) < 3 || input.ActiveHome[1] != ':' || input.CWD == "" {
		return hookpaths.GradeNone
	}
	if input.Command == "" {
		input.Command, _ = trustedBashCommandInput(input)
	}
	if input.Command == "" {
		return hookpaths.GradeNone
	}
	grade := hookpaths.GradeNone
	switch request.ResolvedWriteTargets[hookpaths.ActionDecisionKey] {
	case hookpaths.ProtectedTargetDecision:
		return hookpaths.GradeNamed
	case hookpaths.PossibleTargetDecision:
		grade = hookpaths.GradePossible
	}
	ssh := canonicalSemanticPath(filepath.Join(input.ActiveHome, ".ssh"))
	protectedPaths := hookpaths.ProtectedAuthorizedKeysPaths(input.ActiveHome)
	isNamed := func(path string) bool {
		path = canonicalSemanticPath(path)
		if path == ssh {
			return true
		}
		for _, protected := range protectedPaths {
			if path == canonicalSemanticPath(protected) {
				return true
			}
		}
		return false
	}
	for operand, resolved := range request.ResolvedWriteTargets {
		if strings.HasPrefix(operand, "\x00") {
			continue
		}
		if isNamed(resolved) {
			return hookpaths.GradeNamed
		}
	}
	// A complete source-glob reading includes each destination child. A
	// child may already be a link to a key file even when the copy names
	// only an ordinary destination directory.
	for _, destination := range hookpaths.CopySourceGlobDestinations(input.Command, input.CWD, input.ActiveHome, request.ResolvedWriteTargets) {
		if isNamed(destination) {
			return hookpaths.GradeNamed
		}
		if resolved, ok := hookpaths.ResolveWriteTarget(destination); ok && isNamed(resolved) {
			return hookpaths.GradeNamed
		}
	}
	// A known startup file can run additional statements.
	if os.Getenv("BASH_ENV") != "" && strings.Contains(strings.ToLower(input.Command), "bash") {
		return hookpaths.GradeNamed
	}
	hit := sshKeyShellGrade(request.targetMemo, input, input.ActiveHome, clientGlobFacts(request), input.DialectHint == actionfacts.DialectPOSIX)
	return grade.Max(hit)
}
