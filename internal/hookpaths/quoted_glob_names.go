// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// quotedGlobNameWriteOperands lists the write and append path facts whose
// value the command spells with a quoted or escaped *, ? or [: the name of
// one entry, not a pattern. The target map leaves out a path fact with those
// characters, which may be an unexpanded pattern, so without this list a
// managed gateway that cannot see the home had no answer for such a name and
// a hard link or symlink of a protected file named 'k[1]' was allowed
// (GAP-0293).
func quotedGlobNameWriteOperands(command, cwd, home string, paths []actionfacts.PathFact) []string {
	if !strings.ContainsAny(command, "*?[") || !strings.ContainsAny(command, "'\"\\") {
		return nil
	}
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	names := map[string]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		word, ok := node.(*syntax.Word)
		if !ok || !noDereferenceTouchLiteralWord(word) || actionWordHasUnquotedGlob(word, command) {
			return true
		}
		fields, err := shellparse.Fields(&expand.Config{Env: expand.ListEnviron("HOME=" + home)}, word)
		if err == nil && len(fields) == 1 && strings.ContainsAny(fields[0], "*?[]") {
			names[fields[0]] = true
		}
		return true
	})
	var operands []string
	for _, candidate := range paths {
		if (candidate.Access == actionfacts.PathAccessWrite || candidate.Access == actionfacts.PathAccessAppend) &&
			names[candidate.Value] {
			operands = append(operands, OperandPath(candidate.Value, cwd))
		}
	}
	return operands
}
