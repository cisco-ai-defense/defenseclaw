// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
	"unicode/utf8"
)

// nativeAbsoluteTarget returns the lexically cleaned absolute spelling of the
// file a native file-tool call writes. A relative target is resolved against
// the absolute POSIX working directory of the call, as the tool does; without
// one it names no file.
func nativeAbsoluteTarget(target, cwd string) (string, bool) {
	if target == "" || len(target) > maxScalarBytes || !utf8.ValidString(target) ||
		strings.ContainsRune(target, 0) {
		return "", false
	}
	if !strings.HasPrefix(target, "/") {
		if !strings.HasPrefix(cwd, "/") {
			return "", false
		}
		target = cwd + "/" + target
	}
	return path.Clean(target), true
}

// nativeOperandsCoverTarget reports whether the facts of a native file-tool
// call name a write operand for target and no more operands than the call has
// files: a call whose facts carry an operand the call does not write is not
// the call the proof read.
func nativeOperandsCoverTarget(facts Facts, files int, target string) bool {
	operands := facts.OperandPaths()
	if len(operands) == 0 || len(operands) > files {
		return false
	}
	for _, operand := range operands {
		if (operand.Access == PathAccessWrite || operand.Access == PathAccessAppend) &&
			operand.Flavor == PathFlavorPOSIX &&
			EtcSpelling(path.Clean(operand.Resolved)) == EtcSpelling(target) {
			return true
		}
	}
	return false
}
