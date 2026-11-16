// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// An unknown scalar at the start of a word may be empty in the shell. In
// $D/absolute/path that leaves /absolute/path as a possible write target.
// This is positive evidence only: callers must still check that the possible
// target is protected, and must not use it to prove an ordinary write safe.
func actionOptionalEmptyPrefix(word *syntax.Word, values actionValues, cwd, home string) (string, bool) {
	if word == nil || len(word.Parts) < 2 {
		return "", false
	}
	param, ok := word.Parts[0].(*syntax.ParamExp)
	if !ok || !simpleScalarParameter(param) {
		return "", false
	}
	if _, known := values[param.Param.Value]; known {
		return "", false
	}
	lit, ok := word.Parts[1].(*syntax.Lit)
	if !ok || !strings.HasPrefix(lit.Value, "/") {
		return "", false
	}
	tail := &syntax.Word{Parts: word.Parts[1:]}
	value, fixed := actionWordValue(tail, values, cwd, home)
	return value, fixed && filepath.IsAbs(value)
}
