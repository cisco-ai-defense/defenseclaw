// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// A plain unquoted scalar is field-split before cp reads its options. Return
// only a positive target-directory reading; an uncertain value supplies no
// ordinary-destination proof.
func actionPosixCopyVariableTarget(call *syntax.CallExpr, values actionValues, cwd, home string) (string, bool) {
	if call == nil || len(call.Args) < 3 || len(call.Assigns) != 0 {
		return "", false
	}
	program, fixed := staticProgramWord(call.Args[0], home)
	if !fixed || !slices.Contains(copyPrograms, programBase(program)) {
		return "", false
	}
	if _, changed := values["IFS"]; changed {
		return "", false
	}
	args := make([]string, 0, len(call.Args)+2)
	expanded := false
	for _, word := range call.Args[1:] {
		value, known := actionWordValue(word, values, cwd, home)
		if !known || strings.ContainsAny(value, "*?[]\x00") {
			return "", false
		}
		if len(word.Parts) == 1 {
			if _, unquoted := word.Parts[0].(*syntax.ParamExp); unquoted {
				if _, simple := actionSimpleProgramParameter(word); !simple {
					return "", false
				}
				fields := strings.Fields(value)
				if len(fields) < 1 || len(fields) > 8 {
					return "", false
				}
				args = append(args, fields...)
				expanded = true
				continue
			}
		}
		args = append(args, value)
	}
	if !expanded {
		return "", false
	}
	parsed := cpOperands(args, makeStatic(len(args)))
	return parsed.destination, parsed.ok && parsed.targetDir
}
