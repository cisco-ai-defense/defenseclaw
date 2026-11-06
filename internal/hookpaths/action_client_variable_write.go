// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// A whole-command target scan can also see read operands and the entry of
// an ordinary link removed by rm. Use it as extra client evidence only for
// a variable output redirect or a variable writer destination.
func actionClientVariableWriteCandidate(command, home string) bool {
	if !strings.ContainsRune(command, '$') {
		return false
	}
	file, parsed := parseShell(command)
	if !parsed {
		return false
	}
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		if redirect, ok := node.(*syntax.Redirect); ok && redirect.Word != nil &&
			actionOutputRedirect(redirect.Op) && wordExpandsParameter(redirect.Word) {
			found = true
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		program, fixed := staticProgramWord(call.Args[0], home)
		if !fixed {
			return true
		}
		switch programBase(program) {
		case "cp":
			found = len(call.Args) >= 3 && actionSoleParameter(call.Args[len(call.Args)-1]) != ""
		case "install", "rsync":
			found = len(call.Args) >= 3 && wordExpandsParameter(call.Args[len(call.Args)-1])
		case "tee":
			for _, arg := range call.Args[1:] {
				if wordExpandsParameter(arg) {
					found = true
					break
				}
			}
		case "dd":
			for _, arg := range call.Args[1:] {
				if len(arg.Parts) == 0 {
					continue
				}
				prefix, ok := arg.Parts[0].(*syntax.Lit)
				if ok && strings.HasPrefix(prefix.Value, "of=") && wordExpandsParameter(arg) {
					found = true
					break
				}
			}
		}
		return !found
	})
	return found
}
