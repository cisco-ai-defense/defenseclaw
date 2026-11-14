// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// variableWriteVerbs are the programs whose variable operand the client
// carries its own decision for: a managed gateway behind ProtectHome cannot
// read the user's home, so it cannot settle the operand itself. touch,
// chmod, chown, chgrp and truncate join the earlier writers for GAP-0298 and
// GAP-0327; cp, mv and ln keep the readings of their own destination
// scans, which fixtures (GAP-0403, GAP-0428) pin apart from this one.
var variableWriteVerbs = map[string]bool{
	"touch": true, "gtouch": true, "chmod": true, "chown": true, "chgrp": true, "truncate": true,
	"sed": true, "gsed": true,
}

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
		switch name := programBase(program); {
		case name == "install" || name == "rsync":
			found = len(call.Args) >= 3 && wordExpandsParameter(call.Args[len(call.Args)-1])
		case name == "tee" || variableWriteVerbs[name]:
			for _, arg := range call.Args[1:] {
				if wordExpandsParameter(arg) {
					found = true
					break
				}
			}
		case name == "dd":
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
