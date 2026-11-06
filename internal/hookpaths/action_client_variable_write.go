// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
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
		args := call.Args
		if programBase(program) == "env" {
			words, static := make([]string, len(args)), make([]bool, len(args))
			for i, arg := range args {
				words[i], static[i] = StaticWord(arg, home)
			}
			run, ok := actionfacts.StaticPrefixWrapperChild(words, static)
			if !ok || run.Index >= len(args) || !static[run.Index] {
				return true
			}
			program, args = words[run.Index], args[run.Index:]
		}
		switch programBase(program) {
		case "cp":
			if len(args) < 3 || !wordExpandsParameter(args[len(args)-1]) {
				break
			}
			// The last expanded word is a write destination only if the
			// normal cp option reader places it there. A target-directory or
			// suffix option can make that same word a source or option value.
			words, static := make([]string, len(args)-1), make([]bool, len(args)-1)
			for i, arg := range args[1:] {
				words[i], static[i] = StaticWord(arg, home)
			}
			const destination = "\x00variable-destination"
			words[len(words)-1], static[len(static)-1] = destination, true
			copy := cpOperands(words, static)
			found = copy.ok && copy.destination == destination
		case "install", "rsync":
			found = len(args) >= 3 && wordExpandsParameter(args[len(args)-1])
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
