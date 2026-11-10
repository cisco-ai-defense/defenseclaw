// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// IsShellCommandStringWrapper reports whether wrapper is a POSIX shell run
// with one command string (`bash -c BODY`, `sh -c BODY`): the analysis
// unwraps it, and the string runs as the shell reads it, in the same
// directory. A shell that runs a script file, reads stdin, only parses the
// string (-n) or runs startup files first (login, interactive, zsh), and a
// program that is not a shell, is not one.
func IsShellCommandStringWrapper(wrapper WrapperFact) bool {
	program := strings.ToLower(wrapper.Executable)
	if at := strings.LastIndexAny(program, `/\`); at >= 0 {
		program = program[at+1:]
	}
	program = strings.TrimSuffix(program, ".exe")
	invocation := parsePOSIXShellInvocation(program, wrapper.Argv)
	return invocation.valid && invocation.mode == posixShellModeCommand && !invocation.noExec
}
