// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

// ShellCommandStringIndex is the argv index of the command string a POSIX
// shell call runs (`bash -euo pipefail -c STRING`, `bash -c -- STRING`,
// `bash -O extglob -c STRING`), read with the shell option reader the
// classifier uses, so callers outside this package keep no second option
// list (rel-1-0-5 GAP-0052, pod check32). ok is false when argv is not a
// bash, sh, dash, ksh or mksh call that runs a command string, or when
// noexec is set. A login, interactive or rc-file shell still runs the
// command string after its startup input, so its index is returned too
// (pod check33 P16/P26 `bash -o pipefail -lc STRING`); the classifier keeps
// such a call non-authoritative. argv holds the static text of every word.
func ShellCommandStringIndex(argv []string) (int, bool) {
	if len(argv) == 0 {
		return 0, false
	}
	invocation := parsePOSIXShellInvocation(commandProgram(argv[0]), argv)
	if (!invocation.valid && !invocation.startupInput) || invocation.mode != posixShellModeCommand || invocation.noExec ||
		invocation.commandIndex <= 0 || invocation.commandIndex >= len(argv) {
		return 0, false
	}
	index := invocation.commandIndex
	// `bash -c -- STRING`: the `--` after -c ends the options and STRING
	// runs (real bash and dash); the invocation reader stops at the `--`.
	if argv[index] == "--" && index+1 < len(argv) {
		index++
	}
	return index, true
}
