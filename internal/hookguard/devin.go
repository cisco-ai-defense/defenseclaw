// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookguard

import (
	"fmt"
	"io"
)

// Devin on Windows starts a hook command itself, from one single-quoted,
// forward-slash absolute program path followed by bare words:
//
//	'C:/Users/<u>/.local/bin/defenseclaw-hook.exe' hook --connector devin
//
// When that launcher was missing or damaged, Devin got a start error and ran
// the call, because only exit 2 blocks (rel-1-0-6 GAP-0676). On the events
// Devin can block with a prompt or tool answer, per-user Setup starts this
// guard program instead, in the same word form:
//
//	'C:/Users/<u>/.local/bin/defenseclaw-hook-guard.exe' launcher-guard-devin <Event> hook --connector devin
//
// The guard starts defenseclaw-hook.exe beside it with `hook --connector
// devin`, the launcher's argv today, and passes a started launcher's stdin,
// stdout, stderr and exit code through. When the launcher cannot start, or
// ends with a Windows exception status, it writes the Devin sentence and
// exits 2 on a block event (the stable launcher's unavailable answer for
// Devin); any other event gets the sentence on stderr and exit 0.

// DevinSubcommand is the first argument of the Devin guard argv.
const DevinSubcommand = "launcher-guard-devin"

// DevinBlockEvent reports an event whose Devin guard answers a launcher that
// cannot start with a block: PreToolUse, PermissionRequest and
// UserPromptSubmit. Stop is a Devin block event too, but a blocked stop only
// keeps Devin running, so Setup leaves it on the direct launcher start.
func DevinBlockEvent(event string) bool {
	switch event {
	case "PreToolUse", "PermissionRequest", "UserPromptSubmit":
		return true
	}
	return false
}

// DevinArgv returns the launcher's hook argv and the event of the Devin
// guard argv, its arguments after the program name:
//
//	launcher-guard-devin <Event> hook --connector devin
//
// The event is a bare token (letters, digits, '.', '_', '-').
func DevinArgv(args []string) (hookArgs []string, event string, ok bool) {
	if len(args) != 5 || args[0] != DevinSubcommand || !bareToken(args[1]) ||
		args[2] != "hook" || args[3] != "--connector" || args[4] != "devin" {
		return nil, "", false
	}
	return append([]string(nil), args[2:]...), args[1], true
}

// RunDevin runs launcher with hookArgs and passes its stdin, stdout, stderr
// and exit code through. When the launcher cannot start, or ends with a
// Windows exception status, it writes the Devin sentence on stderr and, for
// a block event (DevinBlockEvent), also on stdout with exit 2, the answer
// Devin shows as the block reason; any other event exits 0.
func RunDevin(launcher string, hookArgs []string, event string, stdin io.Reader, stdout, stderr io.Writer) int {
	code, started, missing := runSiblingLauncher(launcher, hookArgs, stdin, stdout, stderr)
	if started {
		return code
	}
	message := LauncherMessage("Devin", missing)
	fmt.Fprintln(stderr, message)
	if !DevinBlockEvent(event) {
		return 0
	}
	fmt.Fprintln(stdout, message)
	return 2
}
