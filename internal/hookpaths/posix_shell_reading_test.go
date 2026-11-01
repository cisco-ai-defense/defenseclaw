// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// The POSIX-grammar rows are calls a POSIX shell runs. On Windows that shell
// is Git Bash (Claude Code's Bash tool) under the native home, and the
// gateway passes the POSIX dialect hint, which reads the call with the POSIX
// grammar on the Windows file system as well as with the Windows grammars
// (ActionCommandDecisionWithDialectAndGlobFacts, GAP-1717). These helpers
// make the rows read the call that way on every host: elsewhere the home is
// POSIX and the plain decision is that reading.

func posixShellDecision(command, cwd, home string) string {
	return posixShellDecisionWithGlobFacts(command, cwd, home, nil)
}

func posixShellDecisionWithGlobFacts(command, cwd, home string, facts map[string]string) string {
	if runtime.GOOS == "windows" {
		return ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, actionfacts.DialectPOSIX, facts)
	}
	return ActionCommandDecisionWithGlobFacts(command, cwd, home, facts)
}

func posixShellPrivateKeyRead(command, cwd, home string) bool {
	if runtime.GOOS == "windows" {
		return ActionPrivateKeyReadWithDialect(command, cwd, home, actionfacts.DialectPOSIX)
	}
	return ActionPrivateKeyRead(command, cwd, home)
}

func posixShellAuditReason(command, cwd, home string) string {
	if runtime.GOOS == "windows" {
		return ActionCommandAuditReasonWithDialect(command, cwd, home, actionfacts.DialectPOSIX)
	}
	return ActionCommandAuditReason(command, cwd, home)
}

// hookWriteEvidenceHost reports a host whose hook client sends the gateway
// Resolve's write evidence. On Windows it sends none (hookexec
// setHookRequestFacts), so the map is not a Windows product path and its
// rows are pinned on Linux and macOS.
func hookWriteEvidenceHost() bool { return runtime.GOOS != "windows" }
