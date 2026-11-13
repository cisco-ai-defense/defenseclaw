// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import "strings"

// KiroV3PromptCheckedNote is the line a Kiro hook prints when it answers a
// UserPromptSubmit from the .kiro/hooks configuration (hook dialect v3)
// without a block. Kiro v3 (kiro-cli 3.x by default, kiro-cli --v3 before
// it; @kiro/agent 0.66.102 in kiro-cli 3.3.0) adds the result of every such
// command hook to the turn as a new message: its stdout inside
// <HOOK_INSTRUCTION>, or, when stdout is empty, "Output:\n\n\nExit Code: 0",
// the shape of a shell result. After that message models answered as if
// the command they were asked to run had already run and called no tool, so
// no PreToolUse hook fired and nothing was inspected (rel-1-0-10:GAP-0248,
// seen on Windows, Linux and macOS), or refused the prompt as an injection.
// The note says what happened instead, for this prompt only, without
// judging the prompt (an alert answer gets it too). kiro-hook.sh prints the
// same text. A Secure Client render keeps its own contract and prints none.
// The CLI 2.x agent configuration installs no prompt hook (kiroV2HookSpecs
// in the connector package).
const KiroV3PromptCheckedNote = "DefenseClaw prompt hook: this is not command output. No command has run for this prompt yet."

// kiroV3PromptNote reports whether a Kiro answer prints
// KiroV3PromptCheckedNote: the event is a UserPromptSubmit and the hook was
// started from the .kiro/hooks configuration (--hook-surface v3). Kiro v3
// names the event exactly so in its hook payload.
func kiroV3PromptNote(opts Options) bool {
	return !opts.SecureClient && hookDialect(opts) == "v3" && strings.TrimSpace(opts.Event) == "UserPromptSubmit"
}
