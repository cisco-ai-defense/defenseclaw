// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// An in-place editor call (sed -i, perl -i) whose backup file the reader
// cannot name in full (a suffix, operand or directory the words do not give,
// a wrapper that takes its operands from run time, a link --follow-symlinks
// cannot read: hookpaths.SedInPlaceBackupUnresolved) has a path target the
// hook cannot judge. It is truncated at the path targets (bound rule,
// internal/guardrail/bounded, cap paths): what the readers proved still
// decides, and the call is at least the unknown tier of the pack, an alert
// in the default and permissive packs and a block in the strict pack, never
// an allow (rel-1-0-10:GAP-0540, GAP-0541, GAP-0542, GAP-0543).

// trustedSedBackupUnresolved reports an unresolved in-place backup. The hook
// client's fact answers for a managed gateway, which does not open the user
// home; a per-user gateway reads the call itself, as for the recovered-parse
// bound (trustedCallShellParseBound).
func trustedSedBackupUnresolved(request trustedActionRequest) bool {
	if fact := request.ResolvedWriteTargets[hookpaths.BackupUnresolvedKey]; fact != "" || request.ProtectedHomeHook {
		return fact == "1"
	}
	command, ok := trustedBashCommandInput(request.Input)
	return ok && request.targetMemo.SedInPlaceBackupUnresolved(command, request.Input.CWD, request.Input.ActiveHome)
}

// sedBackupUnresolvedFindings adds the truncation of an unresolved backup to
// the findings of the call.
func sedBackupUnresolvedFindings(request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	if !trustedSedBackupUnresolved(request) {
		return findings
	}
	return withBoundedTruncation(findings, bounded.Of(bounded.Paths), request)
}
