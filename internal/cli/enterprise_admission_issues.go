// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// appendAdmissionIssueWarnings reports the skills, plugins and MCP servers
// whose install admission the gateway with data folder dataDir could not
// finish or did not enforce: status and verify printed ok while a CRITICAL
// skill the gateway could not scan or move, or rejected with take_action
// false, stayed in a user's folder (GAP-0825, GAP-0826, GAP-0774).
// A skill or plugin no longer in its folder is not reported.
func appendAdmissionIssueWarnings(result *enterprisestatus.Result, dataDir, guardianDir string) {
	// A quarantine whose original the hook guardian removes when the user
	// next signs in, and why it waits (GAP-0795).
	for _, request := range enforce.QuarantineRemovalChannelFor(dataDir, guardianDir).DeferredRemovals() {
		if _, err := os.Lstat(request.SourcePath); err != nil {
			continue
		}
		result.AddWarning("asset_removal_deferred", "the "+request.TargetType+" "+request.SourcePath+
			" is in quarantine and blocked, but its original folder stays until the guardian can remove it: "+request.Deferred)
	}
	// An enrolled user whose ~/.claude.json the hook enumerator could not
	// read: the gateway refuses that user's Claude Code MCP servers
	// (GAP-0829).
	for _, state := range enterprisehooks.ReadClaudeStateUnreadable(enterprisehooks.ClaudeMCPSpoolDir(guardianDir)) {
		result.AddWarning("claude_state_unreadable", "the Claude Code MCP servers of "+state.Account()+
			" are blocked: the hook enumerator could not read "+state.Path+" ("+state.Reason+
			"); give SYSTEM read access to the file again or repair its JSON")
	}
	issues, err := watcher.ReadAdmissionIssues(dataDir)
	if err != nil {
		result.AddWarning("admission_state_unreadable", "could not read the install watcher's admission state: "+err.Error())
		return
	}
	for _, issue := range issues {
		subject := issue.Type + " " + issue.Name
		if issue.Type == "mcp" {
			subject = "MCP server " + issue.Name
		} else if _, err := os.Lstat(issue.Path); err != nil {
			continue
		}
		if issue.Account != "" {
			subject += " of " + issue.Account
		}
		if issue.Type != "mcp" {
			subject += " (" + issue.Path + ")"
		}
		switch issue.Kind {
		case watcher.AdmissionUnscanned:
			result.AddWarning("asset_not_scanned", subject+" could not be scanned, so it is blocked and disabled where it is; the gateway scans it again: "+issue.Detail)
		case watcher.AdmissionNotQuarantined:
			result.AddWarning("asset_not_quarantined", subject+" is blocked and disabled, but its files could not be moved to quarantine and are still in place; the gateway tries again: "+issue.Detail)
		case watcher.AdmissionNotEnforced:
			result.AddWarning("asset_rejected_not_enforced", subject+" was rejected by install admission ("+issue.Detail+
				") and stays installed and usable; the gateway enforces the verdict once take_action is true again")
		}
	}
}
