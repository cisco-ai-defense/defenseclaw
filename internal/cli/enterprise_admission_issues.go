// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// appendAdmissionIssueWarnings reports the skills, plugins and MCP servers
// whose install admission the gateway with data folder dataDir could not
// finish: status and verify printed ok while a CRITICAL skill the gateway
// could not scan or move stayed in a user's folder (GAP-0825, GAP-0826).
// A skill or plugin no longer in its folder is not reported.
func appendAdmissionIssueWarnings(result *enterprisestatus.Result, dataDir string) {
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
		}
	}
}
