// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// mcpAdmissionAllowedLead leads the agent-visible warning of a call to an MCP
// server DefenseClaw could not scan, which the OSS default and permissive
// tiers allow (GAP-0775).
const mcpAdmissionAllowedLead = "DefenseClaw could not scan MCP server "

// mcpScanIssueClause says why a scan cannot run, from the watcher's reading of
// the definition; "" when the definition does not show it.
func mcpScanIssueClause(issue string) string {
	switch issue {
	case watcher.MCPScanIssueLauncher:
		return "its launcher is not npx or uvx"
	case watcher.MCPScanIssueAddress:
		return "its URL is a loopback, private or link-local address"
	}
	return ""
}

// mcpAdmissionNextStep is the one next step for a server that cannot be
// scanned: the allow command, the definition a scan starts, or where to read
// the cause. The same words reach the agent (hook) and the audit row;
// defenseclaw mcp list words them from the CLI.
func mcpAdmissionNextStep(name, issue string) string {
	switch issue {
	case watcher.MCPScanIssueLauncher:
		return "run: defenseclaw mcp allow " + name + ", or start it with npx or uvx, or serve it from a public URL"
	case watcher.MCPScanIssueAddress:
		return "run: defenseclaw mcp allow " + name + ", or serve it from a public URL"
	}
	return "see: defenseclaw mcp list, or run: defenseclaw mcp allow " + name
}

// mcpAdmissionFailedText words a completed admission scan failure with its
// reason and next step: "MCP server X has a failed admission scan (why); to
// use it, <next step>".
func mcpAdmissionFailedText(name, issue string) string {
	var b strings.Builder
	b.WriteString("MCP server " + name + " has a failed admission scan")
	if clause := mcpScanIssueClause(issue); clause != "" {
		b.WriteString(" (could not be scanned: " + clause + ")")
	}
	b.WriteString("; " + mcpAdmissionNextStep(name, issue))
	return b.String()
}

// mcpAdmissionAllowedWarning is the agent-visible warning of a call allowed
// to a server that could not be scanned.
func mcpAdmissionAllowedWarning(name, issue string) string {
	text := mcpAdmissionAllowedLead + name
	if clause := mcpScanIssueClause(issue); clause != "" {
		text += " (" + clause + ")"
	}
	return text + ". This call is allowed with a warning; the strict profile and managed deployments block it. Next step: " +
		mcpAdmissionNextStep(name, issue)
}
