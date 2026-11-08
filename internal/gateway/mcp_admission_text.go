// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
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
	case watcher.MCPScanIssueArguments:
		return "its npx or uvx arguments run code or name no package"
	case watcher.MCPScanIssueAddress:
		return "its URL is a loopback, private or link-local address"
	}
	return ""
}

// mcpAdmissionNextStep is the next step for a server that cannot be
// scanned: the allow command (or, on a managed device, the administrator's
// policy), the definition a scan starts, or where to read the cause. step is
// config.MCPNextStep*. The same words reach the agent (hook) and the audit
// row; defenseclaw mcp list words them from the CLI.
func mcpAdmissionNextStep(name, issue, step string) string {
	use := ""
	switch step {
	case config.MCPNextStepAllow:
		if name != "" {
			use = "run: defenseclaw mcp allow " + name
		}
	case config.MCPNextStepAdmin:
		use = "ask your administrator to allow it in the managed MCP policy (asset_policy.mcp.allowed)"
	}
	alternative := ""
	switch issue {
	case watcher.MCPScanIssueLauncher:
		alternative = "start it with npx or uvx, or serve it from a public URL"
	case watcher.MCPScanIssueArguments:
		alternative = "start it with npx or uvx and a package name, or serve it from a public URL"
	case watcher.MCPScanIssueAddress:
		alternative = "serve it from a public URL"
	}
	switch {
	case alternative == "" && use == "":
		return "see: defenseclaw mcp list"
	case alternative == "":
		return "see: defenseclaw mcp list, or " + use
	case use == "":
		return "see: defenseclaw mcp list, or " + alternative
	}
	return use + ", or " + alternative
}

// mcpShownName is the name worded for the agent: the placeholder when the
// reason could not carry a name the agent may be shown.
func mcpShownName(name string) string {
	if name == "" {
		return "(name not shown)"
	}
	return name
}

// mcpAdmissionFailedText words a completed admission scan failure with its
// reason and next step: "MCP server X has a failed admission scan (why); to
// use it, <next step>".
func mcpAdmissionFailedText(name, issue, step string) string {
	var b strings.Builder
	b.WriteString("MCP server " + mcpShownName(name) + " has a failed admission scan")
	if clause := mcpScanIssueClause(issue); clause != "" {
		b.WriteString(" (could not be scanned: " + clause + ")")
	}
	b.WriteString("; " + mcpAdmissionNextStep(name, issue, step))
	return b.String()
}

// mcpDefinitionUnprovenStep is the next step for an MCP server whose
// definition DefenseClaw cannot prove (mcp-definition-unproven).
const mcpDefinitionUnprovenStep = "start a new agent session with the server configured, or ask your administrator"

// mcpDefinitionUnprovenText words the block of a call to an MCP server whose
// definition DefenseClaw cannot prove from the agent config or earlier in
// the session, as a sentence instead of the structured reason.
func mcpDefinitionUnprovenText(name string) string {
	return "MCP server " + name + " has a definition DefenseClaw cannot prove, so its calls are blocked; " + mcpDefinitionUnprovenStep
}

// mcpAdmissionAllowedWarning is the agent-visible warning of a call allowed
// to a server that could not be scanned.
func mcpAdmissionAllowedWarning(name, issue, step string) string {
	text := mcpAdmissionAllowedLead + mcpShownName(name)
	if clause := mcpScanIssueClause(issue); clause != "" {
		text += " (" + clause + ")"
	}
	return text + ". This call is allowed with a warning; the strict profile and managed deployments block it. Next step: " +
		mcpAdmissionNextStep(name, issue, step)
}

// mcpAdmissionAgentName is the name of a server worded for the agent: the
// configured name when it is plain text, else the name the agent called it
// by, else "". A configured name with spaces or controls is not copied into
// the reason, and the cause and next step are kept without it.
func mcpAdmissionAgentName(configured, called string) string {
	for _, name := range []string{configured, called} {
		if agentAssetPolicyNamePattern.MatchString(name) {
			return name
		}
	}
	return ""
}
