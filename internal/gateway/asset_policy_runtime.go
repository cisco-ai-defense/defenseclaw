// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/managed/mcpasuser"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

type mcpRuntimeProbe struct {
	ServerName string
	ToolName   string
	URL        string
	Command    string
	Args       []string
	Transport  string
	Surface    string
	Matched    bool
	// WorkspaceDir is the agent's working directory from the hook, used to
	// resolve a name-only probe to the connector's configured server.
	WorkspaceDir string
	// SessionID is the agent session the hook belongs to; the definition a
	// session resolved for a server is remembered for that session only
	// (GAP-0861).
	SessionID string
}

type skillRuntimeProbe struct {
	// TargetType is "skill" by default; Claude Code prompt expansion can
	// surface plugin slash commands through the same shape.
	TargetType string
	SkillName  string
	ToolName   string
	// SourcePath is the raw, agent-supplied skill path (when present).
	// It is preserved verbatim — including any path traversal segments —
	// so audit telemetry can show the difference between "trusted-skill"
	// and "/tmp/attacker/trusted-skill/SKILL.md". Asset policy matches
	// on SkillName by default; operators wanting to constrain by path
	// must use AssetPolicyRule.SourcePathContains.
	SourcePath string
	// ProjectDir resolves relative source paths for project skill admission.
	// SourcePath itself remains unchanged for policy and audit records.
	ProjectDir string
	// RawName preserves the unnormalized input the SkillName was
	// derived from when path-stripping occurred (e.g. SkillName came
	// from filepath.Base on a "/path/to/<name>/SKILL.md") or when a
	// plugin slash command was reduced from "plugin-id:command-id" to
	// "plugin-id" for policy lookup. Empty when SkillName == raw input.
	RawName string
	Surface string
	Matched bool
	// RuntimeDisableOnly limits an identity inferred from incomplete or
	// ambiguous connector metadata to the exact durable runtime-disable
	// lookup. It must not widen ordinary asset-policy matching or record a
	// loaded asset when no disable record exists.
	RuntimeDisableOnly bool
	// DeclaredNames are the names the skill declares in its SKILL.md
	// (declaredSkillNames); a denied rule matches them too.
	DeclaredNames []string
	// SourcePaths are the folders a skill selected by name alone loads
	// from (skillSourcePaths); each is judged with its path.
	SourcePaths []string
}

type runtimeAssetDecision struct {
	targetType string
	decision   config.AssetPolicyDecision
}

const (
	runtimeProvenanceCodexPromptSelection = "codex_prompt_selection"
	runtimeProvenanceClaudeExpansion      = "claudecode_prompt_expansion"
)

func (a *APIServer) claudeCodeMCPAssetDecision(ctx context.Context, req claudeCodeHookRequest) (config.AssetPolicyDecision, bool) {
	probe := mcpProbeFromFields(req.MCPServerName, req.ToolName, req.ToolInput)
	probe.WorkspaceDir = req.CWD
	probe.SessionID = req.SessionID
	rawServer := probe.ServerName
	probe.ServerName = a.claudeCodePluginMCPServerName(ctx, probe)
	if decision, refused := unresolvedPluginMCPDefinitionDecision(a.requestConfig(ctx), rawServer, probe); refused {
		a.emitAssetPolicyDecisionFindings(ctx, decision, "mcp", "claudecode", req.HookEventName)
		a.logAssetPolicyAudit(ctx, "claudecode", "mcp:"+rawServer, "action=block source=mcp-definition-unproven")
		return decision, true
	}
	if decision, refused := a.mcpDefinitionRefreshDecision(ctx, "claudecode", req.HookEventName, probe); refused {
		return decision, true
	}
	if decision, refused := a.mcpStateUnreadableDecision(ctx, "claudecode", req.HookEventName, probe); refused {
		return decision, true
	}
	a.noteHookReportedMCPServer(ctx, "claudecode", req.HookEventName, probe)
	if decision, refused := a.mcpAdmissionPendingDecision(ctx, "claudecode", req.HookEventName, probe); refused {
		return decision, true
	}
	return a.evaluateRuntimeMCPAssetPolicy(ctx, "claudecode", req.HookEventName, probe)
}

// claudeCodePluginMCPServerName is the configured name of an MCP server a
// Claude Code plugin bundles, plugin:<plugin>:<server>, for a tool call that
// spells it plugin_<plugin>_<server>, so asset_policy.mcp rules written for
// it match whatever asset_policy.enabled says (GAP-1191). Other servers keep
// their name. Secure Client keeps main (issue #1092).
func (a *APIServer) claudeCodePluginMCPServerName(ctx context.Context, probe mcpRuntimeProbe) string {
	cfg := a.requestConfig(ctx)
	if cfg == nil || cfg.SecureClientIntegration() || !probe.Matched || probe.Surface != "hook" ||
		!strings.HasPrefix(probe.ServerName, "plugin_") {
		return probe.ServerName
	}
	if entry, ok := a.lookupCallerMCPServer(ctx, cfg, "claudecode", probe.WorkspaceDir, probe.ServerName); ok &&
		strings.HasPrefix(entry.Name, "plugin:") {
		return entry.Name
	}
	return probe.ServerName
}

// mcpStateUnreadableDecision refuses an MCP tool call of an enrolled user
// whose ~/.claude.json (Claude Code, GAP-0829), ~/.kiro/settings/mcp.json
// (Kiro, GAP-1468) or Codex config.toml (GAP-0686) the hook enumerator
// could not read or parse. The gateway
// service cannot read that file itself, so it does not know the user's
// servers and cannot admit one: a server changed while the file was
// unreadable would otherwise run unscanned (fail closed). The refusal names
// the file; status names it too. Secure Client has no enrolled-user watcher
// (issue #1092).
func (a *APIServer) mcpStateUnreadableDecision(ctx context.Context, connectorName, hookEvent string, probe mcpRuntimeProbe) (config.AssetPolicyDecision, bool) {
	cfg := a.requestConfig(ctx)
	if cfg == nil || cfg.SecureClientIntegration() || !probe.Matched || probe.Surface != "hook" {
		return config.AssetPolicyDecision{}, false
	}
	state, ok := mcpStateUnreadableFor(connectorName, trustedActiveHome(ctx))
	if !ok {
		return config.AssetPolicyDecision{}, false
	}
	published, ok := mcpasuser.LookupPublished(connectorName)
	if !ok {
		return config.AssetPolicyDecision{}, false
	}
	source := strings.ReplaceAll(published.Unreadable, "_", "-")
	reason := state.Blocked(published.Label)
	decision := runtimeAssetDisableBlockDecision("mcp", probe.ServerName, connectorName, "hook", reason, source)
	decision.RegistryStatus = "unknown"
	a.logAssetPolicyAudit(ctx, connectorName, "mcp:"+probe.ServerName, fmt.Sprintf(
		"action=block source=%s hook=%s tool=%s connector=%s reason=%s", decision.Source, hookEvent, probe.ToolName, connectorName, reason))
	return decision, true
}

// mcpDefinitionRefreshDecision has a managed Windows gateway read the
// enrolled users' current MCP servers before it decides a tool call about to
// run, so the unreadable-state and pending checks that follow see the
// definition the user has now: a server changed under the same name is then
// refused until its own scan, never run on the old verdict (GAP-0216). A
// refresh that fails preserves a known block or completed scan failure,
// then follows the connector's outage tier and records a warning or refusal;
// gateway.log says why. Every other gateway has nothing to refresh. Secure
// Client keeps main (#1092).
func (a *APIServer) mcpDefinitionRefreshDecision(ctx context.Context, connectorName, hookEvent string, probe mcpRuntimeProbe) (config.AssetPolicyDecision, bool) {
	cfg := a.requestConfig(ctx)
	if a.mcpRefreshBeforeCall == nil || cfg == nil || cfg.SecureClientIntegration() || !probe.Matched ||
		probe.Surface != "hook" || !mcpCallAboutToRun(hookEvent) {
		return config.AssetPolicyDecision{}, false
	}
	if err := a.mcpRefreshBeforeCall(ctx, connectorName); err == nil {
		return config.AssetPolicyDecision{}, false
	}
	// A refresh outage cannot replace a decision already known to be
	// protective. Use the pinned request configuration and the last known
	// admission outcome before applying the connector's outage tier.
	if decision, refused := a.mcpStateUnreadableDecision(ctx, connectorName, hookEvent, probe); refused {
		return decision, true
	}
	if a.mcpAdmissionStatus != nil {
		home, _ := callerHomeForAssets(ctx)
		status := a.mcpAdmissionStatus(connectorName, probe.ServerName, home, probe.WorkspaceDir)
		if status.Failed {
			return a.mcpAdmissionStatusDecision(ctx, cfg, connectorName, hookEvent, probe, status)
		}
	}
	return a.mcpAdmissionStatusDecision(ctx, cfg, connectorName, hookEvent, probe,
		watcher.MCPAdmissionStatus{Name: probe.ServerName, Unavailable: true, RetryAfter: enrolledMCPRefreshBudget})
}

// mcpUnpublishedSourceDecision refuses, on a managed Windows gateway (the
// only one that wires mcpPublished), the tool call of a Codex server the
// account's agent runs from a source the hook enumerator did not publish: a
// session-only CODEX_HOME is not in the account environment the enumerator
// reads, and a project .codex/config.toml is not read at all, so such a
// server has no install admission and no scan verdict (GAP-0686). The hook
// names the source (assetfacts Relocated, ProjectScope) and the launch digest
// of the complete definition it read; a call is admitted by the checks that
// follow only when a published server has that digest, so an ordinary
// server, the default one or one of a persistent CODEX_HOME, stays allowed.
// A project definition no published server matches is refused where it would
// override a published server of that name, and where asset policy enforces
// MCP runtime detection in action mode, which does not let an unscanned asset
// run; elsewhere the project server stays as documented. Secure Client keeps
// main (#1092).
func (a *APIServer) mcpUnpublishedSourceDecision(ctx context.Context, connectorName, hookEvent string, probe mcpRuntimeProbe) (config.AssetPolicyDecision, bool) {
	cfg := a.requestConfig(ctx)
	if a.mcpPublished == nil || cfg == nil || cfg.SecureClientIntegration() ||
		!probe.Matched || probe.Surface != "hook" || !mcpCallAboutToRun(hookEvent) {
		return config.AssetPolicyDecision{}, false
	}
	server := claimedAssetFactsFromContext(ctx).MCP
	home, serviceAccount := callerHomeForAssets(ctx)
	if server == nil || (!server.Relocated && !server.ProjectScope) || !serviceAccount || home == "" ||
		!config.SameMCPToolServer(connectorName, server.Name, probe.ServerName) {
		return config.AssetPolicyDecision{}, false
	}
	published := a.mcpPublished(connectorName, probe.ServerName, home, probe.WorkspaceDir, server.Digest)
	if published.Matched {
		return config.AssetPolicyDecision{}, false
	}
	source := "a Codex config.toml under a CODEX_HOME"
	if server.ProjectScope {
		runtime, _ := cfg.AssetRuntimeDetectionFor("mcp")
		enforcing := cfg.AssetPolicy.Enabled && assetRuntimeModeIsAction(cfg.EffectiveAssetPolicyModeForConnector(connectorName)) && runtime.Enabled
		// A claim that did not fit the header holds the name, the digest and
		// the pins of its endpoint, not the endpoint: a deny pinned to where
		// the server points is checked against the pins, and the call is
		// refused where one may match, or where the claim holds no pins to
		// check it with, as for any definition that cannot be resolved
		// (GAP-1187). A deny pinned to another endpoint does not refuse it.
		unresolved := server.URL == "" && server.Command == "" &&
			deniedRulesMayPinClaim(cfg.AssetPolicy.MCP.Denied, connectorName, probe.ServerName, server.Pins)
		if !published.Named && !enforcing && !unresolved {
			return config.AssetPolicyDecision{}, false
		}
		source = "a project .codex/config.toml"
	}
	reason := fmt.Sprintf("mcp server %q runs from %s that DefenseClaw has not scanned; define it in the account's own Codex config (CODEX_HOME set for the account, not only for the session) so it is admitted", probe.ServerName, source)
	decision := runtimeAssetDisableBlockDecision("mcp", probe.ServerName, connectorName, "hook", reason, "mcp-source-unpublished")
	decision.RegistryStatus = "unknown"
	a.logAssetPolicyAudit(ctx, connectorName, "mcp:"+probe.ServerName, fmt.Sprintf(
		"action=block source=%s hook=%s tool=%s connector=%s reason=%s", decision.Source, hookEvent, probe.ToolName, connectorName, reason))
	return decision, true
}

// mcpCallAboutToRun reports a hook event sent before a tool runs, however
// the connector spells it (Kiro CLI 2.x sends preToolUse).
func mcpCallAboutToRun(hookEvent string) bool {
	switch canonicalEvent(hookEvent) {
	case "pretooluse", "permissionrequest":
		return true
	}
	return false
}

// mcpAdmissionPendingDecision reports a new server's admission state on
// calls about to run. The default and permissive OSS tiers allow a pending
// call with a visible warning; strict and managed tiers wait for the scan.
// A completed scan failure and an existing asset-policy block always refuse
// the call. Secure Client keeps its existing path.
func (a *APIServer) mcpAdmissionPendingDecision(ctx context.Context, connectorName, hookEvent string, probe mcpRuntimeProbe) (config.AssetPolicyDecision, bool) {
	cfg := a.requestConfig(ctx)
	if (a.mcpAdmissionPending == nil && a.mcpAdmissionStatus == nil) || cfg == nil || cfg.SecureClientIntegration() || !probe.Matched ||
		probe.Surface != "hook" || !mcpCallAboutToRun(hookEvent) {
		return config.AssetPolicyDecision{}, false
	}
	home, _ := callerHomeForAssets(ctx)
	status := watcher.MCPAdmissionStatus{}
	if a.mcpAdmissionStatus != nil {
		status = a.mcpAdmissionStatus(connectorName, probe.ServerName, home, probe.WorkspaceDir)
	} else {
		status.Name, status.Pending = a.mcpAdmissionPending(connectorName, probe.ServerName, home, probe.WorkspaceDir)
		status.RetryAfter = time.Minute
	}
	return a.mcpAdmissionStatusDecision(ctx, cfg, connectorName, hookEvent, probe, status)
}

func (a *APIServer) mcpAdmissionStatusDecision(ctx context.Context, cfg *config.Config, connectorName, hookEvent string,
	probe mcpRuntimeProbe, status watcher.MCPAdmissionStatus) (config.AssetPolicyDecision, bool) {
	if !status.Pending && !status.Failed && !status.Unavailable {
		return config.AssetPolicyDecision{}, false
	}
	// Pending admission must not override a listed deny or an earlier runtime
	// disable. This check uses the request's pinned configuration generation.
	existing, matched := a.evaluateRuntimeMCPAssetPolicy(ctx, connectorName, hookEvent, probe)
	if matched && existing.Action == "block" {
		return existing, true
	}
	// A rule the administrator wrote for this server (asset_policy.mcp.allowed
	// by name and URL or launcher, or defenseclaw mcp allow) beats a scan
	// that could not complete in every tier, strict and managed included:
	// the administrator has decided the server, and its scan cannot. An
	// explicit deny was handled above (GAP-0775, GAP-0778). The rule decides
	// the definition the agent config lists; a revoked earlier definition
	// the agent may still run is not that one, so the allow written for the
	// listed one does not answer it (GAP-0920).
	if status.Failed && !status.Revoked && !matched && existing.Enabled && existing.Source == "admin-allow" {
		return config.AssetPolicyDecision{}, false
	}
	name := status.Name
	if name == "" {
		name = probe.ServerName
	}
	if status.Failed {
		// The scan could not be completed, which is not a malicious verdict:
		// the OSS default and permissive tiers allow the call with a visible
		// warning and an audit row naming the cause and the next step; the
		// strict tier and managed profiles stay blocked (fail closed). The
		// decision is the one a still-pending admission gets, so the first
		// call and every later one agree (GAP-0775).
		step := cfg.MCPAdmissionNextStep(name)
		shown := mcpAdmissionAgentName(name, probe.ServerName)
		decision := runtimeAssetDisableBlockDecision("mcp", shown, connectorName, "hook",
			mcpAdmissionFailedText(shown, status.ScanIssue, step), "mcp-admission-failed")
		decision.RegistryStatus = "unknown"
		decision.ScanIssue = status.ScanIssue
		decision.ScanNextStep = step
		if !cfg.MCPAdmissionFailsClosed(connectorName) {
			decision.Action = "allow"
			decision.Mode = config.AssetPolicyModeObserve
		}
		a.recordMCPAdmissionDecision(ctx, connectorName, hookEvent, probe, decision)
		return decision, true
	}
	retrySeconds := int((status.RetryAfter + time.Second - 1) / time.Second)
	if retrySeconds < 1 {
		retrySeconds = 1
	}
	if retrySeconds > 300 {
		retrySeconds = 300
	}
	reason := fmt.Sprintf("DefenseClaw is still scanning the new MCP server %q; retry in about %d s", name, retrySeconds)
	if status.Unavailable {
		reason = fmt.Sprintf("DefenseClaw could not read admission for MCP server %q; retry in about %d s", name, retrySeconds)
	}
	decision := runtimeAssetDisableBlockDecision("mcp", probe.ServerName, connectorName, "hook", reason, "mcp-admission-pending")
	if status.Unavailable {
		decision.Source = "mcp-admission-unavailable"
	}
	decision.RegistryStatus = "unknown"
	decision.TargetName = name
	decision.RetryAfterSeconds = retrySeconds
	if !cfg.MCPAdmissionFailsClosed(connectorName) {
		decision.Action = "allow"
		decision.Mode = config.AssetPolicyModeObserve
	}
	a.recordMCPAdmissionDecision(ctx, connectorName, hookEvent, probe, decision)
	return decision, true
}

func (a *APIServer) recordMCPAdmissionDecision(ctx context.Context, connectorName, hookEvent string, probe mcpRuntimeProbe, decision config.AssetPolicyDecision) {
	evalCtx := a.emitAssetPolicyDecisionFindings(ctx, decision, "mcp", connectorName, hookEvent)
	a.logAssetPolicyAudit(ctx, connectorName, "mcp:"+decision.TargetName, fmt.Sprintf(
		"action=%s source=%s hook=%s tool=%s connector=%s would_block=%v reason=%s",
		decision.Action, decision.Source, hookEvent, probe.ToolName, connectorName, decision.Action == "allow", decision.Reason))
	a.dispatchAssetPolicyNotification(decision, "mcp", connectorName, hookEvent, evalCtx)
}

// A plugin tool name does not prove its command or URL. If the installed
// plugin definition cannot be resolved, an endpoint-pinned deny cannot be
// evaluated safely. This is independent of asset_policy.enabled, like the
// explicit deny itself. Secure Client retains its original lookup behavior.
func unresolvedPluginMCPDefinitionDecision(cfg *config.Config, rawServer string, probe mcpRuntimeProbe) (config.AssetPolicyDecision, bool) {
	if cfg == nil || cfg.SecureClientIntegration() || !probe.Matched || probe.Surface != "hook" ||
		!strings.HasPrefix(rawServer, "plugin_") || strings.HasPrefix(probe.ServerName, "plugin:") ||
		!rulesPinEndpointForServer(cfg.AssetPolicy.MCP.Denied, "claudecode", rawServer) {
		return config.AssetPolicyDecision{}, false
	}
	return config.AssetPolicyDecision{
		Enabled: true, Mode: config.AssetPolicyModeAction, Action: "block", RawAction: "block",
		Source: "mcp-definition-unproven", RegistryStatus: "unknown",
		TargetType: "mcp", TargetName: rawServer, Connector: "claudecode", RuntimeSurface: "hook",
		Reason: fmt.Sprintf("mcp %q: plugin server definition could not be resolved, so its endpoint cannot be checked against asset_policy", rawServer),
	}, true
}

func (a *APIServer) codexMCPAssetDecision(ctx context.Context, req codexHookRequest) (config.AssetPolicyDecision, bool) {
	if a.codexMCPServerAmbiguous(ctx, req) {
		name := serverFromMCPToolName(req.ToolName)
		decision := config.AssetPolicyDecision{
			Enabled: true, Mode: config.AssetPolicyModeAction, Action: "block", RawAction: "block",
			Source: "mcp-server-ambiguous", RegistryStatus: "unknown",
			TargetType: "mcp", TargetName: name, Connector: "codex", RuntimeSurface: "hook",
			Reason: fmt.Sprintf("mcp %q: multiple configured Codex servers use this tool name; the server cannot be identified", name),
		}
		a.emitAssetPolicyDecisionFindings(ctx, decision, "mcp", "codex", req.HookEventName)
		a.logAssetPolicyAudit(ctx, "codex", "mcp:"+name, "action=block source=mcp-server-ambiguous")
		return decision, true
	}
	probe := mcpProbeFromFields(a.codexMCPServerName(ctx, req), req.ToolName, req.ToolInput)
	probe.WorkspaceDir = req.CWD
	probe.SessionID = req.SessionID
	// A managed Windows gateway knows the enrolled users Codex servers only
	// from the record the hook enumerator publishes: it is read again before
	// a call about to run is decided, and an unreadable one refuses the call,
	// as for Claude Code and Kiro (GAP-0686).
	if decision, refused := a.mcpDefinitionRefreshDecision(ctx, "codex", req.HookEventName, probe); refused {
		return decision, true
	}
	if decision, refused := a.mcpStateUnreadableDecision(ctx, "codex", req.HookEventName, probe); refused {
		return decision, true
	}
	if decision, refused := a.mcpUnpublishedSourceDecision(ctx, "codex", req.HookEventName, probe); refused {
		return decision, true
	}
	a.noteHookReportedMCPServer(ctx, "codex", req.HookEventName, probe)
	if decision, refused := a.mcpAdmissionPendingDecision(ctx, "codex", req.HookEventName, probe); refused {
		return decision, true
	}
	return a.evaluateRuntimeMCPAssetPolicy(ctx, "codex", req.HookEventName, probe)
}

// codexMCPServerAmbiguous applies only when the hook did not provide an
// explicit server name. Codex normalizes punctuation in MCP tool names, so
// an exact configured name is not enough to identify a server on collision.
func (a *APIServer) codexMCPServerAmbiguous(ctx context.Context, req codexHookRequest) bool {
	if strings.TrimSpace(firstNonEmpty(req.MCPServerName, payloadString(req.Payload, "mcp_server_name"))) != "" {
		return false
	}
	cfg := a.requestConfig(ctx)
	if cfg == nil || cfg.SecureClientIntegration() {
		return false
	}
	toolServer := serverFromMCPToolName(req.ToolName)
	if toolServer == "" {
		return false
	}
	home, serviceAccount := callerHomeForAssets(ctx)
	if !serviceAccount {
		return cfg.CodexMCPToolServerAmbiguous(req.CWD, toolServer)
	}
	return home != "" && config.CodexMCPToolServerAmbiguousUnderHome(home, req.CWD, toolServer)
}

// codexMCPServerName is the MCP server a Codex tool call names, spelled as
// the caller's Codex configures it. Codex shows hooks mcp__<server>__<tool>
// with every character other than a letter, digit or underscore turned into
// "_", so an approved acme-notes was looked up as acme_notes: refused as
// unregistered, while a deny or a scan-verdict disable of a hyphenated server
// missed it (GAP-0939, GAP-0462). It is resolved whatever asset_policy.enabled
// says, because the lists and runtime disables always apply. "" when the call
// names no server. Secure Client keeps main: only the payload field (#1092).
func (a *APIServer) codexMCPServerName(ctx context.Context, req codexHookRequest) string {
	explicit := strings.TrimSpace(firstNonEmpty(req.MCPServerName, payloadString(req.Payload, "mcp_server_name")))
	cfg := a.requestConfig(ctx)
	if explicit != "" || cfg == nil || cfg.SecureClientIntegration() {
		return explicit
	}
	server := serverFromMCPToolName(req.ToolName)
	if !strings.Contains(server, "_") {
		return server
	}
	if entry, ok := a.lookupCallerMCPServer(ctx, cfg, "codex", req.CWD, server); ok && strings.TrimSpace(entry.Name) != "" {
		return strings.TrimSpace(entry.Name)
	}
	return server
}

func (a *APIServer) claudeCodeSkillAssetDecision(ctx context.Context, req claudeCodeHookRequest) (config.AssetPolicyDecision, bool) {
	a.noteProjectSkillFolders(ctx, "claudecode", req.CWD)
	probe := skillProbeFromFields(req.ToolName, req.ToolInput, req.Payload)
	probe.ProjectDir = req.CWD
	if !probe.Matched {
		if saved := claudeCodeCoworkSkillProbe(req); saved.Matched && coworkInspected(a.requestConfig(ctx)) {
			return a.evaluateRuntimeSkillAssetPolicy(ctx, "claudecode", req.HookEventName, saved)
		}
		return a.skillFolderAccessDecision(ctx, "claudecode", req.HookEventName, req.CWD, req.ToolName, req.ToolInput)
	}
	probe.DeclaredNames = a.declaredSkillNames(ctx, "claudecode", req.CWD, probe)
	if skill := pluginBundledSkillName(a.requestConfig(ctx), probe.SkillName); skill != "" {
		probe.DeclaredNames = append(probe.DeclaredNames, skill)
	}
	probe.SourcePaths = a.skillSourcePaths(ctx, "claudecode", req.CWD, probe)
	return a.evaluateRuntimeSkillAssetPolicy(ctx, "claudecode", req.HookEventName, probe)
}

func (a *APIServer) claudeCodePromptExpansionAssetDecisions(ctx context.Context, req claudeCodeHookRequest) []runtimeAssetDecision {
	switch strings.ToLower(strings.TrimSpace(req.ExpansionType)) {
	case "slash_command":
		return a.claudeCodeSlashCommandAssetDecisions(ctx, req)
	case "mcp_prompt":
		return a.claudeCodeMCPPromptAssetDecisions(ctx, req)
	case "":
		// command metadata is optional in the Claude hook contract. An exact
		// leading slash token is sufficient for a runtime-disable-only lookup;
		// the strict parser below keeps ordinary prompts and MCP/plugin-shaped
		// names out of the standalone-skill namespace.
		if claudeCodePromptSlashCommandName(req.Prompt) != "" {
			return a.claudeCodeSlashCommandAssetDecisions(ctx, req)
		}
		return nil
	default:
		return nil
	}
}

func (a *APIServer) claudeCodeSlashCommandAssetDecisions(ctx context.Context, req claudeCodeHookRequest) []runtimeAssetDecision {
	a.noteProjectSkillFolders(ctx, "claudecode", req.CWD)
	targetType := slashCommandAssetType(req.CommandSource)
	trustedAssetPolicySource := claudeCodeSlashSourceTrustsAssetPolicy(req.CommandSource)
	commandName := strings.TrimSpace(req.CommandName)
	promptName := claudeCodePromptSlashCommandName(req.Prompt)
	commandIdentity, commandOK := claudeCodeSlashAssetIdentity(
		targetType, commandName,
	)
	promptIdentity, promptOK := claudeCodeSlashAssetIdentity(
		targetType, promptName,
	)
	promptPresent := strings.TrimSpace(req.Prompt) != ""
	identityMalformed := trustedAssetPolicySource && (commandName == "" || !commandOK ||
		(promptPresent && !promptOK) ||
		(commandOK && promptOK && !commandIdentity.sameAsset(promptIdentity)))

	identities := make([]claudeCodeSlashIdentity, 0, 3)
	if commandOK {
		identities = append(identities, commandIdentity)
	}
	if promptOK && (!commandOK || !commandIdentity.sameAsset(promptIdentity)) {
		identities = append(identities, promptIdentity)
	}
	if targetType == "plugin" && commandOK && !identityMalformed {
		// /plugin:skill runs a skill the plugin bundles: a skill on
		// asset_policy.skill.denied is refused there too (GAP-1104).
		if skill := pluginBundledSkillName(a.requestConfig(ctx), commandName); skill != "" {
			if bundled, ok := claudeCodeSlashAssetIdentity("skill", skill); ok {
				identities = append(identities, bundled)
			}
		}
	}

	// Only literal skill/plugin provenance with a non-conflicting identity
	// retains the existing full asset-policy behavior. User/project/missing
	// provenance is shared with custom commands, so it may correlate only to
	// an exact runtime-disable record. On disagreement, probe both strict
	// candidates the same way so a spoofed benign field cannot bypass a
	// disabled identity; neither candidate is attributed when neither is
	// disabled.
	runtimeDisableOnly := !trustedAssetPolicySource || identityMalformed
	for _, identity := range identities {
		probe := skillRuntimeProbe{
			TargetType:         identity.targetType,
			SkillName:          identity.name,
			ToolName:           identity.toolName,
			RawName:            identity.rawName,
			SourcePath:         canonicalClaudeCodeSlashSource(req.CommandSource),
			Surface:            "prompt_expansion",
			Matched:            true,
			RuntimeDisableOnly: runtimeDisableOnly,
		}
		if runtimeDisableOnly && !identityMalformed && identity.targetType == "skill" {
			// A settings-origin command that is a skill folder (a user or
			// project skill typed as /name) is held to asset_policy at
			// that folder as the Skill tool is; it used to get the
			// runtime-disable lookup only, so a skill on
			// asset_policy.skill.denied ran (GAP-0968). A custom command
			// with no skill folder of its name keeps that lookup.
			if folders := a.installedSkillFolders(ctx, "claudecode", req.CWD, identity.name); len(folders) > 0 {
				probe.RuntimeDisableOnly = false
				probe.SourcePath = ""
				probe.SourcePaths = folders
			}
		}
		probe.DeclaredNames = a.declaredSkillNames(ctx, "claudecode", req.CWD, probe)
		if decision, matched := a.evaluateNativeRuntimeSkillSelection(
			ctx, "claudecode", req.SessionID, req.HookEventName,
			runtimeProvenanceClaudeExpansion, probe,
		); matched {
			return []runtimeAssetDecision{{targetType: identity.targetType, decision: decision}}
		}
	}
	if identityMalformed {
		name := "unresolved"
		if len(identities) > 0 {
			name = identities[0].name
		}
		probe := skillRuntimeProbe{
			TargetType: targetType,
			SkillName:  name,
			SourcePath: targetType,
			Surface:    "prompt_expansion",
			Matched:    true,
		}
		decision := a.runtimeAssetIdentityDecision(
			ctx, targetType, name, "claudecode", "prompt_expansion",
		)
		a.emitRuntimeSkillAssetPolicyDecision(
			ctx, decision, "claudecode", req.HookEventName, probe,
		)
		return []runtimeAssetDecision{{targetType: targetType, decision: decision}}
	}
	return nil
}

func (a *APIServer) claudeCodeMCPPromptAssetDecisions(ctx context.Context, req claudeCodeHookRequest) []runtimeAssetDecision {
	server := mcpPromptServerName(req.CommandSource, req.CommandName)
	if server == "" {
		return nil
	}
	probe := mcpRuntimeProbe{
		ServerName: server,
		ToolName:   strings.TrimSpace(req.CommandName),
		Surface:    "prompt_expansion",
		Matched:    true,
	}
	if decision, matched := a.evaluateRuntimeMCPAssetPolicy(ctx, "claudecode", req.HookEventName, probe); matched {
		return []runtimeAssetDecision{{targetType: "mcp", decision: decision}}
	}
	return nil
}

func (a *APIServer) codexSkillAssetDecision(ctx context.Context, req codexHookRequest) (config.AssetPolicyDecision, bool) {
	a.noteProjectSkillFolders(ctx, "codex", req.CWD)
	probe := skillProbeFromFields(req.ToolName, req.ToolInput, req.Payload)
	probe.ProjectDir = req.CWD
	if !probe.Matched {
		return a.skillFolderAccessDecision(ctx, "codex", req.HookEventName, req.CWD, req.ToolName, req.ToolInput)
	}
	probe.DeclaredNames = a.declaredSkillNames(ctx, "codex", req.CWD, probe)
	probe.SourcePaths = a.skillSourcePaths(ctx, "codex", req.CWD, probe)
	return a.evaluateRuntimeSkillAssetPolicy(ctx, "codex", req.HookEventName, probe)
}

func (a *APIServer) codexPromptSkillAssetDecision(
	ctx context.Context, req codexHookRequest,
) (config.AssetPolicyDecision, bool) {
	probe := codexSkillProbeFromPrompt(req.Prompt)
	if !probe.Matched {
		return config.AssetPolicyDecision{}, false
	}
	a.noteProjectSkillFolders(ctx, "codex", req.CWD)
	probe.DeclaredNames = a.declaredSkillNames(ctx, "codex", req.CWD, probe)
	probe.SourcePaths = a.skillSourcePaths(ctx, "codex", req.CWD, probe)
	return a.evaluateNativeRuntimeSkillSelection(
		ctx, "codex", req.SessionID, req.HookEventName,
		runtimeProvenanceCodexPromptSelection, probe,
	)
}

func (a *APIServer) evaluateRuntimeMCPAssetPolicy(ctx context.Context, connector, hookEvent string, probe mcpRuntimeProbe) (config.AssetPolicyDecision, bool) {
	cfg := a.requestConfig(ctx)
	if cfg == nil || !probe.Matched {
		return config.AssetPolicyDecision{}, false
	}
	runtimeDetection, _ := cfg.AssetRuntimeDetectionFor("mcp")
	if probe.Surface == "terminal" && !runtimeDetection.TerminalCommands && cfg.SecureClientIntegration() {
		return config.AssetPolicyDecision{}, false
	}
	if !runtimeDetection.Enabled && cfg.SecureClientIntegration() {
		return config.AssetPolicyDecision{}, false
	}
	res := a.resolveMCPProbeEndpoint(ctx, cfg, connector, probe)
	probe = res.probe
	decision := mcpProbeDecision(ctx, cfg, connector, probe)
	denied := mcpDeniedDecision(decision)
	var earlierDenied *mcpEarlier
	for i := range res.earlier {
		// The edit of a config file does not change the connection a running
		// agent holds, and nothing here shows that it reconnected: a call is
		// judged on the definition the config lists now and on those the
		// session was judged on before (remembered, or denied and held apart),
		// each on the policy in force now, and the strictest verdict holds.
		earlier := &res.earlier[i]
		verdict := mcpProbeDecision(ctx, cfg, connector, earlier.probe)
		if earlierDenied == nil && mcpDeniedDecision(verdict) {
			earlierDenied = earlier
		}
		if mcpDecisionRank(verdict) > mcpDecisionRank(decision) {
			decision, probe = verdict, earlier.probe
		}
	}
	a.rememberResolvedMCP(connector, res, denied, earlierDenied)
	if res.unknown || res.lost {
		// A verdict that holds the call stands; one that only observes (a
		// default deny in observe mode) does not stand for an incomplete
		// record, so the closed unknown verdict replaces it.
		if unknown, ok := unknownMCPDefinitionDecision(cfg, connector, probe, res.unknown, res.lost); ok &&
			mcpDecisionRank(unknown) > mcpDecisionRank(decision) {
			decision = unknown
		}
	}
	if !decision.Enabled || decision.RawAction != "block" {
		return decision, false
	}
	evalCtx := a.emitAssetPolicyDecisionFindings(ctx, decision, "mcp", connector, hookEvent)
	if a.logger != nil {
		details := fmt.Sprintf("action=%s source=%s registry_status=%s registry_configured=%v surface=%s hook=%s tool=%s connector=%s would_block=%v reason=%s",
			decision.Action, decision.Source, decision.RegistryStatus, decision.RegistryConfigured, probe.Surface, hookEvent, probe.ToolName, connector, decision.WouldBlock, decision.Reason)
		details = appendHookEvaluationDetails(details, evalCtx)
		a.logAssetPolicyAudit(ctx, connector, "mcp:"+decision.TargetName, details)
	}
	a.dispatchAssetPolicyNotification(decision, "mcp", connector, hookEvent, evalCtx)
	return decision, true
}

// mcpSessionStarted drops the MCP definitions remembered for a session whose
// agent starts again (a new process or a resume): it connects to the servers
// its config lists now, so what it held before no longer says where a call
// goes. A cleared or compacted conversation keeps its connections and its
// memory (GAP-0861).
func (a *APIServer) mcpSessionStarted(ctx context.Context, connector, sessionID, hookEvent, source string) {
	if canonicalEvent(hookEvent) != "sessionstart" || strings.TrimSpace(sessionID) == "" {
		return
	}
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "startup", "resume":
	default:
		return
	}
	home, serviceAccount := callerHomeForAssets(ctx)
	if serviceAccount && home == "" {
		return
	}
	a.mcpResolved.forgetSession(connector, home, sessionID)
}

// mcpProbeDecision is the asset policy verdict on a probe whose definition
// has been resolved; the zero decision when the policy does not apply to it.
func mcpProbeDecision(ctx context.Context, cfg *config.Config, connector string, probe mcpRuntimeProbe) config.AssetPolicyDecision {
	runtimeDetection, _ := cfg.AssetRuntimeDetectionFor("mcp")
	decision, unproven := unprovenMCPDefinitionDecision(ctx, cfg, connector, probe)
	if !unproven {
		input := mcpPolicyInput(connector, probe)
		if !runtimeAssetPolicyApplies(cfg, runtimeDetection, probe.Surface, input) {
			return config.AssetPolicyDecision{}
		}
		decision = cfg.EvaluateAssetPolicy(input)
	}
	// when MCP.Default is "deny" and the asset
	// policy is itself in action mode, an unknown terminal MCP
	// command MUST NOT be silently downgraded to allow just
	// because the secondary `runtime_detection.unknown_terminal_mcp`
	// knob defaults to observe. Operators who explicitly set
	// MCP.Default=deny expect default-deny semantics. We only
	// honor the downgrade for runtime detections that are NOT
	// already covered by the operator's default-deny posture
	// (i.e. when the asset policy is in observe mode OR
	// MCP.Default isn't deny).
	mcpAssetMode, mcpDefaultDeny := assetMCPModeFor(cfg, decision)
	if isUnknownTerminalMCP(probe) &&
		!assetRuntimeModeIsAction(runtimeDetection.UnknownTerminalMCP) &&
		decision.RawAction == "block" &&
		(mcpAssetMode != config.AssetPolicyModeAction || !mcpDefaultDeny) {
		decision.Action = "allow"
		decision.Mode = config.AssetPolicyModeObserve
		decision.WouldBlock = true
	}
	return decision
}

// mcpPolicyInput is the input the asset policy judges an MCP probe on.
func mcpPolicyInput(connector string, probe mcpRuntimeProbe) config.AssetPolicyInput {
	return config.AssetPolicyInput{
		TargetType:     "mcp",
		Name:           probe.ServerName,
		Connector:      connector,
		URL:            probe.URL,
		Command:        probe.Command,
		Args:           probe.Args,
		Transport:      probe.Transport,
		RuntimeSurface: coalesceRuntimeSurface(probe.Surface, "hook"),
	}
}

// mcpDeniedDecision reports a verdict from the denied list.
func mcpDeniedDecision(decision config.AssetPolicyDecision) bool {
	return decision.Enabled && decision.RawAction == "block" && decision.Source == "admin-deny"
}

// mcpDecisionRank orders verdicts by how strongly they hold the call.
func mcpDecisionRank(decision config.AssetPolicyDecision) int {
	switch {
	case !decision.Enabled:
		return 0
	case decision.Action == "block":
		return 2
	case decision.RawAction == "block":
		return 1
	}
	return 0
}

// mcpResolution is how resolveMCPProbeEndpoint found the server of a probe.
type mcpResolution struct {
	// probe is judged first: the definition the config lists now, else the
	// one remembered for the session.
	probe mcpRuntimeProbe
	entry config.MCPServerEntry
	// found is set when probe holds a definition (entry).
	found bool
	// earlier holds the other definitions of the name the session was judged
	// on before: the one remembered when the config lists another now, and
	// the denied one held apart because it did not fit in the memory.
	earlier []mcpEarlier
	// unknown is set when the server was looked up by name and found neither
	// in the config nor in what the session resolved before, or when only the
	// session record names it and that record cannot say which of several
	// definitions the agent holds (it dropped one, or overflowed).
	unknown bool
	// lost is set, for a name a denied rule covers, when the session could
	// not hold every denied definition that did not fit in the memory, or
	// dropped a denied one beside the one it holds, so this name may have had
	// one.
	lost bool
	// track is set when the session memory is used; home and name key it.
	track bool
	home  string
	name  string
}

// mcpEarlier is a definition of the server a call is judged on besides the
// one the config lists now.
type mcpEarlier struct {
	probe mcpRuntimeProbe
	entry config.MCPServerEntry
}

// addDefinition adds the definition entry of the server of base to the ones
// the call is judged on, unless it is one of them. When no definition was
// found yet it becomes the definition of the call.
func (res *mcpResolution) addDefinition(base mcpRuntimeProbe, entry config.MCPServerEntry) {
	if !res.found {
		res.probe, res.entry, res.found, res.unknown = mcpProbeWithEntry(base, entry, true), entry, true, false
		return
	}
	if sameMCPDefinition(res.entry, entry) {
		return
	}
	for _, other := range res.earlier {
		if sameMCPDefinition(other.entry, entry) {
			return
		}
	}
	res.earlier = append(res.earlier, mcpEarlier{probe: mcpProbeWithEntry(base, entry, true), entry: entry})
}

func mcpProbeWithEntry(probe mcpRuntimeProbe, entry config.MCPServerEntry, byConfiguredName bool) mcpRuntimeProbe {
	if byConfiguredName && strings.TrimSpace(entry.Name) != "" {
		// The configured name, not the form the agent tool name carries
		// (acme_notes for acme-notes in Codex), is what the lists and the
		// registry name (GAP-0939).
		probe.ServerName = strings.TrimSpace(entry.Name)
	}
	probe.URL = strings.TrimSpace(entry.URL)
	probe.Command = strings.TrimSpace(entry.Command)
	probe.Args = entry.Args
	probe.Transport = strings.TrimSpace(entry.Transport)
	return probe
}

// rememberResolvedMCP keeps the definition a session was judged on, so a
// later call finds it once the config no longer lists it. A definition that
// the denied list matched is kept in place of a later one: denied is the
// verdict on the one the config lists now, earlierDenied the earlier one the
// denied list matched, if any.
func (a *APIServer) rememberResolvedMCP(connector string, res mcpResolution, denied bool, earlierDenied *mcpEarlier) {
	if !res.track || !res.found {
		return
	}
	entry, dropped := res.entry, mcpOneDefinition
	if earlierDenied != nil {
		// The earlier denied definition is kept in place of the one the
		// config lists now. When the two differ, the record says so: once the
		// entry is gone nothing shows which one the connection is.
		if !sameMCPDefinition(earlierDenied.entry, res.entry) {
			dropped = mcpSeveralDefinitions
			if denied {
				dropped = mcpDeniedDefinitionDropped
			}
		}
		entry, denied = earlierDenied.entry, true
	}
	a.mcpResolved.remember(connector, res.home, res.probe.SessionID, res.probe.WorkspaceDir, res.name, entry, denied, dropped, time.Now())
}

// resolveMCPProbeEndpoint fills a name-only hook probe (mcp__<server>__<tool>)
// with the URL, command and transport the connector has configured for that
// server. Registry-promoted rules are pinned to URL and transport, so without
// this an approved server never matched at runtime and registry-required
// blocked every MCP tool call (GAP-2488). A server the connector does not
// list keeps the bare name and matches only name-only rules.
//
// The explicit lists apply with asset_policy disabled, so the server is
// resolved whatever enabled says, and a standalone gateway resolves it in
// the caller's configuration, not its own service profile: a url rule
// never matched at the hook of a managed device (GAP-0576). Secure Client
// keeps main: enabled gates the lookup, which reads the gateway's own home
// (issue #1092).
func (a *APIServer) resolveMCPProbeEndpoint(ctx context.Context, cfg *config.Config, connector string, probe mcpRuntimeProbe) mcpResolution {
	res := mcpResolution{probe: probe}
	if cfg == nil {
		return res
	}
	secureClient := cfg.SecureClientIntegration()
	if !cfg.AssetPolicy.Enabled && (secureClient || !mcpListsNeedResolving(cfg.AssetPolicy.MCP)) {
		return res
	}
	if probe.Surface != "hook" || probe.URL != "" || probe.Command != "" || probe.ServerName == "" {
		return res
	}
	if secureClient {
		if entry, ok := cfg.LookupMCPServerForConnector(connector, probe.WorkspaceDir, probe.ServerName); ok {
			res.probe, res.entry, res.found = mcpProbeWithEntry(probe, entry, false), entry, true
		}
		return res
	}
	entry, ok := a.lookupCallerMCPServer(ctx, cfg, connector, probe.WorkspaceDir, probe.ServerName)
	// The agent keeps the connection to a server it started after the entry
	// leaves its config, so what its session resolved for the name before is
	// the server the call reaches (GAP-0861). Secure Client keeps main
	// (#1092).
	home, serviceAccount := callerHomeForAssets(ctx)
	res.track, res.home, res.name = !serviceAccount || home != "", home, probe.ServerName
	if ok {
		res.addDefinition(probe, entry)
	}
	if res.track {
		// What the session resolved before: the definition remembered for the
		// name, and the denied one that did not fit in the memory. Either is
		// the definition of the call when the config lists none now.
		if kept, haveKept := a.mcpResolved.recall(connector, home, probe.SessionID, probe.WorkspaceDir, probe.ServerName, time.Now()); haveKept {
			res.addDefinition(probe, kept)
		}
		lostEntry, held, overflow := a.mcpResolved.lostDenied(connector, home, probe.SessionID, probe.WorkspaceDir, probe.ServerName, time.Now())
		if held {
			res.addDefinition(probe, lostEntry)
		}
		// A record that cannot say which definition the agent holds does not
		// stand for it once the config lists none: the call gets the unknown
		// verdict (the denied verdict, if a denied rule covers the name), as
		// for a server found nowhere.
		ambiguity := a.mcpResolved.ambiguity(connector, home, probe.SessionID, probe.WorkspaceDir, probe.ServerName, time.Now())
		res.lost = (overflow || !ok && ambiguity == mcpDeniedDefinitionDropped) &&
			rulesScopeServer(cfg.AssetPolicy.MCP.Denied, connector, probe.ServerName)
		res.unknown = !ok && (overflow || ambiguity != mcpOneDefinition)
	}
	res.unknown = res.unknown || !res.found
	return res
}

// mcpConnectorResolvesByName reports a connector whose MCP servers the
// gateway reads from the caller account, so a name it cannot find there is
// unknown rather than merely outside what is read.
func mcpConnectorResolvesByName(connector string) bool {
	return config.SameConnector(connector, "claudecode") || config.SameConnector(connector, "codex")
}

// unknownMCPDefinitionDecision is the verdict on a tool call of an MCP server
// whose definition cannot be checked against asset_policy.mcp. Two cases.
//
// The server is unknown when its definition is found nowhere: not in the
// agent config, and not among what its session resolved before (a gateway
// restart, a new session, or a server the agent loads from outside the files
// read here), or when the session record names it but dropped or could not
// hold another definition, so it cannot say which one the agent holds. A rule of the denied list that pins where a server points
// cannot be checked against it, and neither can an endpoint rule of the
// allowed list while asset_policy and its runtime detection for MCP are
// enabled, so the call is refused in a strict or managed deployment and
// allowed with a warning in the default and permissive tiers, as for a server
// whose admission is pending (GAP-0861). The allowed list follows
// asset_policy.mode.
//
// The server is lost when a rule of the denied list covers its name and the
// session could not hold every denied definition that did not fit in the
// memory, so this name may have had one that DefenseClaw can no longer judge.
// The call is refused in every tier and profile. A denied definition that did
// fit, or that was held apart, is not lost: it is judged on the policy in
// force now like any other.
//
// The denied list applies whatever asset_policy.enabled says, like the
// explicit deny. Secure Client keeps main (#1092).
func unknownMCPDefinitionDecision(cfg *config.Config, connector string, probe mcpRuntimeProbe, unknown, lost bool) (config.AssetPolicyDecision, bool) {
	if cfg == nil || cfg.SecureClientIntegration() || probe.Surface != "hook" || probe.ServerName == "" ||
		!mcpConnectorResolvesByName(connector) {
		return config.AssetPolicyDecision{}, false
	}
	covered := lost
	denyPins := unknown && rulesPinEndpointForServer(cfg.AssetPolicy.MCP.Denied, connector, probe.ServerName)
	// The allowed list follows runtime detection, as in unprovenMCPDefinitionDecision.
	detection, _ := cfg.AssetRuntimeDetectionFor("mcp")
	allowPins := unknown && cfg.AssetPolicy.Enabled && detection.Enabled &&
		rulesPinEndpointForServer(cfg.AssetPolicy.MCP.Allowed, connector, probe.ServerName)
	if !covered && !denyPins && !allowPins {
		return config.AssetPolicyDecision{}, false
	}
	reason := fmt.Sprintf("mcp server %q: DefenseClaw found no single definition of it in the agent config or earlier in this session, "+
		"so where it points cannot be checked against asset_policy.mcp", probe.ServerName)
	if covered {
		reason = fmt.Sprintf("mcp server %q: asset_policy.mcp.denied covers it, and this session denied more definitions "+
			"than DefenseClaw can keep, so it cannot tell which one the agent holds until it restarts", probe.ServerName)
	}
	decision := runtimeAssetDisableBlockDecision("mcp", probe.ServerName, connector, "hook", reason, "mcp-definition-unproven")
	decision.RegistryStatus = "unknown"
	closed := covered || cfg.MCPAdmissionFailsClosed(connector)
	if !covered && !denyPins && !strings.EqualFold(cfg.EffectiveAssetPolicyModeForConnector(connector), config.AssetPolicyModeAction) {
		closed = false
	}
	if !closed {
		decision.Action = "allow"
		decision.Mode = config.AssetPolicyModeObserve
	}
	return decision, true
}

// unprovenMCPDefinitionDecision refuses an MCP tool call whose server the
// agent loads from a command-line source the standalone hook could not read
// (claude --mcp-config, codex -c mcp_servers.*) when a rule decides on where
// a server points: the server the call reaches cannot be proven, so the call
// fails closed rather than being judged on a config file the agent ignores
// (GAP-0954). A url, command or transport rule in the denied list applies in
// every mode; one in the allowed list or the registry decides only under a
// default deny or registry_required, in asset_policy.mode.
func unprovenMCPDefinitionDecision(ctx context.Context, cfg *config.Config, connector string, probe mcpRuntimeProbe) (config.AssetPolicyDecision, bool) {
	unproven := claimedAssetFactsFromContext(ctx).MCPUnproven
	if unproven == "" || cfg == nil || cfg.SecureClientIntegration() || probe.Surface != "hook" ||
		!config.SameMCPToolServer(connector, probe.ServerName, unproven) {
		return config.AssetPolicyDecision{}, false
	}
	policy, _ := cfg.EffectiveAssetTypePolicy(connector, "mcp")
	mode := config.AssetPolicyModeAction
	if !rulesPinEndpointForServer(cfg.AssetPolicy.MCP.Denied, connector, probe.ServerName) {
		// Explicit endpoint denies survive the off switch; registry, allow
		// and default checks follow runtime detection even when the agent's
		// command-line definition could not be read.
		detection, _ := cfg.AssetRuntimeDetectionFor("mcp")
		gated := cfg.AssetPolicy.Enabled && detection.Enabled &&
			(policy.RegistryRequired || strings.EqualFold(strings.TrimSpace(policy.Default), "deny"))
		if !gated || (!rulesPinEndpointForServer(cfg.AssetPolicy.MCP.Allowed, connector, probe.ServerName) &&
			!rulesPinEndpointForServer(policy.Registry, connector, probe.ServerName)) {
			return config.AssetPolicyDecision{}, false
		}
		mode = cfg.EffectiveAssetPolicyModeForConnector(connector)
	}
	decision := config.AssetPolicyDecision{
		Enabled: true, Mode: mode, Action: "block", RawAction: "block",
		Source: "mcp-definition-unproven", RegistryStatus: "unknown",
		TargetType: "mcp", TargetName: probe.ServerName, Connector: connector, RuntimeSurface: "hook",
		Reason: fmt.Sprintf("mcp %q: the agent loads its MCP servers from its command line (--mcp-config or -c mcp_servers) "+
			"and that definition could not be read, so where the server points cannot be checked against asset_policy", probe.ServerName),
	}
	if !strings.EqualFold(mode, config.AssetPolicyModeAction) {
		decision.Action, decision.WouldBlock = "allow", true
	}
	return decision, true
}

// rulesPinEndpoint reports whether a rule matches on where an MCP server
// points or how it starts.
func rulesPinEndpoint(rules []config.AssetPolicyRule) bool {
	for _, rule := range rules {
		if rule.URL != "" || rule.Command != "" || rule.Transport != "" || len(rule.ArgsPrefix) > 0 {
			return true
		}
	}
	return false
}

// rulesPinEndpointForServer checks only constraints that remain provable when
// the command-line definition is unavailable. An unrelated name or connector
// cannot make this call fail closed.
func rulesPinEndpointForServer(rules []config.AssetPolicyRule, connector, server string) bool {
	for _, rule := range rules {
		if ruleScopesServer(rule, connector, server) && rulesPinEndpoint([]config.AssetPolicyRule{rule}) {
			return true
		}
	}
	return false
}

// rulesScopeServer reports whether a rule names the server (or no server) and
// the connector (or no connector), however it constrains the rest.
func rulesScopeServer(rules []config.AssetPolicyRule, connector, server string) bool {
	for _, rule := range rules {
		if ruleScopesServer(rule, connector, server) {
			return true
		}
	}
	return false
}

func ruleScopesServer(rule config.AssetPolicyRule, connector, server string) bool {
	if rule.Name != "" && !config.SameAssetName(rule.Name, server) &&
		!config.SameMCPToolServer(connector, rule.Name, server) {
		return false
	}
	return rule.Connector == "" || config.SameConnector(rule.Connector, connector)
}

// deniedRulesMayPinClaim reports whether a rule of rules that matches the
// server by name and connector and pins where it points may match the
// definition behind a claim that holds only its pins. Without pins every such
// rule may match. With them a rule is ruled out when the digest of a value it
// compares exactly (the URL, the command's base name, an argument of its
// prefix, the transport) differs, or when it asks for more arguments than the
// definition has; an argument position the claim holds no digest of (past
// assetfacts maxPinArgs plus maxTailPins) cannot be ruled out. It checks the
// constraints assetRuleMatches does.
func deniedRulesMayPinClaim(rules []config.AssetPolicyRule, connector, server string, pins *assetfacts.MCPPins) bool {
	var tail claimTail
	for _, rule := range rules {
		if rule.Name != "" && !config.SameAssetName(rule.Name, server) &&
			!config.SameMCPToolServer(connector, rule.Name, server) {
			continue
		}
		if rule.Connector != "" && !config.SameConnector(rule.Connector, connector) {
			continue
		}
		if !rulesPinEndpoint([]config.AssetPolicyRule{rule}) {
			continue
		}
		if len(rule.SourcePathContains) > 0 {
			// The input an MCP call is judged on carries no source path, so
			// a rule that requires one never matches it, whatever the
			// definition (assetRuleMatches).
			continue
		}
		if pins == nil || ruleMayMatchPins(rule, pins, &tail) {
			return true
		}
	}
	return false
}

// claimTail decodes the tail digests of one claim at most once, however many
// rules are compared with it (a request has one claim).
type claimTail struct {
	raw  []byte
	read bool
}

func (t *claimTail) of(pins *assetfacts.MCPPins) []byte {
	if !t.read {
		t.raw, t.read = pins.TailBytes(), true
	}
	return t.raw
}

func ruleMayMatchPins(rule config.AssetPolicyRule, pins *assetfacts.MCPPins, tail *claimTail) bool {
	if rule.URL != "" && assetfacts.PinSum(rule.URL) != pins.URL {
		return false
	}
	if rule.Command != "" && assetfacts.PinSum(filepath.Base(strings.TrimSpace(rule.Command))) != pins.Command {
		return false
	}
	if len(rule.ArgsPrefix) > pins.ArgCount {
		return false
	}
	var tailDigests []byte
	if len(rule.ArgsPrefix) > len(pins.Args) {
		tailDigests = tail.of(pins)
	}
	for i, want := range rule.ArgsPrefix {
		switch {
		case i < len(pins.Args):
			if !assetfacts.PinArgMatches(want, pins.Args[i]) {
				return false
			}
		default:
			if held := assetfacts.TailDigestAt(tailDigests, i-len(pins.Args)); held != nil && !assetfacts.PinTailMatches(want, held) {
				return false
			}
		}
	}
	if rule.Transport != "" {
		shape := func(sum string) string {
			if sum != "" {
				return "x"
			}
			return ""
		}
		if config.CanonicalMCPTransport(rule.Transport, "", "") != config.CanonicalMCPTransport(pins.Transport, shape(pins.URL), shape(pins.Command)) {
			return false
		}
	}
	return true
}

// mcpListsNeedResolving reports whether the explicit lists need the server of
// a name-only probe resolved while asset_policy is off: a denied rule of any
// kind, because the agent keeps the connection under the name it had when the
// call was judged and a later edit of its config (a rename, a removal) must
// not take the deny off it (GAP-0861), or an allowed rule that matches on how
// a server starts (url, command, args_prefix, transport).
func mcpListsNeedResolving(p config.AssetTypePolicy) bool {
	return len(p.Denied) > 0 || rulesPinEndpoint(p.Allowed)
}

func (a *APIServer) evaluateRuntimeSkillAssetPolicy(ctx context.Context, connector, hookEvent string, probe skillRuntimeProbe) (config.AssetPolicyDecision, bool) {
	decision, matched := a.runtimeSkillAssetPolicyDecision(ctx, connector, probe)
	if matched {
		a.emitRuntimeSkillAssetPolicyDecision(ctx, decision, connector, hookEvent, probe)
	}
	return decision, matched
}

func (a *APIServer) runtimeSkillAssetPolicyDecision(
	ctx context.Context, connector string, probe skillRuntimeProbe,
) (config.AssetPolicyDecision, bool) {
	if !probe.Matched {
		return config.AssetPolicyDecision{}, false
	}
	targetType := runtimeSkillAssetTargetType(probe)
	runtimeSurface := coalesceRuntimeSurface(probe.Surface, "hook")
	if probe.RuntimeDisableOnly && (a == nil || a.store == nil) {
		return runtimeAssetDisableBlockDecision(
			targetType, probe.SkillName, connector, runtimeSurface,
			"runtime provenance store is unavailable - failing closed",
			"runtime-provenance-error",
		), true
	}
	paths := []string{probe.SourcePath}
	if strings.TrimSpace(probe.SourcePath) == "" && len(probe.SourcePaths) > 0 {
		paths = probe.SourcePaths
	}
	cfg := a.requestConfig(ctx)
	if decision, disabled := a.runtimeAssetDisableDecision(ctx, cfg, targetType, probe.SkillName, connector, runtimeSurface, paths); disabled {
		return decision, true
	}
	if probe.RuntimeDisableOnly {
		return config.AssetPolicyDecision{}, false
	}
	if cfg == nil {
		return config.AssetPolicyDecision{}, false
	}
	if decision, refused := a.profileAssetContentDecision(ctx, cfg, connector, targetType, runtimeSurface, probe); refused {
		return decision, true
	}
	if targetType == "plugin" && !cfg.SecureClientIntegration() {
		if decision, blocked := a.pluginJournalBlockDecision(ctx, cfg, probe.SkillName, connector, runtimeSurface, paths); blocked {
			return decision, true
		}
		probe.DeclaredNames = append(probe.DeclaredNames, deniedPluginMarketplaceNames(cfg, probe.SkillName)...)
	}
	if decision, unavailable := a.unavailableRootDecision(cfg, targetType, connector, runtimeSurface, probe.SkillName, paths); unavailable {
		return decision, true
	}
	if strings.TrimSpace(probe.SourcePath) == "" && len(probe.SourcePaths) > 0 {
		// A folder of another name that the call loads (its SKILL.md
		// declares the name) answers to that folder's runtime disable.
		for _, path := range probe.SourcePaths {
			if folder := filepath.Base(path); !config.SameAssetName(folder, probe.SkillName) {
				if decision, disabled := a.runtimeAssetDisableDecision(ctx, cfg, targetType, folder, connector, runtimeSurface, []string{path}); disabled {
					return decision, true
				}
			}
		}
	}
	if targetType == "skill" && !cfg.SecureClientIntegration() {
		for _, path := range paths {
			if absolute := projectSkillAbsolutePath(path, probe.ProjectDir); absolute != "" {
				if decision, refused := a.projectSkillRefusalDecision(absolute, probe.SkillName, connector, runtimeSurface); refused {
					return decision, true
				}
			}
		}
		if probe.SourcePath != "" {
			if decision, refused := a.projectSkillSelectedRefusalDecision(
				ctx, probe.SkillName, connector, runtimeSurface,
			); refused {
				return decision, true
			}
		}
	}
	admissionPaths := make([]string, len(paths))
	for i, path := range paths {
		admissionPaths[i] = projectSkillAdmissionFolder(path, probe.ProjectDir, resolvedWritesFromContext(ctx), cfg.SecureClientIntegration())
	}
	if decision, pending := a.projectSkillScanPending(targetType, connector, runtimeSurface, admissionPaths); pending {
		return decision, true
	}
	var last config.AssetPolicyDecision
	for _, path := range paths {
		decision, applies := runtimeSkillPathDecision(cfg, targetType, connector, runtimeSurface, path, probe)
		if !applies {
			continue
		}
		if decision.Enabled && decision.RawAction == "block" {
			return decision, true
		}
		last = decision
	}
	return last, false
}

// unavailableRootDecision holds a named skill or plugin only when its
// connector's admission root is unavailable and policy requires fail closed.
// Balanced and permissive hosts keep working; watcher health names the gap.
func (a *APIServer) unavailableRootDecision(
	cfg *config.Config, targetType, connector, surface, name string, paths []string,
) (config.AssetPolicyDecision, bool) {
	if a == nil || a.rootCoverage == nil || cfg == nil || cfg.SecureClientIntegration() ||
		(!managed.IsManagedEnterprise(cfg.DeploymentMode) && cfg.HookPolicyTierForConnector(connector) != config.HookPolicyTierStrict) {
		return config.AssetPolicyDecision{}, false
	}
	for _, issue := range a.rootCoverage() {
		if issue.Kind != targetType || (issue.Connector != "" && issue.Connector != connector &&
			!slices.Contains(issue.Connectors, connector)) {
			continue
		}
		root, rootErr := filepath.Abs(issue.Path)
		resolvedRoot, rootResolved := "", false
		if rootErr == nil {
			resolvedRoot, rootResolved = unavailableRootCanonicalPath(root)
		}
		provenOutside := rootResolved
		for _, path := range paths {
			path = strings.TrimSpace(path)
			if path == "" {
				provenOutside = false
				break
			}
			if !filepath.IsAbs(path) {
				provenOutside = false
				break
			}
			// Parent elements and Windows device or stream forms do not prove
			// that a source is outside an unavailable root.
			if hasParentElement(path) || runtime.GOOS == "windows" &&
				(strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\.\`) ||
					strings.Contains(path[len(filepath.VolumeName(path)):], ":")) {
				provenOutside = false
				break
			}
			resolvedPath, pathResolved := unavailableRootCanonicalPath(path)
			if !pathResolved || rootErr == nil && unavailableRootContainsPath(root, path) ||
				rootResolved && unavailableRootContainsPath(resolvedRoot, resolvedPath) {
				provenOutside = false
				break
			}
		}
		if provenOutside {
			continue
		}
		return runtimeAssetDisableBlockDecision(targetType, name, connector, surface,
			fmt.Sprintf("%s %q cannot be checked while admission scanning is off for a connector root; see watcher health", targetType, name),
			"watch-root-unavailable"), true
	}
	return config.AssetPolicyDecision{}, false
}

// projectSkillSelectedRefusalDecision uses the caller's selected-folder fact
// when an explicit source uses a spelling the gateway cannot associate with
// an excluded profile root. The hook binds the fact to the explicit path in
// the caller's filesystem view before it sends the fact, and sends one only
// for a folder that the caller's own profile does not hold privately. The
// gateway applies the fact for every spelling of the source: a path under a
// user skill folder can be a link to a refused target, which only the caller
// can tell.
func (a *APIServer) projectSkillSelectedRefusalDecision(
	ctx context.Context, name, connector, surface string,
) (config.AssetPolicyDecision, bool) {
	for key, selectedName := range resolvedWritesFromContext(ctx) {
		if !strings.HasPrefix(key, hookpaths.ProjectSkillSelectedPrefix) ||
			!config.SameAssetName(selectedName, name) {
			continue
		}
		selected := strings.TrimPrefix(key, hookpaths.ProjectSkillSelectedPrefix)
		if decision, refused := a.projectSkillRefusalDecision(selected, name, connector, surface); refused {
			return decision, true
		}
	}
	return config.AssetPolicyDecision{}, false
}

// unavailableRootCanonicalPath resolves each existing component. A missing
// suffix can be appended to a resolved parent, but a dangling link or any
// other unresolved component cannot prove a source is outside the root.
func unavailableRootCanonicalPath(path string) (string, bool) {
	for candidate := filepath.Clean(path); ; candidate = filepath.Dir(candidate) {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err == nil {
			suffix, err := filepath.Rel(candidate, path)
			if err != nil {
				return "", false
			}
			return filepath.Join(resolved, suffix), true
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", false
		}
		if _, err := os.Lstat(candidate); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return "", false
		}
		if parent := filepath.Dir(candidate); parent == candidate {
			return "", false
		}
	}
}

func unavailableRootContainsPath(root, path string) bool {
	if insideHome(root, path) {
		return true
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(root), filepath.Clean(path))
	}
	return filepath.Clean(root) == filepath.Clean(path)
}

// projectSkillAbsolutePath resolves a source spelling for project admission.
func projectSkillAbsolutePath(path, cwd string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	if !filepath.IsAbs(path) {
		if !filepath.IsAbs(cwd) {
			return ""
		}
		path = filepath.Join(cwd, path)
	}
	return filepath.Clean(path)
}

// projectSkillAdmissionFolder maps the path spellings a skill call accepts to
// the folder that owns its manifest. It only affects project admission; the
// raw source path remains available to asset rules and audit records.
func projectSkillAdmissionFolder(path, cwd string, facts map[string]string, secureClient bool) string {
	path = projectSkillAbsolutePath(path, cwd)
	if path == "" {
		return ""
	}
	if secureClient {
		if strings.EqualFold(filepath.Base(path), "SKILL.md") {
			return filepath.Dir(path)
		}
		return path
	}
	if strings.EqualFold(filepath.Base(path), "SKILL.md") {
		selected := false
		for key := range facts {
			if strings.HasPrefix(key, hookpaths.ProjectSkillSelectedPrefix) &&
				sameCleanPath(strings.TrimPrefix(key, hookpaths.ProjectSkillSelectedPrefix), path) {
				selected = true
				break
			}
		}
		if !selected {
			if gatewaySkillPathCheck(path) != nil {
				path = filepath.Dir(path)
			} else if info, err := os.Stat(path); err != nil || !info.IsDir() {
				path = filepath.Dir(path)
			}
		}
	}
	return path
}

// runtimeSkillPathDecision is the asset_policy decision for one folder a
// skill call can load (path "" when the call names none). applies is false
// when the hook does not evaluate asset_policy for it.
func runtimeSkillPathDecision(
	cfg *config.Config, targetType, connector, runtimeSurface, path string, probe skillRuntimeProbe,
) (config.AssetPolicyDecision, bool) {
	input := config.AssetPolicyInput{
		TargetType:     targetType,
		Name:           probe.SkillName,
		DeclaredNames:  probe.DeclaredNames,
		Connector:      connector,
		SourcePath:     path,
		RuntimeSurface: runtimeSurface,
	}
	runtimeDetection, _ := cfg.AssetRuntimeDetectionFor(targetType)
	if !runtimeAssetPolicyApplies(cfg, runtimeDetection, probe.Surface, input) {
		return config.AssetPolicyDecision{}, false
	}
	decision := cfg.EvaluateAssetPolicy(input)
	// a Claude Code agent can pass a crafted
	// skill_name like "/tmp/attacker/trusted-skill/SKILL.md" and
	// the previous code stripped it down to the basename
	// "trusted-skill", which matches the operator's registered
	// skill by name only. The path itself is attacker-controlled
	// so the registry match is meaningless. We force-rewrite the
	// decision to "unregistered" whenever the agent's literal
	// input was path-shaped (probe.RawName carries the original
	// when normalization changed it). This makes the decision
	// fall through the registry-required guard the operator
	// already configured.
	if targetType == "skill" && probe.RawName != "" && strings.ContainsAny(probe.RawName, `/\`) {
		// Mark unregistered so registry-required policy denies.
		decision.RegistryStatus = "unregistered"
		// If the operator runs registry_required=true and the
		// configured default for unknowns is deny (the policy
		// the test in sets up), assetPolicyViolation
		// already produces a block; we just need to make sure
		// we don't reuse the cached "allow" path. Re-evaluate.
		decision.RawAction = "block"
		if decision.Mode == config.AssetPolicyModeAction {
			decision.Action = "block"
		} else {
			decision.Action = "allow"
			decision.WouldBlock = true
		}
		decision.Reason = appendVerdictReason(decision.Reason,
			"path-shaped skill_name input forced unregistered match")
		if strings.TrimSpace(decision.Source) == "" {
			decision.Source = "skill-path-shaped"
		}
	}
	return decision, true
}

func (a *APIServer) evaluateNativeRuntimeSkillSelection(
	ctx context.Context,
	connector, sessionID, hookEvent, provenance string,
	probe skillRuntimeProbe,
) (config.AssetPolicyDecision, bool) {
	decision, matched := a.runtimeSkillAssetPolicyDecision(ctx, connector, probe)
	if probe.RuntimeDisableOnly && !matched {
		return decision, false
	}
	state := audit.RuntimeAssetSelected
	// Claude's native expansion event is emitted only after the selected
	// skill/command content has actually been expanded into the prompt. That
	// is a proven load boundary. Codex UserPromptSubmit is earlier and remains
	// a selection-only attestation.
	if provenance == runtimeProvenanceClaudeExpansion {
		state = audit.RuntimeAssetLoaded
	}
	if matched && decision.Action == "block" {
		state = audit.RuntimeAssetBlocked
	}
	var persistenceErr error
	if a == nil || a.store == nil {
		persistenceErr = fmt.Errorf("runtime provenance store is unavailable")
	} else {
		persistenceErr = a.store.RecordRuntimeAssetState(ctx, audit.RuntimeAssetState{
			Connector:      connector,
			SessionID:      sessionID,
			TargetType:     runtimeSkillAssetTargetType(probe),
			TargetName:     probe.SkillName,
			SourcePath:     probe.SourcePath,
			RuntimeSurface: coalesceRuntimeSurface(probe.Surface, "hook"),
			HookEvent:      hookEvent,
			Provenance:     provenance,
			State:          state,
		})
	}
	if persistenceErr != nil && (!matched || decision.Action != "block") {
		decision = runtimeAssetDisableBlockDecision(
			runtimeSkillAssetTargetType(probe), probe.SkillName, connector,
			coalesceRuntimeSurface(probe.Surface, "hook"),
			fmt.Sprintf(
				"%s %q runtime provenance write failed - failing closed: %v",
				runtimeSkillAssetTargetType(probe), probe.SkillName, persistenceErr,
			),
			"runtime-provenance-error",
		)
		matched = true
	}
	if matched {
		a.emitRuntimeSkillAssetPolicyDecision(ctx, decision, connector, hookEvent, probe)
	}
	return decision, matched
}

// runtimeAssetPolicyApplies reports whether a hook evaluates asset_policy
// for an asset it identified. runtime_detection (enabled, terminal_commands)
// governs the default, registry and approval rules; an explicit denied entry
// applies whatever it says, as it does on the install watcher and the policy
// API (GAP-0566). Secure Client keeps the runtime_detection gate of main for
// every rule (issue #1092).
func runtimeAssetPolicyApplies(cfg *config.Config, detection config.AssetRuntimeDetection, surface string, in config.AssetPolicyInput) bool {
	if cfg == nil {
		return false
	}
	if cfg.SecureClientIntegration() {
		return detection.Enabled && (surface != "terminal" || detection.TerminalCommands)
	}
	if detection.Enabled && (surface != "terminal" || detection.TerminalCommands) {
		return true
	}
	verdict, _ := cfg.AssetListDecision(in)
	return verdict == config.AssetListDeny
}

func runtimeSkillAssetTargetType(probe skillRuntimeProbe) string {
	switch strings.ToLower(strings.TrimSpace(probe.TargetType)) {
	case "plugin":
		return "plugin"
	default:
		return "skill"
	}
}

func (a *APIServer) runtimeAssetDisableDecision(ctx context.Context, cfg *config.Config, targetType, name, connector, runtimeSurface string, paths []string) (config.AssetPolicyDecision, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return config.AssetPolicyDecision{}, false
	}
	pe := enforce.NewPolicyEngine(nil)
	if a != nil {
		pe = enforce.NewPolicyEngine(a.store)
	}
	disabled, err := pe.IsDisabledForConnector(targetType, name, connector)
	if err != nil {
		return runtimeAssetDisableBlockDecision(targetType, name, connector, runtimeSurface,
			fmt.Sprintf("%s %q runtime-disable check failed - failing closed: %v", targetType, name, err),
			"runtime-disable-error"), true
	}
	if !disabled {
		return config.AssetPolicyDecision{}, false
	}
	if a != nil && a.store != nil && connector != "" && len(paths) > 0 {
		if entry, err := a.store.GetActionForConnector(targetType, name, connector); err == nil &&
			entry != nil && entry.Actions.Runtime == "disable" &&
			slices.Contains(a.policyHoldIgnoredFields(ctx, cfg, connector, entry, paths), "runtime") {
			return config.AssetPolicyDecision{}, false
		}
	}
	return runtimeAssetDisableBlockDecision(targetType, name, connector, runtimeSurface,
		fmt.Sprintf("%s %q is runtime-disabled for connector %q", targetType, name, connector),
		"runtime-disable"), true
}

// policyHoldIgnoredFields are the fields of the policy hold on entry that do
// not cover paths. A policy hold sits on the row of the asset name but was
// written for the copies still denied; a path that resolves outside all of
// them is another copy of the name that an allow rule admitted. Secure Client
// keeps the journal decision of main, so it ignores no field. A held copy
// this process cannot inspect is present, unknown: the strict tier and a
// managed deployment keep the hold, and the other tiers run the call with a
// warning and an audit row.
func (a *APIServer) policyHoldIgnoredFields(ctx context.Context, cfg *config.Config, connector string, entry *audit.ActionEntry, paths []string) []string {
	if cfg == nil || cfg.SecureClientIntegration() {
		return nil
	}
	scope := watcher.PolicyHoldIgnoredFields(entry, paths)
	if len(scope.Ignored) == 0 {
		return nil
	}
	if len(scope.Unknown) > 0 {
		if watcher.PolicyHoldStrict(cfg, connector) {
			return nil
		}
		detail := fmt.Sprintf("a policy hold names a copy this gateway cannot inspect (%s); the call names another path and runs: strict and managed profiles keep the hold",
			strings.Join(scope.Unknown, ","))
		fmt.Fprintf(os.Stderr, "[gateway] warning: connector %s: %s\n", connector, detail)
		a.logAssetPolicyAudit(ctx, connector, strings.TrimSpace(entry.TargetType)+":"+entry.TargetName, "action=allow source=policy-hold-unknown-copy "+detail)
	}
	return scope.Ignored
}

// claudeCodePluginAssetDecision refuses a Claude Code tool call that runs
// part of a plugin, an MCP tool (mcp__plugin_<plugin>_<server>__<tool>), a
// skill (Skill "<plugin>:<skill>") or an agent (subagent_type
// "<plugin>:<agent>"), when the plugin is denied by asset_policy or blocked
// by admission. Claude Code runs a plugin installed from a local
// marketplace folder from that folder: quarantining the cache copy did not
// stop it, and a denied plugin's MCP tool still answered (GAP-1189).
// Secure Client keeps main (issue #1092).
func (a *APIServer) claudeCodePluginAssetDecision(ctx context.Context, req claudeCodeHookRequest) (config.AssetPolicyDecision, bool) {
	cfg := a.requestConfig(ctx)
	if cfg == nil || cfg.SecureClientIntegration() {
		return config.AssetPolicyDecision{}, false
	}
	if offered := claudeCodeCoworkPluginProbe(req); offered.Matched {
		if decision, matched := a.evaluateRuntimeSkillAssetPolicy(ctx, "claudecode", req.HookEventName, offered); matched {
			return decision, true
		}
	}
	owners, candidates := a.claudeCodeToolPlugins(ctx, req)
	// A managed Windows gateway cannot read the plugin registry in a profile:
	// the plugin the hook resolved for a bundled server's tool owns the call
	// (GAP-0699). A plugin the hook names owns the call even when the server
	// name could belong to other plugins: the registry the hook read decides,
	// so the candidates' own missing content does not refuse it.
	ownerClaimed := false
	if profileAssetScanApplies(cfg) && strings.HasPrefix(req.ToolName, "mcp__plugin_") {
		for _, content := range claimedAssetFactsFromContext(ctx).Contents {
			if content.Kind != assetfacts.ContentPlugin {
				continue
			}
			ownerClaimed = true
			if !slices.ContainsFunc(owners, func(o string) bool { return strings.EqualFold(o, content.Name) }) {
				owners = append(owners, content.Name)
			}
		}
	}
	for _, plugin := range owners {
		probe := skillRuntimeProbe{
			TargetType: "plugin", SkillName: plugin, ToolName: req.ToolName, Surface: "hook", Matched: true,
		}
		if decision, matched := a.evaluateRuntimeSkillAssetPolicy(ctx, "claudecode", req.HookEventName, probe); matched {
			return decision, true
		}
	}
	if len(candidates) > 0 {
		return a.claudeCodePluginOwnerUnknownDecision(ctx, req, candidates, ownerClaimed)
	}
	return config.AssetPolicyDecision{}, false
}

// claudeCodePluginOwnerUnknownSource is the decision source of a plugin MCP
// call whose owner plugin the registry could not prove (GAP-0293).
const claudeCodePluginOwnerUnknownSource = "plugin-owner-unknown"

// claudeCodePluginOwnerUnknownDecision decides a plugin MCP call whose owner
// the plugin registry could not prove. The owner is reported as unknown,
// never as a plugin read off the server name: a quarantined or blocked plugin
// whose name is a prefix of the real owner was named as the owner and its
// refusal shown for the other plugin's tool (rel-1-0-6:GAP-0293).
//
// The decision is the one the policy gives an unknown owner. A refusal
// (admin deny, install block, runtime disable, quarantine) of a plugin the
// name can belong to cannot be ruled out without the owner, so the call is
// refused as owner unknown, as a deny that cannot be evaluated is
// (mcp-definition-unproven, GAP-1187) and as before (GAP-1198). Otherwise
// asset_policy.plugin decides an unknown plugin: default-deny and
// registry_required refuse it where they are on, and the default profile
// lets it run. Secure Client never reaches this function.
//
// Where a managed Windows gateway judges the plugin text the hook sends
// (profileAssetContentDecision) and no content names the owner, a candidate
// that holds no content is a plugin nothing scanned, and the call is refused
// as owner unknown like any other refusal of a candidate (GAP-0699).
func (a *APIServer) claudeCodePluginOwnerUnknownDecision(
	ctx context.Context, req claudeCodeHookRequest, candidates []string, ownerClaimed bool,
) (config.AssetPolicyDecision, bool) {
	server := strings.TrimSpace(req.MCPServerName)
	if server == "" {
		server = serverFromMCPToolName(req.ToolName)
	}
	unknown := skillRuntimeProbe{
		TargetType: "plugin", SkillName: "unknown", RawName: server, ToolName: req.ToolName, Surface: "hook", Matched: true,
	}
	for _, plugin := range candidates {
		probe := skillRuntimeProbe{
			TargetType: "plugin", SkillName: plugin, ToolName: req.ToolName, Surface: "hook", Matched: true,
		}
		decision, matched := a.runtimeSkillAssetPolicyDecision(ctx, "claudecode", probe)
		if !matched {
			continue
		}
		refusal := false
		switch decision.Source {
		case "admin-deny", "install-block", "runtime-disable":
			refusal = true
		case "profile-asset-unscanned", "profile-asset-verdict":
			refusal = !ownerClaimed
		}
		if refusal {
			decision.Reason = fmt.Sprintf("plugin owner of mcp server %q is unknown: the plugin registry does not prove it, "+
				"and a refusal of a plugin the name can belong to cannot be ruled out (%s)", server, decision.Source)
			decision.Source = claudeCodePluginOwnerUnknownSource
			decision.TargetName = "unknown"
			decision.RegistryStatus = "unknown"
			a.emitRuntimeSkillAssetPolicyDecision(ctx, decision, "claudecode", req.HookEventName, unknown)
			return decision, true
		}
	}
	cfg := a.requestConfig(ctx)
	if cfg == nil {
		return config.AssetPolicyDecision{}, false
	}
	decision, applies := runtimeSkillPathDecision(cfg, "plugin", "claudecode", "hook", "", skillRuntimeProbe{
		TargetType: "plugin", SkillName: "", Surface: "hook", Matched: true,
	})
	if !applies || !decision.Enabled || decision.RawAction != "block" {
		return config.AssetPolicyDecision{}, false
	}
	decision.TargetName = "unknown"
	decision.Reason = appendVerdictReason(decision.Reason,
		fmt.Sprintf("plugin owner of mcp server %q is unknown: the plugin registry does not prove it", server))
	a.emitRuntimeSkillAssetPolicyDecision(ctx, decision, "claudecode", req.HookEventName, unknown)
	return decision, true
}

// claudeCodeToolPlugins obtains MCP plugin ownership from the configured
// server. An underscore split is only usable when it has one boundary;
// otherwise plugin and server names cannot be distinguished from the hook:
// the owner is unknown, and every plugin name the server name could start
// with is returned in candidates, never reported as the owner (GAP-1198,
// rel-1-0-6:GAP-0293).
func (a *APIServer) claudeCodeToolPlugins(ctx context.Context, req claudeCodeHookRequest) (owners, candidates []string) {
	var out []string
	add := func(name string) {
		if name = strings.TrimSpace(name); validNativeSkillSelectionName(name) && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	server := strings.TrimSpace(req.MCPServerName)
	if server == "" {
		server = serverFromMCPToolName(req.ToolName)
	}
	if rest, ok := strings.CutPrefix(server, "plugin_"); ok {
		cfg := a.requestConfig(ctx)
		resolved := false
		if cfg != nil {
			if entry, found := a.lookupCallerMCPServer(ctx, cfg, "claudecode", req.CWD, server); found {
				if pluginServer, ok := strings.CutPrefix(entry.Name, "plugin:"); ok {
					if plugin, _, ok := strings.Cut(pluginServer, ":"); ok {
						add(plugin)
						resolved = true
					}
				}
			}
		}
		if !resolved && strings.Count(rest, "_") == 1 {
			plugin, _, _ := strings.Cut(rest, "_")
			add(plugin)
		} else if !resolved {
			for i := strings.Index(rest, "_"); i > 0; {
				if name := rest[:i]; validNativeSkillSelectionName(name) && !slices.Contains(candidates, name) {
					candidates = append(candidates, name)
				}
				next := strings.Index(rest[i+1:], "_")
				if next < 0 {
					break
				}
				i += next + 1
			}
		}
	}
	key := ""
	switch strings.TrimSpace(req.ToolName) {
	case "Skill":
		key = "skill"
	case "Task", "Agent":
		key = "subagent_type"
	}
	if value, _ := req.ToolInput[key].(string); key != "" {
		if plugin, rest, ok := strings.Cut(strings.TrimPrefix(strings.TrimSpace(value), "/"), ":"); ok && rest != "" {
			add(plugin)
		}
	}
	return out, candidates
}

// pluginJournalBlockDecision refuses a plugin whose journal entry, under
// its name or plugin@marketplace as the watcher records a Claude Code
// marketplace plugin, holds an install block, a runtime disable or a
// quarantine. The hook sees the plugin name only, and a blocked plugin's
// files can stay where the agent runs them, so its block is enforced here
// too (GAP-1189). Quarantine moves only the cache copy: Claude Code runs a
// local-marketplace plugin's commands, skills and MCP servers from the
// marketplace folder, so `plugin quarantine` alone left /plugin:command
// running (GAP-0270). `plugin restore` clears the file action, which lifts
// this refusal.
func (a *APIServer) pluginJournalBlockDecision(ctx context.Context, cfg *config.Config, name, connector, runtimeSurface string, paths []string) (config.AssetPolicyDecision, bool) {
	if a == nil || a.store == nil || strings.TrimSpace(name) == "" {
		return config.AssetPolicyDecision{}, false
	}
	entries, err := a.store.ListActionsByType("plugin")
	if err != nil {
		return runtimeAssetDisableBlockDecision("plugin", name, connector, runtimeSurface,
			fmt.Sprintf("plugin %q block check failed - failing closed: %v", name, err), "runtime-disable-error"), true
	}
	for _, entry := range entries {
		if strings.TrimSpace(entry.Connector) != "" && !config.SameConnector(entry.Connector, connector) {
			continue
		}
		plugin, _, _ := strings.Cut(entry.TargetName, "@")
		if !config.SameAssetName(plugin, name) && !config.SameAssetName(entry.TargetName, name) {
			continue
		}
		reason, source := fmt.Sprintf("plugin %q is blocked by install admission", entry.TargetName), "install-block"
		ignored := a.policyHoldIgnoredFields(ctx, cfg, connector, &entry, paths)
		switch {
		case entry.Actions.Install == "block" && !slices.Contains(ignored, "install") ||
			entry.Actions.Runtime == "disable" && !slices.Contains(ignored, "runtime"):
		case entry.Actions.File == "quarantine" && !slices.Contains(ignored, "file"):
			// Worded as a disabled plugin for the agent (runtime-disable,
			// agentAssetPolicySubject); the audit reason says quarantined.
			reason, source = fmt.Sprintf("plugin %q is quarantined", entry.TargetName), "runtime-disable"
		default:
			continue
		}
		if detail := strings.TrimSpace(entry.Reason); detail != "" {
			reason += ": " + detail
		}
		return runtimeAssetDisableBlockDecision("plugin", name, connector, runtimeSurface, reason, source), true
	}
	return config.AssetPolicyDecision{}, false
}

// deniedPluginMarketplaceNames are the plugin@marketplace names of the
// denied plugin rules for plugin. The hook sees no marketplace, so a deny
// written as plugin@marketplace refuses the plugin from any of them; these
// names only ever match denied rules.
func deniedPluginMarketplaceNames(cfg *config.Config, plugin string) []string {
	var names []string
	for _, rule := range cfg.AssetPolicy.Plugin.Denied {
		if name, _, ok := strings.Cut(rule.Name, "@"); ok && config.SameAssetName(name, plugin) {
			names = append(names, rule.Name)
		}
	}
	return names
}

func runtimeAssetDisableBlockDecision(targetType, name, connector, runtimeSurface, reason, source string) config.AssetPolicyDecision {
	return config.AssetPolicyDecision{
		Enabled:            true,
		Mode:               config.AssetPolicyModeAction,
		Action:             "block",
		RawAction:          "block",
		WouldBlock:         true,
		Reason:             reason,
		Source:             source,
		RegistryStatus:     "disabled",
		RegistryConfigured: false,
		TargetType:         targetType,
		TargetName:         name,
		Connector:          connector,
		RuntimeSurface:     runtimeSurface,
	}
}

func (a *APIServer) runtimeAssetIdentityDecision(ctx context.Context, targetType, name, connector, runtimeSurface string) config.AssetPolicyDecision {
	mode := config.AssetPolicyModeObserve
	if cfg := a.decisionConfig(ctx); cfg != nil && assetRuntimeModeIsAction(
		cfg.EffectiveAssetPolicyModeForConnector(connector),
	) {
		mode = config.AssetPolicyModeAction
	}
	action := "allow"
	wouldBlock := true
	if mode == config.AssetPolicyModeAction {
		action = "block"
		wouldBlock = false
	}
	return config.AssetPolicyDecision{
		Enabled:            true,
		Mode:               mode,
		Action:             action,
		RawAction:          "block",
		WouldBlock:         wouldBlock,
		Reason:             "Claude Code slash-command asset identity is missing, malformed, or inconsistent - failing closed",
		Source:             "runtime-identity-error",
		RegistryStatus:     "invalid",
		RegistryConfigured: false,
		TargetType:         targetType,
		TargetName:         name,
		Connector:          connector,
		RuntimeSurface:     runtimeSurface,
	}
}

func (a *APIServer) emitRuntimeSkillAssetPolicyDecision(ctx context.Context, decision config.AssetPolicyDecision, connector, hookEvent string, probe skillRuntimeProbe) {
	targetType := runtimeSkillAssetTargetType(probe)
	evalCtx := a.emitAssetPolicyDecisionFindings(ctx, decision, targetType, connector, hookEvent)
	if a.logger != nil {
		details := runtimeSkillAssetPolicyAuditDetails(decision, connector, hookEvent, probe)
		details = appendHookEvaluationDetails(details, evalCtx)
		a.logAssetPolicyAudit(ctx, connector, targetType+":"+decision.TargetName, details)
	}
	a.dispatchAssetPolicyNotification(decision, targetType, connector, hookEvent, evalCtx)
}

func runtimeSkillAssetPolicyAuditDetails(decision config.AssetPolicyDecision, connector, hookEvent string, probe skillRuntimeProbe) string {
	return fmt.Sprintf("action=%s source=%s registry_status=%s registry_configured=%v surface=%s hook=%s tool=%s connector=%s name_raw=%q source_path=%q would_block=%v reason=%s",
		decision.Action, decision.Source, decision.RegistryStatus, decision.RegistryConfigured, probe.Surface, hookEvent, probe.ToolName, connector, probe.RawName, probe.SourcePath, decision.WouldBlock, decision.Reason)
}

func hookNotificationCoveredByAssetPolicy(rawActionBeforeAssets string, assetDecisions []runtimeAssetDecision) bool {
	if len(assetDecisions) == 0 {
		return false
	}
	switch normalizeCodexAction(rawActionBeforeAssets) {
	case "block", "confirm":
		return false
	default:
		return true
	}
}

// hookResponseRuleIDs are the rule IDs a hook response carries: the hook
// rules' own IDs plus the asset_policy.<type>.<source> ID of every blocking
// asset decision, as the asset-policy audit row records them. The tool span
// takes its defenseclaw.guardrail.rule_id from the first ID, so the asset
// rule leads when asset policy, not a hook rule, raised the block
// (GAP-2489).
func hookResponseRuleIDs(hookRuleIDs []string, rawActionBeforeAssets string, assetDecisions []runtimeAssetDecision) []string {
	var assetRuleIDs []string
	for _, asset := range assetDecisions {
		if asset.decision.RawAction == "block" {
			assetRuleIDs = append(assetRuleIDs, assetPolicyDecisionRuleID(asset.decision, asset.targetType))
		}
	}
	if len(assetRuleIDs) == 0 {
		return hookRuleIDs
	}
	if normalizeCodexAction(rawActionBeforeAssets) == "block" {
		return mergeBoundedRuleIDs(8, hookRuleIDs, assetRuleIDs)
	}
	return mergeBoundedRuleIDs(8, assetRuleIDs, hookRuleIDs)
}

// dispatchAssetPolicyNotification fires an OS toast for an asset
// policy block / would-block decision. Only the runtime evaluators
// call this helper, and only after they have already decided the
// decision is blocking (RawAction == "block" + matched). The
// dispatcher's per-source gate keeps it silent when an operator
// turns off `notifications.sources.asset_policy` even with the
// master switch on. Reason is run through redaction.ForSinkReason
// for parity with the hook / proxy / HILT helpers — the toast is
// rendered locally but a screenshot or screen recording is still a
// data-exfil surface.
func (a *APIServer) dispatchAssetPolicyNotification(decision config.AssetPolicyDecision, targetKind, connectorName, hookEvent string, evalCtx ...hookEvaluationContext) {
	if a == nil || a.notifier == nil {
		return
	}
	var ec hookEvaluationContext
	if len(evalCtx) > 0 {
		ec = evalCtx[0]
	}
	target := strings.TrimSpace(decision.TargetName)
	if target == "" {
		target = strings.ToLower(strings.TrimSpace(targetKind))
	} else {
		target = strings.ToLower(strings.TrimSpace(targetKind)) + ":" + target
	}
	ev := notifier.BlockEvent{
		Source:       notifier.SourceAssetPolicy,
		Target:       target,
		Reason:       string(redaction.ForSinkReason(decision.Reason)),
		Severity:     "HIGH",
		Connector:    connectorName,
		Event:        hookEvent,
		EvaluationID: ec.EvaluationID,
		RuleIDs:      ec.RuleIDs,
	}
	if decision.Action == "block" {
		a.notifier.OnBlock(ev)
		return
	}
	if decision.WouldBlock {
		a.notifier.OnWouldBlock(ev)
	}
}

func isUnknownTerminalMCP(probe mcpRuntimeProbe) bool {
	return probe.Surface == "terminal" && strings.EqualFold(strings.TrimSpace(probe.ServerName), "terminal-mcp")
}

// assetMCPModeFor returns the effective AssetPolicy mode and whether
// the operator's MCP.Default is "deny". Used by to refuse the
// `unknown_terminal_mcp=observe` downgrade when the operator has
// already opted into MCP default-deny in action mode.
func assetMCPModeFor(cfg *config.Config, decision config.AssetPolicyDecision) (string, bool) {
	if cfg == nil {
		return decision.Mode, false
	}
	// Resolve mode + MCP.Default per-connector (OTHER-7) so a connector with
	// an override gets its own posture rather than the global one. The
	// connector travels on the decision (set from AssetPolicyInput.Connector).
	mode := strings.TrimSpace(cfg.EffectiveAssetPolicyModeForConnector(decision.Connector))
	if mode == "" {
		mode = decision.Mode
	}
	mcpPolicy, _ := cfg.EffectiveAssetTypePolicy(decision.Connector, "mcp")
	defaultDeny := strings.EqualFold(strings.TrimSpace(mcpPolicy.Default), "deny")
	return mode, defaultDeny
}

func assetRuntimeModeIsAction(mode string) bool {
	return strings.EqualFold(strings.TrimSpace(mode), config.AssetPolicyModeAction)
}

func mcpProbeFromFields(serverName, toolName string, toolInput map[string]interface{}) mcpRuntimeProbe {
	toolName = strings.TrimSpace(toolName)
	if server := strings.TrimSpace(serverName); server != "" {
		return mcpRuntimeProbe{ServerName: server, ToolName: toolName, Surface: "hook", Matched: true}
	}
	if server := serverFromMCPToolName(toolName); server != "" {
		return mcpRuntimeProbe{ServerName: server, ToolName: toolName, Surface: "hook", Matched: true}
	}
	if commandText := commandFromToolInput(toolInput); commandText != "" && isTerminalTool(toolName) {
		cmd, args := splitCommandLine(commandText)
		if terminalMCPBypass(commandText) || looksLikeMCPServerCommand(cmd, args) {
			name := serverNameFromTerminalCommand(commandText)
			if name == "" {
				name = "terminal-mcp"
			}
			return mcpRuntimeProbe{
				ServerName: name,
				ToolName:   toolName,
				Command:    cmd,
				Args:       args,
				Surface:    "terminal",
				Matched:    true,
			}
		}
	}
	return mcpRuntimeProbe{ToolName: toolName}
}

// cursorMCPProbeFromPayload preserves Cursor's authoritative beforeMCPExecution
// endpoint/command fields and derives a collision-resistant local identity.
// Cursor does not supply a vendor/server name, so the identity deliberately
// describes only the source kind and digest rather than inventing one.
func cursorMCPProbeFromPayload(payload map[string]interface{}, toolName string) mcpRuntimeProbe {
	url := strings.TrimSpace(payloadString(payload, "url"))
	commandLine := strings.TrimSpace(payloadString(payload, "command"))
	if url == "" && commandLine == "" {
		return mcpRuntimeProbe{ToolName: strings.TrimSpace(toolName)}
	}

	kind := "endpoint"
	transport := "http"
	if url == "" {
		kind = "command"
		transport = "stdio"
	} else if commandLine != "" {
		kind = "endpoint-command"
		transport = "mixed"
	}
	// JSON string lengths/escaping provide unambiguous framing even if an
	// attacker places NULs or field-label text inside an endpoint/command.
	identityMaterial, _ := json.Marshal(struct {
		URL     string `json:"url"`
		Command string `json:"command"`
	}{URL: url, Command: commandLine})
	digest := sha256.Sum256(identityMaterial)
	command, args := splitCommandLine(commandLine)
	return mcpRuntimeProbe{
		ServerName: fmt.Sprintf("%s-sha256:%x", kind, digest),
		ToolName:   strings.TrimSpace(toolName),
		URL:        url,
		Command:    command,
		Args:       args,
		Transport:  transport,
		Surface:    "hook",
		Matched:    true,
	}
}

// pluginBundledSkillName is the skill part of a plugin-qualified name
// (usm-kit:notes, as Claude Code names a skill or command a plugin bundles),
// or "". A denied skill name matches it, so "skill block notes" stops the
// plugin's copy as well as a standalone one (GAP-1104). Secure Client keeps
// main's name match (issue #1092).
func pluginBundledSkillName(cfg *config.Config, name string) string {
	if cfg == nil || cfg.SecureClientIntegration() {
		return ""
	}
	plugin, skill, namespaced := strings.Cut(strings.TrimPrefix(strings.TrimSpace(name), "/"), ":")
	if !namespaced || !validNativeSkillSelectionName(plugin) || !validNativeSkillSelectionName(skill) {
		return ""
	}
	return skill
}

func slashCommandAssetType(commandSource string) string {
	switch strings.ToLower(strings.TrimSpace(commandSource)) {
	case "skill", "policysettings", "usersettings", "projectsettings", "bundled":
		return "skill"
	case "plugin":
		return "plugin"
	default:
		return ""
	}
}

func claudeCodeSlashSourceTrustsAssetPolicy(commandSource string) bool {
	switch strings.ToLower(strings.TrimSpace(commandSource)) {
	case "skill", "plugin":
		return true
	default:
		return false
	}
}

func canonicalClaudeCodeSlashSource(commandSource string) string {
	switch strings.ToLower(strings.TrimSpace(commandSource)) {
	case "skill":
		return "skill"
	case "plugin":
		return "plugin"
	case "policysettings":
		return "policySettings"
	case "usersettings":
		return "userSettings"
	case "projectsettings":
		return "projectSettings"
	case "bundled":
		return "bundled"
	default:
		return ""
	}
}

type claudeCodeSlashIdentity struct {
	targetType string
	name       string
	rawName    string
	toolName   string
	selector   string
}

func (i claudeCodeSlashIdentity) sameAsset(other claudeCodeSlashIdentity) bool {
	return i.targetType == other.targetType && i.name == other.name && i.selector == other.selector
}

func claudeCodePromptSlashCommandName(prompt string) string {
	fields := strings.Fields(strings.TrimSpace(prompt))
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "/") {
		return ""
	}
	return fields[0]
}

func claudeCodeSlashAssetIdentity(targetType, rawName string) (claudeCodeSlashIdentity, bool) {
	resolvedType := targetType
	if resolvedType == "" {
		resolvedType = "skill"
	}
	name, canonicalRawName := claudeCodeSlashCommandAssetName(resolvedType, rawName)
	if name == "" {
		return claudeCodeSlashIdentity{}, false
	}
	selector := strings.TrimSpace(rawName)
	selector = strings.TrimPrefix(selector, "/")
	return claudeCodeSlashIdentity{
		targetType: resolvedType,
		name:       name,
		rawName:    canonicalRawName,
		toolName:   strings.TrimSpace(rawName),
		selector:   selector,
	}, true
}

// claudeCodeSlashCommandAssetName returns the asset identifier used for
// runtime-disable and asset-policy lookup plus the original command name when
// canonicalization changed it. Claude Code identifies plugin commands as
// "plugin-id:command-id", while plugin policies are keyed by the bare plugin id.
// Skill slash-command names retain their existing semantics.
func claudeCodeSlashCommandAssetName(targetType, commandName string) (string, string) {
	rawName := strings.TrimSpace(commandName)
	if rawName == "" {
		return "", ""
	}
	name := strings.TrimPrefix(rawName, "/")
	if !strings.EqualFold(strings.TrimSpace(targetType), "plugin") {
		if !validNativeSkillSelectionName(name) {
			return "", ""
		}
		if name != rawName {
			return name, rawName
		}
		return name, ""
	}
	pluginID, commandID, namespaced := strings.Cut(name, ":")
	if namespaced {
		if pluginID != strings.TrimSpace(pluginID) || commandID != strings.TrimSpace(commandID) {
			return "", ""
		}
		if !validNativeSkillSelectionName(pluginID) || !validNativeSkillSelectionName(commandID) {
			return "", ""
		}
		return pluginID, rawName
	}
	if !validNativeSkillSelectionName(name) {
		return "", ""
	}
	if name != rawName {
		return name, rawName
	}
	return name, ""
}

func mcpPromptServerName(commandSource, commandName string) string {
	for _, value := range []string{commandSource, commandName} {
		if server := mcpServerNameFromPromptField(value); server != "" {
			return server
		}
	}
	return ""
}

// mcpServerNameFromPromptField extracts an MCP server name from one of
// the prompt-expansion fields ("command_source"/"command_name") emitted
// by Claude Code for /mcp prompt invocations. Recognized shapes:
//   - "mcp:<server>:<prompt>"
//   - "mcp__<server>__<prompt>"
//   - "mcp/<server>/<prompt>"
//   - "<server>__<prompt>" (when the connector already stripped the prefix)
//   - "<server>"            (bare server name)
//
// The bare-name case is intentional: Claude Code's CommandSource
// frequently arrives as just the server identifier (e.g. "github"). To
// avoid false matches on the literal placeholder "mcp"/"mcp_prompt"/
// "prompt", we filter those out before falling through.
//
// Repeated "mcp" prefixes are stripped iteratively rather than once so
// that pathological inputs like "mcp__mcp__server" do not collapse to
// "mcp" (which would then be filtered) — they collapse to "server".
func mcpServerNameFromPromptField(value string) string {
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	if value == "" {
		return ""
	}
	// Strip any number of "mcp:" / "mcp__" / "mcp/" prefixes, in any
	// order. Loops because chained prefixes ("mcp:mcp__foo") otherwise
	// only get one prefix removed. Bound the loop iterations as a
	// belt-and-braces guard against pathological inputs.
	for i := 0; i < 8; i++ {
		stripped := false
		lower := strings.ToLower(value)
		for _, prefix := range []string{"mcp:", "mcp__", "mcp/"} {
			if strings.HasPrefix(lower, prefix) {
				value = value[len(prefix):]
				stripped = true
				break
			}
		}
		if !stripped {
			break
		}
	}
	if value == "" {
		return ""
	}
	for _, sep := range []string{"__", ":", "/", "."} {
		if idx := strings.Index(value, sep); idx > 0 {
			candidate := strings.TrimSpace(value[:idx])
			if isMCPPromptPlaceholder(candidate) {
				return ""
			}
			return candidate
		}
	}
	value = strings.TrimSpace(value)
	if isMCPPromptPlaceholder(value) {
		return ""
	}
	return value
}

func isMCPPromptPlaceholder(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "mcp", "mcp_prompt", "prompt":
		return true
	default:
		return false
	}
}

func skillProbeFromFields(toolName string, toolInput, payload map[string]interface{}) skillRuntimeProbe {
	toolName = strings.TrimSpace(toolName)
	if name, sourcePath, rawName := assetfacts.SkillSelection(payload); name != "" {
		return skillRuntimeProbe{
			SkillName:  name,
			RawName:    rawName,
			ToolName:   toolName,
			SourcePath: sourcePath,
			Surface:    "hook",
			Matched:    true,
		}
	}
	if name, sourcePath, rawName := assetfacts.SkillSelection(toolInput); name != "" {
		return skillRuntimeProbe{
			SkillName:  name,
			RawName:    rawName,
			ToolName:   toolName,
			SourcePath: sourcePath,
			Surface:    "hook",
			Matched:    true,
		}
	}
	if name := skillFromToolName(toolName); name != "" {
		return skillRuntimeProbe{
			SkillName: name,
			ToolName:  toolName,
			Surface:   "hook",
			Matched:   true,
		}
	}
	return skillRuntimeProbe{ToolName: toolName}
}

// nativeSkillLoaderTools are the skill-loading tools of hook connectors
// whose input names the skill under a plain "name" key, which
// skillProbeFromFields does not read (an ordinary tool's "name" argument is
// not a skill). Measured shapes: Amp skill {"name": <skill>} and Hermes
// skill_view {"name": "<category>:<skill>"} (live audit, GAP-1234); OpenCode
// skill {"name": <skill>} (its tool/skill.ts); Kiro CLI v3 disclose_context
// {"name": <skill>} (live capture, kiro-cli 2.26.1 --v3: it loads the skill
// with no file read, so the folder fallback saw nothing, GAP-1249).
var nativeSkillLoaderTools = map[string]string{
	"amp":      "skill",
	"hermes":   "skill_view",
	"kiro":     "disclose_context",
	"opencode": "skill",
}

// nativeSkillToolProbe recognizes a call of the connector's own skill
// loader. A qualified "<plugin or category>:<skill>" name is matched as the
// skill and keeps the qualified form as a declared name, so a denied rule
// written either way refuses it. An Amp skill on asset_policy.skill.denied
// was loaded and followed because the probe saw no skill (GAP-1234).
func nativeSkillToolProbe(connector, toolName string, toolInput map[string]interface{}) skillRuntimeProbe {
	loader, ok := nativeSkillLoaderTools[strings.ToLower(strings.TrimSpace(connector))]
	if !ok || !strings.EqualFold(strings.TrimSpace(toolName), loader) {
		return skillRuntimeProbe{}
	}
	raw := firstMapString(toolInput, "name")
	bare := raw
	if i := strings.LastIndex(bare, ":"); i >= 0 {
		bare = bare[i+1:]
	}
	name := assetfacts.SkillRuntimeName(bare)
	if name == "" {
		return skillRuntimeProbe{}
	}
	probe := skillRuntimeProbe{
		TargetType: "skill",
		SkillName:  name,
		ToolName:   strings.TrimSpace(toolName),
		RawName:    assetfacts.SkillRawNameIfNormalized(raw, name),
		Surface:    "hook",
		Matched:    true,
	}
	if qualified := assetfacts.SkillRuntimeName(raw); qualified != "" && !config.SameAssetName(qualified, name) {
		probe.DeclaredNames = []string{qualified}
	}
	return probe
}

// codexSkillProbeFromPrompt recognizes Codex's native fresh-session skill
// selection shape: UserPromptSubmit carries the literal prompt and a selected
// skill is the first token, written as "$<skill-name>". Codex does not emit a
// Skill tool call or a synthetic skill_name field for this path.
func codexSkillProbeFromPrompt(prompt string) skillRuntimeProbe {
	name := hookpaths.CodexSelectedSkillName(prompt)
	if name == "" {
		return skillRuntimeProbe{}
	}
	raw := "$" + name
	return skillRuntimeProbe{
		TargetType: "skill",
		SkillName:  name,
		ToolName:   raw,
		RawName:    raw,
		Surface:    "prompt_selection",
		Matched:    true,
	}
}

func validNativeSkillSelectionName(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	for index, r := range name {
		alphaNumeric := r >= 'a' && r <= 'z' ||
			r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9'
		if alphaNumeric {
			continue
		}
		if index > 0 && (r == '-' || r == '_' || r == '.') {
			continue
		}
		return false
	}
	return true
}

func skillFromToolName(toolName string) string {
	toolName = strings.TrimSpace(toolName)
	if strings.HasPrefix(toolName, "skill__") {
		parts := strings.Split(toolName, "__")
		if len(parts) >= 3 && strings.TrimSpace(parts[1]) != "" {
			return assetfacts.SkillRuntimeName(parts[1])
		}
	}
	if strings.HasPrefix(toolName, "skill:") {
		parts := strings.SplitN(toolName, ":", 3)
		if len(parts) >= 2 && strings.TrimSpace(parts[1]) != "" {
			return assetfacts.SkillRuntimeName(parts[1])
		}
	}
	return ""
}

func serverFromMCPToolName(toolName string) string {
	toolName = strings.TrimSpace(toolName)
	if strings.HasPrefix(toolName, "mcp__") {
		parts := strings.Split(toolName, "__")
		if len(parts) >= 3 && strings.TrimSpace(parts[1]) != "" {
			return strings.TrimSpace(parts[1])
		}
	}
	if strings.HasPrefix(toolName, "mcp:") {
		parts := strings.Split(toolName, ":")
		if len(parts) >= 3 && strings.TrimSpace(parts[1]) != "" {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func commandFromToolInput(input map[string]interface{}) string {
	for _, key := range []string{"command", "cmd", "input", "script"} {
		if s := firstMapString(input, key); s != "" {
			return s
		}
	}
	return ""
}

func isTerminalTool(toolName string) bool {
	switch strings.ToLower(strings.TrimSpace(toolName)) {
	case "bash", "shell", "terminal", "run_command", "exec":
		return true
	default:
		return false
	}
}

func terminalMCPBypass(command string) bool {
	lower := strings.ToLower(strings.TrimSpace(command))
	return strings.HasPrefix(lower, "mcp add ") ||
		strings.Contains(lower, " mcp add ") ||
		strings.Contains(lower, "claude mcp add") ||
		strings.Contains(lower, "codex mcp add") ||
		strings.Contains(lower, ".mcp.json") ||
		strings.Contains(lower, "/.claude/settings.json") ||
		strings.Contains(lower, "~/.claude/settings.json") ||
		strings.Contains(lower, "/.codex/config.toml") ||
		strings.Contains(lower, "~/.codex/config.toml")
}

func looksLikeMCPServerCommand(cmd string, args []string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(cmd)))
	if strings.Contains(base, "mcp-server") {
		return true
	}
	for _, arg := range args {
		lower := strings.ToLower(arg)
		if strings.Contains(lower, "@modelcontextprotocol/server-") ||
			strings.Contains(lower, "mcp-server") {
			return true
		}
	}
	return false
}

func serverNameFromTerminalCommand(command string) string {
	fields := strings.Fields(command)
	for i := 0; i+2 < len(fields); i++ {
		if strings.EqualFold(fields[i], "mcp") && strings.EqualFold(fields[i+1], "add") {
			return firstNonFlag(fields[i+2:])
		}
		if (strings.EqualFold(fields[i], "claude") || strings.EqualFold(fields[i], "codex")) &&
			i+3 < len(fields) && strings.EqualFold(fields[i+1], "mcp") && strings.EqualFold(fields[i+2], "add") {
			return firstNonFlag(fields[i+3:])
		}
	}
	return ""
}

func firstNonFlag(values []string) string {
	for _, v := range values {
		if strings.HasPrefix(v, "-") {
			continue
		}
		return strings.Trim(v, `"'`)
	}
	return ""
}

func splitCommandLine(command string) (string, []string) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], fields[1:]
}

// payloadString is a thin alias retained for symmetry with the older
// single-key helper used by codex/claude hooks. Prefer firstMapString
// for new call sites.
func payloadString(payload map[string]interface{}, key string) string {
	return firstMapString(payload, key)
}

// firstMapString returns the first non-empty string-valued field for
// the given keys. It deliberately rejects non-string values rather than
// stringifying them: agent-controlled hook payloads can carry numbers,
// booleans, nested maps, etc., and silently coercing those into
// "asset names" via fmt.Sprint widens the registry-match surface (e.g.
// a boolean false becoming the literal string "false") and produces
// nonsense names like "map[a:b]" that bypass intent. Callers that need
// to handle structured values should branch on type explicitly.
func firstMapString(values map[string]interface{}, keys ...string) string {
	if values == nil {
		return ""
	}
	for _, key := range keys {
		v, ok := values[key]
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		if t := strings.TrimSpace(s); t != "" {
			return t
		}
	}
	return ""
}

// mergeAssetDecision folds a single asset-policy decision into the
// running hook verdict. Contract:
//
//   - matched=false (or non-blocking decision) is a no-op — caller's
//     existing verdict is returned unchanged with wouldBlock=false.
//   - matched=true with a blocking decision always sets rawAction=block
//     and severity>=HIGH, regardless of whether enforcement runs.
//   - When the current hook event is enforceable (UserPromptSubmit,
//     UserPromptExpansion, PreToolUse, PermissionRequest), action=block and
//     the returned wouldBlock=false (because the action IS the block —
//     "would" only makes sense in observe mode / non-enforceable events).
//   - Otherwise the merge stays in advisory mode: action stays "allow"
//     (or "block" if a prior asset already blocked), and wouldBlock=true
//     so callers know the request would have been blocked under
//     enforceable events.
//
// Callers must filter to blocking-only decisions before invoking this
// (evaluateRuntime{MCP,Skill}AssetPolicy already does); a non-blocking
// decision reaching this function is treated as a no-op rather than an
// error so the hook flow degrades gracefully.
func mergeAssetDecision(
	decision config.AssetPolicyDecision,
	matched bool,
	targetType string,
	event string,
	action, rawAction, severity, reason string,
	findings []string,
) (string, string, string, string, []string, bool) {
	if !matched || decision.RawAction != "block" {
		return action, rawAction, severity, reason, findings, false
	}
	alreadyBlocking := action == "block"
	rawAction = "block"
	if severity == "" || severity == "NONE" {
		severity = "HIGH"
	}
	if decision.Reason != "" && !alreadyBlocking {
		reason = assetPolicyResponseReason(decision)
	}
	finding := "ASSET-POLICY-" + strings.ToUpper(strings.TrimSpace(targetType))
	if finding == "ASSET-POLICY-" {
		finding = "ASSET-POLICY-ASSET"
	}
	findings = append(findings, finding)
	canBlock := decision.Action == "block" && runtimeAssetCanEnforce(event)
	if canBlock {
		if decision.Reason != "" {
			reason = assetPolicyResponseReason(decision)
		}
		action = "block"
		// wouldBlock=false: the block is happening for real, so
		// "would-have-blocked" is no longer the relevant signal.
		return action, rawAction, severity, reason, findings, false
	}
	if !alreadyBlocking {
		action = "allow"
	}
	// wouldBlock=true: matched + raw=block + non-enforceable event ⇒
	// downstream observability should record that this would have been
	// blocked under enforcement. Operators rely on this to size the
	// false-positive rate before flipping a connector to action mode.
	return action, rawAction, severity, reason, findings, true
}

// mapAssetBlockForProfile checks whether the connector can veto an asset
// decision that mergeAssetDecision has already made blocking. The guardrail
// mode governs guardrail findings, not an action-mode asset-policy decision.
// Secure Client retains its existing guardrail-mode mapping.
func mapAssetBlockForProfile(guardrailMode, event string, caps connector.HookCapability, profile connector.HookProfile, payload map[string]interface{}, secureClient bool) (string, bool) {
	mode := config.AssetPolicyModeAction
	if secureClient {
		mode = guardrailMode
	}
	return mapHookActionForProfile("block", mode, event, caps, profile, payload)
}

// assetPolicyResponseReason renders a structured, machine-parseable
// reason string for downstream consumers (Claude Code / Codex hook
// reason field, gateway logs, OTel attributes).
//
// Layout choices:
//
//   - All values are emitted as plain key=value with no quoting. The
//     gateway's redaction layer (internal/redaction.ForSinkReason) is
//     the canonical place for value-safety: it walks key=value tokens
//     and redacts any value that isn't in its rule-id-style allow-list.
//     If we wrapped values in quotes here, the value would no longer
//     match the redactor's safe-value pattern and every routine
//     allowlist-style asset_name would be redacted into
//     "<redacted len=N sha=...>" — making operator audit useless.
//
//   - The structured fields (reason_code, source, asset_type,
//     asset_name, connector, registry_status, registry_configured,
//     surface) are sufficient for SIEM correlation, so we deliberately
//     do NOT also append the human-readable decision.Reason: it would
//     duplicate the same information, contains free-form spaces, and
//     would always be redacted away anyway.
//
//   - Empty fields are skipped to keep reasons short, except
//     registry_configured which is always emitted because telemetry
//     filtering on its boolean value (`registry_configured=false`) is a
//     strong signal that an operator forgot to populate the registry.
//
//   - Asset names with characters that fall outside the redactor's
//     safe charset are passed through as-is and the redactor will
//     scrub them — this is the desired behavior because such names are
//     necessarily attacker-controlled.
func assetPolicyResponseReason(decision config.AssetPolicyDecision) string {
	parts := []string{"ASSET-POLICY"}
	if decision.Source != "" {
		parts = append(parts, "reason_code="+assetPolicyReasonCode(decision.Source))
		parts = append(parts, "source="+decision.Source)
	}
	if decision.TargetType != "" {
		parts = append(parts, "asset_type="+decision.TargetType)
	}
	if decision.TargetName != "" {
		parts = append(parts, "asset_name="+decision.TargetName)
	}
	if decision.Connector != "" {
		parts = append(parts, "connector="+decision.Connector)
	}
	if decision.RegistryStatus != "" {
		// The decision vocabulary as is ("unregistered"), as the asset-policy
		// audit row and finding.observed record it, so one SIEM filter on
		// registry_status finds every event of the evaluation (GAP-2516).
		parts = append(parts, "registry_status="+decision.RegistryStatus)
	}
	parts = append(parts, fmt.Sprintf("registry_configured=%t", decision.RegistryConfigured))
	if decision.RuntimeSurface != "" {
		parts = append(parts, "surface="+decision.RuntimeSurface)
	}
	if (decision.Source == "mcp-admission-pending" || decision.Source == "mcp-admission-unavailable") && decision.RetryAfterSeconds > 0 {
		parts = append(parts, fmt.Sprintf("retry_after_s=%d", decision.RetryAfterSeconds))
	}
	if decision.Source == "mcp-admission-failed" && decision.ScanIssue != "" {
		parts = append(parts, "scan_issue="+decision.ScanIssue)
	}
	if decision.Source == "mcp-admission-failed" && decision.ScanNextStep != "" {
		parts = append(parts, "next_step="+decision.ScanNextStep)
	}
	return strings.Join(parts, " ")
}

func assetPolicyReasonCode(source string) string {
	switch strings.TrimSpace(source) {
	case "registry-required":
		return "not-in-approved-registry"
	case "registry-required-empty":
		// Distinct from registry-required so operators can tell
		// "you tried to use an unregistered asset" apart from
		// "the registry itself is unconfigured / fail-closed
		// guard tripped". Same family of failure, different fix.
		return "registry-required-but-empty"
	case "default-deny":
		return "default-deny"
	case "admin-deny":
		return "admin-deny"
	default:
		return source
	}
}

func runtimeAssetCanEnforce(event string) bool {
	// Claude Code / Codex use canonical PascalCase event names. Prompt
	// submission/expansion are native pre-load selection surfaces, while
	// tool and permission events are native pre-execution surfaces.
	switch event {
	case "UserPromptSubmit", "UserPromptExpansion", "PreToolUse", "PermissionRequest":
		return true
	}
	// Generic hook-only connectors (hermes, cursor, devin, copilot)
	// use varied case/spacing for the same semantic events
	// (preToolUse, pre_tool_call, beforeMCPExecution, beforeShellExecution,
	// pre_run_command, premcptooluse, ...). Reusing the canonical
	// tool-inspection set keeps the asset-policy enforcement gate
	// in lockstep with the inspect path: anything we already classify
	// as a tool-inspection event is also a valid surface to enforce
	// asset-policy blocks on.
	if isGenericToolInspectionEvent(event) {
		return true
	}
	return false
}

func coalesceRuntimeSurface(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func rawPayloadFromJSONDecoder(dec *json.Decoder) (map[string]interface{}, []byte, error) {
	var payload map[string]interface{}
	if err := dec.Decode(&payload); err != nil {
		return nil, nil, err
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	return payload, b, nil
}
