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
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
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
	probe.ServerName = a.claudeCodePluginMCPServerName(ctx, probe)
	if decision, refused := a.claudeStateUnreadableDecision(ctx, req.HookEventName, probe); refused {
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
	cfg := a.liveConfig()
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

// claudeStateUnreadableDecision refuses a Claude Code MCP tool call of an
// enrolled user whose ~/.claude.json the hook enumerator could not read or
// parse. The gateway service cannot read that file itself, so it does not
// know the user's servers and cannot admit one: a server changed while the
// file was unreadable would otherwise run unscanned (GAP-0829, fail closed).
// The refusal names the file; status names it too. Secure Client has no
// enrolled-user watcher (issue #1092).
func (a *APIServer) claudeStateUnreadableDecision(ctx context.Context, hookEvent string, probe mcpRuntimeProbe) (config.AssetPolicyDecision, bool) {
	cfg := a.liveConfig()
	if cfg == nil || cfg.SecureClientIntegration() || !probe.Matched || probe.Surface != "hook" {
		return config.AssetPolicyDecision{}, false
	}
	state, ok := claudeStateUnreadableFor(trustedActiveHome(ctx))
	if !ok {
		return config.AssetPolicyDecision{}, false
	}
	reason := fmt.Sprintf("the Claude Code MCP servers of %s are blocked: DefenseClaw could not read %s (%s), so it cannot admit them; "+
		"give SYSTEM read access to the file again or repair its JSON", state.Account(), state.Path, state.Reason)
	decision := runtimeAssetDisableBlockDecision("mcp", probe.ServerName, "claudecode", "hook", reason, "claude-state-unreadable")
	decision.RegistryStatus = "unknown"
	a.logAssetPolicyAudit(ctx, "claudecode", "mcp:"+probe.ServerName, fmt.Sprintf(
		"action=block source=%s hook=%s tool=%s connector=claudecode reason=%s", decision.Source, hookEvent, probe.ToolName, reason))
	return decision, true
}

func (a *APIServer) codexMCPAssetDecision(ctx context.Context, req codexHookRequest) (config.AssetPolicyDecision, bool) {
	// Two configured servers that share the tool segment: the call is
	// judged as each of them and refused if any one is refused.
	for _, name := range a.codexMCPServerCandidates(ctx, req) {
		probe := mcpProbeFromFields(name, req.ToolName, req.ToolInput)
		probe.WorkspaceDir = req.CWD
		if decision, blocked := a.evaluateRuntimeMCPAssetPolicy(ctx, "codex", req.HookEventName, probe); blocked {
			return decision, true
		}
	}
	probe := mcpProbeFromFields(a.codexMCPServerName(ctx, req), req.ToolName, req.ToolInput)
	probe.WorkspaceDir = req.CWD
	return a.evaluateRuntimeMCPAssetPolicy(ctx, "codex", req.HookEventName, probe)
}

// codexMCPServerCandidates are the configured Codex servers a tool call
// could belong to when the hook names no server and distinct names share
// its tool segment (Codex normalizes punctuation); nil otherwise.
func (a *APIServer) codexMCPServerCandidates(ctx context.Context, req codexHookRequest) []string {
	if strings.TrimSpace(firstNonEmpty(req.MCPServerName, payloadString(req.Payload, "mcp_server_name"))) != "" {
		return nil
	}
	cfg := a.liveConfig()
	if cfg == nil || cfg.SecureClientIntegration() {
		return nil
	}
	toolServer := serverFromMCPToolName(req.ToolName)
	if toolServer == "" {
		return nil
	}
	home, serviceAccount := callerHomeForAssets(ctx)
	if !serviceAccount {
		return cfg.CodexMCPToolServerCandidates(req.CWD, toolServer)
	}
	if home == "" {
		return nil
	}
	return config.CodexMCPToolServerCandidatesUnderHome(home, req.CWD, toolServer)
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
	cfg := a.liveConfig()
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
	probe := skillProbeFromFields(req.ToolName, req.ToolInput, req.Payload)
	if !probe.Matched {
		return a.skillFolderAccessDecision(ctx, "claudecode", req.HookEventName, req.CWD, req.ToolName, req.ToolInput)
	}
	probe.DeclaredNames = a.declaredSkillNames(ctx, "claudecode", req.CWD, probe)
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

	identities := make([]claudeCodeSlashIdentity, 0, 2)
	if commandOK {
		identities = append(identities, commandIdentity)
	}
	if promptOK && (!commandOK || !commandIdentity.sameAsset(promptIdentity)) {
		identities = append(identities, promptIdentity)
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
	probe := skillProbeFromFields(req.ToolName, req.ToolInput, req.Payload)
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
	probe.DeclaredNames = a.declaredSkillNames(ctx, "codex", req.CWD, probe)
	probe.SourcePaths = a.skillSourcePaths(ctx, "codex", req.CWD, probe)
	return a.evaluateNativeRuntimeSkillSelection(
		ctx, "codex", req.SessionID, req.HookEventName,
		runtimeProvenanceCodexPromptSelection, probe,
	)
}

func (a *APIServer) evaluateRuntimeMCPAssetPolicy(ctx context.Context, connector, hookEvent string, probe mcpRuntimeProbe) (config.AssetPolicyDecision, bool) {
	cfg := a.liveConfig()
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
	probe = a.resolveMCPProbeEndpoint(ctx, cfg, connector, probe)
	decision, unproven := unprovenMCPDefinitionDecision(ctx, cfg, connector, probe)
	if !unproven {
		input := config.AssetPolicyInput{
			TargetType:     "mcp",
			Name:           probe.ServerName,
			Connector:      connector,
			URL:            probe.URL,
			Command:        probe.Command,
			Args:           probe.Args,
			Transport:      probe.Transport,
			RuntimeSurface: coalesceRuntimeSurface(probe.Surface, "hook"),
		}
		if !runtimeAssetPolicyApplies(cfg, runtimeDetection, probe.Surface, input) {
			return config.AssetPolicyDecision{}, false
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
		!(mcpAssetMode == config.AssetPolicyModeAction && mcpDefaultDeny) {
		decision.Action = "allow"
		decision.Mode = config.AssetPolicyModeObserve
		decision.WouldBlock = true
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
func (a *APIServer) resolveMCPProbeEndpoint(ctx context.Context, cfg *config.Config, connector string, probe mcpRuntimeProbe) mcpRuntimeProbe {
	if cfg == nil {
		return probe
	}
	secureClient := cfg.SecureClientIntegration()
	if !cfg.AssetPolicy.Enabled && (secureClient || !mcpListsPinEndpoint(cfg.AssetPolicy.MCP)) {
		return probe
	}
	if probe.Surface != "hook" || probe.URL != "" || probe.Command != "" || probe.ServerName == "" {
		return probe
	}
	var entry config.MCPServerEntry
	var ok bool
	if secureClient {
		entry, ok = cfg.LookupMCPServerForConnector(connector, probe.WorkspaceDir, probe.ServerName)
	} else {
		entry, ok = a.lookupCallerMCPServer(ctx, cfg, connector, probe.WorkspaceDir, probe.ServerName)
	}
	if !ok {
		return probe
	}
	if !secureClient && strings.TrimSpace(entry.Name) != "" {
		// The configured name, not the form the agent's tool name carries
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
	if !rulesPinEndpoint(cfg.AssetPolicy.MCP.Denied) {
		gated := cfg.AssetPolicy.Enabled && (policy.RegistryRequired || strings.EqualFold(strings.TrimSpace(policy.Default), "deny"))
		if !gated || !(rulesPinEndpoint(cfg.AssetPolicy.MCP.Allowed) || rulesPinEndpoint(policy.Registry)) {
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

// mcpListsPinEndpoint reports whether a denied or allowed MCP rule matches
// on how a server starts (url, command, args_prefix, transport), which a
// name-only probe needs resolving for.
func mcpListsPinEndpoint(p config.AssetTypePolicy) bool {
	return rulesPinEndpoint(p.Denied) || rulesPinEndpoint(p.Allowed)
}

func (a *APIServer) evaluateRuntimeSkillAssetPolicy(ctx context.Context, connector, hookEvent string, probe skillRuntimeProbe) (config.AssetPolicyDecision, bool) {
	decision, matched := a.runtimeSkillAssetPolicyDecision(connector, probe)
	if matched {
		a.emitRuntimeSkillAssetPolicyDecision(ctx, decision, connector, hookEvent, probe)
	}
	return decision, matched
}

func (a *APIServer) runtimeSkillAssetPolicyDecision(
	connector string, probe skillRuntimeProbe,
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
	if decision, disabled := a.runtimeAssetDisableDecision(targetType, probe.SkillName, connector, runtimeSurface); disabled {
		return decision, true
	}
	if probe.RuntimeDisableOnly {
		return config.AssetPolicyDecision{}, false
	}
	cfg := a.liveConfig()
	if cfg == nil {
		return config.AssetPolicyDecision{}, false
	}
	if targetType == "plugin" && !cfg.SecureClientIntegration() {
		if decision, blocked := a.pluginJournalBlockDecision(probe.SkillName, connector, runtimeSurface); blocked {
			return decision, true
		}
		probe.DeclaredNames = append(probe.DeclaredNames, deniedPluginMarketplaceNames(cfg, probe.SkillName)...)
	}
	paths := []string{probe.SourcePath}
	if strings.TrimSpace(probe.SourcePath) == "" && len(probe.SourcePaths) > 0 {
		paths = probe.SourcePaths
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
	decision, matched := a.runtimeSkillAssetPolicyDecision(connector, probe)
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

func (a *APIServer) runtimeAssetDisableDecision(targetType, name, connector, runtimeSurface string) (config.AssetPolicyDecision, bool) {
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
	return runtimeAssetDisableBlockDecision(targetType, name, connector, runtimeSurface,
		fmt.Sprintf("%s %q is runtime-disabled for connector %q", targetType, name, connector),
		"runtime-disable"), true
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
	cfg := a.liveConfig()
	if cfg == nil || cfg.SecureClientIntegration() {
		return config.AssetPolicyDecision{}, false
	}
	for _, plugin := range claudeCodeToolPlugins(req) {
		probe := skillRuntimeProbe{
			TargetType: "plugin", SkillName: plugin, ToolName: req.ToolName, Surface: "hook", Matched: true,
		}
		if decision, matched := a.evaluateRuntimeSkillAssetPolicy(ctx, "claudecode", req.HookEventName, probe); matched {
			return decision, true
		}
	}
	return config.AssetPolicyDecision{}, false
}

// claudeCodeToolPlugins lists the plugins a Claude Code tool call may run
// part of. Claude Code names a plugin's MCP server plugin_<plugin>_<server>,
// and both names may hold "_", so every split is a candidate.
func claudeCodeToolPlugins(req claudeCodeHookRequest) []string {
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
		for i := 1; i < len(rest)-1; i++ {
			if rest[i] == '_' {
				add(rest[:i])
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
	return out
}

// pluginJournalBlockDecision refuses a plugin whose journal entry, under
// its name or plugin@marketplace as the watcher records a Claude Code
// marketplace plugin, holds an install block or a runtime disable. The hook
// sees the plugin name only, and a blocked plugin's files can stay where
// the agent runs them, so its block is enforced here too (GAP-1189).
func (a *APIServer) pluginJournalBlockDecision(name, connector, runtimeSurface string) (config.AssetPolicyDecision, bool) {
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
		if entry.Actions.Install != "block" && entry.Actions.Runtime != "disable" {
			continue
		}
		reason := fmt.Sprintf("plugin %q is blocked by install admission", entry.TargetName)
		if detail := strings.TrimSpace(entry.Reason); detail != "" {
			reason += ": " + detail
		}
		return runtimeAssetDisableBlockDecision("plugin", name, connector, runtimeSurface, reason, "install-block"), true
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
	name := rawName
	if strings.HasPrefix(name, "/") {
		name = strings.TrimPrefix(name, "/")
	}
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
	if name, sourcePath, rawName := skillFromMap(payload); name != "" {
		return skillRuntimeProbe{
			SkillName:  name,
			RawName:    rawName,
			ToolName:   toolName,
			SourcePath: sourcePath,
			Surface:    "hook",
			Matched:    true,
		}
	}
	if name, sourcePath, rawName := skillFromMap(toolInput); name != "" {
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

// codexSkillProbeFromPrompt recognizes Codex's native fresh-session skill
// selection shape: UserPromptSubmit carries the literal prompt and a selected
// skill is the first token, written as "$<skill-name>". Codex does not emit a
// Skill tool call or a synthetic skill_name field for this path.
func codexSkillProbeFromPrompt(prompt string) skillRuntimeProbe {
	fields := strings.Fields(strings.TrimSpace(prompt))
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "$") {
		return skillRuntimeProbe{}
	}
	raw := fields[0]
	name := strings.TrimPrefix(raw, "$")
	if !validNativeSkillSelectionName(name) {
		return skillRuntimeProbe{}
	}
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

// skillFromMap returns (normalizedName, sourcePath, rawName).
// rawName is the original input string when normalization stripped a
// path (e.g. "/path/to/foo/SKILL.md" -> "foo"); empty otherwise.
// Callers propagate this so audit/OTel can show the agent's literal
// input alongside the registry-matching name.
func skillFromMap(values map[string]interface{}) (string, string, string) {
	if values == nil {
		return "", "", ""
	}
	sourcePath := firstMapString(values, "skill_path", "skillPath", "source_path", "sourcePath")
	rawName := firstMapString(values, "skill_name", "skillName", "skill_key", "skillKey", "skill_id", "skillId")
	if rawName != "" {
		normalized := normalizeSkillRuntimeName(rawName)
		return normalized, sourcePath, skillRawNameIfNormalized(rawName, normalized)
	}
	for _, key := range []string{"skill", "skill_info", "skillInfo", "source_skill", "sourceSkill"} {
		if v, ok := values[key]; ok {
			if nestedName, nestedPath, nestedRaw := skillFromValue(v); nestedName != "" {
				if sourcePath == "" {
					sourcePath = nestedPath
				}
				return nestedName, sourcePath, nestedRaw
			}
		}
	}
	if sourcePath != "" {
		normalized := normalizeSkillRuntimeName(sourcePath)
		return normalized, sourcePath, skillRawNameIfNormalized(sourcePath, normalized)
	}
	return "", "", ""
}

func skillFromValue(value interface{}) (string, string, string) {
	switch v := value.(type) {
	case string:
		normalized := normalizeSkillRuntimeName(v)
		return normalized, pathIfLooksLikePath(v), skillRawNameIfNormalized(v, normalized)
	case map[string]interface{}:
		sourcePath := firstMapString(v, "path", "source_path", "sourcePath", "skill_path", "skillPath")
		raw := firstMapString(v, "name", "key", "id", "skill_name", "skillName", "skill_key", "skillKey", "skill_id", "skillId")
		if raw == "" && sourcePath != "" {
			raw = sourcePath
		}
		normalized := normalizeSkillRuntimeName(raw)
		return normalized, sourcePath, skillRawNameIfNormalized(raw, normalized)
	default:
		return "", "", ""
	}
}

// skillRawNameIfNormalized returns raw only when normalization changed
// the input (path-stripping, quote-stripping, "@" prefix removal). The
// caller uses a non-empty rawName to flag "agent supplied a value that
// did not match the registry verbatim — audit may want to see the raw
// form to detect allowlist-bypass attempts via crafted skill paths".
func skillRawNameIfNormalized(raw, normalized string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	if raw == normalized {
		return ""
	}
	return raw
}

func skillFromToolName(toolName string) string {
	toolName = strings.TrimSpace(toolName)
	if strings.HasPrefix(toolName, "skill__") {
		parts := strings.Split(toolName, "__")
		if len(parts) >= 3 && strings.TrimSpace(parts[1]) != "" {
			return normalizeSkillRuntimeName(parts[1])
		}
	}
	if strings.HasPrefix(toolName, "skill:") {
		parts := strings.SplitN(toolName, ":", 3)
		if len(parts) >= 2 && strings.TrimSpace(parts[1]) != "" {
			return normalizeSkillRuntimeName(parts[1])
		}
	}
	return ""
}

func normalizeSkillRuntimeName(value string) string {
	name := strings.Trim(strings.TrimSpace(value), `"'`)
	if name == "" {
		return ""
	}
	if strings.ContainsAny(name, `/\`) {
		path := filepath.Clean(name)
		if strings.EqualFold(filepath.Base(path), "SKILL.md") {
			path = filepath.Dir(path)
		}
		name = filepath.Base(path)
	}
	name = strings.TrimPrefix(name, "@")
	return strings.TrimSpace(name)
}

func pathIfLooksLikePath(value string) string {
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	if strings.ContainsAny(value, `/\`) {
		return value
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
	// Generic hook-only connectors (hermes, cursor, devin,
	// copilot, openhands) use varied case/spacing for the same semantic events
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
