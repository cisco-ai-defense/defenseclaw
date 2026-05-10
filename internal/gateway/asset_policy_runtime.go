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
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

type mcpRuntimeProbe struct {
	ServerName string
	ToolName   string
	Command    string
	Args       []string
	Surface    string
	Matched    bool
}

type skillRuntimeProbe struct {
	SkillName string
	ToolName  string
	// SourcePath is the raw, agent-supplied skill path (when present).
	// It is preserved verbatim — including any path traversal segments —
	// so audit telemetry can show the difference between "trusted-skill"
	// and "/tmp/attacker/trusted-skill/SKILL.md". Asset policy matches
	// on SkillName by default; operators wanting to constrain by path
	// must use AssetPolicyRule.SourcePathContains.
	SourcePath string
	// RawName preserves the unnormalized input the SkillName was
	// derived from when path-stripping occurred (e.g. SkillName came
	// from filepath.Base on a "/path/to/<name>/SKILL.md"). Empty when
	// SkillName == raw input.
	RawName string
	Surface string
	Matched bool
}

type runtimeAssetDecision struct {
	targetType string
	decision   config.AssetPolicyDecision
}

func (a *APIServer) claudeCodeMCPAssetDecision(ctx context.Context, req claudeCodeHookRequest) (config.AssetPolicyDecision, bool) {
	probe := mcpProbeFromFields(req.MCPServerName, req.ToolName, req.ToolInput)
	return a.evaluateRuntimeMCPAssetPolicy(ctx, "claudecode", req.HookEventName, probe)
}

func (a *APIServer) codexMCPAssetDecision(ctx context.Context, req codexHookRequest) (config.AssetPolicyDecision, bool) {
	probe := mcpProbeFromFields(payloadString(req.Payload, "mcp_server_name"), req.ToolName, req.ToolInput)
	return a.evaluateRuntimeMCPAssetPolicy(ctx, "codex", req.HookEventName, probe)
}

func (a *APIServer) claudeCodeSkillAssetDecision(ctx context.Context, req claudeCodeHookRequest) (config.AssetPolicyDecision, bool) {
	probe := skillProbeFromFields(req.ToolName, req.ToolInput, req.Payload)
	return a.evaluateRuntimeSkillAssetPolicy(ctx, "claudecode", req.HookEventName, probe)
}

func (a *APIServer) claudeCodePromptExpansionAssetDecisions(ctx context.Context, req claudeCodeHookRequest) []runtimeAssetDecision {
	switch strings.ToLower(strings.TrimSpace(req.ExpansionType)) {
	case "slash_command":
		return a.claudeCodeSlashCommandAssetDecisions(ctx, req)
	case "mcp_prompt":
		return a.claudeCodeMCPPromptAssetDecisions(ctx, req)
	default:
		return nil
	}
}

func (a *APIServer) claudeCodeSlashCommandAssetDecisions(ctx context.Context, req claudeCodeHookRequest) []runtimeAssetDecision {
	if !slashCommandLooksSkill(req.CommandSource) {
		return nil
	}
	name := normalizeSkillRuntimeName(req.CommandName)
	if name == "" {
		return nil
	}
	probe := skillRuntimeProbe{
		SkillName:  name,
		ToolName:   strings.TrimSpace(req.CommandName),
		SourcePath: strings.TrimSpace(req.CommandSource),
		Surface:    "prompt_expansion",
		Matched:    true,
	}
	if decision, matched := a.evaluateRuntimeSkillAssetPolicy(ctx, "claudecode", req.HookEventName, probe); matched {
		return []runtimeAssetDecision{{targetType: "skill", decision: decision}}
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
	return a.evaluateRuntimeSkillAssetPolicy(ctx, "codex", req.HookEventName, probe)
}

func (a *APIServer) evaluateRuntimeMCPAssetPolicy(ctx context.Context, connector, hookEvent string, probe mcpRuntimeProbe) (config.AssetPolicyDecision, bool) {
	if a.scannerCfg == nil || !probe.Matched {
		return config.AssetPolicyDecision{}, false
	}
	runtimeDetection, _ := a.scannerCfg.AssetRuntimeDetectionFor("mcp")
	if !runtimeDetection.Enabled {
		return config.AssetPolicyDecision{}, false
	}
	if probe.Surface == "terminal" && !runtimeDetection.TerminalCommands {
		return config.AssetPolicyDecision{}, false
	}
	decision := a.scannerCfg.EvaluateAssetPolicy(config.AssetPolicyInput{
		TargetType:     "mcp",
		Name:           probe.ServerName,
		Connector:      connector,
		Command:        probe.Command,
		Args:           probe.Args,
		RuntimeSurface: coalesceRuntimeSurface(probe.Surface, "hook"),
	})
	// Avarice F-1510: when MCP.Default is "deny" and the asset
	// policy is itself in action mode, an unknown terminal MCP
	// command MUST NOT be silently downgraded to allow just
	// because the secondary `runtime_detection.unknown_terminal_mcp`
	// knob defaults to observe. Operators who explicitly set
	// MCP.Default=deny expect default-deny semantics. We only
	// honor the downgrade for runtime detections that are NOT
	// already covered by the operator's default-deny posture
	// (i.e. when the asset policy is in observe mode OR
	// MCP.Default isn't deny).
	mcpAssetMode, mcpDefaultDeny := assetMCPModeFor(a, decision)
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
	if a.otel != nil {
		a.otel.EmitPolicyDecision("asset-policy", decision.Action, decision.TargetName, "mcp", decision.Reason, map[string]string{
			"source":              decision.Source,
			"registry_status":     decision.RegistryStatus,
			"registry_configured": fmt.Sprintf("%t", decision.RegistryConfigured),
			"runtime_surface":     coalesceRuntimeSurface(probe.Surface, "hook"),
			"hook_event_name":     hookEvent,
			"tool_name":           probe.ToolName,
			"mcp_server_name":     probe.ServerName,
			"would_block":         fmt.Sprintf("%t", decision.WouldBlock),
		})
	}
	if a.logger != nil {
		a.logAssetPolicyAudit(ctx, "mcp:"+decision.TargetName,
			fmt.Sprintf("action=%s source=%s registry_status=%s registry_configured=%v surface=%s hook=%s tool=%s connector=%s would_block=%v reason=%s",
				decision.Action, decision.Source, decision.RegistryStatus, decision.RegistryConfigured, probe.Surface, hookEvent, probe.ToolName, connector, decision.WouldBlock, decision.Reason))
	}
	a.dispatchAssetPolicyNotification(decision, "mcp", connector, hookEvent)
	return decision, true
}

func (a *APIServer) evaluateRuntimeSkillAssetPolicy(ctx context.Context, connector, hookEvent string, probe skillRuntimeProbe) (config.AssetPolicyDecision, bool) {
	if a.scannerCfg == nil || !probe.Matched {
		return config.AssetPolicyDecision{}, false
	}
	runtimeDetection, _ := a.scannerCfg.AssetRuntimeDetectionFor("skill")
	if !runtimeDetection.Enabled {
		return config.AssetPolicyDecision{}, false
	}
	if probe.Surface == "terminal" && !runtimeDetection.TerminalCommands {
		return config.AssetPolicyDecision{}, false
	}
	decision := a.scannerCfg.EvaluateAssetPolicy(config.AssetPolicyInput{
		TargetType:     "skill",
		Name:           probe.SkillName,
		Connector:      connector,
		SourcePath:     probe.SourcePath,
		RuntimeSurface: coalesceRuntimeSurface(probe.Surface, "hook"),
	})
	// Avarice F-1506: a Claude Code agent can pass a crafted
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
	if probe.RawName != "" && strings.ContainsAny(probe.RawName, `/\`) {
		// Mark unregistered so registry-required policy denies.
		decision.RegistryStatus = "unregistered"
		// If the operator runs registry_required=true and the
		// configured default for unknowns is deny (the policy
		// the test in F-1506 sets up), assetPolicyViolation
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
			"path-shaped skill_name input forced unregistered match (F-1506)")
		if strings.TrimSpace(decision.Source) == "" {
			decision.Source = "skill-path-shaped"
		}
	}
	if !decision.Enabled || decision.RawAction != "block" {
		return decision, false
	}
	if a.otel != nil {
		attrs := map[string]string{
			"source":              decision.Source,
			"registry_status":     decision.RegistryStatus,
			"registry_configured": fmt.Sprintf("%t", decision.RegistryConfigured),
			"runtime_surface":     coalesceRuntimeSurface(probe.Surface, "hook"),
			"hook_event_name":     hookEvent,
			"tool_name":           probe.ToolName,
			"skill_name":          probe.SkillName,
			"would_block":         fmt.Sprintf("%t", decision.WouldBlock),
		}
		// Surface raw inputs whenever path-stripping or other
		// normalization changed the agent's literal value into a
		// different registry-matching name. This is the audit
		// signal for "agent passed /tmp/x/<approved>/SKILL.md to
		// match an approved name" attempts.
		if probe.RawName != "" {
			attrs["skill_name_raw"] = probe.RawName
		}
		if probe.SourcePath != "" {
			attrs["skill_source_path"] = probe.SourcePath
		}
		a.otel.EmitPolicyDecision("asset-policy", decision.Action, decision.TargetName, "skill", decision.Reason, attrs)
	}
	if a.logger != nil {
		a.logAssetPolicyAudit(ctx, "skill:"+decision.TargetName,
			fmt.Sprintf("action=%s source=%s registry_status=%s registry_configured=%v surface=%s hook=%s tool=%s connector=%s skill_name_raw=%q source_path=%q would_block=%v reason=%s",
				decision.Action, decision.Source, decision.RegistryStatus, decision.RegistryConfigured, probe.Surface, hookEvent, probe.ToolName, connector, probe.RawName, probe.SourcePath, decision.WouldBlock, decision.Reason))
	}
	a.dispatchAssetPolicyNotification(decision, "skill", connector, hookEvent)
	return decision, true
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
func (a *APIServer) dispatchAssetPolicyNotification(decision config.AssetPolicyDecision, targetKind, connectorName, hookEvent string) {
	if a == nil || a.notifier == nil {
		return
	}
	target := strings.TrimSpace(decision.TargetName)
	if target == "" {
		target = strings.ToLower(strings.TrimSpace(targetKind))
	} else {
		target = strings.ToLower(strings.TrimSpace(targetKind)) + ":" + target
	}
	ev := notifier.BlockEvent{
		Source:    notifier.SourceAssetPolicy,
		Target:    target,
		Reason:    string(redaction.ForSinkReason(decision.Reason)),
		Severity:  "HIGH",
		Connector: connectorName,
		Event:     hookEvent,
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
// the operator's MCP.Default is "deny". Used by F-1510 to refuse the
// `unknown_terminal_mcp=observe` downgrade when the operator has
// already opted into MCP default-deny in action mode.
func assetMCPModeFor(a *APIServer, decision config.AssetPolicyDecision) (string, bool) {
	if a == nil || a.scannerCfg == nil {
		return decision.Mode, false
	}
	mode := strings.TrimSpace(a.scannerCfg.AssetPolicy.Mode)
	if mode == "" {
		mode = decision.Mode
	}
	defaultDeny := strings.EqualFold(
		strings.TrimSpace(a.scannerCfg.AssetPolicy.MCP.Default),
		"deny")
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

func slashCommandLooksSkill(commandSource string) bool {
	switch strings.ToLower(strings.TrimSpace(commandSource)) {
	case "skill", "plugin":
		return true
	default:
		return false
	}
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
//   - When the current hook event is enforceable (PreToolUse,
//     PermissionRequest, UserPromptExpansion), action=block and the
//     returned wouldBlock=false (because the action IS the block —
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
		parts = append(parts, "registry_status="+assetPolicyRegistryStatusForReason(decision.RegistryStatus))
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

func assetPolicyRegistryStatusForReason(status string) string {
	switch strings.TrimSpace(status) {
	case "unregistered":
		return "not-registered"
	default:
		return status
	}
}

func runtimeAssetCanEnforce(event string) bool {
	// Claude Code / Codex use canonical PascalCase event names — keep
	// these literal switches so the original behavior is byte-identical
	// for those high-traffic hooks.
	switch event {
	case "UserPromptExpansion", "PreToolUse", "PermissionRequest":
		return true
	}
	// Generic hook-only connectors (hermes, cursor, windsurf, geminicli,
	// copilot) use varied case/spacing for the same semantic events
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
