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
)

type mcpRuntimeProbe struct {
	ServerName string
	ToolName   string
	Command    string
	Args       []string
	Surface    string
	Matched    bool
}

func (a *APIServer) claudeCodeMCPAssetDecision(ctx context.Context, req claudeCodeHookRequest) (config.AssetPolicyDecision, bool) {
	probe := mcpProbeFromFields(req.MCPServerName, req.ToolName, req.ToolInput)
	return a.evaluateRuntimeMCPAssetPolicy(ctx, "claudecode", req.HookEventName, probe)
}

func (a *APIServer) codexMCPAssetDecision(ctx context.Context, req codexHookRequest) (config.AssetPolicyDecision, bool) {
	probe := mcpProbeFromFields(payloadString(req.Payload, "mcp_server_name"), req.ToolName, req.ToolInput)
	return a.evaluateRuntimeMCPAssetPolicy(ctx, "codex", req.HookEventName, probe)
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
	if isUnknownTerminalMCP(probe) && !assetRuntimeModeIsAction(runtimeDetection.UnknownTerminalMCP) && decision.RawAction == "block" {
		decision.Action = "allow"
		decision.Mode = config.AssetPolicyModeObserve
		decision.WouldBlock = true
	}
	if !decision.Enabled || decision.RawAction != "block" {
		return decision, false
	}
	if a.otel != nil {
		a.otel.EmitPolicyDecision("asset-policy", decision.Action, decision.TargetName, "mcp", decision.Reason, map[string]string{
			"source":          decision.Source,
			"registry_status": decision.RegistryStatus,
			"runtime_surface": coalesceRuntimeSurface(probe.Surface, "hook"),
			"hook_event_name": hookEvent,
			"tool_name":       probe.ToolName,
			"mcp_server_name": probe.ServerName,
			"would_block":     fmt.Sprintf("%t", decision.WouldBlock),
		})
	}
	if a.logger != nil {
		_ = a.logger.LogActionCtx(ctx, "asset-policy", "mcp:"+decision.TargetName,
			fmt.Sprintf("action=%s source=%s registry_status=%s surface=%s hook=%s tool=%s would_block=%v reason=%s",
				decision.Action, decision.Source, decision.RegistryStatus, probe.Surface, hookEvent, probe.ToolName, decision.WouldBlock, decision.Reason))
	}
	return decision, true
}

func isUnknownTerminalMCP(probe mcpRuntimeProbe) bool {
	return probe.Surface == "terminal" && strings.EqualFold(strings.TrimSpace(probe.ServerName), "terminal-mcp")
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
		if v, ok := input[key]; ok {
			if s := strings.TrimSpace(fmt.Sprint(v)); s != "" {
				return s
			}
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

func payloadString(payload map[string]interface{}, key string) string {
	if payload == nil {
		return ""
	}
	if v, ok := payload[key]; ok {
		return strings.TrimSpace(fmt.Sprint(v))
	}
	return ""
}

func mergeAssetDecision(
	decision config.AssetPolicyDecision,
	matched bool,
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
		reason = decision.Reason
	}
	findings = append(findings, "ASSET-POLICY-MCP")
	canBlock := decision.Action == "block" && runtimeMCPAssetCanEnforce(event)
	if canBlock {
		if decision.Reason != "" {
			reason = decision.Reason
		}
		action = "block"
		return action, rawAction, severity, reason, findings, false
	}
	if !alreadyBlocking {
		action = "allow"
	}
	return action, rawAction, severity, reason, findings, true
}

func runtimeMCPAssetCanEnforce(event string) bool {
	switch event {
	case "PreToolUse", "PermissionRequest":
		return true
	default:
		return false
	}
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
