// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// hookAssetFacts is the assetfacts.Header value of a standalone managed
// hook: the names the skill folders this event names or reaches into declare
// in their SKILL.md, and the definition of the MCP server a tool call names,
// read as the user (GAP-0570, GAP-0576). The gateway, a service account,
// may not read this home.
func hookAssetFacts(connector string, payload []byte) string {
	connector = strings.ToLower(strings.TrimSpace(connector))
	if connector != "claudecode" && connector != "codex" {
		return ""
	}
	var event struct {
		ToolName      string         `json:"tool_name"`
		ToolInput     map[string]any `json:"tool_input"`
		CWD           string         `json:"cwd"`
		Prompt        string         `json:"prompt"`
		MCPServerName string         `json:"mcp_server_name"`
	}
	if json.Unmarshal(payload, &event) != nil {
		return ""
	}
	home, _ := os.UserHomeDir()
	var facts assetfacts.Facts
	addSkill := func(folder, dir string) {
		declared := assetfacts.DeclaredSkillName(dir)
		if declared != "" && !config.SameAssetName(declared, folder) {
			facts.Skills = append(facts.Skills, assetfacts.Skill{Folder: folder, Declared: declared})
		}
	}
	if name := hookInvokedSkillName(event.ToolName, event.ToolInput, event.Prompt); name != "" {
		for _, root := range assetfacts.SkillRoots(connector, home, event.CWD) {
			addSkill(name, filepath.Join(root, name))
		}
	}
	for _, ref := range assetfacts.SkillFolderRefs(event.ToolInput, home, event.CWD) {
		addSkill(ref.Name, ref.Dir)
	}
	if server := hookMCPServerName(event.ToolName, event.MCPServerName); server != "" {
		if entry, ok := (*config.Config)(nil).LookupMCPServerForConnector(connector, event.CWD, server); ok {
			facts.MCP = &assetfacts.MCPServer{
				Name: entry.Name, URL: entry.URL, Command: entry.Command, Args: entry.Args, Transport: entry.Transport,
			}
		}
	}
	return assetfacts.Encode(facts)
}

// hookInvokedSkillName is the skill a Claude Code Skill call or a Codex
// "$name" prompt selects, when it is a plain folder name.
func hookInvokedSkillName(toolName string, toolInput map[string]any, prompt string) string {
	name := ""
	if strings.EqualFold(strings.TrimSpace(toolName), "Skill") {
		name, _ = toolInput["skill"].(string)
	} else if fields := strings.Fields(prompt); len(fields) > 0 && strings.HasPrefix(fields[0], "$") {
		name = strings.TrimPrefix(fields[0], "$")
	}
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\:`) {
		return ""
	}
	return name
}

// hookMCPServerName is the MCP server a tool call names: mcp__<server>__<tool>
// or the event's mcp_server_name.
func hookMCPServerName(toolName, serverName string) string {
	if server := strings.TrimSpace(serverName); server != "" {
		return server
	}
	parts := strings.Split(strings.TrimSpace(toolName), "__")
	if len(parts) >= 3 && parts[0] == "mcp" && strings.TrimSpace(parts[1]) != "" {
		return strings.TrimSpace(parts[1])
	}
	return ""
}
