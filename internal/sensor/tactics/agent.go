// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package tactics

import (
	"path/filepath"
	"regexp"
	"strings"
)

// agentProcessPattern matches executables that *are* an AI agent, as opposed
// to the generic interpreters that merely might be hosting one.
//
// The distinction is the whole false-positive control for the host plane.
// Every host-plane signal is gated on agent lineage: a generic python3 reading
// ~/.aws/credentials is ordinary developer tooling; the same read by a child of
// claude is not. Without that gate this would be a mediocre EDR.
// The trailing extension group is load-bearing rather than cosmetic: on
// Windows every one of these ships as an .exe, and an executable-name pattern
// that does not tolerate the extension gates the entire host plane on that
// platform. A real Windows host proved it -- every kernel observation was
// discarded for having no agent above it, because the agent was "claude.exe".
var agentProcessPattern = regexp.MustCompile(
	`(?i)^(claude|codex|cursor|cursor-agent|aider|goose|crush|opencode|continue|` +
		`cline|windsurf|copilot|copilot-language-server|gh-copilot|` +
		`amp|devin|openhands|swe-agent|autogpt|agentgpt|babyagi|` +
		`gptme|interpreter|open-interpreter|smol.*|langgraph.*|crewai.*)` +
		`(\.(exe|cmd|bat|com|ps1))?$`)

// agentCmdlinePatterns recognise an agent running inside a generic
// interpreter, where the executable name alone gives nothing away.
//
// This is precisely the gap the inventory process detector leaves open by
// design: it matches executable basenames and discards argv, so an agent
// framework inside a bare python3 is invisible to it. The runtime plane reads
// argv to close that gap.
var agentCmdlinePatterns = []struct {
	pattern *regexp.Regexp
	reason  string
}{
	{regexp.MustCompile(`(?i)\b(langchain|langgraph|llama_index|llamaindex|crewai|autogen|` +
		`pydantic_ai|openai_agents|strands)\b`), "agent framework module"},
	{regexp.MustCompile(`(?i)@modelcontextprotocol/`), "MCP server package"},
	{regexp.MustCompile(`(?i)\bmcp[-_]server[-_]`), "MCP server entry point"},
	{regexp.MustCompile(`(?i)\b(openai|anthropic|litellm|ollama)\b\s+\w`), "provider SDK CLI"},
}

// mcpProcessPattern matches MCP server processes, which are the agent's hands:
// an agent reaches the filesystem, a database, or a cloud API through one of
// these rather than directly. They are agent processes in their own right.
var mcpProcessPattern = regexp.MustCompile(`(?i)(mcp[-_]server|server[-_]mcp|modelcontextprotocol)`)

// IsAgentProcess reports whether an executable name is itself a known agent.
func IsAgentProcess(exeName string) bool {
	return agentProcessPattern.MatchString(BaseName(exeName))
}

// AgentCmdlineReason explains why a command line looks like an agent, or
// returns "" when it does not.
func AgentCmdlineReason(cmdline string) string {
	text := strings.TrimSpace(cmdline)
	if text == "" {
		return ""
	}
	if mcpProcessPattern.MatchString(text) {
		return "MCP server process"
	}
	for _, candidate := range agentCmdlinePatterns {
		if candidate.pattern.MatchString(text) {
			return candidate.reason
		}
	}
	return ""
}

// AgentIdentity returns a short label for the agent, or "" when this is not
// one. Checked in order of confidence: a name we recognise beats a command
// line we merely find suggestive.
func AgentIdentity(exeName, cmdline string) string {
	name := BaseName(exeName)
	if IsAgentProcess(name) {
		return strings.ToLower(name)
	}
	if AgentCmdlineReason(cmdline) != "" {
		if lowered := strings.ToLower(name); lowered != "" {
			return lowered
		}
		return "agent"
	}
	return ""
}

// BaseName trims a path down to its executable name. It handles both
// separators explicitly because a Windows image path reaches this code
// unchanged on a Linux gateway parsing a forwarded event.
func BaseName(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if index := strings.LastIndexAny(trimmed, `/\`); index >= 0 {
		return trimmed[index+1:]
	}
	return filepath.Base(trimmed)
}
