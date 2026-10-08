// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

// windowsAgentSessionsRestartCode names agent sessions that started before
// the standalone deployment was installed, as on Linux and macOS. An agent
// reads its hooks when it starts, so a session left open through the first
// install ran a blocked command while status was healthy (GAP-0755).
const windowsAgentSessionsRestartCode = "agent_sessions_restart_required"

// windowsAgentImages are the executables of the agent CLIs DefenseClaw
// registers hooks for.
var windowsAgentImages = map[string]string{
	"claude.exe": "claude", "codex.exe": "codex", "cursor-agent.exe": "cursor-agent", "copilot.exe": "copilot",
	"opencode.exe": "opencode", "amp.exe": "amp", "devin.exe": "devin", "hermes.exe": "hermes",
	"openhands.exe": "openhands", "omnigent.exe": "omnigent", "agy.exe": "agy", "kiro-cli.exe": "kiro-cli",
}

// windowsAgentScriptHosts run an agent CLI installed as an npm package.
var windowsAgentScriptHosts = map[string]bool{"node.exe": true, "bun.exe": true, "deno.exe": true}

// windowsAgentPackages are the package folders those hosts run an agent from.
var windowsAgentPackages = []struct{ fragment, agent string }{
	{`\@anthropic-ai\claude-code\`, "claude"},
	{`\@openai\codex\`, "codex"},
	{`\@github\copilot\`, "copilot"},
	{`\@sourcegraph\amp\`, "amp"},
	{`\opencode-ai\`, "opencode"},
}

// windowsServiceAccountNames run services, never an agent a user opened.
var windowsServiceAccountNames = map[string]bool{"": true, "system": true, "local service": true, "network service": true}

// windowsAgentOf names the agent CLI a process runs, or "".
func windowsAgentOf(image, commandLine string) string {
	name := strings.ToLower(strings.TrimSpace(image))
	if agent := windowsAgentImages[name]; agent != "" {
		return agent
	}
	if !windowsAgentScriptHosts[name] {
		return ""
	}
	line := strings.ToLower(strings.ReplaceAll(commandLine, "/", `\`))
	for _, known := range windowsAgentPackages {
		if strings.Contains(line, known.fragment) {
			return known.agent
		}
	}
	return ""
}

// windowsAgentSessionsBefore are the agent CLI processes of user accounts
// that started before installed.
func windowsAgentSessionsBefore(rows []procprobe.Process, installed time.Time) map[string][]string {
	byUser := map[string][]string{}
	for _, row := range rows {
		agent := windowsAgentOf(row.Name, row.Cmdline)
		if agent == "" || row.StartedAt.IsZero() || !row.StartedAt.Before(installed) ||
			windowsServiceAccountNames[strings.ToLower(strings.TrimSpace(row.User))] ||
			strings.HasPrefix(strings.ToLower(row.User), "defenseclaw") {
			continue
		}
		byUser[row.User] = append(byUser[row.User], fmt.Sprintf("%s (pid %d)", agent, row.PID))
	}
	return byUser
}

// windowsAgentSessionWarnings is one agent_sessions_restart_required warning
// per account, in account order.
func windowsAgentSessionWarnings(byUser map[string][]string, installed time.Time) []enterprisestatus.Message {
	users := make([]string, 0, len(byUser))
	for user := range byUser {
		users = append(users, user)
	}
	sort.Strings(users)
	warnings := make([]enterprisestatus.Message, 0, len(users))
	for _, user := range users {
		warnings = append(warnings, enterprisestatus.Message{
			Code: windowsAgentSessionsRestartCode,
			Message: fmt.Sprintf(
				"user %s runs %s, started before DefenseClaw was installed on this computer at %s; an agent reads its hooks when it starts, so these sessions run without DefenseClaw until they are restarted: ask that user to restart them",
				user, strings.Join(byUser[user], ", "), installed.UTC().Format(time.RFC3339)),
		})
	}
	return warnings
}
