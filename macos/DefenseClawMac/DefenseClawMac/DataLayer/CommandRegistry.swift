// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

// Synchronized with DefenseClaw mainline cli/defenseclaw/tui/registry_data.py.
// Keep these 226 entries aligned when the TUI command palette changes.

import Foundation

struct CommandDefinition: Identifiable, Hashable, Sendable {
    let id: Int
    let title: String
    let binary: String
    let arguments: [String]
    let summary: String
    let category: String
    let requiresInput: Bool
    let usage: String

    var isDestructive: Bool {
        let tokens = arguments.map { $0.lowercased() }
        return !Set(tokens).isDisjoint(with: ["remove", "delete", "reset", "uninstall", "quarantine", "teardown", "destroy"])
    }

    var changesState: Bool {
        !["info", "scan"].contains(category)
    }

    var requiresTerminal: Bool {
        summary.localizedCaseInsensitiveContains("interactive")
            || arguments.last == "shell"
    }

    func displayCommand(extraArguments: [String] = []) -> String {
        ([binary] + arguments + extraArguments).map(Self.quote).joined(separator: " ")
    }

    private static func quote(_ value: String) -> String {
        guard value.contains(where: { $0.isWhitespace || "'\"\\".contains($0) }) else { return value }
        return "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}

enum CommandRegistry {
    static let sourceCount = 226
    static let all: [CommandDefinition] = [
        CommandDefinition(id: 0, title: "init", binary: "defenseclaw", arguments: ["init"], summary: "Initialize DefenseClaw", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 1, title: "init first-run", binary: "defenseclaw", arguments: ["init", "--non-interactive", "--yes", "--verify"], summary: "Run guided first-run backend with defaults", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 2, title: "quickstart", binary: "defenseclaw", arguments: ["quickstart", "--non-interactive", "--yes"], summary: "Compatibility first-run wrapper", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 3, title: "setup llm", binary: "defenseclaw", arguments: ["setup", "llm"], summary: "Configure the unified LLM interactively", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 4, title: "setup llm show", binary: "defenseclaw", arguments: ["setup", "llm", "--show"], summary: "Show unified LLM settings", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 5, title: "setup migrate-llm", binary: "defenseclaw", arguments: ["setup", "migrate-llm"], summary: "Migrate legacy LLM config into unified llm: block", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 6, title: "setup skill-scanner", binary: "defenseclaw", arguments: ["setup", "skill-scanner"], summary: "Configure skill scanner (interactive)", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 7, title: "setup mcp-scanner", binary: "defenseclaw", arguments: ["setup", "mcp-scanner"], summary: "Configure MCP scanner (interactive)", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 8, title: "setup openclaw", binary: "defenseclaw", arguments: ["setup", "openclaw", "--yes"], summary: "Configure OpenClaw guardrail setup", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 9, title: "setup zeptoclaw", binary: "defenseclaw", arguments: ["setup", "zeptoclaw", "--yes"], summary: "Configure ZeptoClaw guardrail setup", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 10, title: "setup codex", binary: "defenseclaw", arguments: ["setup", "codex", "--yes"], summary: "Configure Codex observability hooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 11, title: "setup claude-code", binary: "defenseclaw", arguments: ["setup", "claude-code", "--yes"], summary: "Configure Claude Code observability hooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 12, title: "setup hermes", binary: "defenseclaw", arguments: ["setup", "hermes", "--yes"], summary: "Configure Hermes observability hooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 13, title: "setup cursor", binary: "defenseclaw", arguments: ["setup", "cursor", "--yes"], summary: "Configure Cursor observability hooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 14, title: "setup windsurf", binary: "defenseclaw", arguments: ["setup", "windsurf", "--yes"], summary: "Configure Windsurf observability hooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 15, title: "setup geminicli", binary: "defenseclaw", arguments: ["setup", "geminicli", "--yes"], summary: "Configure Gemini CLI observability hooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 16, title: "setup copilot", binary: "defenseclaw", arguments: ["setup", "copilot", "--yes"], summary: "Configure Copilot observability hooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 17, title: "setup openhands", binary: "defenseclaw", arguments: ["setup", "openhands", "--yes"], summary: "Configure OpenHands observability hooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 18, title: "setup antigravity", binary: "defenseclaw", arguments: ["setup", "antigravity", "--yes"], summary: "Configure Antigravity observability hooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 19, title: "setup opencode", binary: "defenseclaw", arguments: ["setup", "opencode", "--yes"], summary: "Configure OpenCode observability hooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 20, title: "setup rotate-token", binary: "defenseclaw", arguments: ["setup", "rotate-token", "--yes"], summary: "Rotate the gateway token", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 21, title: "setup gateway", binary: "defenseclaw", arguments: ["setup", "gateway"], summary: "Configure gateway connection (interactive)", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 22, title: "setup guardrail", binary: "defenseclaw", arguments: ["setup", "guardrail"], summary: "Configure LLM guardrail", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 23, title: "setup redaction", binary: "defenseclaw", arguments: ["setup", "redaction"], summary: "Show/toggle redaction state", category: "setup", requiresInput: true, usage: "<status|on|off> [--yes]"),
        CommandDefinition(id: 24, title: "setup notifications", binary: "defenseclaw", arguments: ["setup", "notifications"], summary: "Show/toggle desktop notifications", category: "setup", requiresInput: true, usage: "<status|on|off> [--yes]"),
        CommandDefinition(id: 25, title: "setup splunk", binary: "defenseclaw", arguments: ["setup", "splunk"], summary: "Configure Splunk / O11y", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 26, title: "setup local-observability up", binary: "defenseclaw", arguments: ["setup", "local-observability", "up"], summary: "Start local Prom/Loki/Tempo/Grafana stack", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 27, title: "setup local-observability down", binary: "defenseclaw", arguments: ["setup", "local-observability", "down"], summary: "Stop local observability stack", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 28, title: "setup local-observability reset", binary: "defenseclaw", arguments: ["setup", "local-observability", "reset", "--yes"], summary: "Stop local observability and wipe stored event volumes", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 29, title: "setup local-observability status", binary: "defenseclaw", arguments: ["setup", "local-observability", "status"], summary: "Show local observability stack status", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 30, title: "setup local-observability url", binary: "defenseclaw", arguments: ["setup", "local-observability", "url"], summary: "Show local observability URLs", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 31, title: "setup local-observability logs", binary: "defenseclaw", arguments: ["setup", "local-observability", "logs"], summary: "Tail local observability logs", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 32, title: "setup observability add", binary: "defenseclaw", arguments: ["setup", "observability", "add"], summary: "Add an observability/audit destination preset", category: "setup", requiresInput: true, usage: "<preset> [flags]"),
        CommandDefinition(id: 33, title: "setup observability list", binary: "defenseclaw", arguments: ["setup", "observability", "list"], summary: "List configured observability destinations", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 34, title: "setup observability enable", binary: "defenseclaw", arguments: ["setup", "observability", "enable"], summary: "Enable an observability destination", category: "setup", requiresInput: true, usage: "<name>"),
        CommandDefinition(id: 35, title: "setup observability disable", binary: "defenseclaw", arguments: ["setup", "observability", "disable"], summary: "Disable an observability destination", category: "setup", requiresInput: true, usage: "<name>"),
        CommandDefinition(id: 36, title: "setup observability remove", binary: "defenseclaw", arguments: ["setup", "observability", "remove", "--yes"], summary: "Remove an observability destination", category: "setup", requiresInput: true, usage: "<name>"),
        CommandDefinition(id: 37, title: "setup observability test", binary: "defenseclaw", arguments: ["setup", "observability", "test"], summary: "Probe an observability destination", category: "setup", requiresInput: true, usage: "<name>"),
        CommandDefinition(id: 38, title: "setup observability migrate-splunk", binary: "defenseclaw", arguments: ["setup", "observability", "migrate-splunk", "--apply"], summary: "Migrate legacy splunk: block into audit_sinks[]", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 39, title: "setup webhook add", binary: "defenseclaw", arguments: ["setup", "webhook", "add"], summary: "Add a notifier webhook", category: "setup", requiresInput: true, usage: "<name> --type <slack|teams|pagerduty|generic>"),
        CommandDefinition(id: 40, title: "setup webhook list", binary: "defenseclaw", arguments: ["setup", "webhook", "list"], summary: "List notifier webhooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 41, title: "setup webhook show", binary: "defenseclaw", arguments: ["setup", "webhook", "show"], summary: "Show a notifier webhook", category: "setup", requiresInput: true, usage: "<name>"),
        CommandDefinition(id: 42, title: "setup webhook enable", binary: "defenseclaw", arguments: ["setup", "webhook", "enable"], summary: "Enable a notifier webhook", category: "setup", requiresInput: true, usage: "<name>"),
        CommandDefinition(id: 43, title: "setup webhook disable", binary: "defenseclaw", arguments: ["setup", "webhook", "disable"], summary: "Disable a notifier webhook", category: "setup", requiresInput: true, usage: "<name>"),
        CommandDefinition(id: 44, title: "setup webhook remove", binary: "defenseclaw", arguments: ["setup", "webhook", "remove", "--yes"], summary: "Remove a notifier webhook", category: "setup", requiresInput: true, usage: "<name>"),
        CommandDefinition(id: 45, title: "setup webhook test", binary: "defenseclaw", arguments: ["setup", "webhook", "test"], summary: "Send/probe a notifier webhook", category: "setup", requiresInput: true, usage: "<name>"),
        CommandDefinition(id: 46, title: "setup provider add", binary: "defenseclaw", arguments: ["setup", "provider", "add"], summary: "Add a custom LLM provider to the overlay", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 47, title: "setup provider remove", binary: "defenseclaw", arguments: ["setup", "provider", "remove"], summary: "Remove a custom LLM provider from the overlay", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 48, title: "setup provider list", binary: "defenseclaw", arguments: ["setup", "provider", "list"], summary: "List overlay provider entries", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 49, title: "setup provider show", binary: "defenseclaw", arguments: ["setup", "provider", "show"], summary: "Show merged provider registry", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 50, title: "agent discover", binary: "defenseclaw", arguments: ["agent", "discover"], summary: "Discover installed agents and emit sanitized telemetry", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 51, title: "agent usage", binary: "defenseclaw", arguments: ["agent", "usage"], summary: "Show continuous AI visibility from the sidecar", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 52, title: "agent usage --refresh", binary: "defenseclaw", arguments: ["agent", "usage", "--refresh"], summary: "Trigger an AI-usage scan and render results", category: "scan", requiresInput: false, usage: ""),
        CommandDefinition(id: 53, title: "agent discovery setup", binary: "defenseclaw", arguments: ["agent", "discovery", "setup"], summary: "Interactive AI discovery wizard (mode, intervals, sources)", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 54, title: "agent discovery enable", binary: "defenseclaw", arguments: ["agent", "discovery", "enable", "--yes"], summary: "Enable AI discovery, save config, restart, and scan", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 55, title: "agent discovery disable", binary: "defenseclaw", arguments: ["agent", "discovery", "disable", "--yes"], summary: "Disable AI discovery and restart the gateway", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 56, title: "agent discovery status", binary: "defenseclaw", arguments: ["agent", "discovery", "status"], summary: "Show on-disk vs live AI discovery state", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 57, title: "agent discovery scan", binary: "defenseclaw", arguments: ["agent", "discovery", "scan"], summary: "Trigger one immediate AI discovery scan", category: "scan", requiresInput: false, usage: ""),
        CommandDefinition(id: 58, title: "agent signatures list", binary: "defenseclaw", arguments: ["agent", "signatures", "list"], summary: "List the merged AI discovery signature catalog", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 59, title: "scan skill", binary: "defenseclaw", arguments: ["skill", "scan"], summary: "Scan a skill", category: "scan", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 60, title: "scan skill --all", binary: "defenseclaw", arguments: ["skill", "scan", "--all"], summary: "Scan all skills", category: "scan", requiresInput: false, usage: ""),
        CommandDefinition(id: 61, title: "scan mcp", binary: "defenseclaw", arguments: ["mcp", "scan"], summary: "Scan an MCP server", category: "scan", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 62, title: "scan mcp --all", binary: "defenseclaw", arguments: ["mcp", "scan", "--all"], summary: "Scan all MCP servers", category: "scan", requiresInput: false, usage: ""),
        CommandDefinition(id: 63, title: "scan plugin", binary: "defenseclaw", arguments: ["plugin", "scan"], summary: "Scan a plugin", category: "scan", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 64, title: "scan aibom", binary: "defenseclaw", arguments: ["aibom", "scan"], summary: "Generate AIBOM inventory", category: "scan", requiresInput: false, usage: ""),
        CommandDefinition(id: 65, title: "scan code", binary: "defenseclaw-gateway", arguments: ["scan", "code"], summary: "CodeGuard scan", category: "scan", requiresInput: true, usage: "<path>"),
        CommandDefinition(id: 66, title: "block skill", binary: "defenseclaw", arguments: ["skill", "block"], summary: "Block a skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 67, title: "allow skill", binary: "defenseclaw", arguments: ["skill", "allow"], summary: "Allow-list a skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 68, title: "unblock skill", binary: "defenseclaw", arguments: ["skill", "unblock"], summary: "Unblock a skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 69, title: "disable skill", binary: "defenseclaw", arguments: ["skill", "disable"], summary: "Disable a skill at runtime", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 70, title: "enable skill", binary: "defenseclaw", arguments: ["skill", "enable"], summary: "Enable a skill at runtime", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 71, title: "quarantine skill", binary: "defenseclaw", arguments: ["skill", "quarantine"], summary: "Quarantine a skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 72, title: "restore skill", binary: "defenseclaw", arguments: ["skill", "restore"], summary: "Restore a quarantined skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 73, title: "block mcp", binary: "defenseclaw", arguments: ["mcp", "block"], summary: "Block an MCP server", category: "enforce", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 74, title: "allow mcp", binary: "defenseclaw", arguments: ["mcp", "allow"], summary: "Allow-list an MCP server", category: "enforce", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 75, title: "unblock mcp", binary: "defenseclaw", arguments: ["mcp", "unblock"], summary: "Unblock an MCP server", category: "enforce", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 76, title: "set mcp", binary: "defenseclaw", arguments: ["mcp", "set"], summary: "Scan + set MCP server in the active connector's config", category: "enforce", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 77, title: "unset mcp", binary: "defenseclaw", arguments: ["mcp", "unset"], summary: "Unset MCP server from the active connector's config", category: "enforce", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 78, title: "block plugin", binary: "defenseclaw", arguments: ["plugin", "block"], summary: "Block a plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 79, title: "allow plugin", binary: "defenseclaw", arguments: ["plugin", "allow"], summary: "Allow-list a plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 80, title: "disable plugin", binary: "defenseclaw", arguments: ["plugin", "disable"], summary: "Disable a plugin at runtime", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 81, title: "enable plugin", binary: "defenseclaw", arguments: ["plugin", "enable"], summary: "Enable a plugin at runtime", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 82, title: "quarantine plugin", binary: "defenseclaw", arguments: ["plugin", "quarantine"], summary: "Quarantine a plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 83, title: "restore plugin", binary: "defenseclaw", arguments: ["plugin", "restore"], summary: "Restore a quarantined plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 84, title: "remove plugin", binary: "defenseclaw", arguments: ["plugin", "remove"], summary: "Remove a plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 85, title: "block tool", binary: "defenseclaw", arguments: ["tool", "block"], summary: "Block a tool", category: "enforce", requiresInput: true, usage: "<tool-name>"),
        CommandDefinition(id: 86, title: "allow tool", binary: "defenseclaw", arguments: ["tool", "allow"], summary: "Allow-list a tool", category: "enforce", requiresInput: true, usage: "<tool-name>"),
        CommandDefinition(id: 87, title: "unblock tool", binary: "defenseclaw", arguments: ["tool", "unblock"], summary: "Unblock a tool", category: "enforce", requiresInput: true, usage: "<tool-name>"),
        CommandDefinition(id: 88, title: "install skill", binary: "defenseclaw", arguments: ["skill", "install"], summary: "Install a skill from ClawHub", category: "install", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 89, title: "install plugin", binary: "defenseclaw", arguments: ["plugin", "install"], summary: "Install a plugin", category: "install", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 90, title: "install codeguard", binary: "defenseclaw", arguments: ["codeguard", "install-skill"], summary: "Install CodeGuard skill", category: "install", requiresInput: false, usage: ""),
        CommandDefinition(id: 91, title: "policy list", binary: "defenseclaw", arguments: ["policy", "list"], summary: "List policies", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 92, title: "policy show", binary: "defenseclaw", arguments: ["policy", "show"], summary: "Show policy details", category: "policy", requiresInput: true, usage: "<policy-name>"),
        CommandDefinition(id: 93, title: "policy create", binary: "defenseclaw", arguments: ["policy", "create"], summary: "Create a new policy", category: "policy", requiresInput: true, usage: "<policy-name>"),
        CommandDefinition(id: 94, title: "policy activate", binary: "defenseclaw", arguments: ["policy", "activate"], summary: "Activate a policy", category: "policy", requiresInput: true, usage: "<policy-name>"),
        CommandDefinition(id: 95, title: "policy delete", binary: "defenseclaw", arguments: ["policy", "delete"], summary: "Delete a user policy", category: "policy", requiresInput: true, usage: "<policy-name>"),
        CommandDefinition(id: 96, title: "policy validate", binary: "defenseclaw", arguments: ["policy", "validate"], summary: "Validate policy data + Rego", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 97, title: "policy test", binary: "defenseclaw", arguments: ["policy", "test"], summary: "Run OPA policy tests", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 98, title: "policy edit actions", binary: "defenseclaw", arguments: ["policy", "edit", "actions"], summary: "Edit severity action rules", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 99, title: "policy edit scanner", binary: "defenseclaw", arguments: ["policy", "edit", "scanner"], summary: "Edit scanner overrides", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 100, title: "policy edit guardrail", binary: "defenseclaw", arguments: ["policy", "edit", "guardrail"], summary: "Edit guardrail policy", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 101, title: "policy edit firewall", binary: "defenseclaw", arguments: ["policy", "edit", "firewall"], summary: "Edit firewall policy", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 102, title: "policy evaluate", binary: "defenseclaw-gateway", arguments: ["policy", "evaluate"], summary: "Dry-run admission evaluation", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 103, title: "policy evaluate-firewall", binary: "defenseclaw-gateway", arguments: ["policy", "evaluate-firewall"], summary: "Dry-run firewall evaluation", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 104, title: "policy reload", binary: "defenseclaw-gateway", arguments: ["policy", "reload"], summary: "Reload policy in running sidecar", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 105, title: "policy domains", binary: "defenseclaw-gateway", arguments: ["policy", "domains"], summary: "Show firewall domain lists", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 106, title: "list skills", binary: "defenseclaw", arguments: ["skill", "list"], summary: "List skills with scan status", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 107, title: "list mcps", binary: "defenseclaw", arguments: ["mcp", "list"], summary: "List MCP servers with status", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 108, title: "list plugins", binary: "defenseclaw", arguments: ["plugin", "list"], summary: "List installed plugins", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 109, title: "list tools", binary: "defenseclaw", arguments: ["tool", "list"], summary: "List tool rules", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 110, title: "info skill", binary: "defenseclaw", arguments: ["skill", "info"], summary: "Show skill details", category: "info", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 111, title: "info plugin", binary: "defenseclaw", arguments: ["plugin", "info"], summary: "Show plugin details", category: "info", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 112, title: "tool status", binary: "defenseclaw", arguments: ["tool", "status"], summary: "Show tool block/allow status", category: "info", requiresInput: true, usage: "<tool-name>"),
        CommandDefinition(id: 113, title: "status", binary: "defenseclaw", arguments: ["status"], summary: "Show DefenseClaw status", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 114, title: "doctor", binary: "defenseclaw", arguments: ["doctor"], summary: "Run health checks", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 115, title: "doctor run", binary: "defenseclaw", arguments: ["doctor"], summary: "Run health checks", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 116, title: "doctor --fix", binary: "defenseclaw", arguments: ["doctor", "--fix", "--yes"], summary: "Auto-repair safe health issues", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 117, title: "config validate", binary: "defenseclaw", arguments: ["config", "validate"], summary: "Validate config.yaml", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 118, title: "config show", binary: "defenseclaw", arguments: ["config", "show"], summary: "Show resolved config with secrets masked", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 119, title: "config path", binary: "defenseclaw", arguments: ["config", "path"], summary: "Show DefenseClaw filesystem paths", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 120, title: "keys list", binary: "defenseclaw", arguments: ["keys", "list"], summary: "List configured and missing credentials", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 121, title: "keys list --json", binary: "defenseclaw", arguments: ["keys", "list", "--json"], summary: "List credentials as JSON for setup parity", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 122, title: "keys check", binary: "defenseclaw", arguments: ["keys", "check"], summary: "Fail if required credentials are missing", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 123, title: "keys set", binary: "defenseclaw", arguments: ["keys", "set"], summary: "Persist a credential to the DefenseClaw .env", category: "setup", requiresInput: true, usage: "<ENV_NAME> --value <secret>"),
        CommandDefinition(id: 124, title: "keys fill-missing", binary: "defenseclaw", arguments: ["keys", "fill-missing", "--yes"], summary: "List missing required credentials", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 125, title: "settings save", binary: "defenseclaw", arguments: ["settings", "save"], summary: "Persist current settings/config", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 126, title: "guardrail status", binary: "defenseclaw", arguments: ["guardrail", "status"], summary: "Show guardrail status", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 127, title: "guardrail enable", binary: "defenseclaw", arguments: ["guardrail", "enable", "--yes"], summary: "Enable guardrail", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 128, title: "guardrail disable", binary: "defenseclaw", arguments: ["guardrail", "disable", "--yes"], summary: "Disable guardrail", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 129, title: "version", binary: "defenseclaw", arguments: ["version"], summary: "Show DefenseClaw version information", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 130, title: "start", binary: "defenseclaw-gateway", arguments: ["start"], summary: "Start gateway sidecar", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 131, title: "stop", binary: "defenseclaw-gateway", arguments: ["stop"], summary: "Stop gateway sidecar", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 132, title: "restart", binary: "defenseclaw-gateway", arguments: ["restart"], summary: "Restart gateway sidecar", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 133, title: "gateway status", binary: "defenseclaw-gateway", arguments: ["status"], summary: "Show gateway health", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 134, title: "watchdog start", binary: "defenseclaw-gateway", arguments: ["watchdog", "start"], summary: "Start health watchdog", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 135, title: "watchdog stop", binary: "defenseclaw-gateway", arguments: ["watchdog", "stop"], summary: "Stop health watchdog", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 136, title: "watchdog status", binary: "defenseclaw-gateway", arguments: ["watchdog", "status"], summary: "Show watchdog status", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 137, title: "connector verify", binary: "defenseclaw-gateway", arguments: ["connector", "verify"], summary: "Verify connector config is clean/current", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 138, title: "connector teardown", binary: "defenseclaw-gateway", arguments: ["connector", "teardown"], summary: "Remove active connector config patches", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 139, title: "connector list-backups", binary: "defenseclaw-gateway", arguments: ["connector", "list-backups"], summary: "List connector backup files", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 140, title: "gateway audit export", binary: "defenseclaw-gateway", arguments: ["audit", "export"], summary: "Export gateway audit log", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 141, title: "gateway provenance show", binary: "defenseclaw-gateway", arguments: ["provenance", "show"], summary: "Show gateway binary/config provenance", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 142, title: "sandbox init", binary: "defenseclaw", arguments: ["sandbox", "init"], summary: "Initialize sandbox environment", category: "sandbox", requiresInput: false, usage: ""),
        CommandDefinition(id: 143, title: "sandbox setup", binary: "defenseclaw", arguments: ["sandbox", "setup"], summary: "Configure sandbox networking", category: "sandbox", requiresInput: false, usage: ""),
        CommandDefinition(id: 144, title: "sandbox start", binary: "defenseclaw-gateway", arguments: ["sandbox", "start"], summary: "Start sandbox services", category: "sandbox", requiresInput: false, usage: ""),
        CommandDefinition(id: 145, title: "sandbox stop", binary: "defenseclaw-gateway", arguments: ["sandbox", "stop"], summary: "Stop sandbox services", category: "sandbox", requiresInput: false, usage: ""),
        CommandDefinition(id: 146, title: "sandbox restart", binary: "defenseclaw-gateway", arguments: ["sandbox", "restart"], summary: "Restart sandbox services", category: "sandbox", requiresInput: false, usage: ""),
        CommandDefinition(id: 147, title: "sandbox status", binary: "defenseclaw-gateway", arguments: ["sandbox", "status"], summary: "Show sandbox status", category: "sandbox", requiresInput: false, usage: ""),
        CommandDefinition(id: 148, title: "sandbox exec", binary: "defenseclaw-gateway", arguments: ["sandbox", "exec"], summary: "Run command in sandbox", category: "sandbox", requiresInput: true, usage: "<command>"),
        CommandDefinition(id: 149, title: "sandbox shell", binary: "defenseclaw-gateway", arguments: ["sandbox", "shell"], summary: "Open sandbox shell", category: "sandbox", requiresInput: false, usage: ""),
        CommandDefinition(id: 150, title: "sandbox policy diff", binary: "defenseclaw-gateway", arguments: ["sandbox", "policy", "diff"], summary: "Compare policy vs endpoints", category: "sandbox", requiresInput: false, usage: ""),
        CommandDefinition(id: 151, title: "upgrade", binary: "defenseclaw", arguments: ["upgrade", "--yes"], summary: "Upgrade DefenseClaw", category: "other", requiresInput: false, usage: ""),
        CommandDefinition(id: 152, title: "uninstall dry-run", binary: "defenseclaw", arguments: ["uninstall", "--dry-run"], summary: "Preview uninstall changes without modifying the system", category: "other", requiresInput: false, usage: ""),
        CommandDefinition(id: 153, title: "uninstall --yes", binary: "defenseclaw", arguments: ["uninstall", "--yes"], summary: "Uninstall DefenseClaw after showing the plan", category: "other", requiresInput: false, usage: ""),
        CommandDefinition(id: 154, title: "uninstall --all --yes", binary: "defenseclaw", arguments: ["uninstall", "--all", "--yes"], summary: "Uninstall DefenseClaw and wipe local data", category: "other", requiresInput: false, usage: ""),
        CommandDefinition(id: 155, title: "reset --yes", binary: "defenseclaw", arguments: ["reset", "--yes"], summary: "Wipe DefenseClaw local data and keep binaries", category: "other", requiresInput: false, usage: ""),
        CommandDefinition(id: 156, title: "setup", binary: "defenseclaw", arguments: ["setup"], summary: "Show setup command help", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 157, title: "setup local-observability", binary: "defenseclaw", arguments: ["setup", "local-observability"], summary: "Show local observability commands", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 158, title: "setup observability", binary: "defenseclaw", arguments: ["setup", "observability"], summary: "Show observability sink commands", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 159, title: "setup provider", binary: "defenseclaw", arguments: ["setup", "provider"], summary: "Show provider registry commands", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 160, title: "setup webhook", binary: "defenseclaw", arguments: ["setup", "webhook"], summary: "Show webhook commands", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 161, title: "skill", binary: "defenseclaw", arguments: ["skill"], summary: "Show skill commands", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 162, title: "skill list", binary: "defenseclaw", arguments: ["skill", "list"], summary: "List skills with scan status", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 163, title: "skill search", binary: "defenseclaw", arguments: ["skill", "search"], summary: "Search available skills", category: "info", requiresInput: true, usage: "<query>"),
        CommandDefinition(id: 164, title: "skill scan", binary: "defenseclaw", arguments: ["skill", "scan"], summary: "Scan a skill", category: "scan", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 165, title: "skill info", binary: "defenseclaw", arguments: ["skill", "info"], summary: "Show skill details", category: "info", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 166, title: "skill allow", binary: "defenseclaw", arguments: ["skill", "allow"], summary: "Allow-list a skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 167, title: "skill block", binary: "defenseclaw", arguments: ["skill", "block"], summary: "Block a skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 168, title: "skill disable", binary: "defenseclaw", arguments: ["skill", "disable"], summary: "Disable a skill at runtime", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 169, title: "skill enable", binary: "defenseclaw", arguments: ["skill", "enable"], summary: "Enable a skill at runtime", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 170, title: "skill install", binary: "defenseclaw", arguments: ["skill", "install"], summary: "Install a skill from ClawHub", category: "install", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 171, title: "skill quarantine", binary: "defenseclaw", arguments: ["skill", "quarantine"], summary: "Quarantine a skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 172, title: "skill restore", binary: "defenseclaw", arguments: ["skill", "restore"], summary: "Restore a quarantined skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 173, title: "skill unblock", binary: "defenseclaw", arguments: ["skill", "unblock"], summary: "Unblock a skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 174, title: "mcp", binary: "defenseclaw", arguments: ["mcp"], summary: "Show MCP commands", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 175, title: "mcp list", binary: "defenseclaw", arguments: ["mcp", "list"], summary: "List MCP servers with status", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 176, title: "mcp scan", binary: "defenseclaw", arguments: ["mcp", "scan"], summary: "Scan an MCP server", category: "scan", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 177, title: "mcp allow", binary: "defenseclaw", arguments: ["mcp", "allow"], summary: "Allow-list an MCP server", category: "enforce", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 178, title: "mcp block", binary: "defenseclaw", arguments: ["mcp", "block"], summary: "Block an MCP server", category: "enforce", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 179, title: "mcp set", binary: "defenseclaw", arguments: ["mcp", "set"], summary: "Scan + set MCP server in the active connector's config", category: "enforce", requiresInput: true, usage: "<name> [--url <url>]"),
        CommandDefinition(id: 180, title: "mcp unblock", binary: "defenseclaw", arguments: ["mcp", "unblock"], summary: "Unblock an MCP server", category: "enforce", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 181, title: "mcp unset", binary: "defenseclaw", arguments: ["mcp", "unset"], summary: "Unset MCP server from the active connector's config", category: "enforce", requiresInput: true, usage: "<name-or-url>"),
        CommandDefinition(id: 182, title: "plugin", binary: "defenseclaw", arguments: ["plugin"], summary: "Show plugin commands", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 183, title: "plugin list", binary: "defenseclaw", arguments: ["plugin", "list"], summary: "List installed plugins", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 184, title: "plugin scan", binary: "defenseclaw", arguments: ["plugin", "scan"], summary: "Scan a plugin", category: "scan", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 185, title: "plugin info", binary: "defenseclaw", arguments: ["plugin", "info"], summary: "Show plugin details", category: "info", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 186, title: "plugin allow", binary: "defenseclaw", arguments: ["plugin", "allow"], summary: "Allow-list a plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 187, title: "plugin block", binary: "defenseclaw", arguments: ["plugin", "block"], summary: "Block a plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 188, title: "plugin disable", binary: "defenseclaw", arguments: ["plugin", "disable"], summary: "Disable a plugin at runtime", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 189, title: "plugin enable", binary: "defenseclaw", arguments: ["plugin", "enable"], summary: "Enable a plugin at runtime", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 190, title: "plugin install", binary: "defenseclaw", arguments: ["plugin", "install"], summary: "Install a plugin", category: "install", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 191, title: "plugin quarantine", binary: "defenseclaw", arguments: ["plugin", "quarantine"], summary: "Quarantine a plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 192, title: "plugin remove", binary: "defenseclaw", arguments: ["plugin", "remove"], summary: "Remove a plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 193, title: "plugin restore", binary: "defenseclaw", arguments: ["plugin", "restore"], summary: "Restore a quarantined plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 194, title: "tool", binary: "defenseclaw", arguments: ["tool"], summary: "Show tool commands", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 195, title: "tool list", binary: "defenseclaw", arguments: ["tool", "list"], summary: "List tool rules", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 196, title: "tool allow", binary: "defenseclaw", arguments: ["tool", "allow"], summary: "Allow-list a tool", category: "enforce", requiresInput: true, usage: "<tool-name>"),
        CommandDefinition(id: 197, title: "tool block", binary: "defenseclaw", arguments: ["tool", "block"], summary: "Block a tool", category: "enforce", requiresInput: true, usage: "<tool-name>"),
        CommandDefinition(id: 198, title: "tool unblock", binary: "defenseclaw", arguments: ["tool", "unblock"], summary: "Unblock a tool", category: "enforce", requiresInput: true, usage: "<tool-name>"),
        CommandDefinition(id: 199, title: "policy", binary: "defenseclaw", arguments: ["policy"], summary: "Show policy commands", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 200, title: "policy edit", binary: "defenseclaw", arguments: ["policy", "edit"], summary: "Show policy edit commands", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 201, title: "keys", binary: "defenseclaw", arguments: ["keys"], summary: "Show credential commands", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 202, title: "config", binary: "defenseclaw", arguments: ["config"], summary: "Show config commands", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 203, title: "guardrail", binary: "defenseclaw", arguments: ["guardrail"], summary: "Show guardrail commands", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 204, title: "settings", binary: "defenseclaw", arguments: ["settings"], summary: "Show settings commands", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 205, title: "audit", binary: "defenseclaw", arguments: ["audit"], summary: "Show audit commands", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 206, title: "codeguard", binary: "defenseclaw", arguments: ["codeguard"], summary: "Show CodeGuard commands", category: "install", requiresInput: false, usage: ""),
        CommandDefinition(id: 207, title: "codeguard install-skill", binary: "defenseclaw", arguments: ["codeguard", "install-skill"], summary: "Install CodeGuard skill", category: "install", requiresInput: false, usage: ""),
        CommandDefinition(id: 208, title: "aibom", binary: "defenseclaw", arguments: ["aibom"], summary: "Show AIBOM commands", category: "scan", requiresInput: false, usage: ""),
        CommandDefinition(id: 209, title: "sandbox", binary: "defenseclaw", arguments: ["sandbox"], summary: "Show sandbox commands", category: "sandbox", requiresInput: false, usage: ""),
        CommandDefinition(id: 210, title: "reset", binary: "defenseclaw", arguments: ["reset"], summary: "Run interactive local data reset", category: "other", requiresInput: false, usage: ""),
        CommandDefinition(id: 211, title: "uninstall", binary: "defenseclaw", arguments: ["uninstall"], summary: "Run interactive uninstall flow", category: "other", requiresInput: false, usage: ""),
        CommandDefinition(id: 212, title: "skills", binary: "defenseclaw", arguments: ["skill", "list"], summary: "List skills", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 213, title: "mcps", binary: "defenseclaw", arguments: ["mcp", "list"], summary: "List MCP servers", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 214, title: "plugins", binary: "defenseclaw", arguments: ["plugin", "list"], summary: "List plugins", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 215, title: "tools", binary: "defenseclaw", arguments: ["tool", "list"], summary: "List tools", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 216, title: "alerts", binary: "defenseclaw", arguments: ["alerts", "--no-tui"], summary: "List alerts", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 217, title: "alerts acknowledge", binary: "defenseclaw", arguments: ["alerts", "acknowledge"], summary: "Acknowledge alerts by severity", category: "enforce", requiresInput: true, usage: "--severity HIGH"),
        CommandDefinition(id: 218, title: "alerts dismiss", binary: "defenseclaw", arguments: ["alerts", "dismiss"], summary: "Dismiss alerts by severity", category: "enforce", requiresInput: true, usage: "--severity HIGH"),
        CommandDefinition(id: 219, title: "audit log-activity", binary: "defenseclaw", arguments: ["audit", "log-activity"], summary: "Log operator activity (payload via --payload-file)", category: "other", requiresInput: true, usage: "--payload-file <path>"),
        CommandDefinition(id: 220, title: "fix credentials", binary: "defenseclaw", arguments: ["keys", "fill-missing", "--yes"], summary: "List missing required credentials", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 221, title: "setup connector", binary: "defenseclaw", arguments: ["setup"], summary: "Open connector setup choices in the CLI", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 222, title: "restart gateway", binary: "defenseclaw-gateway", arguments: ["restart"], summary: "Restart the gateway sidecar", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 223, title: "open setup", binary: "defenseclaw", arguments: ["setup"], summary: "Jump to the TUI Setup panel", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 224, title: "readiness", binary: "defenseclaw", arguments: ["doctor"], summary: "Run health checks that feed Setup Readiness", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 225, title: "help", binary: "defenseclaw", arguments: ["--help"], summary: "Show CLI help", category: "info", requiresInput: false, usage: ""),
    ]
}
