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

// CommandRegistry.all is generated from cli/defenseclaw/tui/registry_data.py:
// run scripts/sync-macos-command-registry.py after a palette change or an
// upstream import (make macos-app-test-scripts fails when they differ).

import Foundation

enum ShellQuoting {
    private static let safeCharacters = CharacterSet(
        charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-"
    )

    static func quote(_ value: String) -> String {
        guard value.isEmpty || !value.unicodeScalars.allSatisfy(safeCharacters.contains) else { return value }
        return "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}

/// `keys set` secret transport. Runtime 1.0.0+ documents `--value-stdin`
/// ("read the value from the first line of stdin; for scripts and the TUI")
/// as the non-interactive path; without it the CLI falls into click's hidden
/// prompt, which reads /dev/tty when the app has a controlling terminal and
/// only falls back to the stdin pipe otherwise. The flag is appended only when
/// the installed runtime is known to accept it, so a pre-1.0 runtime keeps
/// the prompt-fallback path that works for it.
enum SecretStandardInputTransport {
    static let flag = "--value-stdin"

    static func supportsValueStandardInput(runtimeVersion: String?) -> Bool {
        guard let runtimeVersion,
              let major = runtimeVersion.split(separator: ".").first.flatMap({ Int($0) })
        else { return false }
        return major >= 1
    }

    /// The argv to run for a command whose secret travels over stdin.
    static func arguments(
        _ arguments: [String],
        binary: String,
        standardInput: String?,
        runtimeVersion: String?
    ) -> [String] {
        guard standardInput != nil, binary == "defenseclaw",
              arguments.prefix(2) == ["keys", "set"],
              !arguments.contains(flag),
              supportsValueStandardInput(runtimeVersion: runtimeVersion)
        else { return arguments }
        return arguments + [flag]
    }
}

struct CommandDefinition: Identifiable, Hashable, Sendable {
    let title: String
    let binary: String
    let arguments: [String]
    let summary: String
    let category: String
    let requiresInput: Bool
    let usage: String

    /// Stable command identity derived from the command itself. The legacy
    /// numeric initializer argument is accepted for source-table parity but
    /// cannot create duplicate SwiftUI identifiers when rows are reordered.
    var id: String { ([binary] + arguments + [title]).joined(separator: "\u{1F}") }

    init(
        id _: Int,
        title: String,
        binary: String,
        arguments: [String],
        summary: String,
        category: String,
        requiresInput: Bool,
        usage: String
    ) {
        self.title = title
        self.binary = binary
        self.arguments = arguments
        self.summary = summary
        self.category = category
        self.requiresInput = requiresInput
        self.usage = usage
    }

    var isDestructive: Bool {
        let tokens = arguments.map { $0.lowercased() }
        return !Set(tokens).isDisjoint(with: ["remove", "rm", "delete", "reset", "uninstall", "quarantine", "teardown", "destroy"])
    }

    var changesState: Bool {
        let tokens = arguments.map { $0.lowercased() }
        // Scan commands refresh on-disk caches, and doctor always rewrites
        // doctor_cache.json even when it only reports checks. Treat those as
        // mutations so managed/invalid installations cannot bypass the
        // lower-level CLIRunner gate through the command palette.
        if category == "scan" || tokens.first == "doctor" { return true }
        if tokens.starts(with: ["agent", "discover"]) { return true }
        return category != "info"
    }

    var requiresTerminal: Bool {
        summary.localizedCaseInsensitiveContains("interactive")
            || arguments.last == "shell"
            || title == "setup galileo"
    }

    var acceptsSecretInput: Bool {
        title == "keys set"
    }

    func invocation(extraArguments: [String], secretInput: String) throws -> CommandInvocation {
        guard acceptsSecretInput else {
            let invocationArguments = arguments + extraArguments
            let suppliesAlertConfirmation = invocationArguments.starts(with: ["alerts", "acknowledge"])
                || invocationArguments.starts(with: ["alerts", "dismiss"])
            return CommandInvocation(
                arguments: invocationArguments,
                standardInput: suppliesAlertConfirmation ? "y" : nil
            )
        }
        guard extraArguments.count == 1,
              extraArguments[0].range(
                  of: "^[A-Za-z_][A-Za-z0-9_]*$",
                  options: .regularExpression
              ) != nil else {
            throw CommandInvocationError.invalidCredentialName
        }
        guard !secretInput.isEmpty else {
            throw CommandInvocationError.missingCredentialValue
        }
        return CommandInvocation(
            arguments: arguments + extraArguments,
            standardInput: secretInput
        )
    }

    /// `keys set` must receive its credential over stdin. Keeping this
    /// property on the registry entry gives every command-palette surface the
    /// same source of truth for rendering, validation, and execution.
    var requiresSecretStandardInput: Bool {
        binary == "defenseclaw" && arguments == ["keys", "set"]
    }

    func displayCommand(extraArguments: [String] = []) -> String {
        // Never echo legacy `--value <secret>` input into the preview or the
        // pasteboard. The execution plan below rejects it as well.
        let visibleArguments = requiresSecretStandardInput
            ? Array(extraArguments.prefix(1))
            : extraArguments
        return ([binary] + arguments + visibleArguments).map(ShellQuoting.quote).joined(separator: " ")
    }

    func executionPlan(
        extraArguments: [String] = [],
        secretInput: String? = nil
    ) throws -> CommandExecutionPlan {
        guard requiresSecretStandardInput else {
            return CommandExecutionPlan(arguments: arguments + extraArguments, standardInput: nil)
        }
        let environmentName = extraArguments.first ?? ""
        let environmentNameRange = environmentName.startIndex..<environmentName.endIndex
        guard extraArguments.count == 1,
              environmentName.range(
                  of: #"^[A-Za-z_][A-Za-z0-9_]*$"#,
                  options: .regularExpression
              ) == environmentNameRange else {
            throw CommandExecutionPlan.Error.invalidCredentialName
        }
        guard let secretInput, !secretInput.isEmpty else {
            throw CommandExecutionPlan.Error.missingSecret
        }
        return CommandExecutionPlan(
            arguments: arguments + [environmentName],
            standardInput: secretInput
        )
    }
}

struct CommandExecutionPlan: Equatable, Sendable {
    enum Error: LocalizedError {
        case invalidCredentialName
        case missingSecret

        var errorDescription: String? {
            switch self {
            case .invalidCredentialName:
                "Enter one environment name using letters, digits, and underscores."
            case .missingSecret:
                "Enter the secret value."
            }
        }
    }

    let arguments: [String]
    let standardInput: String?
}

struct CommandInvocation: Equatable, Sendable {
    let arguments: [String]
    let standardInput: String?
}

enum CommandInvocationError: LocalizedError, Equatable {
    case invalidCredentialName
    case missingCredentialValue

    var errorDescription: String? {
        switch self {
        case .invalidCredentialName:
            return "Enter one credential environment name."
        case .missingCredentialValue:
            return "Enter the credential value."
        }
    }
}

enum CommandRegistry {
    static var sourceCount: Int { all.count }
    static let all: [CommandDefinition] = [
        CommandDefinition(id: 0, title: "init", binary: "defenseclaw", arguments: ["init"], summary: "Initialize DefenseClaw", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 1, title: "init first-run", binary: "defenseclaw", arguments: ["init", "--non-interactive", "--yes", "--verify"], summary: "Run guided first-run backend with defaults", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 2, title: "quickstart", binary: "defenseclaw", arguments: ["quickstart"], summary: "Compatibility first-run wrapper", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 3, title: "setup llm", binary: "defenseclaw", arguments: ["setup", "llm"], summary: "Configure the unified LLM interactively", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 4, title: "setup llm show", binary: "defenseclaw", arguments: ["setup", "llm", "--show"], summary: "Show unified LLM settings", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 5, title: "setup migrate-llm", binary: "defenseclaw", arguments: ["setup", "migrate-llm"], summary: "Migrate legacy LLM config into unified llm: block", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 6, title: "setup skill-scanner", binary: "defenseclaw", arguments: ["setup", "skill-scanner"], summary: "Configure skill scanner (interactive)", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 7, title: "setup mcp-scanner", binary: "defenseclaw", arguments: ["setup", "mcp-scanner"], summary: "Configure MCP scanner (interactive)", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 8, title: "setup openclaw", binary: "defenseclaw", arguments: ["setup", "openclaw", "--yes"], summary: "Configure OpenClaw guardrail setup", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 9, title: "setup zeptoclaw", binary: "defenseclaw", arguments: ["setup", "zeptoclaw", "--yes"], summary: "Configure ZeptoClaw guardrail setup", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 10, title: "setup codex", binary: "defenseclaw", arguments: ["setup", "codex", "--yes"], summary: "Configure Codex observability hooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 11, title: "setup claude-code", binary: "defenseclaw", arguments: ["setup", "claude-code", "--yes"], summary: "Configure Claude Code observability hooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 12, title: "setup hermes", binary: "defenseclaw", arguments: ["setup", "hermes", "--yes"], summary: "Configure supported Hermes hooks (JSON block; failures open)", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 13, title: "setup cursor", binary: "defenseclaw", arguments: ["setup", "cursor", "--yes"], summary: "Configure supported Cursor action or observe hooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 14, title: "setup devin", binary: "defenseclaw", arguments: ["setup", "devin", "--yes"], summary: "Configure Devin project hooks and local catalogs", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 15, title: "setup copilot", binary: "defenseclaw", arguments: ["setup", "copilot", "--yes"], summary: "Configure supported Copilot CLI hooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 16, title: "setup antigravity", binary: "defenseclaw", arguments: ["setup", "antigravity", "--yes"], summary: "Configure supported Antigravity hooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 17, title: "setup opencode", binary: "defenseclaw", arguments: ["setup", "opencode", "--yes"], summary: "Configure OpenCode observability hooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 18, title: "setup amp", binary: "defenseclaw", arguments: ["setup", "amp", "--yes"], summary: "Configure Amp synchronous policy plugin", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 19, title: "setup kiro", binary: "defenseclaw", arguments: ["setup", "kiro", "--yes"], summary: "Configure the Kiro IDE or CLI connector", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 20, title: "setup cowork", binary: "defenseclaw", arguments: ["setup", "cowork", "--yes"], summary: "Build the Claude Cowork plugin (sets up Claude Code hooks if off)", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 21, title: "setup rotate-token", binary: "defenseclaw", arguments: ["setup", "rotate-token", "--yes"], summary: "Rotate gateway and scoped hook tokens", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 22, title: "setup gateway", binary: "defenseclaw", arguments: ["setup", "gateway"], summary: "Configure gateway connection (interactive)", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 23, title: "setup guardrail", binary: "defenseclaw", arguments: ["setup", "guardrail"], summary: "Configure LLM guardrail", category: "setup", requiresInput: false, usage: ""),
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
        CommandDefinition(id: 38, title: "setup galileo", binary: "defenseclaw", arguments: ["setup", "galileo"], summary: "Configure Galileo Cloud or self-hosted OTLP traces", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 39, title: "setup galileo status", binary: "defenseclaw", arguments: ["setup", "galileo", "status"], summary: "Show Galileo destination status", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 40, title: "setup galileo test", binary: "defenseclaw", arguments: ["setup", "galileo", "test"], summary: "Send a Galileo OTLP canary trace", category: "scan", requiresInput: false, usage: ""),
        CommandDefinition(id: 41, title: "setup webhook add", binary: "defenseclaw", arguments: ["setup", "webhook", "add"], summary: "Add a notifier webhook", category: "setup", requiresInput: true, usage: "<name> --type <slack|teams|pagerduty|generic>"),
        CommandDefinition(id: 42, title: "setup webhook list", binary: "defenseclaw", arguments: ["setup", "webhook", "list"], summary: "List notifier webhooks", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 43, title: "setup webhook show", binary: "defenseclaw", arguments: ["setup", "webhook", "show"], summary: "Show a notifier webhook", category: "setup", requiresInput: true, usage: "<name>"),
        CommandDefinition(id: 44, title: "setup webhook enable", binary: "defenseclaw", arguments: ["setup", "webhook", "enable"], summary: "Enable a notifier webhook", category: "setup", requiresInput: true, usage: "<name>"),
        CommandDefinition(id: 45, title: "setup webhook disable", binary: "defenseclaw", arguments: ["setup", "webhook", "disable"], summary: "Disable a notifier webhook", category: "setup", requiresInput: true, usage: "<name>"),
        CommandDefinition(id: 46, title: "setup webhook remove", binary: "defenseclaw", arguments: ["setup", "webhook", "remove", "--yes"], summary: "Remove a notifier webhook", category: "setup", requiresInput: true, usage: "<name>"),
        CommandDefinition(id: 47, title: "setup webhook test", binary: "defenseclaw", arguments: ["setup", "webhook", "test"], summary: "Send/probe a notifier webhook", category: "setup", requiresInput: true, usage: "<name>"),
        CommandDefinition(id: 48, title: "setup provider add", binary: "defenseclaw", arguments: ["setup", "provider", "add"], summary: "Add a custom LLM provider to the overlay", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 49, title: "setup provider remove", binary: "defenseclaw", arguments: ["setup", "provider", "remove"], summary: "Remove a custom LLM provider from the overlay", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 50, title: "setup provider list", binary: "defenseclaw", arguments: ["setup", "provider", "list"], summary: "List overlay provider entries", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 51, title: "setup provider show", binary: "defenseclaw", arguments: ["setup", "provider", "show"], summary: "Show merged provider registry", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 52, title: "agent discover", binary: "defenseclaw", arguments: ["agent", "discover"], summary: "Discover installed agents and emit sanitized telemetry", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 53, title: "agent usage", binary: "defenseclaw", arguments: ["agent", "usage"], summary: "Show continuous AI visibility from the sidecar", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 54, title: "agent usage --refresh", binary: "defenseclaw", arguments: ["agent", "usage", "--refresh"], summary: "Trigger an AI-usage scan and render results", category: "scan", requiresInput: false, usage: ""),
        CommandDefinition(id: 55, title: "agent discovery setup", binary: "defenseclaw", arguments: ["agent", "discovery", "setup"], summary: "Interactive AI discovery wizard (mode, intervals, sources)", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 56, title: "agent discovery enable", binary: "defenseclaw", arguments: ["agent", "discovery", "enable", "--yes"], summary: "Enable AI discovery, save config, restart, and scan", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 57, title: "agent discovery disable", binary: "defenseclaw", arguments: ["agent", "discovery", "disable", "--yes"], summary: "Disable AI discovery and restart the gateway", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 58, title: "agent discovery status", binary: "defenseclaw", arguments: ["agent", "discovery", "status"], summary: "Show on-disk vs live AI discovery state", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 59, title: "agent discovery scan", binary: "defenseclaw", arguments: ["agent", "discovery", "scan"], summary: "Trigger one immediate AI discovery scan", category: "scan", requiresInput: false, usage: ""),
        CommandDefinition(id: 60, title: "agent discovery runtime enable", binary: "defenseclaw", arguments: ["agent", "discovery", "runtime", "enable", "--yes", "--no-enable-host-plane"], summary: "Enable user-level runtime planes and restart", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 61, title: "agent discovery runtime scan", binary: "defenseclaw", arguments: ["agent", "discovery", "runtime", "scan"], summary: "Poll the runtime planes now", category: "scan", requiresInput: false, usage: ""),
        CommandDefinition(id: 62, title: "agent discovery runtime permissions", binary: "defenseclaw", arguments: ["agent", "discovery", "runtime", "permissions"], summary: "Show the host grants each runtime plane needs", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 63, title: "agent signatures list", binary: "defenseclaw", arguments: ["agent", "signatures", "list"], summary: "List the merged AI discovery signature catalog", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 64, title: "scan skill", binary: "defenseclaw", arguments: ["skill", "scan"], summary: "Scan a skill", category: "scan", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 65, title: "scan skill --all", binary: "defenseclaw", arguments: ["skill", "scan", "--all"], summary: "Scan all skills", category: "scan", requiresInput: false, usage: ""),
        CommandDefinition(id: 66, title: "scan mcp", binary: "defenseclaw", arguments: ["mcp", "scan"], summary: "Scan an MCP server", category: "scan", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 67, title: "scan mcp --all", binary: "defenseclaw", arguments: ["mcp", "scan", "--all"], summary: "Scan all MCP servers", category: "scan", requiresInput: false, usage: ""),
        CommandDefinition(id: 68, title: "scan plugin", binary: "defenseclaw", arguments: ["plugin", "scan"], summary: "Scan a plugin", category: "scan", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 69, title: "scan aibom", binary: "defenseclaw", arguments: ["aibom", "scan"], summary: "Generate AIBOM inventory", category: "scan", requiresInput: false, usage: ""),
        CommandDefinition(id: 70, title: "scan code", binary: "defenseclaw-gateway", arguments: ["scan", "code"], summary: "CodeGuard scan", category: "scan", requiresInput: true, usage: "<path>"),
        CommandDefinition(id: 71, title: "block skill", binary: "defenseclaw", arguments: ["skill", "block"], summary: "Block a skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 72, title: "allow skill", binary: "defenseclaw", arguments: ["skill", "allow"], summary: "Allow-list a skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 73, title: "unblock skill", binary: "defenseclaw", arguments: ["skill", "unblock"], summary: "Unblock a skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 74, title: "disable skill", binary: "defenseclaw", arguments: ["skill", "disable"], summary: "Disable a skill at runtime", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 75, title: "enable skill", binary: "defenseclaw", arguments: ["skill", "enable"], summary: "Enable a skill at runtime", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 76, title: "quarantine skill", binary: "defenseclaw", arguments: ["skill", "quarantine"], summary: "Quarantine a skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 77, title: "restore skill", binary: "defenseclaw", arguments: ["skill", "restore"], summary: "Restore a quarantined skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 78, title: "block mcp", binary: "defenseclaw", arguments: ["mcp", "block"], summary: "Block an MCP server", category: "enforce", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 79, title: "allow mcp", binary: "defenseclaw", arguments: ["mcp", "allow"], summary: "Allow-list an MCP server", category: "enforce", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 80, title: "unblock mcp", binary: "defenseclaw", arguments: ["mcp", "unblock"], summary: "Unblock an MCP server", category: "enforce", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 81, title: "set mcp", binary: "defenseclaw", arguments: ["mcp", "set"], summary: "Scan + set MCP server in the active connector's config", category: "enforce", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 82, title: "unset mcp", binary: "defenseclaw", arguments: ["mcp", "unset"], summary: "Unset MCP server from the active connector's config", category: "enforce", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 83, title: "block plugin", binary: "defenseclaw", arguments: ["plugin", "block"], summary: "Block a plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 84, title: "allow plugin", binary: "defenseclaw", arguments: ["plugin", "allow"], summary: "Allow-list a plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 85, title: "disable plugin", binary: "defenseclaw", arguments: ["plugin", "disable"], summary: "Disable a plugin at runtime", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 86, title: "enable plugin", binary: "defenseclaw", arguments: ["plugin", "enable"], summary: "Enable a plugin at runtime", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 87, title: "quarantine plugin", binary: "defenseclaw", arguments: ["plugin", "quarantine"], summary: "Quarantine a plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 88, title: "restore plugin", binary: "defenseclaw", arguments: ["plugin", "restore"], summary: "Restore a quarantined plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 89, title: "remove plugin", binary: "defenseclaw", arguments: ["plugin", "remove"], summary: "Remove a plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 90, title: "block tool", binary: "defenseclaw", arguments: ["tool", "block"], summary: "Block a tool", category: "enforce", requiresInput: true, usage: "<tool-name>"),
        CommandDefinition(id: 91, title: "allow tool", binary: "defenseclaw", arguments: ["tool", "allow"], summary: "Allow-list a tool", category: "enforce", requiresInput: true, usage: "<tool-name>"),
        CommandDefinition(id: 92, title: "unblock tool", binary: "defenseclaw", arguments: ["tool", "unblock"], summary: "Unblock a tool", category: "enforce", requiresInput: true, usage: "<tool-name>"),
        CommandDefinition(id: 93, title: "install skill", binary: "defenseclaw", arguments: ["skill", "install"], summary: "Install a skill from ClawHub", category: "install", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 94, title: "install plugin", binary: "defenseclaw", arguments: ["plugin", "install"], summary: "Install a plugin", category: "install", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 95, title: "install codeguard", binary: "defenseclaw", arguments: ["codeguard", "install-skill"], summary: "Install CodeGuard skill", category: "install", requiresInput: false, usage: ""),
        CommandDefinition(id: 96, title: "policy list", binary: "defenseclaw", arguments: ["policy", "list"], summary: "List policies", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 97, title: "policy show", binary: "defenseclaw", arguments: ["policy", "show"], summary: "Show policy details", category: "policy", requiresInput: true, usage: "<policy-name>"),
        CommandDefinition(id: 98, title: "policy create", binary: "defenseclaw", arguments: ["policy", "create"], summary: "Create a new policy", category: "policy", requiresInput: true, usage: "<policy-name>"),
        CommandDefinition(id: 99, title: "policy activate", binary: "defenseclaw", arguments: ["policy", "activate"], summary: "Activate a policy", category: "policy", requiresInput: true, usage: "<policy-name>"),
        CommandDefinition(id: 100, title: "policy delete", binary: "defenseclaw", arguments: ["policy", "delete"], summary: "Delete a user policy", category: "policy", requiresInput: true, usage: "<policy-name>"),
        CommandDefinition(id: 101, title: "policy validate", binary: "defenseclaw", arguments: ["policy", "validate"], summary: "Validate policy data + Rego", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 102, title: "policy test", binary: "defenseclaw", arguments: ["policy", "test"], summary: "Run OPA policy tests", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 103, title: "policy edit actions", binary: "defenseclaw", arguments: ["policy", "edit", "actions"], summary: "Edit severity action rules", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 104, title: "policy edit scanner", binary: "defenseclaw", arguments: ["policy", "edit", "scanner"], summary: "Edit scanner overrides", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 105, title: "policy edit guardrail", binary: "defenseclaw", arguments: ["policy", "edit", "guardrail"], summary: "Edit guardrail policy", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 106, title: "policy edit firewall", binary: "defenseclaw", arguments: ["policy", "edit", "firewall"], summary: "Edit firewall policy", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 107, title: "policy evaluate", binary: "defenseclaw-gateway", arguments: ["policy", "evaluate"], summary: "Dry-run admission evaluation", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 108, title: "policy reload", binary: "defenseclaw-gateway", arguments: ["policy", "reload"], summary: "Reload policy in running sidecar", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 109, title: "list skills", binary: "defenseclaw", arguments: ["skill", "list"], summary: "List skills with scan status", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 110, title: "list mcps", binary: "defenseclaw", arguments: ["mcp", "list"], summary: "List MCP servers with status", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 111, title: "list plugins", binary: "defenseclaw", arguments: ["plugin", "list"], summary: "List installed plugins", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 112, title: "list tools", binary: "defenseclaw", arguments: ["tool", "list"], summary: "List tool rules", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 113, title: "info skill", binary: "defenseclaw", arguments: ["skill", "info"], summary: "Show skill details", category: "info", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 114, title: "info plugin", binary: "defenseclaw", arguments: ["plugin", "info"], summary: "Show plugin details", category: "info", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 115, title: "tool status", binary: "defenseclaw", arguments: ["tool", "status"], summary: "Show tool block/allow status", category: "info", requiresInput: true, usage: "<tool-name>"),
        CommandDefinition(id: 116, title: "status", binary: "defenseclaw", arguments: ["status"], summary: "Show DefenseClaw status", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 117, title: "doctor", binary: "defenseclaw", arguments: ["doctor"], summary: "Run health checks", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 118, title: "doctor run", binary: "defenseclaw", arguments: ["doctor"], summary: "Run health checks", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 119, title: "doctor --fix", binary: "defenseclaw", arguments: ["doctor", "--fix", "--yes"], summary: "Auto-repair safe health issues", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 120, title: "sandbox status", binary: "defenseclaw", arguments: ["sandbox", "status"], summary: "Show the OpenShell sandbox subsystem", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 121, title: "sandbox list", binary: "defenseclaw", arguments: ["sandbox", "list"], summary: "List OpenShell sandboxes", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 122, title: "sandbox doctor", binary: "defenseclaw", arguments: ["sandbox", "doctor"], summary: "Check that this machine can run sandboxes", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 123, title: "sandbox setup", binary: "defenseclaw", arguments: ["sandbox", "setup"], summary: "One-time sandbox setup (interactive; or use Setup → Sandboxes (OpenShell))", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 124, title: "sandbox approvals", binary: "defenseclaw", arguments: ["sandbox", "approvals"], summary: "List the asks waiting for you", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 125, title: "sandbox activity", binary: "defenseclaw", arguments: ["sandbox", "activity"], summary: "Show the sandbox activity feed", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 126, title: "sandbox policy explain", binary: "defenseclaw", arguments: ["sandbox", "policy", "explain"], summary: "Show the sandbox policy and where each setting comes from", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 127, title: "sandbox pack list", binary: "defenseclaw", arguments: ["sandbox", "pack", "list"], summary: "List sandbox policy packs", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 128, title: "sandbox image list", binary: "defenseclaw", arguments: ["sandbox", "image", "list"], summary: "List the harness images", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 129, title: "sandbox image build", binary: "defenseclaw", arguments: ["sandbox", "image", "build"], summary: "Build and hook-verify harness images", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 130, title: "sandbox image rm", binary: "defenseclaw", arguments: ["sandbox", "image", "rm", "--yes"], summary: "Remove a harness's images (and on a Mac its MicroVM disks)", category: "setup", requiresInput: true, usage: "<harness>"),
        CommandDefinition(id: 131, title: "sandbox review", binary: "defenseclaw", arguments: ["sandbox", "review"], summary: "Review a sandbox session's changes", category: "info", requiresInput: true, usage: "<sandbox>"),
        CommandDefinition(id: 132, title: "sandbox stop", binary: "defenseclaw", arguments: ["sandbox", "stop"], summary: "Stop a sandbox (kept for connect)", category: "sandbox", requiresInput: true, usage: "<sandbox>"),
        CommandDefinition(id: 133, title: "sandbox start", binary: "defenseclaw", arguments: ["sandbox", "start"], summary: "Start a stopped sandbox", category: "sandbox", requiresInput: true, usage: "<sandbox>"),
        CommandDefinition(id: 134, title: "sandbox delete", binary: "defenseclaw", arguments: ["sandbox", "delete", "--yes"], summary: "Delete a sandbox with its providers and snapshot", category: "sandbox", requiresInput: true, usage: "<sandbox>"),
        CommandDefinition(id: 135, title: "sandbox unblock", binary: "defenseclaw", arguments: ["sandbox", "unblock"], summary: "Lift an egress block (--sandbox NAME or --always)", category: "sandbox", requiresInput: true, usage: "<host> --sandbox <name>"),
        CommandDefinition(id: 136, title: "sandbox enable", binary: "defenseclaw", arguments: ["sandbox", "enable"], summary: "Make a harness command run sandboxed (shell wrapper)", category: "setup", requiresInput: true, usage: "<harness>"),
        CommandDefinition(id: 137, title: "substrate login", binary: "defenseclaw", arguments: ["substrate", "login"], summary: "Sign in to Agent Substrate (interactive)", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 138, title: "substrate run claude", binary: "defenseclaw", arguments: ["substrate", "run", "claude"], summary: "Start Claude Code in an Agent Substrate cluster", category: "sandbox", requiresInput: false, usage: ""),
        CommandDefinition(id: 139, title: "substrate list", binary: "defenseclaw", arguments: ["substrate", "list"], summary: "List your Agent Substrate agents", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 140, title: "substrate connect", binary: "defenseclaw", arguments: ["substrate", "connect"], summary: "Put a running Agent Substrate agent on this terminal", category: "sandbox", requiresInput: true, usage: "<name>"),
        CommandDefinition(id: 141, title: "substrate pull", binary: "defenseclaw", arguments: ["substrate", "pull"], summary: "Review an Agent Substrate agent's changes and bring them home", category: "sandbox", requiresInput: true, usage: "<name>"),
        CommandDefinition(id: 142, title: "substrate approvals", binary: "defenseclaw", arguments: ["substrate", "approvals"], summary: "List what your Agent Substrate agents wait for you to approve", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 143, title: "substrate doctor", binary: "defenseclaw", arguments: ["substrate", "doctor"], summary: "Check that this machine can reach Agent Substrate", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 144, title: "substrate usage", binary: "defenseclaw", arguments: ["substrate", "usage"], summary: "Show what your Agent Substrate agents used", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 145, title: "sandbox disable", binary: "defenseclaw", arguments: ["sandbox", "disable"], summary: "Stop a harness command from running sandboxed", category: "setup", requiresInput: true, usage: "<harness>"),
        CommandDefinition(id: 146, title: "config validate", binary: "defenseclaw", arguments: ["config", "validate"], summary: "Validate config.yaml", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 147, title: "config show", binary: "defenseclaw", arguments: ["config", "show"], summary: "Show every config section with secrets masked", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 148, title: "config get", binary: "defenseclaw", arguments: ["config", "get"], summary: "Print one config value by dotted key", category: "info", requiresInput: true, usage: "<key>"),
        CommandDefinition(id: 149, title: "config show effective observability", binary: "defenseclaw", arguments: ["config", "show", "--effective", "--section", "observability"], summary: "Show effective observability policy", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 150, title: "config reference observability", binary: "defenseclaw", arguments: ["config", "reference", "observability"], summary: "Show the complete observability reference", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 151, title: "observability plan", binary: "defenseclaw", arguments: ["observability", "plan"], summary: "Show collection and destination routing plan", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 152, title: "config path", binary: "defenseclaw", arguments: ["config", "path"], summary: "Show DefenseClaw filesystem paths", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 153, title: "keys list", binary: "defenseclaw", arguments: ["keys", "list"], summary: "List configured and missing credentials", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 154, title: "keys list --json", binary: "defenseclaw", arguments: ["keys", "list", "--json"], summary: "List credentials as JSON for setup parity", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 155, title: "keys check", binary: "defenseclaw", arguments: ["keys", "check"], summary: "Fail if required credentials are missing", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 156, title: "keys set", binary: "defenseclaw", arguments: ["keys", "set"], summary: "Persist a credential to the DefenseClaw .env", category: "setup", requiresInput: true, usage: "<ENV_NAME>"),
        CommandDefinition(id: 157, title: "keys remove", binary: "defenseclaw", arguments: ["keys", "remove", "--yes"], summary: "Remove a credential from the DefenseClaw .env", category: "setup", requiresInput: true, usage: "<ENV_NAME>"),
        CommandDefinition(id: 158, title: "keys fill-missing", binary: "defenseclaw", arguments: ["keys", "fill-missing", "--yes"], summary: "List missing required credentials", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 159, title: "settings save", binary: "defenseclaw", arguments: ["settings", "save"], summary: "Persist current settings/config", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 160, title: "guardrail status", binary: "defenseclaw", arguments: ["guardrail", "status"], summary: "Show guardrail status", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 161, title: "guardrail enable", binary: "defenseclaw", arguments: ["guardrail", "enable", "--yes"], summary: "Enable guardrail", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 162, title: "guardrail disable", binary: "defenseclaw", arguments: ["guardrail", "disable", "--yes"], summary: "Disable guardrail", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 163, title: "guardrail list-packs", binary: "defenseclaw", arguments: ["guardrail", "list-packs"], summary: "List rule packs and the pack each connector enforces", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 164, title: "guardrail validate-pack", binary: "defenseclaw", arguments: ["guardrail", "validate-pack"], summary: "Validate a rule pack folder offline", category: "info", requiresInput: true, usage: "<path>"),
        CommandDefinition(id: 165, title: "guardrail use-pack", binary: "defenseclaw", arguments: ["guardrail", "use-pack"], summary: "Switch the rule pack (add --connector NAME for one connector)", category: "policy", requiresInput: true, usage: "<pack>"),
        CommandDefinition(id: 166, title: "guardrail mode", binary: "defenseclaw", arguments: ["guardrail", "mode"], summary: "Switch between observe and action (add --connector NAME for one connector)", category: "policy", requiresInput: true, usage: "<observe|action>"),
        CommandDefinition(id: 167, title: "guardrail block-at", binary: "defenseclaw", arguments: ["guardrail", "block-at"], summary: "Set the guardrail block level for tool calls, prompts and LLM traffic (add --connector NAME for one connector)", category: "policy", requiresInput: true, usage: "<CRITICAL|HIGH|MEDIUM|LOW|inherit>"),
        CommandDefinition(id: 168, title: "guardrail alert-at", binary: "defenseclaw", arguments: ["guardrail", "alert-at"], summary: "Set the guardrail alert level for tool calls, prompts and LLM traffic (add --connector NAME for one connector)", category: "policy", requiresInput: true, usage: "<CRITICAL|HIGH|MEDIUM|LOW|inherit>"),
        CommandDefinition(id: 169, title: "guardrail protection list", binary: "defenseclaw", arguments: ["guardrail", "protection", "list"], summary: "List the opt-in protection packs and where each is on", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 170, title: "guardrail protection enable", binary: "defenseclaw", arguments: ["guardrail", "protection", "enable"], summary: "Turn an opt-in protection pack on (add --connector NAME for one connector)", category: "policy", requiresInput: true, usage: "<pack>"),
        CommandDefinition(id: 171, title: "guardrail protection disable", binary: "defenseclaw", arguments: ["guardrail", "protection", "disable"], summary: "Turn an opt-in protection pack off (add --connector NAME for one connector)", category: "policy", requiresInput: true, usage: "<pack>"),
        CommandDefinition(id: 172, title: "version", binary: "defenseclaw", arguments: ["version"], summary: "Show DefenseClaw version information", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 173, title: "start", binary: "defenseclaw-gateway", arguments: ["start"], summary: "Start gateway sidecar", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 174, title: "stop", binary: "defenseclaw-gateway", arguments: ["stop"], summary: "Stop gateway sidecar", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 175, title: "restart", binary: "defenseclaw-gateway", arguments: ["restart"], summary: "Restart gateway sidecar", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 176, title: "gateway status", binary: "defenseclaw-gateway", arguments: ["status"], summary: "Show gateway health", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 177, title: "watchdog start", binary: "defenseclaw-gateway", arguments: ["watchdog", "start"], summary: "Start health watchdog", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 178, title: "watchdog stop", binary: "defenseclaw-gateway", arguments: ["watchdog", "stop"], summary: "Stop health watchdog", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 179, title: "watchdog status", binary: "defenseclaw-gateway", arguments: ["watchdog", "status"], summary: "Show watchdog status", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 180, title: "connector verify", binary: "defenseclaw-gateway", arguments: ["connector", "verify"], summary: "Verify connector config is clean/current", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 181, title: "connector teardown", binary: "defenseclaw-gateway", arguments: ["connector", "teardown"], summary: "Remove active connector config patches", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 182, title: "connector list-backups", binary: "defenseclaw-gateway", arguments: ["connector", "list-backups"], summary: "List connector backup files", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 183, title: "gateway audit export", binary: "defenseclaw-gateway", arguments: ["audit", "export"], summary: "Export gateway audit log", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 184, title: "gateway provenance show", binary: "defenseclaw-gateway", arguments: ["provenance", "show"], summary: "Show gateway binary/config provenance", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 185, title: "upgrade", binary: "defenseclaw", arguments: ["upgrade", "--yes"], summary: "Upgrade DefenseClaw", category: "other", requiresInput: false, usage: ""),
        CommandDefinition(id: 186, title: "uninstall dry-run", binary: "defenseclaw", arguments: ["uninstall", "--dry-run"], summary: "Preview uninstall changes without modifying the system", category: "other", requiresInput: false, usage: ""),
        CommandDefinition(id: 187, title: "uninstall --yes", binary: "defenseclaw", arguments: ["uninstall", "--yes"], summary: "Uninstall DefenseClaw after showing the plan", category: "other", requiresInput: false, usage: ""),
        CommandDefinition(id: 188, title: "uninstall --all --yes", binary: "defenseclaw", arguments: ["uninstall", "--all", "--yes"], summary: "Uninstall DefenseClaw and wipe local data", category: "other", requiresInput: false, usage: ""),
        CommandDefinition(id: 189, title: "reset --yes", binary: "defenseclaw", arguments: ["reset", "--yes"], summary: "Wipe DefenseClaw local data and keep binaries", category: "other", requiresInput: false, usage: ""),
        CommandDefinition(id: 190, title: "setup", binary: "defenseclaw", arguments: ["setup"], summary: "Show setup command help", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 191, title: "setup local-observability", binary: "defenseclaw", arguments: ["setup", "local-observability"], summary: "Show local observability commands", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 192, title: "setup observability", binary: "defenseclaw", arguments: ["setup", "observability"], summary: "Show observability sink commands", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 193, title: "setup provider", binary: "defenseclaw", arguments: ["setup", "provider"], summary: "Show provider registry commands", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 194, title: "setup webhook", binary: "defenseclaw", arguments: ["setup", "webhook"], summary: "Show webhook commands", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 195, title: "skill", binary: "defenseclaw", arguments: ["skill"], summary: "Show skill commands", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 196, title: "skill list", binary: "defenseclaw", arguments: ["skill", "list"], summary: "List skills with scan status", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 197, title: "skill search", binary: "defenseclaw", arguments: ["skill", "search"], summary: "Search available skills", category: "info", requiresInput: true, usage: "<query>"),
        CommandDefinition(id: 198, title: "skill scan", binary: "defenseclaw", arguments: ["skill", "scan"], summary: "Scan a skill", category: "scan", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 199, title: "skill info", binary: "defenseclaw", arguments: ["skill", "info"], summary: "Show skill details", category: "info", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 200, title: "skill allow", binary: "defenseclaw", arguments: ["skill", "allow"], summary: "Allow-list a skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 201, title: "skill block", binary: "defenseclaw", arguments: ["skill", "block"], summary: "Block a skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 202, title: "skill disable", binary: "defenseclaw", arguments: ["skill", "disable"], summary: "Disable a skill at runtime", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 203, title: "skill enable", binary: "defenseclaw", arguments: ["skill", "enable"], summary: "Enable a skill at runtime", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 204, title: "skill install", binary: "defenseclaw", arguments: ["skill", "install"], summary: "Install a skill from ClawHub", category: "install", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 205, title: "skill quarantine", binary: "defenseclaw", arguments: ["skill", "quarantine"], summary: "Quarantine a skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 206, title: "skill restore", binary: "defenseclaw", arguments: ["skill", "restore"], summary: "Restore a quarantined skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 207, title: "skill unblock", binary: "defenseclaw", arguments: ["skill", "unblock"], summary: "Unblock a skill", category: "enforce", requiresInput: true, usage: "<skill-name>"),
        CommandDefinition(id: 208, title: "mcp", binary: "defenseclaw", arguments: ["mcp"], summary: "Show MCP commands", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 209, title: "mcp list", binary: "defenseclaw", arguments: ["mcp", "list"], summary: "List MCP servers with status", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 210, title: "mcp scan", binary: "defenseclaw", arguments: ["mcp", "scan"], summary: "Scan an MCP server", category: "scan", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 211, title: "mcp allow", binary: "defenseclaw", arguments: ["mcp", "allow"], summary: "Allow-list an MCP server", category: "enforce", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 212, title: "mcp block", binary: "defenseclaw", arguments: ["mcp", "block"], summary: "Block an MCP server", category: "enforce", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 213, title: "mcp set", binary: "defenseclaw", arguments: ["mcp", "set"], summary: "Scan + set MCP server in the active connector's config", category: "enforce", requiresInput: true, usage: "<name> [--url <url>]"),
        CommandDefinition(id: 214, title: "mcp unblock", binary: "defenseclaw", arguments: ["mcp", "unblock"], summary: "Unblock an MCP server", category: "enforce", requiresInput: true, usage: "<url>"),
        CommandDefinition(id: 215, title: "mcp unset", binary: "defenseclaw", arguments: ["mcp", "unset"], summary: "Unset MCP server from the active connector's config", category: "enforce", requiresInput: true, usage: "<name-or-url>"),
        CommandDefinition(id: 216, title: "plugin", binary: "defenseclaw", arguments: ["plugin"], summary: "Show plugin commands", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 217, title: "plugin list", binary: "defenseclaw", arguments: ["plugin", "list"], summary: "List installed plugins", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 218, title: "plugin scan", binary: "defenseclaw", arguments: ["plugin", "scan"], summary: "Scan a plugin", category: "scan", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 219, title: "plugin info", binary: "defenseclaw", arguments: ["plugin", "info"], summary: "Show plugin details", category: "info", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 220, title: "plugin allow", binary: "defenseclaw", arguments: ["plugin", "allow"], summary: "Allow-list a plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 221, title: "plugin block", binary: "defenseclaw", arguments: ["plugin", "block"], summary: "Block a plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 222, title: "plugin disable", binary: "defenseclaw", arguments: ["plugin", "disable"], summary: "Disable a plugin at runtime", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 223, title: "plugin enable", binary: "defenseclaw", arguments: ["plugin", "enable"], summary: "Enable a plugin at runtime", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 224, title: "plugin install", binary: "defenseclaw", arguments: ["plugin", "install"], summary: "Install a plugin", category: "install", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 225, title: "plugin quarantine", binary: "defenseclaw", arguments: ["plugin", "quarantine"], summary: "Quarantine a plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 226, title: "plugin remove", binary: "defenseclaw", arguments: ["plugin", "remove"], summary: "Remove a plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 227, title: "plugin restore", binary: "defenseclaw", arguments: ["plugin", "restore"], summary: "Restore a quarantined plugin", category: "enforce", requiresInput: true, usage: "<plugin-name>"),
        CommandDefinition(id: 228, title: "tool", binary: "defenseclaw", arguments: ["tool"], summary: "Show tool commands", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 229, title: "tool list", binary: "defenseclaw", arguments: ["tool", "list"], summary: "List tool rules", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 230, title: "tool allow", binary: "defenseclaw", arguments: ["tool", "allow"], summary: "Allow-list a tool", category: "enforce", requiresInput: true, usage: "<tool-name>"),
        CommandDefinition(id: 231, title: "tool block", binary: "defenseclaw", arguments: ["tool", "block"], summary: "Block a tool", category: "enforce", requiresInput: true, usage: "<tool-name>"),
        CommandDefinition(id: 232, title: "tool unblock", binary: "defenseclaw", arguments: ["tool", "unblock"], summary: "Unblock a tool", category: "enforce", requiresInput: true, usage: "<tool-name>"),
        CommandDefinition(id: 233, title: "policy", binary: "defenseclaw", arguments: ["policy"], summary: "Show policy commands", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 234, title: "policy edit", binary: "defenseclaw", arguments: ["policy", "edit"], summary: "Show policy edit commands", category: "policy", requiresInput: false, usage: ""),
        CommandDefinition(id: 235, title: "keys", binary: "defenseclaw", arguments: ["keys"], summary: "Show credential commands", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 236, title: "config", binary: "defenseclaw", arguments: ["config"], summary: "Show config commands", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 237, title: "guardrail", binary: "defenseclaw", arguments: ["guardrail"], summary: "Show guardrail commands", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 238, title: "settings", binary: "defenseclaw", arguments: ["settings"], summary: "Show settings commands", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 239, title: "audit", binary: "defenseclaw", arguments: ["audit"], summary: "Show audit commands", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 240, title: "codeguard", binary: "defenseclaw", arguments: ["codeguard"], summary: "Show CodeGuard commands", category: "install", requiresInput: false, usage: ""),
        CommandDefinition(id: 241, title: "codeguard install-skill", binary: "defenseclaw", arguments: ["codeguard", "install-skill"], summary: "Install CodeGuard skill", category: "install", requiresInput: false, usage: ""),
        CommandDefinition(id: 242, title: "aibom", binary: "defenseclaw", arguments: ["aibom"], summary: "Show AIBOM commands", category: "scan", requiresInput: false, usage: ""),
        CommandDefinition(id: 243, title: "reset", binary: "defenseclaw", arguments: ["reset"], summary: "Run interactive local data reset", category: "other", requiresInput: false, usage: ""),
        CommandDefinition(id: 244, title: "uninstall", binary: "defenseclaw", arguments: ["uninstall"], summary: "Run interactive uninstall flow", category: "other", requiresInput: false, usage: ""),
        CommandDefinition(id: 245, title: "skills", binary: "defenseclaw", arguments: ["skill", "list"], summary: "List skills", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 246, title: "mcps", binary: "defenseclaw", arguments: ["mcp", "list"], summary: "List MCP servers", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 247, title: "plugins", binary: "defenseclaw", arguments: ["plugin", "list"], summary: "List plugins", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 248, title: "tools", binary: "defenseclaw", arguments: ["tool", "list"], summary: "List tools", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 249, title: "alerts", binary: "defenseclaw", arguments: ["alerts"], summary: "List alerts", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 250, title: "alerts acknowledge", binary: "defenseclaw", arguments: ["alerts", "acknowledge"], summary: "Acknowledge alerts by severity", category: "enforce", requiresInput: true, usage: "--severity HIGH"),
        CommandDefinition(id: 251, title: "alerts dismiss", binary: "defenseclaw", arguments: ["alerts", "dismiss"], summary: "Dismiss alerts by severity", category: "enforce", requiresInput: true, usage: "--severity HIGH"),
        CommandDefinition(id: 252, title: "fix credentials", binary: "defenseclaw", arguments: ["keys", "fill-missing", "--yes"], summary: "List missing required credentials", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 253, title: "setup connector", binary: "defenseclaw", arguments: ["setup"], summary: "Open connector setup choices in the CLI", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 254, title: "restart gateway", binary: "defenseclaw-gateway", arguments: ["restart"], summary: "Restart the gateway sidecar", category: "daemon", requiresInput: false, usage: ""),
        CommandDefinition(id: 255, title: "open setup", binary: "defenseclaw", arguments: ["setup"], summary: "Jump to the TUI Setup panel", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 256, title: "readiness", binary: "defenseclaw", arguments: ["doctor"], summary: "Run health checks that feed Setup Readiness", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 257, title: "routing status", binary: "defenseclaw", arguments: ["routing", "status"], summary: "Show model routing: on or off, models, rules, health and your last decisions", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 258, title: "routing setup", binary: "defenseclaw", arguments: ["routing", "setup", "--yes"], summary: "Set up model routing with the models already configured, then test it", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 259, title: "routing enable", binary: "defenseclaw", arguments: ["routing", "enable"], summary: "Turn model routing on", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 260, title: "routing disable", binary: "defenseclaw", arguments: ["routing", "disable"], summary: "Turn model routing off", category: "setup", requiresInput: false, usage: ""),
        CommandDefinition(id: 261, title: "routing enable connector", binary: "defenseclaw", arguments: ["routing", "enable", "--connector"], summary: "Route one hook connector's model calls through DefenseClaw", category: "setup", requiresInput: true, usage: "codex"),
        CommandDefinition(id: 262, title: "routing disable connector", binary: "defenseclaw", arguments: ["routing", "disable", "--connector"], summary: "Stop routing one connector and restore its own model settings", category: "setup", requiresInput: true, usage: "codex"),
        CommandDefinition(id: 263, title: "routing models list", binary: "defenseclaw", arguments: ["routing", "models", "list"], summary: "List the model aliases routing can choose", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 264, title: "routing models add", binary: "defenseclaw", arguments: ["routing", "models", "add"], summary: "Add a model alias", category: "setup", requiresInput: true, usage: "NAME --provider anthropic --model MODEL"),
        CommandDefinition(id: 265, title: "routing models remove", binary: "defenseclaw", arguments: ["routing", "models", "remove"], summary: "Remove a model alias", category: "setup", requiresInput: true, usage: "NAME"),
        CommandDefinition(id: 266, title: "routing models set-default", binary: "defenseclaw", arguments: ["routing", "models", "set-default"], summary: "Use a model when the classifier picks nothing", category: "setup", requiresInput: true, usage: "NAME"),
        CommandDefinition(id: 267, title: "routing rules list", binary: "defenseclaw", arguments: ["routing", "rules", "list"], summary: "List the routing rules in order", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 268, title: "routing rules add", binary: "defenseclaw", arguments: ["routing", "rules", "add"], summary: "Add a routing rule (all matching rules apply)", category: "setup", requiresInput: true, usage: "ID --groups GROUP --allow ALIAS"),
        CommandDefinition(id: 269, title: "routing rules remove", binary: "defenseclaw", arguments: ["routing", "rules", "remove"], summary: "Remove a routing rule", category: "setup", requiresInput: true, usage: "ID"),
        CommandDefinition(id: 270, title: "routing rules move", binary: "defenseclaw", arguments: ["routing", "rules", "move"], summary: "Move a routing rule", category: "setup", requiresInput: true, usage: "ID --to 1"),
        CommandDefinition(id: 271, title: "routing budgets list", binary: "defenseclaw", arguments: ["routing", "budgets", "list"], summary: "List spend budgets with this period's spend", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 272, title: "routing budgets add", binary: "defenseclaw", arguments: ["routing", "budgets", "add"], summary: "Add a spend budget", category: "setup", requiresInput: true, usage: "ID --scope user --subject * --period day --limit-usd 20 --on-exceed warn"),
        CommandDefinition(id: 273, title: "routing budgets remove", binary: "defenseclaw", arguments: ["routing", "budgets", "remove"], summary: "Remove a spend budget", category: "setup", requiresInput: true, usage: "ID"),
        CommandDefinition(id: 274, title: "routing pricing show", binary: "defenseclaw", arguments: ["routing", "pricing", "show"], summary: "Show the model price table", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 275, title: "routing pricing set", binary: "defenseclaw", arguments: ["routing", "pricing", "set"], summary: "Set one model's prices (USD per million tokens)", category: "setup", requiresInput: true, usage: "PROVIDER/MODEL --input 3 --output 15"),
        CommandDefinition(id: 276, title: "routing pricing import", binary: "defenseclaw", arguments: ["routing", "pricing", "import"], summary: "Replace the price table from a file", category: "setup", requiresInput: true, usage: "PATH"),
        CommandDefinition(id: 277, title: "routing test", binary: "defenseclaw", arguments: ["routing", "test"], summary: "Dry run: which model a prompt would go to and why", category: "info", requiresInput: true, usage: "\"write a parser\""),
        CommandDefinition(id: 278, title: "routing explain", binary: "defenseclaw", arguments: ["routing", "explain"], summary: "Explain where a recent call went", category: "info", requiresInput: true, usage: "REQUEST_ID"),
        CommandDefinition(id: 279, title: "routing usage", binary: "defenseclaw", arguments: ["routing", "usage"], summary: "Show tokens, calls and cost by model", category: "info", requiresInput: false, usage: ""),
        CommandDefinition(id: 280, title: "help", binary: "defenseclaw", arguments: ["--help"], summary: "Show CLI help", category: "info", requiresInput: false, usage: ""),
    ]

    /// Keep the generated source table exact while exposing only commands the
    /// installed runtime reports in its setup catalog.
    static func paletteCommands(
        supportedSetupCommands: Set<String>?, supportedRuntimeCommands: Set<String>? = nil
    ) -> [CommandDefinition] {
        all.filter { command in
            if command.arguments.starts(with: ["agent", "discovery", "runtime"]) {
                return command.arguments.count > 3
                    && supportedRuntimeCommands?.contains(command.arguments[3]) == true
            }
            guard command.arguments.count == 3,
                  command.arguments[0] == "setup",
                  ["amp", "kiro", "cowork"].contains(command.arguments[1]),
                  command.arguments[2] == "--yes" else { return true }
            return supportedSetupCommands?.contains(command.arguments[1]) == true
        }
    }

    static func setupCommands(from help: String) -> Set<String> {
        var insideCommands = false
        var commands: Set<String> = []
        for line in help.components(separatedBy: .newlines) {
            if line.trimmingCharacters(in: .whitespaces) == "Commands:" {
                insideCommands = true
                continue
            }
            guard insideCommands else { continue }
            if !line.isEmpty, line.first?.isWhitespace == false { break }
            guard line.hasPrefix("  "), !line.hasPrefix("    ") else { continue }
            let command = line.trimmingCharacters(in: .whitespaces)
                .split(whereSeparator: \.isWhitespace)
                .first.map(String.init) ?? ""
            guard !command.isEmpty,
                  command.range(of: #"^[a-z0-9][a-z0-9-]*$"#, options: .regularExpression) != nil
            else { continue }
            commands.insert(command)
        }
        return commands
    }
}

enum CommandArgumentParser {
    struct ParseError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    static func parse(_ input: String) throws -> [String] {
        var result: [String] = []
        var current = ""
        var quote: Character?
        var escaped = false
        var tokenStarted = false

        for character in input {
            if escaped {
                current.append(character)
                escaped = false
                tokenStarted = true
                continue
            }
            if character == "\\" && quote != "'" {
                escaped = true
                tokenStarted = true
                continue
            }
            if let activeQuote = quote {
                if character == activeQuote { quote = nil }
                else {
                    current.append(character)
                    tokenStarted = true
                }
                continue
            }
            if character == "'" || character == "\"" {
                quote = character
                tokenStarted = true
            } else if character.isWhitespace {
                if tokenStarted {
                    result.append(current)
                    current = ""
                    tokenStarted = false
                }
            } else {
                current.append(character)
                tokenStarted = true
            }
        }

        if escaped { throw ParseError(message: "The final backslash does not escape a character.") }
        if quote != nil { throw ParseError(message: "A quoted argument is not closed.") }
        if tokenStarted { result.append(current) }
        return result
    }
}
