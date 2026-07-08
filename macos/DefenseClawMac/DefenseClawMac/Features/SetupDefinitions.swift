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

import Foundation

/// Setup areas exposed by the DefenseClaw TUI. Definitions stay
/// data-driven so the native form, command review, and CLI execution use one
/// source of truth.
enum TUIWizards {
    static let connectors = ["openclaw", "zeptoclaw", "codex", "claudecode", "hermes",
                             "cursor", "windsurf", "geminicli", "copilot", "openhands",
                             "antigravity", "opencode", "omnigent"]
    static let proxyConnectors = ["openclaw", "zeptoclaw"]
    static let hookConnectors = connectors.filter { !proxyConnectors.contains($0) }
    static let llmProviders = ["anthropic", "openai", "openrouter", "azure", "gemini",
                               "gemini-openai", "groq", "mistral", "cohere", "deepseek",
                               "xai", "bedrock", "vertex_ai", "fireworks_ai", "perplexity",
                               "huggingface", "replicate", "together_ai", "cerebras",
                               "ollama", "vllm", "lm_studio", "custom"]
    static let needsBaseURL = ["azure", "ollama", "vllm", "lm_studio", "custom", "openrouter"]

    static let all: [WizardDefinition] = [
        connector,
        credentials,
        aiDefense,
        llm,
        localObservability,
        galileo,
        tokenRotation,
        customProviders,
        skillScanner,
        mcpScanner,
        gateway,
        guardrail,
        splunk,
        observability,
        webhooks,
        sandbox,
        registries,
        notificationsRouting,
        aiDiscovery,
        splunkDashboards,
        trustedPaths,
        guardrailActions,
    ]

    /// TUI connector wizard (setup / batch / remove). The argv builder mirrors
    /// `_build_connector_setup_args` byte-for-byte: `setup <alias> --yes …`,
    /// bare `setup --yes --connector … [--detected] [--all] …` for batch, and
    /// `setup remove <name> --yes [--no-restart] [--force]`.
    private static let connector = WizardDefinition(
        id: "connector", title: "Connector Setup", icon: "cable.connector",
        blurb: "Add or re-run a connector, choose the active hook connector set (batch), or remove one.",
        baseArgs: ["setup"], // unused — commandBuilder supplies the full argv

        commandBuilder: connectorCommands,
        validation: connectorValidation,
        fields: [
            WizardField(key: "action", label: "Action", kind: .choice(options: ["setup", "batch", "remove"]),
                        defaultValue: "setup",
                        help: "Set up/add one connector, choose the active connector set, or remove one."),
            WizardField(key: "connector", label: "Framework", kind: .choice(options: connectors),
                        defaultValue: "claudecode",
                        visibleWhen: (key: "action", equals: ["setup", "remove"])),
            WizardField(key: "connectors-csv", label: "Connectors (CSV)",
                        kind: .text(placeholder: "codex,hermes,antigravity"),
                        visibleWhen: (key: "action", equals: ["batch"]),
                        help: "Batch setup only: comma-separated hook connector names. Batch REPLACES the active hook set."),
            WizardField(key: "detected", label: "Detected connectors", kind: .bool, defaultValue: "no",
                        visibleWhen: (key: "action", equals: ["batch"]),
                        help: "Include every locally detected hook connector."),
            WizardField(key: "all", label: "All supported connectors", kind: .bool, defaultValue: "no",
                        visibleWhen: (key: "action", equals: ["batch"]),
                        help: "Include every supported hook connector."),
            WizardField(key: "mode", label: "Guardrail mode", kind: .choice(options: ["observe", "action"]),
                        defaultValue: "observe",
                        visibleWhen: (key: "action", equals: ["setup", "batch"])),
            WizardField(key: "scanner-mode", label: "Scanner mode", kind: .choice(options: ["local", "remote", "both"]),
                        defaultValue: "local",
                        visibleWhen: (key: "action", equals: ["setup"]),
                        visibleWhen2: (key: "connector", equals: proxyConnectors)),
            WizardField(key: "verify", label: "Verify after setup", kind: .bool, defaultValue: "yes",
                        visibleWhen: (key: "action", equals: ["setup"]),
                        visibleWhen2: (key: "connector", equals: proxyConnectors)),
            WizardField(key: "replace", label: "Replace existing", kind: .bool, defaultValue: "no",
                        visibleWhen: (key: "action", equals: ["setup"]),
                        visibleWhen2: (key: "connector", equals: hookConnectors),
                        help: "Replace the configured connector set instead of adding this connector as a peer."),
            WizardField(key: "workspace", label: "Workspace dir", kind: .text(placeholder: "Optional"),
                        visibleWhen: (key: "action", equals: ["setup"]),
                        visibleWhen2: (key: "connector", equals: hookConnectors),
                        help: "Optional workspace-scoped connector config directory."),
            WizardField(key: "local-stack", label: "Local stack", kind: .bool, defaultValue: "no",
                        visibleWhen: (key: "action", equals: ["setup"]),
                        visibleWhen2: (key: "connector", equals: hookConnectors)),
            WizardField(key: "restart", label: "Restart gateway", kind: .bool, defaultValue: "yes"),
            WizardField(key: "force", label: "Force last connector removal", kind: .bool, defaultValue: "no",
                        visibleWhen: (key: "action", equals: ["remove"]),
                        help: "Allow removing the final connector and fully unconfiguring enforcement."),
        ]
    )

    /// Mirrors the TUI connector-wizard argv builder (`_build_connector_setup_args`).
    private static func connectorCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        let action = value(v, "action", "setup")
        let restartOff = value(v, "restart", "yes") == "no"

        if action == "batch" {
            var args = ["setup", "--yes"]
            appendCSV(v, "connectors-csv", flag: "--connector", to: &args)
            flag(v, "detected", "--detected", to: &args)
            flag(v, "all", "--all", to: &args)
            append(v, "mode", flag: "--mode", to: &args)
            if restartOff { args.append("--no-restart") }
            return [args]
        }

        let connector = value(v, "connector", "openclaw")
        if action == "remove" {
            var args = ["setup", "remove", connector, "--yes"]
            if restartOff { args.append("--no-restart") }
            flag(v, "force", "--force", to: &args)
            return [args]
        }

        // setup — subcommand alias: claudecode → claude-code, else identity.
        let alias = connector == "claudecode" ? "claude-code" : connector
        var args = ["setup", alias, "--yes"]
        append(v, "mode", flag: "--mode", to: &args)
        if restartOff { args.append("--no-restart") }
        if proxyConnectors.contains(connector) {
            append(v, "scanner-mode", flag: "--scanner-mode", to: &args)
            if value(v, "verify", "yes") == "no" { args.append("--no-verify") }
            return [args]
        }
        flag(v, "replace", "--replace", to: &args)
        append(v, "workspace", flag: "--workspace", to: &args)
        flag(v, "local-stack", "--with-local-stack", to: &args)
        return [args]
    }

    /// Batch requires a target set: CSV names, detected, or all (TUI
    /// missing_required_fields connector branch).
    private static func connectorValidation(_ v: [String: String]) -> String? {
        guard value(v, "action", "setup") == "batch" else { return nil }
        let csv = value(v, "connectors-csv")
        if csv.isEmpty, !yes(v, "detected"), !yes(v, "all") {
            return "Missing required field(s): Connectors (CSV) or Detected/All"
        }
        let invalid = csv.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            .filter { !$0.isEmpty && !hookConnectors.contains($0) }
        if !invalid.isEmpty {
            return "Not hook-enforced connector(s): \(invalid.joined(separator: ", ")). Proxy connectors (openclaw/zeptoclaw) use their own setup."
        }
        return nil
    }

    private static let credentials = WizardDefinition(
        id: "credentials", title: "Credentials", icon: "key.horizontal",
        blurb: "List, validate, or securely set env-backed credentials.",
        baseArgs: ["keys"],
        commandBuilder: credentialCommands,
        secretInputField: "secret",
        validation: credentialValidation,
        fields: [
            // fill-missing is terminal-only: it prompts per missing key with
            // no non-interactive path and would hang a GUI-spawned process.
            WizardField(key: "action", label: "Action", kind: .choice(options: ["list", "check", "set"]),
                        defaultValue: "list"),
            WizardField(key: "env", label: "Environment variable", kind: .text(placeholder: "OPENAI_API_KEY"),
                        visibleWhen: (key: "action", equals: ["set"])),
            WizardField(key: "secret", label: "Secret value", kind: .secure(placeholder: "Written through hidden stdin"),
                        visibleWhen: (key: "action", equals: ["set"]),
                        help: "The value is never placed in argv or the command preview."),
        ]
    )

    private static let aiDefense = WizardDefinition(
        id: "ai-defense", title: "Cisco AI Defense", icon: "shield.lefthalf.filled",
        blurb: "Configure the cloud inspection endpoint, credential, scanner mode, and connectivity verification.",
        baseArgs: ["setup", "guardrail"],
        commandBuilder: aiDefenseCommands,
        secretInputField: "secret",
        fields: [
            WizardField(
                key: "endpoint",
                label: "Endpoint",
                kind: .text(placeholder: "https://us.api.inspect.aidefense.security.cisco.com"),
                defaultValue: "https://us.api.inspect.aidefense.security.cisco.com",
                help: "Use the regional endpoint associated with your Cisco AI Defense tenant."
            ),
            WizardField(
                key: "api-key-env",
                label: "API key environment variable",
                kind: .text(placeholder: "CISCO_AI_DEFENSE_API_KEY"),
                defaultValue: "CISCO_AI_DEFENSE_API_KEY",
                help: "Only this variable name is stored in config.yaml."
            ),
            WizardField(
                key: "secret",
                label: "API key",
                kind: .secure(placeholder: "Leave blank to keep the existing key"),
                help: "When supplied, the key is written to ~/.defenseclaw/.env through hidden stdin and never placed in argv."
            ),
            WizardField(
                key: "scanner-mode",
                label: "Guardrail scanner mode",
                kind: .choice(options: ["remote", "both"]),
                defaultValue: "both",
                help: "Remote uses Cisco AI Defense; both also retains local scanning."
            ),
            WizardField(
                key: "timeout-ms",
                label: "Request timeout (ms)",
                kind: .text(placeholder: "3000"),
                defaultValue: "3000"
            ),
            WizardField(
                key: "skill-scanner",
                label: "Use Cisco AI Defense for skill scans",
                kind: .flagOnly,
                defaultValue: "no"
            ),
            WizardField(key: "restart", label: "Restart gateway", kind: .bool, defaultValue: "yes"),
            WizardField(key: "verify", label: "Verify connectivity", kind: .bool, defaultValue: "yes"),
        ]
    )

    private static let llm = WizardDefinition(
        id: "llm", title: "LLM", icon: "brain",
        blurb: "Configure the unified analyzer and guardrail model.",
        baseArgs: ["setup", "llm"],
        commandBuilder: llmCommands,
        secretInputField: "api-key",
        validation: llmValidation,
        fields: [
            WizardField(key: "provider", label: "Provider", kind: .choice(options: llmProviders), defaultValue: "anthropic"),
            WizardField(key: "model", label: "Model", kind: .text(placeholder: "claude-sonnet-4-6")),
            WizardField(key: "role", label: "Role", kind: .choice(options: ["unified", "agent", "judge"]), defaultValue: "unified"),
            WizardField(key: "api-key", label: "API key", kind: .secure(placeholder: "Stored via hidden stdin, never argv"),
                        help: "When supplied, the key is written with `keys set` through stdin; only the env var name reaches setup llm."),
            WizardField(key: "api-key-env", label: "API key env var", kind: .text(placeholder: "ANTHROPIC_API_KEY")),
            WizardField(key: "base-url", label: "Base URL", kind: .text(placeholder: "https://…"),
                        visibleWhen: (key: "provider", equals: needsBaseURL)),
            WizardField(key: "bedrock-region", label: "AWS region", kind: .text(placeholder: "us-east-1"),
                        visibleWhen: (key: "provider", equals: ["bedrock"])),
            WizardField(key: "bedrock-auth-mode", label: "Bedrock auth", kind: .choice(options: ["api_key", "iam_credentials", "profile", "instance_role"]),
                        defaultValue: "profile", visibleWhen: (key: "provider", equals: ["bedrock"])),
        ]
    )

    private static let localObservability = WizardDefinition(
        id: "local-observability", title: "Local OTel", icon: "chart.bar.xaxis",
        blurb: "Manage the bundled Prometheus, Loki, Tempo, and Grafana stack.",
        baseArgs: ["setup", "local-observability"], commandBuilder: localObservabilityCommands,
        fields: [
            WizardField(key: "action", label: "Action", kind: .choice(options: ["status", "url", "up", "logs", "down", "reset"]), defaultValue: "status"),
            WizardField(key: "timeout", label: "Startup timeout", kind: .text(placeholder: "180"), defaultValue: "180", visibleWhen: (key: "action", equals: ["up"])),
            WizardField(key: "signals", label: "Signals", kind: .text(placeholder: "traces,metrics,logs"), defaultValue: "traces,metrics,logs", visibleWhen: (key: "action", equals: ["up"])),
            WizardField(key: "service-name", label: "Service name", kind: .text(placeholder: "defenseclaw"), defaultValue: "defenseclaw", visibleWhen: (key: "action", equals: ["up"])),
            WizardField(key: "no-wait", label: "Do not wait for readiness", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "action", equals: ["up"])),
            WizardField(key: "no-config", label: "Do not update config", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "action", equals: ["up"])),
            WizardField(key: "audit-sink", label: "Configure audit sink", kind: .bool, defaultValue: "yes", visibleWhen: (key: "action", equals: ["up"])),
            // --follow streams forever and would hang the wizard's apply
            // loop; the GUI always fetches a bounded snapshot.
            WizardField(key: "service", label: "Log service", kind: .text(placeholder: "optional service"), visibleWhen: (key: "action", equals: ["logs"])),
            WizardField(key: "json", label: "JSON output", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "action", equals: ["url"])),
            WizardField(key: "confirm", label: "Confirm destructive reset", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "action", equals: ["reset"])),
        ]
    )

    private static let galileo = WizardDefinition(
        id: "galileo", title: "Galileo", icon: "chart.xyaxis.line",
        blurb: "Send GenAI traces to Galileo Cloud or self-hosted Galileo without replacing local observability.",
        baseArgs: ["setup", "galileo"],
        commandBuilder: galileoCommands,
        secretInputField: "secret",
        validation: galileoValidation,
        fields: [
            WizardField(
                key: "action",
                label: "Action",
                kind: .choice(options: ["cloud", "self-hosted", "status", "test", "enable", "disable", "remove"]),
                defaultValue: "cloud",
                help: "Cloud and self-hosted configure the named Galileo destination; other actions manage the existing destination."
            ),
            WizardField(
                key: "project",
                label: "Project",
                kind: .text(placeholder: "Galileo project name or ID"),
                defaultValue: "defenseclaw",
                visibleWhen: (key: "action", equals: ["cloud", "self-hosted"])
            ),
            WizardField(
                key: "logstream",
                label: "Log stream",
                kind: .text(placeholder: "Galileo Log stream name or ID"),
                defaultValue: "production",
                visibleWhen: (key: "action", equals: ["cloud", "self-hosted"])
            ),
            WizardField(
                key: "console-url",
                label: "Console URL",
                kind: .text(placeholder: "https://console.galileo.example.com"),
                visibleWhen: (key: "action", equals: ["self-hosted"]),
                help: "DefenseClaw derives the API hostname and appends /otel/traces."
            ),
            WizardField(
                key: "trace-endpoint",
                label: "Exact trace endpoint",
                kind: .text(placeholder: "https://api.example.com/galileo/otel/traces"),
                visibleWhen: (key: "action", equals: ["self-hosted"]),
                help: "Optional override for custom self-hosted hostname or path conventions."
            ),
            WizardField(
                key: "secret",
                label: "API key",
                kind: .secure(placeholder: "Leave blank to use the existing GALILEO_API_KEY"),
                visibleWhen: (key: "action", equals: ["cloud", "self-hosted"]),
                help: "When supplied, the key is saved through hidden stdin and never included in command arguments or config.yaml."
            ),
            WizardField(
                key: "persist-api-key",
                label: "Persist inherited API key",
                kind: .flagOnly,
                defaultValue: "no",
                visibleWhen: (key: "action", equals: ["cloud", "self-hosted"]),
                help: "Copies GALILEO_API_KEY from the app environment into the owner-only DefenseClaw .env file."
            ),
            WizardField(
                key: "enabled",
                label: "Enable destination",
                kind: .bool,
                defaultValue: "yes",
                visibleWhen: (key: "action", equals: ["cloud", "self-hosted"])
            ),
            WizardField(
                key: "test-after",
                label: "Test after setup",
                kind: .bool,
                defaultValue: "yes",
                visibleWhen: (key: "action", equals: ["cloud", "self-hosted"]),
                help: "Sends a canonical trace through the running gateway and waits for Galileo's OTLP acknowledgement."
            ),
            WizardField(
                key: "json",
                label: "JSON output",
                kind: .flagOnly,
                defaultValue: "no",
                visibleWhen: (key: "action", equals: ["status"])
            ),
            WizardField(
                key: "timeout",
                label: "Test timeout (seconds)",
                kind: .text(placeholder: "15"),
                defaultValue: "15",
                visibleWhen: (key: "action", equals: ["test"])
            ),
            WizardField(
                key: "direct",
                label: "Test Galileo directly",
                kind: .flagOnly,
                defaultValue: "no",
                visibleWhen: (key: "action", equals: ["test"]),
                help: "Troubleshooting only: bypasses gateway filtering, batching, and fan-out."
            ),
        ]
    )

    private static let tokenRotation = WizardDefinition(
        id: "token-rotation", title: "Token Rotation", icon: "arrow.triangle.2.circlepath",
        blurb: "Rotate the gateway token and refresh connector hooks.",
        baseArgs: ["setup", "rotate-token"], commandBuilder: tokenRotationCommands,
        fields: [
            WizardField(key: "connector", label: "Connector", kind: .choice(options: ["auto"] + connectors), defaultValue: "auto"),
            WizardField(key: "restart", label: "Refresh hooks and restart", kind: .bool, defaultValue: "yes"),
        ]
    )

    private static let customProviders = WizardDefinition(
        id: "custom-providers", title: "Custom Providers", icon: "point.3.connected.trianglepath.dotted",
        blurb: "List, add, inspect, or remove custom LLM provider overlays.",
        baseArgs: ["setup", "provider"], commandBuilder: providerCommands,
        validation: { v in
            let action = value(v, "action", "list")
            if action == "add" {
                if value(v, "name").isEmpty { return "Provider name is required for add (blank routes into the CLI's interactive wizard)." }
                if value(v, "domain").isEmpty, value(v, "base-url").isEmpty {
                    return "Supply at least one domain or a base URL."
                }
            }
            if action == "remove", value(v, "name").isEmpty { return "Provider name is required for remove." }
            return nil
        },
        fields: [
            WizardField(key: "action", label: "Action", kind: .choice(options: ["list", "show", "add", "remove"]), defaultValue: "list"),
            WizardField(key: "name", label: "Provider name", kind: .text(placeholder: "internal-llm"), visibleWhen: (key: "action", equals: ["add", "remove"])),
            WizardField(key: "base-provider-type", label: "Provider family", kind: .choice(options: llmProviders.filter { $0 != "custom" }), defaultValue: "openai", visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "base-url", label: "Base URL", kind: .text(placeholder: "https://llm.internal:8443"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "domain", label: "Domains", kind: .text(placeholder: "comma-separated domains"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "env-key", label: "API key env vars", kind: .text(placeholder: "comma-separated names"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "available-model", label: "Available models", kind: .text(placeholder: "comma-separated model ids"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "reload", label: "Reload sidecar", kind: .bool, defaultValue: "yes", visibleWhen: (key: "action", equals: ["add", "remove"])),
        ]
    )

    private static let skillScanner = WizardDefinition(
        id: "skill-scanner", title: "Skill Scanner", icon: "wand.and.rays.inverse",
        blurb: "Configure skill analyzers, policy, and optional cloud checks.",
        baseArgs: ["setup", "skill-scanner"], appendNonInteractive: true,
        liveDefaults: { raw in
            var out: [String: String] = [:]
            if let policy = raw["scanners.skill_scanner.policy"]?.string { out["policy"] = policy }
            if let provider = raw["scanners.skill_scanner.llm.provider"]?.string ?? raw["llm.provider"]?.string,
               ["anthropic", "openai"].contains(provider) { out["llm-provider"] = provider }
            if let runs = raw["scanners.skill_scanner.llm_consensus_runs"]?.int { out["llm-consensus-runs"] = String(runs) }
            return out
        },
        fields: [
            WizardField(key: "use-behavioral", label: "Behavioral analyzer", kind: .flagOnly, defaultValue: "no",
                        help: "Unchecked leaves the current setting unchanged (the CLI has no off switch)."),
            WizardField(key: "use-llm", label: "LLM analyzer", kind: .flagOnly, defaultValue: "no",
                        help: "Unchecked leaves the current setting unchanged (the CLI has no off switch)."),
            WizardField(key: "llm-provider", label: "LLM provider", kind: .choice(options: ["anthropic", "openai"]), defaultValue: "anthropic"),
            WizardField(key: "llm-model", label: "LLM model", kind: .text(placeholder: "optional model")),
            WizardField(key: "llm-consensus-runs", label: "Consensus runs", kind: .text(placeholder: "0"), defaultValue: "0"),
            WizardField(key: "enable-meta", label: "Meta analyzer", kind: .flagOnly, defaultValue: "no",
                        help: "Unchecked leaves the current setting unchanged (the CLI has no off switch)."),
            WizardField(key: "use-trigger", label: "Trigger analyzer", kind: .flagOnly, defaultValue: "no",
                        help: "Unchecked leaves the current setting unchanged (the CLI has no off switch)."),
            WizardField(key: "use-virustotal", label: "VirusTotal", kind: .flagOnly, defaultValue: "no",
                        help: "Unchecked leaves the current setting unchanged (the CLI has no off switch)."),
            WizardField(key: "use-aidefense", label: "Cisco AI Defense", kind: .flagOnly, defaultValue: "no",
                        help: "Unchecked leaves the current setting unchanged (the CLI has no off switch)."),
            WizardField(key: "policy", label: "Policy", kind: .choice(options: ["strict", "balanced", "permissive", "none"]), defaultValue: "balanced"),
            WizardField(key: "lenient", label: "Lenient parsing", kind: .flagOnly, defaultValue: "no",
                        help: "Unchecked leaves the current setting unchanged (the CLI has no off switch)."),
            WizardField(key: "verify", label: "Verify after setup", kind: .bool, defaultValue: "yes"),
        ]
    )

    private static let mcpScanner = WizardDefinition(
        id: "mcp-scanner", title: "MCP Scanner", icon: "server.rack",
        blurb: "Configure MCP analyzers and prompt, resource, and instruction scanning.",
        baseArgs: ["setup", "mcp-scanner"], appendNonInteractive: true,
        liveDefaults: { raw in
            var out: [String: String] = [:]
            if let analyzers = raw["scanners.mcp_scanner.analyzers"]?.string { out["analyzers"] = analyzers }
            if case .sequence(let items)? = raw["scanners.mcp_scanner.analyzers"] {
                out["analyzers"] = items.compactMap(\.string).joined(separator: ",")
            }
            if let provider = raw["scanners.mcp_scanner.llm.provider"]?.string ?? raw["llm.provider"]?.string,
               ["anthropic", "openai"].contains(provider) { out["llm-provider"] = provider }
            return out
        },
        fields: [
            WizardField(key: "analyzers", label: "Analyzers", kind: .text(placeholder: "yara,api,llm,behavioral,readiness"), defaultValue: "yara,api,llm,behavioral,readiness"),
            WizardField(key: "llm-provider", label: "LLM provider", kind: .choice(options: ["anthropic", "openai"]), defaultValue: "anthropic"),
            WizardField(key: "llm-model", label: "LLM model", kind: .text(placeholder: "optional model")),
            WizardField(key: "scan-prompts", label: "Scan prompts", kind: .flagOnly, defaultValue: "no",
                        help: "Unchecked leaves the current setting unchanged (the CLI has no off switch)."),
            WizardField(key: "scan-resources", label: "Scan resources", kind: .flagOnly, defaultValue: "no",
                        help: "Unchecked leaves the current setting unchanged (the CLI has no off switch)."),
            WizardField(key: "scan-instructions", label: "Scan instructions", kind: .flagOnly, defaultValue: "no",
                        help: "Unchecked leaves the current setting unchanged (the CLI has no off switch)."),
            WizardField(key: "verify", label: "Verify after setup", kind: .bool, defaultValue: "yes"),
        ]
    )

    private static let gateway = WizardDefinition(
        id: "gateway", title: "Gateway", icon: "network",
        blurb: "Configure gateway host, ports, TLS posture, and authentication.",
        baseArgs: ["setup", "gateway"],
        commandBuilder: gatewayCommands,
        secretInputField: "token",
        liveDefaults: { raw in
            var out: [String: String] = [:]
            if let host = raw["gateway.host"]?.string { out["host"] = host }
            if let port = raw["gateway.port"]?.int { out["port"] = String(port) }
            if let api = raw["gateway.api_port"]?.int { out["api-port"] = String(api) }
            return out
        },
        fields: [
            WizardField(key: "remote", label: "Remote mode", kind: .flagOnly, defaultValue: "no"),
            WizardField(key: "host", label: "Host", kind: .text(placeholder: "localhost"), defaultValue: "localhost"),
            WizardField(key: "port", label: "WebSocket port", kind: .text(placeholder: "9090"), defaultValue: "9090"),
            WizardField(key: "api-port", label: "REST API port", kind: .text(placeholder: "9099"), defaultValue: "9099"),
            WizardField(key: "token", label: "Auth token", kind: .secure(placeholder: "Stored via hidden stdin, never argv"),
                        help: "When supplied, the token is persisted with `keys set OPENCLAW_GATEWAY_TOKEN` through stdin."),
            WizardField(key: "ssm-param", label: "SSM parameter", kind: .text(placeholder: "optional parameter")),
            WizardField(key: "ssm-region", label: "SSM region", kind: .text(placeholder: "us-east-1")),
            WizardField(key: "ssm-profile", label: "SSM profile", kind: .text(placeholder: "optional profile")),
            WizardField(key: "verify", label: "Verify after setup", kind: .bool, defaultValue: "yes"),
        ]
    )

    private static let guardrail = WizardDefinition(
        id: "guardrail", title: "Guardrail", icon: "shield.checkered",
        blurb: "Configure guardrail mode, scanners, detection strategy, and judge.",
        baseArgs: ["setup", "guardrail"], appendNonInteractive: true,
        liveDefaults: { raw in
            // Prefill from live config so an apply with untouched fields
            // never silently downgrades the current posture.
            var out: [String: String] = [:]
            if let mode = raw["guardrail.mode"]?.string { out["mode"] = mode }
            if let scanner = raw["guardrail.scanner_mode"]?.string { out["scanner-mode"] = scanner }
            if let strategy = raw["guardrail.detection_strategy"]?.string { out["detection-strategy"] = strategy }
            if let packDir = raw["guardrail.rule_pack_dir"]?.string, !packDir.isEmpty {
                let pack = (packDir as NSString).lastPathComponent
                if ["default", "strict", "permissive"].contains(pack) { out["rule-pack"] = pack }
            }
            if let message = raw["guardrail.block_message"]?.string { out["block-message"] = message }
            if let judge = raw["guardrail.judge.model"]?.string { out["judge-model"] = judge }
            return out
        },
        fields: [
            WizardField(key: "connector", label: "Connector", kind: .choice(options: connectors), defaultValue: "claudecode"),
            WizardField(key: "mode", label: "Mode", kind: .choice(options: ["observe", "action"]), defaultValue: "observe"),
            WizardField(key: "scanner-mode", label: "Scanner mode", kind: .choice(options: ["local", "remote", "both"]), defaultValue: "local"),
            WizardField(key: "detection-strategy", label: "Detection strategy", kind: .choice(options: ["regex_only", "regex_judge", "judge_first"]), defaultValue: "regex_only"),
            WizardField(key: "rule-pack", label: "Rule pack", kind: .choice(options: ["default", "strict", "permissive"]), defaultValue: "default"),
            WizardField(key: "judge-model", label: "Judge model", kind: .text(placeholder: "provider/model"), visibleWhen: (key: "detection-strategy", equals: ["regex_judge", "judge_first"])),
            WizardField(key: "block-message", label: "Block message", kind: .text(placeholder: "optional message")),
        ]
    )

    private static let splunk = WizardDefinition(
        id: "splunk", title: "Splunk", icon: "waveform.path.ecg.rectangle",
        blurb: "Configure Splunk O11y, local logs, or Enterprise HEC pipelines.",
        baseArgs: ["setup", "splunk"], commandBuilder: splunkCommands,
        validation: { v in
            if value(v, "mode", "splunk-o11y") == "local-docker", !yes(v, "accept-splunk-license") {
                return "Local Docker mode requires accepting the Splunk license."
            }
            return nil
        },
        fields: [
            WizardField(key: "mode", label: "Pipeline", kind: .choice(options: ["splunk-o11y", "local-docker", "enterprise"]), defaultValue: "splunk-o11y"),
            WizardField(key: "realm", label: "O11y realm", kind: .text(placeholder: "us1"), visibleWhen: (key: "mode", equals: ["splunk-o11y"])),
            WizardField(key: "access-token", label: "Access token", kind: .secure(placeholder: "O11y token"), visibleWhen: (key: "mode", equals: ["splunk-o11y"])),
            WizardField(key: "hec-endpoint", label: "HEC endpoint", kind: .text(placeholder: "https://host:8088"), visibleWhen: (key: "mode", equals: ["enterprise"])),
            WizardField(key: "hec-token", label: "HEC token", kind: .secure(placeholder: "HEC token"), visibleWhen: (key: "mode", equals: ["enterprise"])),
            WizardField(key: "accept-splunk-license", label: "Accept Splunk license", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "mode", equals: ["local-docker"])),
            WizardField(key: "traces", label: "Export traces", kind: .bool, defaultValue: "yes"),
            WizardField(key: "metrics", label: "Export metrics", kind: .bool, defaultValue: "yes"),
            WizardField(key: "logs-export", label: "Export logs", kind: .bool, defaultValue: "no"),
        ]
    )

    private static let observability = WizardDefinition(
        id: "observability", title: "Observability", icon: "chart.xyaxis.line",
        blurb: "Add, list, enable, disable, or remove OTel and audit destinations.",
        baseArgs: ["setup", "observability"], commandBuilder: observabilityCommands,
        validation: { v in
            let action = value(v, "action", "add")
            if ["enable", "disable", "remove"].contains(action), value(v, "name").isEmpty {
                return "Destination name is required for \(action)."
            }
            if action == "add", value(v, "preset", "local-otlp") == "webhook", value(v, "endpoint").isEmpty {
                return "The webhook preset requires an endpoint URL."
            }
            return nil
        },
        fields: [
            WizardField(key: "action", label: "Action", kind: .choice(options: ["add", "list", "enable", "disable", "remove"]), defaultValue: "add"),
            WizardField(key: "preset", label: "Destination", kind: .choice(options: ["local-otlp", "otlp", "splunk-o11y", "splunk-hec", "splunk-enterprise", "datadog", "honeycomb", "newrelic", "grafana-cloud", "webhook"]), defaultValue: "local-otlp", visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "name", label: "Destination name", kind: .text(placeholder: "name"), visibleWhen: (key: "action", equals: ["add", "enable", "disable", "remove"])),
            WizardField(key: "endpoint", label: "Endpoint", kind: .text(placeholder: "host:port or URL"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "token", label: "Token / API key", kind: .secure(placeholder: "optional token"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "signals", label: "Signals", kind: .text(placeholder: "traces,metrics,logs"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "connector", label: "Connector", kind: .choice(options: ["all"] + connectors), defaultValue: "all"),
            WizardField(key: "json", label: "JSON output", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "action", equals: ["list"])),
        ]
    )

    private static let webhooks = WizardDefinition(
        id: "webhooks", title: "Webhooks", icon: "link.badge.plus",
        blurb: "Add, list, enable, disable, or remove alert notifier webhooks.",
        baseArgs: ["setup", "webhook"], commandBuilder: webhookCommands,
        validation: { v in
            let action = value(v, "action", "add")
            if action == "add", value(v, "url").isEmpty { return "Webhook URL is required for add." }
            if ["enable", "disable", "remove"].contains(action), value(v, "name").isEmpty {
                return "Destination name is required for \(action)."
            }
            return nil
        },
        fields: [
            WizardField(key: "action", label: "Action", kind: .choice(options: ["add", "list", "enable", "disable", "remove"]), defaultValue: "add"),
            WizardField(key: "type", label: "Type", kind: .choice(options: ["slack", "pagerduty", "webex", "generic"]), defaultValue: "slack", visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "name", label: "Destination name", kind: .text(placeholder: "name"), visibleWhen: (key: "action", equals: ["add", "enable", "disable", "remove"])),
            WizardField(key: "url", label: "Webhook URL", kind: .text(placeholder: "https://…"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "secret-env", label: "Secret env var", kind: .text(placeholder: "DEFENSECLAW_WEBHOOK_SECRET"), visibleWhen: (key: "type", equals: ["pagerduty", "webex", "generic"])),
            WizardField(key: "room-id", label: "Webex room ID", kind: .text(placeholder: "room id"), visibleWhen: (key: "type", equals: ["webex"])),
            WizardField(key: "min-severity", label: "Minimum severity", kind: .choice(options: ["critical", "high", "medium", "low", "info"]), defaultValue: "high", visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "events", label: "Events", kind: .text(placeholder: "block,scan,guardrail,drift,health"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "connector", label: "Connector", kind: .choice(options: ["all"] + connectors), defaultValue: "all"),
            WizardField(key: "json", label: "JSON output", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "action", equals: ["list"])),
        ]
    )

    private static let sandbox = WizardDefinition(
        id: "sandbox", title: "Sandbox", icon: "cube.transparent",
        blurb: "Initialize OpenShell sandbox networking and policy controls (Linux hosts only).",
        baseArgs: ["sandbox", "setup"], appendNonInteractive: true,
        validation: { _ in
            // cmd_init_sandbox exits on non-Linux, and --disable needs sudo
            // this GUI can't provide — surface that before Run.
            "Sandbox setup requires a Linux host; run `defenseclaw sandbox setup` there instead."
        },
        fields: [
            WizardField(key: "sandbox-ip", label: "Sandbox IP", kind: .text(placeholder: "10.200.0.2"), defaultValue: "10.200.0.2"),
            WizardField(key: "host-ip", label: "Host IP", kind: .text(placeholder: "10.200.0.1"), defaultValue: "10.200.0.1"),
            WizardField(key: "sandbox-home", label: "Sandbox home", kind: .text(placeholder: "/home/sandbox"), defaultValue: "/home/sandbox"),
            WizardField(key: "openclaw-port", label: "OpenClaw port", kind: .text(placeholder: "18789"), defaultValue: "18789"),
            WizardField(key: "policy", label: "Policy", kind: .choice(options: ["default", "strict", "permissive"]), defaultValue: "permissive"),
            WizardField(key: "dns", label: "DNS servers", kind: .text(placeholder: "8.8.8.8,1.1.1.1"), defaultValue: "8.8.8.8,1.1.1.1"),
            WizardField(key: "no-auto-pair", label: "Disable automatic pairing", kind: .flagOnly, defaultValue: "no"),
            WizardField(key: "no-host-networking", label: "Disable host networking", kind: .flagOnly, defaultValue: "no"),
            WizardField(key: "no-guardrail", label: "Disable guardrail", kind: .flagOnly, defaultValue: "no"),
            WizardField(key: "disable", label: "Disable sandbox", kind: .flagOnly, defaultValue: "no"),
        ]
    )

    private static let registries = WizardDefinition(
        id: "registries", title: "Registries", icon: "books.vertical",
        blurb: "Add an external skill or MCP catalog and optionally sync and scan it.",
        baseArgs: ["registry", "add"], commandBuilder: registryCommands,
        validation: registryValidation,
        fields: [
            WizardField(key: "id", label: "Source ID", kind: .text(placeholder: "corp-skills"), defaultValue: "corp-skills"),
            WizardField(key: "kind", label: "Kind", kind: .choice(options: ["clawhub", "smithery", "skills_sh", "http_yaml", "http_json", "git", "file"]), defaultValue: "http_yaml"),
            WizardField(key: "content", label: "Content", kind: .choice(options: ["skill", "mcp", "both"]), defaultValue: "skill"),
            WizardField(key: "url", label: "Manifest URL", kind: .text(placeholder: "https://…")),
            WizardField(key: "auth-env", label: "Auth env var", kind: .text(placeholder: "optional env var")),
            WizardField(key: "enabled", label: "Enable source", kind: .bool, defaultValue: "yes"),
            WizardField(key: "sync", label: "Sync after adding", kind: .bool, defaultValue: "yes"),
            WizardField(key: "scan", label: "Scan during sync", kind: .bool, defaultValue: "yes",
                        visibleWhen: (key: "sync", equals: ["yes"]),
                        help: "registry sync scans entries by default; off adds --no-scan."),
        ]
    )

    private static let notificationsRouting = WizardDefinition(
        id: "notification-routing", title: "Notifications Routing", icon: "bell.and.waves.left.and.right",
        blurb: "Route enforced blocks, observe findings, approvals, and source categories.",
        baseArgs: ["setup", "notifications-set"], commandBuilder: notificationCommands,
        fields: [
            routingField("block_enforced", "Enforced blocks"),
            routingField("block_would_block", "Would-block findings"),
            routingField("hitl_approval", "HITL approvals"),
            routingField("sources.hook", "Hook source"),
            routingField("sources.guardrail", "Guardrail source"),
            routingField("sources.asset_policy", "Asset policy source"),
            WizardField(key: "restart", label: "Restart gateway after changes", kind: .bool, defaultValue: "yes"),
        ]
    )

    private static let aiDiscovery = WizardDefinition(
        id: "ai-discovery", title: "AI Discovery", icon: "sparkle.magnifyingglass",
        blurb: "Enable, disable, and tune AI discovery cadence, scope, and privacy.",
        baseArgs: ["agent", "discovery"], commandBuilder: aiDiscoveryCommands,
        fields: [
            WizardField(key: "enable", label: "Enable", kind: .bool, defaultValue: "yes"),
            WizardField(key: "mode", label: "Mode", kind: .choice(options: ["passive", "enhanced"]), defaultValue: "enhanced", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "scan-interval-min", label: "Scan interval (minutes)", kind: .text(placeholder: "5"), defaultValue: "5", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "process-interval-s", label: "Process poll (seconds)", kind: .text(placeholder: "60"), defaultValue: "60", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "scan-roots", label: "Scan roots", kind: .text(placeholder: "~"), defaultValue: "~", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "include-shell-history", label: "Include shell history", kind: .bool, defaultValue: "yes", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "include-package-manifests", label: "Include package manifests", kind: .bool, defaultValue: "yes", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "include-env-var-names", label: "Include env var names", kind: .bool, defaultValue: "yes", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "include-network-domains", label: "Include network domains", kind: .bool, defaultValue: "yes", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "emit-otel", label: "Emit OTel", kind: .bool, defaultValue: "yes", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "store-raw-local-paths", label: "Store raw local paths", kind: .bool, defaultValue: "no", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "restart", label: "Restart gateway", kind: .bool, defaultValue: "yes"),
            WizardField(key: "scan", label: "Scan immediately", kind: .bool, defaultValue: "yes", visibleWhen: (key: "enable", equals: ["yes"])),
        ]
    )

    private static let splunkDashboards = WizardDefinition(
        id: "splunk-dashboards", title: "Splunk Dashboards", icon: "rectangle.3.group.bubble.left",
        blurb: "Apply or destroy the DefenseClaw Splunk O11y dashboards and detectors.",
        baseArgs: ["setup", "splunk", "dashboards"], commandBuilder: splunkDashboardCommands,
        fields: [
            WizardField(key: "action", label: "Action", kind: .choice(options: ["apply", "destroy"]), defaultValue: "apply"),
            WizardField(key: "with-detectors", label: "Include detectors", kind: .bool, defaultValue: "no"),
            WizardField(key: "enable-detectors", label: "Enable detectors", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "with-detectors", equals: ["yes"])),
            WizardField(key: "name-prefix", label: "Name prefix", kind: .text(placeholder: "optional prefix")),
            WizardField(key: "o11y-api-token", label: "O11y API token", kind: .secure(placeholder: "optional override")),
            WizardField(key: "api-url", label: "API URL", kind: .text(placeholder: "optional override")),
        ]
    )

    private static let trustedPaths = WizardDefinition(
        id: "trusted-paths", title: "Trusted Paths", icon: "checkmark.shield",
        blurb: "List, add, or remove trusted connector-binary discovery prefixes.",
        baseArgs: ["setup", "trusted-paths"], commandBuilder: trustedPathCommands,
        validation: { v in
            if ["add", "remove"].contains(value(v, "action", "list")), value(v, "directory").isEmpty {
                return "Directory is required for add/remove."
            }
            return nil
        },
        fields: [
            WizardField(key: "action", label: "Action", kind: .choice(options: ["list", "add", "remove"]), defaultValue: "list"),
            WizardField(key: "directory", label: "Directory", kind: .text(placeholder: "/opt/company/bin"), visibleWhen: (key: "action", equals: ["add", "remove"])),
            WizardField(key: "force", label: "Force add despite warnings", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "json", label: "JSON output", kind: .flagOnly, defaultValue: "no"),
        ]
    )

    private static let guardrailActions = WizardDefinition(
        id: "guardrail-actions", title: "Guardrail Actions", icon: "shield.lefthalf.filled.badge.checkmark",
        blurb: "Run connector-scoped guardrail status and policy quick actions.",
        baseArgs: ["guardrail"], commandBuilder: guardrailActionCommands,
        fields: [
            WizardField(key: "connector", label: "Connector", kind: .choice(options: ["all"] + connectors), defaultValue: "all"),
            WizardField(key: "action", label: "Action", kind: .choice(options: ["status", "enable", "disable", "fail-mode", "hilt", "block-message"]), defaultValue: "status"),
            WizardField(key: "fail-mode", label: "Fail mode", kind: .choice(options: ["open", "closed"]), defaultValue: "open", visibleWhen: (key: "action", equals: ["fail-mode"])),
            WizardField(key: "hilt", label: "HITL state", kind: .choice(options: ["on", "off"]), defaultValue: "on", visibleWhen: (key: "action", equals: ["hilt"])),
            WizardField(key: "min-severity", label: "Approval minimum severity", kind: .choice(options: ["CRITICAL", "HIGH", "MEDIUM", "LOW"]), defaultValue: "HIGH", visibleWhen: (key: "action", equals: ["hilt"])),
            WizardField(key: "block-message", label: "Block message", kind: .text(placeholder: "custom message"), visibleWhen: (key: "action", equals: ["block-message"])),
            WizardField(key: "clear", label: "Clear custom message", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "action", equals: ["block-message"])),
            WizardField(key: "restart", label: "Restart gateway", kind: .bool, defaultValue: "yes", visibleWhen: (key: "action", equals: ["enable", "disable", "fail-mode", "hilt", "block-message"])),
        ]
    )

    private static func routingField(_ key: String, _ label: String) -> WizardField {
        WizardField(key: key, label: label, kind: .choice(options: ["unchanged", "on", "off"]), defaultValue: "unchanged")
    }

    // MARK: Argument builders

    private static func credentialCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        switch value(v, "action", "list") {
        case "check": [["keys", "check"]]
        case "set": [["keys", "set", value(v, "env")]]
        default: [["keys", "list", "--json"]]
        }
    }

    /// Secret hygiene: the API key travels via `keys set` on stdin; setup llm
    /// only ever sees the env-var NAME.
    private static func llmCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        var commands: [[String]] = []
        if !value(v, "api-key").isEmpty {
            commands.append(["keys", "set", value(v, "api-key-env")])
        }
        var args = ["setup", "llm"]
        append(v, "provider", flag: "--provider", to: &args)
        append(v, "model", flag: "--model", to: &args)
        append(v, "role", flag: "--role", to: &args)
        append(v, "api-key-env", flag: "--api-key-env", to: &args)
        append(v, "base-url", flag: "--base-url", to: &args)
        append(v, "bedrock-region", flag: "--bedrock-region", to: &args)
        if value(v, "provider") == "bedrock" {
            append(v, "bedrock-auth-mode", flag: "--bedrock-auth-mode", to: &args)
        }
        args.append("--non-interactive")
        commands.append(args)
        return commands
    }

    private static func llmValidation(_ v: [String: String]) -> String? {
        if !value(v, "api-key").isEmpty, value(v, "api-key-env").isEmpty {
            return "API key env var name is required when supplying an API key."
        }
        return nil
    }

    /// Gateway argv without the raw token; the secret persists via keys set.
    private static func gatewayCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        var commands: [[String]] = []
        if !value(v, "token").isEmpty {
            commands.append(["keys", "set", "OPENCLAW_GATEWAY_TOKEN"])
        }
        var args = ["setup", "gateway"]
        flag(v, "remote", "--remote", to: &args)
        append(v, "host", flag: "--host", to: &args)
        append(v, "port", flag: "--port", to: &args)
        append(v, "api-port", flag: "--api-port", to: &args)
        append(v, "ssm-param", flag: "--ssm-param", to: &args)
        append(v, "ssm-region", flag: "--ssm-region", to: &args)
        append(v, "ssm-profile", flag: "--ssm-profile", to: &args)
        args.append(yes(v, "verify") ? "--verify" : "--no-verify")
        args.append("--non-interactive")
        commands.append(args)
        return commands
    }

    private static func credentialValidation(_ v: [String: String]) -> String? {
        guard value(v, "action", "list") == "set" else { return nil }
        if value(v, "env").isEmpty { return "Environment variable name is required for set." }
        if value(v, "secret").isEmpty { return "Secret value is required for set." }
        return nil
    }

    private static func aiDefenseCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        let keyEnv = value(v, "api-key-env", "CISCO_AI_DEFENSE_API_KEY")
        var commands: [[String]] = []
        if !value(v, "secret").isEmpty {
            commands.append(["keys", "set", keyEnv])
        }

        var guardrail = ["setup", "guardrail"]
        append(v, "endpoint", flag: "--cisco-endpoint", to: &guardrail)
        guardrail += ["--cisco-api-key-env", keyEnv]
        append(v, "timeout-ms", flag: "--cisco-timeout-ms", to: &guardrail)
        append(v, "scanner-mode", flag: "--scanner-mode", to: &guardrail)
        guardrail.append(yes(v, "restart") ? "--restart" : "--no-restart")
        guardrail.append(yes(v, "verify") ? "--verify" : "--no-verify")
        guardrail.append("--non-interactive")
        commands.append(guardrail)

        if yes(v, "skill-scanner") {
            commands.append([
                "setup", "skill-scanner", "--use-aidefense",
                yes(v, "verify") ? "--verify" : "--no-verify",
                "--non-interactive",
            ])
        }
        return commands
    }

    private static func localObservabilityCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        let action = value(v, "action", "status")
        var args = ["setup", "local-observability", action]
        if action == "up" {
            append(v, "timeout", flag: "--timeout", to: &args, unless: "180")
            append(v, "signals", flag: "--signals", to: &args, unless: "traces,metrics,logs")
            append(v, "service-name", flag: "--service-name", to: &args, unless: "defenseclaw")
            flag(v, "no-wait", "--no-wait", to: &args)
            flag(v, "no-config", "--no-config", to: &args)
            if !yes(v, "audit-sink") { args.append("--no-audit-sink") }
        } else if action == "logs" {
            append(v, "service", flag: "--service", to: &args)
            flag(v, "follow", "--follow", to: &args)
        } else if action == "url" {
            flag(v, "json", "--json", to: &args)
        } else if action == "reset" {
            guard yes(v, "confirm") else { return [] }
            args.append("--yes")
        }
        return [args]
    }

    private static func galileoCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        let action = value(v, "action", "cloud")
        switch action {
        case "status":
            var args = ["setup", "galileo", "status"]
            flag(v, "json", "--json", to: &args)
            return [args]
        case "test":
            var args = ["setup", "galileo", "test"]
            append(v, "timeout", flag: "--timeout", to: &args, unless: "15")
            flag(v, "direct", "--direct", to: &args)
            return [args]
        case "enable", "disable":
            return [["setup", "galileo", action]]
        case "remove":
            return [["setup", "galileo", "remove", "--yes"]]
        default:
            var commands: [[String]] = []
            if !value(v, "secret").isEmpty {
                commands.append(["keys", "set", "GALILEO_API_KEY"])
            }

            var args = [
                "setup", "galileo",
                "--deployment", action,
                "--project", value(v, "project"),
                "--logstream", value(v, "logstream"),
            ]
            if action == "self-hosted" {
                append(v, "console-url", flag: "--console-url", to: &args)
                append(v, "trace-endpoint", flag: "--trace-endpoint", to: &args)
            }
            flag(v, "persist-api-key", "--persist-api-key", to: &args)
            if !yes(v, "enabled") { args.append("--disabled") }
            args.append("--non-interactive")
            commands.append(args)

            if yes(v, "enabled") && yes(v, "test-after") {
                commands.append(["setup", "galileo", "test"])
            }
            return commands
        }
    }

    private static func galileoValidation(_ v: [String: String]) -> String? {
        let action = value(v, "action", "cloud")
        if action == "cloud" || action == "self-hosted" {
            let project = value(v, "project").trimmingCharacters(in: .whitespacesAndNewlines)
            let logstream = value(v, "logstream").trimmingCharacters(in: .whitespacesAndNewlines)
            if project.isEmpty { return "A Galileo project name or ID is required." }
            if logstream.isEmpty { return "A Galileo Log stream name or ID is required." }
            if project.count > 512 || logstream.count > 512 {
                return "Project and Log stream values must be 512 characters or fewer."
            }
            let invalidRoutingCharacter: (Unicode.Scalar) -> Bool = {
                $0.value < 0x20 || $0.value == 0x7F
            }
            if project.contains("$") || logstream.contains("$")
                || project.unicodeScalars.contains(where: invalidRoutingCharacter)
                || logstream.unicodeScalars.contains(where: invalidRoutingCharacter) {
                return "Project and Log stream values cannot contain '$' or control characters."
            }
            if action == "self-hosted" {
                let consoleURL = value(v, "console-url")
                let traceEndpoint = value(v, "trace-endpoint")
                if consoleURL.isEmpty && traceEndpoint.isEmpty {
                    return "Enter a self-hosted console URL or an exact trace endpoint."
                }
                if !traceEndpoint.isEmpty {
                    if !isCredentialFreeHTTPSURL(traceEndpoint) {
                        return "The exact trace endpoint must be credential-free HTTPS without a query or fragment."
                    }
                } else {
                    guard isCredentialFreeHTTPSURL(consoleURL),
                          let host = URLComponents(string: consoleURL)?.host else {
                        return "The Galileo console URL must be credential-free HTTPS."
                    }
                    if host != "console" && !host.hasPrefix("console.") && !host.hasPrefix("console-") {
                        return "The console hostname must start with console. or console-; otherwise use an exact trace endpoint."
                    }
                }
            }
        } else if action == "test" {
            guard let timeout = Double(value(v, "timeout", "15")), timeout > 0 else {
                return "Test timeout must be a positive number."
            }
        }
        return nil
    }

    private static func isCredentialFreeHTTPSURL(_ value: String) -> Bool {
        guard let components = URLComponents(string: value),
              components.scheme == "https",
              components.host?.isEmpty == false,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil else {
            return false
        }
        return true
    }

    private static func tokenRotationCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        var args = ["setup", "rotate-token", "--yes"]
        let connector = value(v, "connector", "auto")
        if connector != "auto" { args += ["--connector", connector] }
        if !yes(v, "restart") { args.append("--no-restart") }
        return [args]
    }

    private static func providerCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        let action = value(v, "action", "list")
        if action == "list" || action == "show" { return [["setup", "provider", action]] }
        var args = ["setup", "provider", action]
        append(v, "name", flag: "--name", to: &args)
        if action == "add" {
            appendCSV(v, "domain", flag: "--domain", to: &args)
            appendCSV(v, "env-key", flag: "--env-key", to: &args)
            appendCSV(v, "available-model", flag: "--available-model", to: &args)
            append(v, "base-provider-type", flag: "--base-provider-type", to: &args)
            append(v, "base-url", flag: "--base-url", to: &args)
        }
        if !yes(v, "reload") { args.append("--no-reload") }
        return [args]
    }

    private static func splunkCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        let mode = value(v, "mode", "splunk-o11y")
        let modeFlag = mode == "splunk-o11y" ? "--o11y" : mode == "local-docker" ? "--logs" : "--enterprise"
        var args = ["setup", "splunk", modeFlag, "--non-interactive"]
        append(v, "realm", flag: "--realm", to: &args)
        appendSecure(v, "access-token", flag: "--access-token", mask: mask, to: &args)
        append(v, "hec-endpoint", flag: "--hec-endpoint", to: &args)
        appendSecure(v, "hec-token", flag: "--hec-token", mask: mask, to: &args)
        flag(v, "accept-splunk-license", "--accept-splunk-license", to: &args)
        args.append(yes(v, "traces") ? "--traces" : "--no-traces")
        args.append(yes(v, "metrics") ? "--metrics" : "--no-metrics")
        args.append(yes(v, "logs-export") ? "--logs-export" : "--no-logs-export")
        return [args]
    }

    private static func observabilityCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        let action = value(v, "action", "add")
        var args = ["setup", "observability", action]
        if action == "add" {
            let preset = value(v, "preset", "local-otlp")
            args += [preset, "--non-interactive"]
            append(v, "name", flag: "--name", to: &args)
            // The webhook preset reads --url, not --endpoint.
            append(v, "endpoint", flag: preset == "webhook" ? "--url" : "--endpoint", to: &args)
            appendSecure(v, "token", flag: "--token", mask: mask, to: &args)
            append(v, "signals", flag: "--signals", to: &args)
        } else if ["enable", "disable", "remove"].contains(action) {
            let name = value(v, "name")
            if !name.isEmpty { args.append(name) }
            if action == "remove" { args.append("--yes") }
        } else if action == "list" {
            flag(v, "json", "--json", to: &args)
        }
        connector(v, to: &args)
        return [args]
    }

    private static func webhookCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        let action = value(v, "action", "add")
        var args = ["setup", "webhook", action]
        if action == "add" {
            args += [value(v, "type", "slack"), "--non-interactive"]
            append(v, "name", flag: "--name", to: &args)
            append(v, "url", flag: "--url", to: &args)
            append(v, "secret-env", flag: "--secret-env", to: &args)
            append(v, "room-id", flag: "--room-id", to: &args)
            append(v, "min-severity", flag: "--min-severity", to: &args)
            append(v, "events", flag: "--events", to: &args)
        } else if ["enable", "disable", "remove"].contains(action) {
            let name = value(v, "name")
            if !name.isEmpty { args.append(name) }
            if action == "remove" { args.append("--yes") }
        } else if action == "list" {
            flag(v, "json", "--json", to: &args)
        }
        connector(v, to: &args)
        return [args]
    }

    private static func registryCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        let id = value(v, "id")
        var add = ["registry", "add", id, "--kind", value(v, "kind", "http_yaml"),
                   "--content", value(v, "content", "skill")]
        append(v, "url", flag: "--url", to: &add)
        append(v, "auth-env", flag: "--auth-env", to: &add)
        add.append(yes(v, "enabled") ? "--enabled" : "--disabled")
        add.append("--non-interactive")
        var commands = [add]
        // `registry sync` runs the scanners itself (--scan defaults on);
        // --no-scan opts out. There is no separate scan command to chain.
        if yes(v, "sync") {
            var sync = ["registry", "sync", id]
            if !yes(v, "scan") { sync.append("--no-scan") }
            commands.append(sync)
        }
        return commands
    }

    private static func registryValidation(_ v: [String: String]) -> String? {
        if value(v, "id").isEmpty { return "Source ID is required." }
        let kind = value(v, "kind", "http_yaml")
        if ["http_yaml", "http_json", "git", "file"].contains(kind), value(v, "url").isEmpty {
            return "Manifest URL is required for kind=\(kind)."
        }
        return nil
    }

    private static func notificationCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        let slots = ["block_enforced", "block_would_block", "hitl_approval", "sources.hook", "sources.guardrail", "sources.asset_policy"]
        var commands = slots.compactMap { slot -> [String]? in
            let choice = value(v, slot, "unchanged")
            return choice == "unchanged" ? nil : ["setup", "notifications-set", slot, choice]
        }
        if commands.count > 1 || (!yes(v, "restart") && !commands.isEmpty) {
            for index in commands.indices where index < commands.count - (yes(v, "restart") ? 1 : 0) {
                commands[index].append("--no-restart")
            }
        }
        return commands
    }

    private static func aiDiscoveryCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        if !yes(v, "enable") {
            var args = ["agent", "discovery", "disable", "--yes"]
            if !yes(v, "restart") { args.append("--no-restart") }
            return [args]
        }
        var args = ["agent", "discovery", "enable", "--yes"]
        for key in ["mode", "scan-interval-min", "process-interval-s", "scan-roots"] {
            append(v, key, flag: "--\(key)", to: &args)
        }
        for key in ["include-shell-history", "include-package-manifests", "include-env-var-names",
                    "include-network-domains", "emit-otel", "store-raw-local-paths"] {
            args.append(yes(v, key) ? "--\(key)" : "--no-\(key)")
        }
        if !yes(v, "restart") { args.append("--no-restart") }
        if !yes(v, "scan") { args.append("--no-scan") }
        return [args]
    }

    private static func splunkDashboardCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        var args = ["setup", "splunk", "dashboards", value(v, "action", "apply"), "--yes"]
        if yes(v, "with-detectors") {
            args.append("--with-detectors")
            flag(v, "enable-detectors", "--enable-detectors", to: &args)
        }
        append(v, "name-prefix", flag: "--name-prefix", to: &args)
        appendSecure(v, "o11y-api-token", flag: "--o11y-api-token", mask: mask, to: &args)
        append(v, "api-url", flag: "--api-url", to: &args)
        return [args]
    }

    private static func trustedPathCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        let action = value(v, "action", "list")
        var args = ["setup", "trusted-paths", action]
        if ["add", "remove"].contains(action) {
            let directory = value(v, "directory")
            if !directory.isEmpty { args.append(directory) }
        }
        if action == "add" { flag(v, "force", "--force", to: &args) }
        flag(v, "json", "--json", to: &args)
        return [args]
    }

    private static func guardrailActionCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        let action = value(v, "action", "status")
        var args: [String]
        switch action {
        case "enable", "disable": args = ["guardrail", action, "--yes"]
        case "fail-mode": args = ["guardrail", "fail-mode", value(v, "fail-mode", "open"), "--yes"]
        case "hilt":
            args = ["guardrail", "hilt", value(v, "hilt", "on"), "--yes", "--min-severity", value(v, "min-severity", "HIGH")]
        case "block-message":
            args = ["guardrail", "block-message"]
            if yes(v, "clear") { args.append("--clear") }
            else if !value(v, "block-message").isEmpty { args.append(value(v, "block-message")) }
            args.append("--yes")
        default: args = ["guardrail", "status"]
        }
        connector(v, to: &args)
        if action != "status" && !yes(v, "restart") { args.append("--no-restart") }
        return [args]
    }

    private static func value(_ values: [String: String], _ key: String, _ fallback: String = "") -> String {
        values[key]?.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty ?? fallback
    }

    private static func yes(_ values: [String: String], _ key: String) -> Bool {
        value(values, key, "no") == "yes"
    }

    private static func append(_ values: [String: String], _ key: String, flag: String,
                               to args: inout [String], unless skipped: String? = nil) {
        let item = value(values, key)
        if !item.isEmpty && item != skipped { args += [flag, item] }
    }

    private static func appendSecure(_ values: [String: String], _ key: String, flag: String,
                                     mask: Bool, to args: inout [String]) {
        let item = value(values, key)
        if !item.isEmpty { args += [flag, mask ? "••••••" : item] }
    }

    private static func appendCSV(_ values: [String: String], _ key: String, flag: String, to args: inout [String]) {
        value(values, key).split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }.forEach { args += [flag, $0] }
    }

    private static func flag(_ values: [String: String], _ key: String, _ flag: String, to args: inout [String]) {
        if yes(values, key) { args.append(flag) }
    }

    private static func connector(_ values: [String: String], to args: inout [String]) {
        let selected = value(values, "connector", "all")
        if selected != "all" { args += ["--connector", selected] }
    }
}
