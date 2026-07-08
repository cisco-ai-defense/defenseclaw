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

// Typed config-editor catalog — a port of the TUI's Setup config sections
// (tui/panels/setup.py build of ConfigSection/ConfigField, DefenseClaw 0.8.3).
// Every editable field carries its exact config.yaml dotted key, kind, choice
// options, and hint; read-only sections render as headers with guidance.

import Foundation

// MARK: - Models

struct ConfigEditorField: Identifiable, Hashable {
    enum Kind: Hashable {
        case string, bool, int, choice, password, header
    }

    var label: String
    var key: String              // dotted config.yaml path; "" for pure headers
    var kind: Kind = .string
    var options: [String] = []   // choice kinds only
    var hint: String = ""
    var headerValue: String = "" // read-only display value for header rows

    var id: String { key.isEmpty ? "header-\(label)" : key }
    var interactive: Bool { kind != .header }

    /// Secret-y fields get masked in the diff review (TUI is_secret_config_field).
    var secret: Bool {
        if kind == .password { return true }
        let lower = key.lowercased()
        return lower.contains("api_key") || lower.contains("token") || lower.contains("secret")
    }
}

struct ConfigEditorSection: Identifiable, Hashable {
    var name: String
    var summary: String
    var help: String = ""
    var fields: [ConfigEditorField]
    var id: String { name }

    var editable: Bool { fields.contains { $0.interactive } }
}

/// One pending change for the diff-review sheet.
struct ConfigDiffEntry: Identifiable {
    var key: String
    var before: String
    var after: String
    var secret: Bool
    var id: String { key }
}

// MARK: - Validation (port of setup_state.validate_config_field)

enum ConfigFieldValidation {
    struct Result {
        var severity: String = ""   // "", "warning", "error"
        var message: String = ""
        var isError: Bool { severity == "error" }
    }

    static func validate(_ field: ConfigEditorField, value rawValue: String) -> Result {
        let value = rawValue.trimmingCharacters(in: .whitespaces)
        guard field.kind != .header else { return Result() }

        if field.kind == .bool, !["true", "false"].contains(value) {
            return Result(severity: "error", message: "expected true or false")
        }
        if field.kind == .choice, !field.options.isEmpty, !field.options.contains(value) {
            return Result(severity: "error", message: "choose one of: " + field.options.joined(separator: ", "))
        }
        if field.kind == .int {
            guard let number = Int(value) else {
                return Result(severity: "error", message: "expected an integer")
            }
            if field.key.contains("port"), !(1...65535).contains(number) {
                return Result(severity: "error", message: "port must be between 1 and 65535")
            }
            if ["timeout", "interval", "retries", "max_"].contains(where: field.key.contains), number < 0 {
                return Result(severity: "error", message: "value must be zero or greater")
            }
        }
        // Env-var NAME fields must look like NAMES, not secret values.
        if field.key.hasSuffix("_env"), !value.isEmpty {
            let envName = value.range(of: "^[A-Z_][A-Z0-9_]*$", options: .regularExpression) != nil
            if !envName {
                if value.count > 20, value.rangeOfCharacter(from: .lowercaseLetters) != nil {
                    return Result(severity: "warning", message: "this looks like a secret value, not an env var name")
                }
                return Result(severity: "error", message: "env var names must match A-Z, 0-9, and underscores")
            }
        }
        if ["url", "endpoint", "api_base", "base_url"].contains(where: field.key.contains), !value.isEmpty {
            guard let comps = URLComponents(string: value),
                  comps.scheme != nil, comps.host?.isEmpty == false else {
                return Result(severity: "error", message: "expected a URL with scheme and host")
            }
            if comps.user != nil || comps.password != nil {
                return Result(severity: "error", message: "URL must not embed credentials")
            }
            if let scheme = comps.scheme, !["http", "https", "grpc"].contains(scheme) {
                return Result(severity: "warning", message: "uncommon URL scheme")
            }
        }
        if field.key.contains("dedup_window"), !value.isEmpty,
           value.range(of: "^\\d+$", options: .regularExpression) == nil,
           value.range(of: "^(?:\\d+(?:\\.\\d+)?(?:ns|us|\u{00B5}s|ms|s|m|h))+$", options: .regularExpression) == nil {
            return Result(severity: "error", message: "duration must be like 30s, 1m, or a seconds integer")
        }
        if field.key.contains("tls_skip_verify"), value == "true" {
            return Result(severity: "warning", message: "TLS verification is disabled; dev-only")
        }
        return Result()
    }
}

// MARK: - Catalog

enum ConfigEditorCatalog {
    static let llmProviders = [
        "anthropic", "openai", "openrouter", "azure", "gemini", "gemini-openai",
        "groq", "mistral", "cohere", "deepseek", "xai", "bedrock", "vertex_ai",
        "fireworks_ai", "perplexity", "huggingface", "replicate", "together_ai",
        "cerebras", "ollama", "vllm", "lm_studio", "custom",
    ]
    static var llmOverrideProviders: [String] { [""] + llmProviders }
    static let connectors = [
        "openclaw", "zeptoclaw", "codex", "claudecode", "hermes", "cursor",
        "windsurf", "geminicli", "copilot", "openhands", "antigravity",
        "opencode", "omnigent",
    ]
    static let detectionStrategies = ["regex_only", "regex_judge", "judge_first"]

    /// Seven-field "<Component> LLM Override" group (TUI _component_llm_fields).
    private static func llmOverrideFields(_ title: String, _ prefix: String) -> [ConfigEditorField] {
        [
            .init(label: ".. \(title) LLM Override ..", key: "", kind: .header),
            .init(label: "Provider", key: "\(prefix).provider", kind: .choice,
                  options: llmOverrideProviders, hint: "Blank inherits Unified LLM."),
            .init(label: "Model", key: "\(prefix).model", hint: "Blank inherits Unified LLM model."),
            .init(label: "API Key Env", key: "\(prefix).api_key_env", hint: "Env var NAME for this component."),
            .init(label: "API Key (redacted)", key: "\(prefix).api_key", kind: .password, hint: "Inline component key."),
            .init(label: "Base URL", key: "\(prefix).base_url", hint: "Optional local/proxy endpoint."),
            .init(label: "Timeout (s)", key: "\(prefix).timeout", kind: .int, hint: "Per-request timeout."),
            .init(label: "Max Retries", key: "\(prefix).max_retries", kind: .int, hint: "Retry count."),
        ]
    }

    /// Agent-hook policy group (TUI _agent_hook_fields).
    private static func agentHookFields(_ title: String, _ prefix: String) -> [ConfigEditorField] {
        [
            .init(label: ".. \(title) ..", key: "", kind: .header),
            .init(label: "Enabled", key: "\(prefix).enabled", kind: .bool, hint: "\(title) hooks master switch."),
            .init(label: "Mode", key: "\(prefix).mode", kind: .choice, options: ["", "observe", "action"],
                  hint: "Blank inherits connector defaults."),
            .init(label: "Fail Mode", key: "\(prefix).fail_mode", kind: .choice, options: ["", "open", "closed"],
                  hint: "Legacy policy-layer hint."),
            .init(label: "Scan on Session Start", key: "\(prefix).scan_on_session_start", kind: .bool,
                  hint: "Run checks when a session begins."),
            .init(label: "Scan on Stop", key: "\(prefix).scan_on_stop", kind: .bool,
                  hint: "Run checks when a session stops."),
            .init(label: "Scan Paths", key: "\(prefix).scan_paths", hint: "CSV extra paths scanned by hooks."),
            .init(label: "Component Scan Interval (min)", key: "\(prefix).component_scan_interval_minutes",
                  kind: .int, hint: "Minimum minutes between repeated scans."),
        ]
    }

    /// Severity → file/runtime/install action matrix (TUI action_matrix_fields).
    private static func actionMatrixFields(_ prefix: String) -> [ConfigEditorField] {
        var out: [ConfigEditorField] = [
            .init(label: ".. \(prefix.replacingOccurrences(of: "_", with: " ").uppercased()) (severity -> file / runtime / install) ..",
                  key: "", kind: .header,
                  headerValue: "file: quarantine/none; runtime: enable/disable; install: none/block/allow"),
        ]
        for severity in ["critical", "high", "medium", "low", "info"] {
            let label = severity.prefix(1).uppercased() + severity.dropFirst()
            out += [
                .init(label: "\(label) - file", key: "\(prefix).\(severity).file", kind: .choice,
                      options: ["none", "quarantine"],
                      hint: "On \(severity.uppercased()): quarantine moves the artifact; none leaves it in place."),
                .init(label: "\(label) - runtime", key: "\(prefix).\(severity).runtime", kind: .choice,
                      options: ["enable", "disable"],
                      hint: "On \(severity.uppercased()): disable stops runtime invocation."),
                .init(label: "\(label) - install", key: "\(prefix).\(severity).install", kind: .choice,
                      options: ["none", "block", "allow"],
                      hint: "On \(severity.uppercased()): block/allow pins the install decision."),
            ]
        }
        return out
    }

    /// The full section catalog, in TUI order. Per-connector override groups
    /// are generated for the active roster.
    static func sections(activeConnectors: [String]) -> [ConfigEditorSection] {
        var sections: [ConfigEditorSection] = []

        sections.append(ConfigEditorSection(
            name: "General",
            summary: "Global paths, environment label, and the shared LLM key fallback.",
            help: "Config Version is read-only; edit unified LLM fields here instead of legacy inspect_llm.",
            fields: [
                .init(label: "Config Version", key: "config_version", kind: .header),
                .init(label: ".. Paths ..", key: "", kind: .header),
                .init(label: "Data Dir", key: "data_dir", hint: "Root directory for DefenseClaw state."),
                .init(label: "Audit DB", key: "audit_db", hint: "SQLite file path for the audit log."),
                .init(label: "Quarantine Dir", key: "quarantine_dir", hint: "Where quarantined assets are moved."),
                .init(label: "Plugin Dir", key: "plugin_dir", hint: "Directory scanned for installed plugins."),
                .init(label: "Policy Dir", key: "policy_dir", hint: "Root of policy packs."),
                .init(label: "Environment", key: "environment", hint: "Free-form deployment label."),
                .init(label: ".. Unified LLM (shared by scanners + guardrail) ..", key: "", kind: .header),
                .init(label: "Provider", key: "llm.provider", kind: .choice, options: llmProviders,
                      hint: "LLM provider family."),
                .init(label: "Model", key: "llm.model", hint: "Model identifier."),
                .init(label: "API Key Env", key: "llm.api_key_env", hint: "Env var NAME holding the unified key."),
                .init(label: "API Key (redacted)", key: "llm.api_key", kind: .password, hint: "Inline key; prefer API Key Env."),
                .init(label: "Base URL", key: "llm.base_url", hint: "Override provider base URL."),
                .init(label: "Timeout (s)", key: "llm.timeout", kind: .int, hint: "Per-request timeout in seconds."),
                .init(label: "Max Retries", key: "llm.max_retries", kind: .int, hint: "Retries with exponential backoff."),
            ]
        ))

        sections.append(ConfigEditorSection(
            name: "Agent",
            summary: "Logical agent identity used for aggregation, webhooks, and enterprise reporting.",
            fields: [
                .init(label: "Agent ID", key: "agent.id", hint: "Stable lower-kebab-case identity."),
                .init(label: "Agent Name", key: "agent.name", hint: "Human-readable display name."),
            ]
        ))

        sections.append(ConfigEditorSection(
            name: "Privacy",
            summary: "Redaction and privacy controls for audit DB, OTel, Splunk, webhooks, and terminal logs.",
            fields: [
                .init(label: "Disable Redaction", key: "privacy.disable_redaction", kind: .bool,
                      hint: "true stores raw content in all sinks."),
            ]
        ))

        sections.append(ConfigEditorSection(
            name: "Notifications",
            summary: "User-session desktop toasts for blocks, would-blocks, and HITL approvals.",
            help: "Restart the gateway after editing; the dispatcher snapshots config at boot.",
            fields: [
                .init(label: "Enabled", key: "notifications.enabled", kind: .bool, hint: "Master desktop notification switch."),
                .init(label: ".. Categories ..", key: "", kind: .header),
                .init(label: "Block (enforced)", key: "notifications.block_enforced", kind: .bool,
                      hint: "Toast when a request is actually denied."),
                .init(label: "Block (would-block)", key: "notifications.block_would_block", kind: .bool,
                      hint: "Toast for observe-mode would-block verdicts."),
                .init(label: "HITL Approval", key: "notifications.hitl_approval", kind: .bool,
                      hint: "Toast when a HITL approval prompt is pending."),
                .init(label: ".. Sources ..", key: "", kind: .header),
                .init(label: "Source: Hook", key: "notifications.sources.hook", kind: .bool, hint: "Allow hook notifications."),
                .init(label: "Source: Guardrail", key: "notifications.sources.guardrail", kind: .bool,
                      hint: "Allow guardrail notifications."),
                .init(label: "Source: Asset Policy", key: "notifications.sources.asset_policy", kind: .bool,
                      hint: "Allow asset-policy notifications."),
                .init(label: ".. Throttle ..", key: "", kind: .header),
                .init(label: "Dedup Window", key: "notifications.dedup_window", hint: "Duration string like 30s, 1m, or 500ms."),
                .init(label: "Max Per Minute", key: "notifications.max_per_minute", kind: .int, hint: "Global notification rate cap."),
            ]
        ))

        sections.append(ConfigEditorSection(
            name: "Claw",
            summary: "Which agent framework DefenseClaw defends.",
            fields: [
                .init(label: "Mode", key: "claw.mode", kind: .choice, options: connectors, hint: "Active agent framework."),
                .init(label: "Home Dir", key: "claw.home_dir", hint: "Override for connector home directory."),
                .init(label: "Config File", key: "claw.config_file", hint: "Connector primary config file."),
            ]
        ))

        sections.append(ConfigEditorSection(
            name: "Agent Hooks",
            summary: "Dedicated agent hook policy: when scans run, fail behavior, and watched paths.",
            fields: agentHookFields("Claude Code", "claude_code") + agentHookFields("Codex", "codex")
        ))

        sections.append(ConfigEditorSection(
            name: "Connector Hooks",
            summary: "Advanced connector_hooks map for configured and future agent connectors.",
            fields: Array(Set(connectors + activeConnectors)).sorted().flatMap {
                agentHookFields(friendlyConnectorName($0), "connector_hooks.\($0)")
            }
        ))

        sections.append(ConfigEditorSection(
            name: "Gateway",
            summary: "Sidecar WebSocket gateway: connection settings, TLS/auth, API bind, reconnect tuning.",
            fields: [
                .init(label: "Host", key: "gateway.host", hint: "Where clients reach the gateway."),
                .init(label: "Port", key: "gateway.port", kind: .int, hint: "WebSocket port."),
                .init(label: "API Port", key: "gateway.api_port", kind: .int, hint: "REST sidecar port."),
                .init(label: "API Bind", key: "gateway.api_bind", hint: "Bind address for API Port."),
                .init(label: "Auto Approve Safe", key: "gateway.auto_approve_safe", kind: .bool, hint: "Auto-approve CLEAN scans."),
                .init(label: "TLS", key: "gateway.tls", kind: .bool, hint: "Force wss:// and cert validation."),
                .init(label: "TLS Skip Verify", key: "gateway.tls_skip_verify", kind: .bool, hint: "Skip cert verification."),
                .init(label: "Reconnect MS", key: "gateway.reconnect_ms", kind: .int, hint: "Initial reconnect backoff."),
                .init(label: "Max Reconnect MS", key: "gateway.max_reconnect_ms", kind: .int, hint: "Reconnect backoff ceiling."),
                .init(label: "Approval Timeout (s)", key: "gateway.approval_timeout_s", kind: .int,
                      hint: "Operator approval wait budget."),
                .init(label: "Token Env", key: "gateway.token_env", hint: "Env var NAME holding gateway auth token."),
                .init(label: "Token (redacted)", key: "gateway.token", kind: .password, hint: "Inline gateway token."),
                .init(label: "Device Key File", key: "gateway.device_key_file", hint: "Path to per-machine private key."),
            ]
        ))

        // Guardrail (largest section) — core, LLM override, detection, judge,
        // judge categories, per-connector overrides.
        var guardrail: [ConfigEditorField] = [
            .init(label: ".. Core ..", key: "", kind: .header),
            .init(label: "Enabled", key: "guardrail.enabled", kind: .bool, hint: "Master guardrail switch."),
            .init(label: "Mode", key: "guardrail.mode", kind: .choice, options: ["observe", "action"],
                  hint: "observe=log only; action=block."),
            .init(label: "Hook Fail Mode", key: "guardrail.hook_fail_mode", kind: .choice, options: ["open", "closed"],
                  hint: "open=allow on hook failures; closed=block."),
            .init(label: "Scanner Mode", key: "guardrail.scanner_mode", kind: .choice, options: ["local", "remote", "both"],
                  hint: "local=regex/judge; remote=Cisco AI Defense; both=chained."),
            .init(label: "Connector", key: "guardrail.connector", kind: .choice, options: [""] + connectors,
                  hint: "Blank follows claw.mode."),
            .init(label: "Allow Empty Providers", key: "guardrail.allow_empty_providers", kind: .bool,
                  hint: "Let sidecar boot with no upstream providers."),
            .init(label: "Allow Unknown LLM Domains", key: "guardrail.allow_unknown_llm_domains", kind: .bool,
                  hint: "Permit unknown LLM-looking hosts."),
            .init(label: "Human Approval", key: "guardrail.hilt.enabled", kind: .bool,
                  hint: "Ask before supported high-risk actions."),
            .init(label: "Approval Min Severity", key: "guardrail.hilt.min_severity", kind: .choice,
                  options: ["HIGH", "MEDIUM", "LOW", "CRITICAL"], hint: "Minimum severity for approval prompts."),
            .init(label: "Host", key: "guardrail.host", hint: "Proxy bind address."),
            .init(label: "Port", key: "guardrail.port", kind: .int, hint: "Proxy listen port."),
            .init(label: "Model", key: "guardrail.model", hint: "Legacy upstream model identifier."),
            .init(label: "Model Name", key: "guardrail.model_name", hint: "Display name shown to agents."),
            .init(label: "Original Model", key: "guardrail.original_model", hint: "Client-visible original model."),
            .init(label: "API Key Env", key: "guardrail.api_key_env", hint: "Legacy upstream API key env name."),
            .init(label: "API Base", key: "guardrail.api_base", hint: "Legacy upstream API URL."),
            .init(label: "Block Message", key: "guardrail.block_message", hint: "Response text returned when blocked."),
            .init(label: "Stream Buffer", key: "guardrail.stream_buffer_bytes", kind: .int,
                  hint: "Chunk size for streaming inspection."),
            .init(label: "Retain Judge Bodies", key: "guardrail.retain_judge_bodies", kind: .bool,
                  hint: "Persist raw judge verdicts locally."),
        ]
        guardrail += llmOverrideFields("Guardrail", "guardrail.llm")
        guardrail += [
            .init(label: ".. Detection ..", key: "", kind: .header),
            .init(label: "Strategy", key: "guardrail.detection_strategy", kind: .choice,
                  options: detectionStrategies, hint: "Global detection strategy."),
            .init(label: "Strategy (Prompt)", key: "guardrail.detection_strategy_prompt", kind: .choice,
                  options: [""] + detectionStrategies, hint: "Prompt override; blank=inherit."),
            .init(label: "Strategy (Completion)", key: "guardrail.detection_strategy_completion", kind: .choice,
                  options: [""] + detectionStrategies, hint: "Completion override; blank=inherit."),
            .init(label: "Strategy (Tool Call)", key: "guardrail.detection_strategy_tool_call", kind: .choice,
                  options: [""] + detectionStrategies, hint: "Tool-call override; blank=inherit."),
            .init(label: "Rule Pack Dir", key: "guardrail.rule_pack_dir", hint: "Path to active rule pack."),
            .init(label: "Judge Sweep", key: "guardrail.judge_sweep", kind: .bool,
                  hint: "Judge all requests in regex_only mode."),
            .init(label: ".. LLM Judge ..", key: "", kind: .header),
            .init(label: "Judge Enabled", key: "guardrail.judge.enabled", kind: .bool, hint: "Enable LLM-as-judge scanner."),
            .init(label: "Judge Model", key: "guardrail.judge.model", hint: "Legacy judge model id."),
            .init(label: "Judge API Key Env", key: "guardrail.judge.api_key_env", hint: "Legacy judge API key env."),
            .init(label: "Judge API Base", key: "guardrail.judge.api_base", hint: "Legacy judge API base URL."),
            .init(label: "Judge Timeout", key: "guardrail.judge.timeout", hint: "Seconds to wait for one judge call."),
            .init(label: "Adjudication Timeout", key: "guardrail.judge.adjudication_timeout",
                  hint: "Total judge fallback budget."),
            .init(label: "Fallbacks", key: "guardrail.judge.fallbacks", hint: "CSV of backup judge models."),
        ]
        guardrail += llmOverrideFields("Judge", "guardrail.judge.llm")
        guardrail += [
            .init(label: ".. Judge Categories ..", key: "", kind: .header),
            .init(label: "Injection", key: "guardrail.judge.injection", kind: .bool, hint: "Detect prompt injection."),
            .init(label: "Exfiltration", key: "guardrail.judge.exfil", kind: .bool, hint: "Detect data exfiltration attempts."),
            .init(label: "PII", key: "guardrail.judge.pii", kind: .bool, hint: "Master PII toggle."),
            .init(label: "PII (Prompt)", key: "guardrail.judge.pii_prompt", kind: .bool, hint: "Flag PII on inbound prompts."),
            .init(label: "PII (Completion)", key: "guardrail.judge.pii_completion", kind: .bool,
                  hint: "Flag PII on completions."),
            .init(label: "Tool Injection", key: "guardrail.judge.tool_injection", kind: .bool,
                  hint: "Detect payloads in tool-call args."),
        ]
        // The TUI only surfaces the per-connector override groups on
        // multi-connector rosters.
        for connector in (activeConnectors.count > 1 ? activeConnectors : []) {
            guardrail += [
                .init(label: ".. \(friendlyConnectorName(connector)) Override ..", key: "", kind: .header),
                .init(label: "Mode", key: "guardrail.connectors.\(connector).mode", kind: .choice,
                      options: ["observe", "action"], hint: "Per-connector mode."),
                .init(label: "Rule Pack Dir", key: "guardrail.connectors.\(connector).rule_pack_dir",
                      hint: "Per-connector rule pack (blank inherits)."),
                .init(label: "Enabled", key: "guardrail.connectors.\(connector).enabled", kind: .bool,
                      hint: "Per-connector switch (off tears down hooks)."),
                .init(label: "Hook Fail Mode", key: "guardrail.connectors.\(connector).hook_fail_mode", kind: .choice,
                      options: ["open", "closed"], hint: "Per-connector fail mode."),
                .init(label: "Human Approval", key: "guardrail.connectors.\(connector).hilt.enabled", kind: .bool,
                      hint: "Ask before high-risk actions."),
                .init(label: "Approval Min Severity", key: "guardrail.connectors.\(connector).hilt.min_severity",
                      kind: .choice, options: ["HIGH", "MEDIUM", "LOW", "CRITICAL"],
                      hint: "Min severity for approval prompts."),
                .init(label: "Block Message", key: "guardrail.connectors.\(connector).block_message",
                      hint: "Per-connector message (blank inherits)."),
                .init(label: "LLM Judge (hook lane)", key: "guardrail.judge.hook_connectors.\(connector)", kind: .bool,
                      hint: "Add/remove from the hook-lane judge gate."),
            ]
        }
        sections.append(ConfigEditorSection(
            name: "Guardrail",
            summary: "Proxy/hook guardrail: mode, detection strategies, LLM judge, per-connector overrides.",
            fields: guardrail
        ))

        var scanners: [ConfigEditorField] = [
            .init(label: ".. Skill Scanner ..", key: "", kind: .header),
            .init(label: "Binary", key: "scanners.skill_scanner.binary", hint: "Path/name of skill-scanner executable."),
            .init(label: "Policy", key: "scanners.skill_scanner.policy", kind: .choice,
                  options: ["strict", "balanced", "permissive", "none"], hint: "Skill scanner policy."),
            .init(label: "Lenient", key: "scanners.skill_scanner.lenient", kind: .bool,
                  hint: "Downgrade findings by one severity."),
            .init(label: "Use LLM", key: "scanners.skill_scanner.use_llm", kind: .bool,
                  hint: "Enable LLM-assisted classification."),
            .init(label: "LLM Consensus Runs", key: "scanners.skill_scanner.llm_consensus_runs", kind: .int,
                  hint: "Number of LLM votes."),
            .init(label: "Use Behavioral", key: "scanners.skill_scanner.use_behavioral", kind: .bool,
                  hint: "Run behavioral analysis."),
            .init(label: "Enable Meta", key: "scanners.skill_scanner.enable_meta", kind: .bool, hint: "Scan skill metadata."),
            .init(label: "Use Trigger", key: "scanners.skill_scanner.use_trigger", kind: .bool,
                  hint: "Enable trigger-word heuristics."),
            .init(label: "Use VirusTotal", key: "scanners.skill_scanner.use_virustotal", kind: .bool,
                  hint: "Submit artifact hashes."),
            .init(label: "VirusTotal Key Env", key: "scanners.skill_scanner.virustotal_api_key_env",
                  hint: "Env var NAME for the VirusTotal key."),
            .init(label: "VirusTotal API Key (redacted)", key: "scanners.skill_scanner.virustotal_api_key",
                  kind: .password, hint: "Inline VirusTotal key."),
            .init(label: "Use AI Defense", key: "scanners.skill_scanner.use_aidefense", kind: .bool,
                  hint: "Chain Cisco AI Defense scan."),
        ]
        scanners += llmOverrideFields("Skill Scanner", "scanners.skill_scanner.llm")
        scanners += [
            .init(label: ".. MCP Scanner ..", key: "", kind: .header),
            .init(label: "Binary", key: "scanners.mcp_scanner.binary", hint: "Path/name of mcp-scanner executable."),
            .init(label: "Analyzers", key: "scanners.mcp_scanner.analyzers", hint: "CSV of analyzer IDs."),
            .init(label: "Scan Prompts", key: "scanners.mcp_scanner.scan_prompts", kind: .bool,
                  hint: "Scan MCP prompt templates."),
            .init(label: "Scan Resources", key: "scanners.mcp_scanner.scan_resources", kind: .bool,
                  hint: "Scan MCP resource contents."),
            .init(label: "Scan Instructions", key: "scanners.mcp_scanner.scan_instructions", kind: .bool,
                  hint: "Scan server instructions."),
        ]
        scanners += llmOverrideFields("MCP Scanner", "scanners.mcp_scanner.llm")
        scanners += [
            .init(label: ".. Plugin / CodeGuard ..", key: "", kind: .header),
            .init(label: "Plugin Scanner", key: "scanners.plugin_scanner", hint: "Command to scan connector plugins."),
        ]
        scanners += llmOverrideFields("Plugin Scanner", "scanners.plugin_llm")
        scanners.append(.init(label: "CodeGuard", key: "scanners.codeguard", hint: "Command for the CodeGuard skill."))
        sections.append(ConfigEditorSection(
            name: "Scanners",
            summary: "Skill/MCP/plugin scanner binaries, policies, and per-component LLM overrides.",
            fields: scanners
        ))

        var assetPolicy: [ConfigEditorField] = [
            .init(label: "Enabled", key: "asset_policy.enabled", kind: .bool, hint: "Master asset admission switch."),
            .init(label: "Mode", key: "asset_policy.mode", kind: .choice, options: ["observe", "action"],
                  hint: "observe=log; action=block."),
        ]
        for kind in ["skill", "mcp", "plugin"] {
            assetPolicy += [
                .init(label: ".. \(kind.prefix(1).uppercased() + kind.dropFirst()) ..", key: "", kind: .header),
                .init(label: "Default", key: "asset_policy.\(kind).default", kind: .choice, options: ["allow", "deny"],
                      hint: "Fallback action."),
                .init(label: "Registry Required", key: "asset_policy.\(kind).registry_required", kind: .bool,
                      hint: "Require an approved registry entry."),
                .init(label: "Empty Registry Action", key: "asset_policy.\(kind).registry_empty_action", kind: .choice,
                      options: ["deny", "allow"], hint: "Behavior when registry required but empty."),
            ]
            if kind == "mcp" {
                assetPolicy += [
                    .init(label: "Runtime Detection", key: "asset_policy.mcp.runtime_detection.enabled", kind: .bool,
                          hint: "Detect runtime MCP usage."),
                    .init(label: "Terminal Commands", key: "asset_policy.mcp.runtime_detection.terminal_commands", kind: .bool,
                          hint: "Inspect terminal command surfaces."),
                    .init(label: "Unknown Terminal MCP", key: "asset_policy.mcp.runtime_detection.unknown_terminal_mcp",
                          kind: .choice, options: ["observe", "action"], hint: "Unknown MCP posture."),
                ]
            }
        }
        // Per-connector overrides (multi-connector rosters, TUI
        // _per_connector_asset_policy_fields): blank = inherit; the override
        // empty-registry action adds warn/block choices.
        for connector in (activeConnectors.count > 1 ? activeConnectors : []) {
            assetPolicy.append(.init(label: ".. \(friendlyConnectorName(connector)) Override ..", key: "", kind: .header))
            assetPolicy.append(.init(label: "Mode", key: "asset_policy.connectors.\(connector).mode",
                                     kind: .choice, options: ["", "observe", "action"],
                                     hint: "Per-connector mode (blank inherits)."))
            for kind in ["skill", "mcp", "plugin"] {
                let label = kind.prefix(1).uppercased() + kind.dropFirst()
                assetPolicy += [
                    .init(label: "Default (\(label))", key: "asset_policy.connectors.\(connector).\(kind).default",
                          kind: .choice, options: ["", "allow", "deny"], hint: "Override (blank inherits)."),
                    .init(label: "Registry Required (\(label))",
                          key: "asset_policy.connectors.\(connector).\(kind).registry_required",
                          kind: .choice, options: ["", "true", "false"], hint: "Override (blank inherits)."),
                    .init(label: "Empty Registry Action (\(label))",
                          key: "asset_policy.connectors.\(connector).\(kind).registry_empty_action",
                          kind: .choice, options: ["", "deny", "warn", "allow", "block"],
                          hint: "Override (blank inherits)."),
                ]
            }
        }
        sections.append(ConfigEditorSection(
            name: "Asset Policy",
            summary: "Registry requirements and default allow/deny behavior.",
            fields: assetPolicy
        ))

        sections.append(ConfigEditorSection(
            name: "AI Discovery",
            summary: "Background discovery of AI components, SDKs, and provider usage.",
            fields: [
                .init(label: "Enabled", key: "ai_discovery.enabled", kind: .bool, hint: "Run the AI discovery service."),
                .init(label: "Mode", key: "ai_discovery.mode", kind: .choice, options: ["passive", "enhanced"],
                      hint: "passive or enhanced."),
                .init(label: "Scan Interval (min)", key: "ai_discovery.scan_interval_min", kind: .int,
                      hint: "Minutes between full scans."),
                .init(label: "Process Interval (s)", key: "ai_discovery.process_interval_s", kind: .int,
                      hint: "Seconds between process scans."),
                .init(label: "Scan Roots", key: "ai_discovery.scan_roots", hint: "CSV roots for artifact scans."),
                .init(label: "Signature Packs", key: "ai_discovery.signature_packs", hint: "CSV custom signature packs."),
                .init(label: "Workspace Signatures", key: "ai_discovery.allow_workspace_signatures", kind: .bool,
                      hint: "Allow workspace signatures."),
                .init(label: "Disabled Signatures", key: "ai_discovery.disabled_signature_ids",
                      hint: "CSV signature IDs to suppress."),
                .init(label: "Shell History", key: "ai_discovery.include_shell_history", kind: .bool,
                      hint: "Match known AI command patterns."),
                .init(label: "Package Manifests", key: "ai_discovery.include_package_manifests", kind: .bool,
                      hint: "Detect AI SDK dependencies."),
                .init(label: "Env Var Names", key: "ai_discovery.include_env_var_names", kind: .bool,
                      hint: "Detect env var names only."),
                .init(label: "Provider Domains", key: "ai_discovery.include_network_domains", kind: .bool,
                      hint: "Detect provider domains."),
                .init(label: "Max Files", key: "ai_discovery.max_files_per_scan", kind: .int, hint: "Max files per scan."),
                .init(label: "Max File Bytes", key: "ai_discovery.max_file_bytes", kind: .int, hint: "Skip larger files."),
                .init(label: "Emit OTel", key: "ai_discovery.emit_otel", kind: .bool,
                      hint: "Emit sanitized AI visibility telemetry."),
                .init(label: "Store Raw Local Paths", key: "ai_discovery.store_raw_local_paths", kind: .bool,
                      hint: "Store raw paths locally only."),
            ]
        ))

        sections.append(ConfigEditorSection(
            name: "Gateway Watcher",
            summary: "Filesystem watchers re-applying enforcement when skills/plugins/MCP configs change.",
            fields: [
                .init(label: "Enabled", key: "gateway.watcher.enabled", kind: .bool, hint: "Master switch for all watchers."),
                .init(label: ".. Skill ..", key: "", kind: .header),
                .init(label: "Enabled", key: "gateway.watcher.skill.enabled", kind: .bool, hint: "Watch skill directories."),
                .init(label: "Take Action", key: "gateway.watcher.skill.take_action", kind: .bool,
                      hint: "Re-apply enforcement on changes."),
                .init(label: "Dirs", key: "gateway.watcher.skill.dirs", hint: "CSV extra skill directories."),
                .init(label: ".. Plugin ..", key: "", kind: .header),
                .init(label: "Enabled", key: "gateway.watcher.plugin.enabled", kind: .bool, hint: "Watch plugin_dir."),
                .init(label: "Take Action", key: "gateway.watcher.plugin.take_action", kind: .bool,
                      hint: "Re-apply enforcement."),
                .init(label: "Dirs", key: "gateway.watcher.plugin.dirs", hint: "CSV extra plugin directories."),
                .init(label: ".. MCP ..", key: "", kind: .header),
                .init(label: "Take Action", key: "gateway.watcher.mcp.take_action", kind: .bool,
                      hint: "Re-apply enforcement on MCP config changes."),
            ]
        ))

        sections.append(ConfigEditorSection(
            name: "Gateway Watchdog",
            summary: "Health-check loop that restarts the gateway process when it becomes unresponsive.",
            fields: [
                .init(label: "Enabled", key: "gateway.watchdog.enabled", kind: .bool, hint: "Turn the watchdog on/off."),
                .init(label: "Interval (s)", key: "gateway.watchdog.interval", kind: .int,
                      hint: "Seconds between health checks."),
                .init(label: "Debounce (failures)", key: "gateway.watchdog.debounce", kind: .int,
                      hint: "Consecutive failures before restart."),
            ]
        ))

        sections.append(ConfigEditorSection(
            name: "Audit Sinks",
            summary: "Read-only audit sink summary.",
            help: "Manage via Setup → Observability (Splunk) or `defenseclaw setup observability`.",
            fields: [
                .init(label: "How to edit", key: "", kind: .header,
                      headerValue: "Use the Observability / Splunk wizards; sinks appear in the Overview destinations table."),
            ]
        ))

        sections.append(ConfigEditorSection(
            name: "Webhooks",
            summary: "Read-only notifier webhook summary.",
            help: "Manage via Setup → Webhooks or `defenseclaw setup webhook`.",
            fields: [
                .init(label: "How to edit", key: "", kind: .header,
                      headerValue: "Use the Webhooks wizard in Setup to add or change notifier webhooks."),
            ]
        ))

        sections.append(ConfigEditorSection(
            name: "OTel",
            summary: "OpenTelemetry exporter config.",
            fields: [
                .init(label: ".. Process-wide policy ..", key: "", kind: .header),
                .init(label: "Enabled", key: "otel.enabled", kind: .bool, hint: "Master OpenTelemetry export switch."),
                .init(label: ".. Traces ..", key: "", kind: .header),
                .init(label: "Sampler", key: "otel.traces.sampler", kind: .choice,
                      options: ["always_on", "always_off", "traceidratio",
                                "parentbased_always_on", "parentbased_always_off", "parentbased_traceidratio"],
                      hint: "Trace sampler."),
                .init(label: "Sampler Arg", key: "otel.traces.sampler_arg", hint: "Trace sampler argument."),
                .init(label: ".. Logs ..", key: "", kind: .header),
                .init(label: "Emit individual findings", key: "otel.logs.emit_individual_findings", kind: .bool,
                      hint: "One record per finding."),
                .init(label: ".. Metrics ..", key: "", kind: .header),
                .init(label: "Export interval (s)", key: "otel.metrics.export_interval_s", kind: .int,
                      hint: "Seconds between metric pushes."),
                .init(label: "Temporality", key: "otel.metrics.temporality", kind: .choice,
                      options: ["delta", "cumulative"], hint: "Metric temporality."),
                .init(label: ".. Batch ..", key: "", kind: .header),
                .init(label: "Max export batch size", key: "otel.batch.max_export_batch_size", kind: .int,
                      hint: "Max records per request."),
                .init(label: "Scheduled delay (ms)", key: "otel.batch.scheduled_delay_ms", kind: .int,
                      hint: "Batch flush delay."),
                .init(label: "Max queue size", key: "otel.batch.max_queue_size", kind: .int, hint: "In-memory queue size."),
                .init(label: ".. Resource ..", key: "", kind: .header),
                .init(label: "Attributes", key: "otel.resource.attributes", hint: "CSV resource attributes."),
            ]
        ))

        sections.append(ConfigEditorSection(
            name: "Skill Actions", summary: "Skill admission response matrix.",
            fields: actionMatrixFields("skill_actions")
        ))
        sections.append(ConfigEditorSection(
            name: "MCP Actions", summary: "MCP admission response matrix.",
            fields: actionMatrixFields("mcp_actions")
        ))
        sections.append(ConfigEditorSection(
            name: "Plugin Actions", summary: "Plugin admission response matrix.",
            fields: actionMatrixFields("plugin_actions")
        ))

        sections.append(ConfigEditorSection(
            name: "Watch",
            summary: "Debounce/auto-block behavior for the file watchers.",
            fields: [
                .init(label: "Debounce MS", key: "watch.debounce_ms", kind: .int,
                      hint: "Milliseconds to wait for edits to settle."),
                .init(label: "Auto Block", key: "watch.auto_block", kind: .bool, hint: "Block high findings automatically."),
                .init(label: "Allow List Bypass", key: "watch.allow_list_bypass_scan", kind: .bool,
                      hint: "Skip allow-listed rescans."),
                .init(label: "Rescan Enabled", key: "watch.rescan_enabled", kind: .bool,
                      hint: "Periodically re-scan installed artifacts."),
                .init(label: "Rescan Interval Min", key: "watch.rescan_interval_min", kind: .int,
                      hint: "Minutes between rescans."),
            ]
        ))

        sections.append(ConfigEditorSection(
            name: "OpenShell",
            summary: "OpenShell sandbox integration.",
            fields: [
                .init(label: "Binary", key: "openshell.binary", hint: "Path to the openshell executable."),
                .init(label: "Policy Dir", key: "openshell.policy_dir", hint: "OpenShell policy YAML directory."),
                .init(label: "Mode", key: "openshell.mode", kind: .choice, options: ["", "docker", "standalone"],
                      hint: "docker, standalone, or blank auto-detect."),
                .init(label: "Version", key: "openshell.version", hint: "Pinned OpenShell version."),
                .init(label: "Sandbox Home", key: "openshell.sandbox_home", hint: "Root of per-sandbox state."),
                .init(label: "Auto Pair (tristate)", key: "openshell.auto_pair", kind: .choice,
                      options: ["", "true", "false"], hint: "Blank=default true."),
                .init(label: "Host Networking (tristate)", key: "openshell.host_networking", kind: .choice,
                      options: ["", "true", "false"], hint: "Blank=default false."),
            ]
        ))

        sections.append(ConfigEditorSection(
            name: "Inspect LLM (legacy - read-only)",
            summary: "Deprecated v4 block. Edit the Unified LLM section instead.",
            fields: [
                .init(label: "Provider", key: "inspect_llm.provider", kind: .header),
                .init(label: "Model", key: "inspect_llm.model", kind: .header),
                .init(label: "API Key Env", key: "inspect_llm.api_key_env", kind: .header),
                .init(label: "Base URL", key: "inspect_llm.base_url", kind: .header),
                .init(label: "Timeout (s)", key: "inspect_llm.timeout", kind: .header),
                .init(label: "Max Retries", key: "inspect_llm.max_retries", kind: .header),
            ]
        ))

        sections.append(ConfigEditorSection(
            name: "Cisco AI Defense",
            summary: "Cloud-hosted prompt/response moderation.",
            fields: [
                .init(label: "Endpoint", key: "cisco_ai_defense.endpoint", hint: "Cisco AI Defense API endpoint."),
                .init(label: "API Key (redacted)", key: "cisco_ai_defense.api_key", kind: .password,
                      hint: "Inline Cisco key."),
                .init(label: "API Key Env", key: "cisco_ai_defense.api_key_env", hint: "Env var NAME holding the Cisco key."),
                .init(label: "Timeout (ms)", key: "cisco_ai_defense.timeout_ms", kind: .int, hint: "HTTP timeout for probes."),
                .init(label: "Enabled Rules", key: "cisco_ai_defense.enabled_rules", hint: "CSV cloud rules."),
            ]
        ))

        sections.append(ConfigEditorSection(
            name: "Firewall",
            summary: "Host firewall anchor paths. Read-only.",
            fields: [
                .init(label: "Config File", key: "firewall.config_file", kind: .header),
                .init(label: "Rules File", key: "firewall.rules_file", kind: .header),
                .init(label: "Anchor Name", key: "firewall.anchor_name", kind: .header),
                .init(label: "How to edit", key: "", kind: .header,
                      headerValue: "Edit config.yaml directly — these paths bind to system-owned files."),
            ]
        ))

        sections.append(ConfigEditorSection(
            name: "Trusted Paths",
            summary: "Binary locations trusted for connector discovery. Read-only here.",
            help: "Manage via Setup → Trusted Paths or `defenseclaw setup trusted-paths`.",
            fields: [
                .init(label: "How to edit", key: "", kind: .header,
                      headerValue: "defenseclaw setup trusted-paths add|remove <dir>"),
            ]
        ))

        return sections
    }
}
