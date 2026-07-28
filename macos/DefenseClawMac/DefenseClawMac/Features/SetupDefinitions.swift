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
                help: "When supplied, the key is written to the selected installation's .env through hidden stdin and never placed in argv."
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
        liveDefaults: llmLiveDefaults,
        fields: [
            WizardField(key: "provider", label: "Provider", kind: .choice(options: llmProviders), defaultValue: "anthropic"),
            WizardField(key: "model", label: "Model", kind: .text(placeholder: "claude-sonnet-4-6")),
            WizardField(key: "role", label: "Role", kind: .choice(options: ["unified", "agent", "judge"]), defaultValue: "unified"),
            WizardField(key: "api-key", label: "API key", kind: .secure(placeholder: "Stored via hidden stdin, never argv"),
                        help: "When supplied, the key is written with `keys set` through stdin; only the env var name reaches setup llm."),
            WizardField(key: "api-key-env", label: "API key env var", kind: .text(placeholder: "DEFENSECLAW_LLM_KEY"), defaultValue: "DEFENSECLAW_LLM_KEY"),
            WizardField(key: "base-url", label: "Base URL", kind: .text(placeholder: "optional provider endpoint"),
                        help: "Optional for every provider; local and custom providers commonly require it."),
            WizardField(key: "timeout", label: "Timeout (seconds)", kind: .text(placeholder: "30"), defaultValue: "30"),
            WizardField(key: "max-retries", label: "Max retries", kind: .text(placeholder: "2"), defaultValue: "2"),
            WizardField(key: "bedrock-region", label: "AWS region", kind: .text(placeholder: "us-east-1"),
                        visibleWhen: (key: "provider", equals: ["bedrock"])),
            WizardField(key: "bedrock-auth-mode", label: "Bedrock auth", kind: .choice(options: ["api_key", "iam_credentials", "profile", "instance_role"]),
                        defaultValue: "api_key", visibleWhen: (key: "provider", equals: ["bedrock"])),
        ]
    )

    static func llmLiveDefaults(_ raw: YAMLNode) -> [String: String] {
        var out: [String: String] = [:]
        if let provider = raw["llm.provider"]?.string, llmProviders.contains(provider) {
            out["provider"] = provider
        }
        if let model = raw["llm.model"]?.string { out["model"] = model }
        if let env = raw["llm.api_key_env"]?.string { out["api-key-env"] = env }
        if let baseURL = raw["llm.base_url"]?.string { out["base-url"] = baseURL }
        if let timeout = raw["llm.timeout"]?.int { out["timeout"] = String(timeout) }
        if let retries = raw["llm.max_retries"]?.int { out["max-retries"] = String(retries) }
        if let region = raw["llm.bedrock.region"]?.string { out["bedrock-region"] = region }
        if let auth = raw["llm.bedrock.auth_mode"]?.string,
           ["api_key", "iam_credentials", "profile", "instance_role"].contains(auth) {
            out["bedrock-auth-mode"] = auth
        }
        return out
    }

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
        validation: providerValidation,
        fields: [
            WizardField(key: "action", label: "Action", kind: .choice(options: ["list", "show", "add", "remove"]), defaultValue: "list"),
            WizardField(key: "name", label: "Provider name", kind: .text(placeholder: "internal-llm"), visibleWhen: (key: "action", equals: ["add", "remove"])),
            WizardField(key: "base-provider-type", label: "Provider family", kind: .choice(options: [""] + llmProviders.filter { $0 != "custom" }), visibleWhen: (key: "action", equals: ["add"]), help: "Blank lets the runtime infer the upstream family."),
            WizardField(key: "base-url", label: "Base URL", kind: .text(placeholder: "https://llm.internal:8443"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "domain", label: "Domains", kind: .text(placeholder: "comma-separated domains"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "env-key", label: "API key env vars", kind: .text(placeholder: "comma-separated names"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "profile-id", label: "OpenClaw profile ID", kind: .text(placeholder: "optional auth profile"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "ollama-port", label: "Ollama ports", kind: .text(placeholder: "11434,11435"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "allowed-request", label: "Allowed request types", kind: .text(placeholder: "chat,embedding,responses"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "available-model", label: "Available models", kind: .text(placeholder: "comma-separated model ids"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "request-path-override", label: "Request path overrides", kind: .text(placeholder: "chat=/v1/chat/completions"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "ca-cert-file", label: "CA certificate file", kind: .text(placeholder: "/path/to/ca.pem"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "insecure-skip-verify", label: "Disable TLS verification", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "action", equals: ["add"]), help: "Trusted labs only. Mutually exclusive with a CA certificate."),

            WizardField(key: "bedrock-region", label: "Bedrock region", kind: .text(placeholder: "us-east-1"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "base-provider-type", equals: ["bedrock"])),
            WizardField(key: "bedrock-auth-mode", label: "Bedrock auth", kind: .choice(options: ["", "api_key", "iam_credentials", "profile", "instance_role"]), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "base-provider-type", equals: ["bedrock"])),
            WizardField(key: "bedrock-access-key-env", label: "AWS access-key env", kind: .text(placeholder: "AWS_ACCESS_KEY_ID"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "base-provider-type", equals: ["bedrock"]), visibleWhen3: (key: "bedrock-auth-mode", equals: ["iam_credentials"])),
            WizardField(key: "bedrock-secret-key-env", label: "AWS secret-key env", kind: .text(placeholder: "AWS_SECRET_ACCESS_KEY"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "base-provider-type", equals: ["bedrock"]), visibleWhen3: (key: "bedrock-auth-mode", equals: ["iam_credentials"])),
            WizardField(key: "bedrock-session-token-env", label: "AWS session-token env", kind: .text(placeholder: "AWS_SESSION_TOKEN"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "base-provider-type", equals: ["bedrock"]), visibleWhen3: (key: "bedrock-auth-mode", equals: ["iam_credentials"])),
            WizardField(key: "bedrock-profile-name", label: "AWS profile name", kind: .text(placeholder: "default"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "base-provider-type", equals: ["bedrock"]), visibleWhen3: (key: "bedrock-auth-mode", equals: ["profile"])),
            WizardField(key: "bedrock-inference-profile", label: "Inference profile prefix", kind: .text(placeholder: "us."), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "base-provider-type", equals: ["bedrock"])),
            WizardField(key: "bedrock-deployment", label: "Bedrock aliases", kind: .text(placeholder: "alias=model-id,fast=model-id"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "base-provider-type", equals: ["bedrock"])),

            WizardField(key: "vertex-project-id", label: "Vertex project ID", kind: .text(placeholder: "gcp-project"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "base-provider-type", equals: ["vertex_ai"])),
            WizardField(key: "vertex-region", label: "Vertex region", kind: .text(placeholder: "us-central1"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "base-provider-type", equals: ["vertex_ai"])),
            WizardField(key: "vertex-auth-mode", label: "Vertex auth", kind: .choice(options: ["", "service_account", "adc", "workload_identity"]), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "base-provider-type", equals: ["vertex_ai"])),
            WizardField(key: "vertex-service-account-json-env", label: "Service-account JSON env", kind: .text(placeholder: "GOOGLE_APPLICATION_CREDENTIALS"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "base-provider-type", equals: ["vertex_ai"]), visibleWhen3: (key: "vertex-auth-mode", equals: ["service_account"])),

            WizardField(key: "azure-endpoint", label: "Azure endpoint", kind: .text(placeholder: "https://name.openai.azure.com"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "base-provider-type", equals: ["azure"])),
            WizardField(key: "azure-api-version", label: "Azure API version", kind: .text(placeholder: "2024-10-21"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "base-provider-type", equals: ["azure"])),
            WizardField(key: "azure-auth-mode", label: "Azure auth", kind: .choice(options: ["", "api_key", "managed_identity"]), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "base-provider-type", equals: ["azure"])),
            WizardField(key: "azure-deployment-alias", label: "Azure deployment aliases", kind: .text(placeholder: "model=deployment"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "base-provider-type", equals: ["azure"])),
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
        validation: guardrailValidation,
        liveDefaults: guardrailLiveDefaults,
        fields: [
            WizardField(key: "connector", label: "Connector", kind: .choice(options: [""] + connectors),
                        help: "Choose a connector. Multi-connector installs start blank to avoid targeting the wrong peer."),
            WizardField(key: "mode", label: "Mode", kind: .choice(options: ["observe", "action"]), defaultValue: "observe"),
            WizardField(key: "scanner-mode", label: "Scanner mode", kind: .choice(options: ["local", "remote", "both"]), defaultValue: "local"),
            WizardField(key: "detection-strategy", label: "Detection strategy", kind: .choice(options: ["regex_only", "regex_judge", "judge_first"]), defaultValue: "regex_only"),
            WizardField(key: "rule-pack", label: "Rule pack", kind: .choice(options: ["default", "strict", "permissive"]), defaultValue: "default"),
            WizardField(key: "judge-model", label: "Judge model", kind: .text(placeholder: "provider/model"), visibleWhen: (key: "detection-strategy", equals: ["regex_judge", "judge_first"])),
            WizardField(key: "block-message", label: "Block message", kind: .text(placeholder: "optional message")),
        ]
    )

    static func guardrailLiveDefaults(_ raw: YAMLNode) -> [String: String] {
        // Prefill from live config so an apply with untouched fields never
        // silently downgrades posture or targets the wrong connector.
        var out: [String: String] = [:]
        let connectorOverrides = raw["guardrail.connectors"]?.mapping ?? [:]
        if connectorOverrides.count > 1 {
            out["connector"] = ""
        } else if connectorOverrides.count == 1,
                  let onlyConnector = connectorOverrides.keys.first,
                  connectors.contains(onlyConnector) {
            out["connector"] = onlyConnector
        } else if let connector = raw["guardrail.connector"]?.string ?? raw["claw.mode"]?.string,
                  connectors.contains(connector) {
            out["connector"] = connector
        }
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
    }

    static func guardrailValidation(_ values: [String: String]) -> String? {
        value(values, "connector").isEmpty
            ? "Choose the connector whose guardrail settings should be updated."
            : nil
    }

    private static let splunk = WizardDefinition(
        id: "splunk", title: "Splunk", icon: "waveform.path.ecg.rectangle",
        blurb: "Configure Splunk O11y, local logs, or Enterprise HEC pipelines.",
        baseArgs: ["setup", "splunk"], commandBuilder: splunkCommands,
        secretEnvironment: { v in
            var environment: [String: String] = [:]
            let accessToken = value(v, "access-token")
            let hecToken = value(v, "hec-token")
            if !accessToken.isEmpty { environment["SPLUNK_ACCESS_TOKEN"] = accessToken }
            if !hecToken.isEmpty { environment["DEFENSECLAW_SPLUNK_HEC_TOKEN"] = hecToken }
            return environment
        },
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
        secretEnvironment: { v in
            let token = value(v, "token")
            return token.isEmpty ? [:] : ["DEFENSECLAW_SETUP_OBSERVABILITY_TOKEN": token]
        },
        validation: observabilityValidation,
        fields: [
            WizardField(key: "action", label: "Action", kind: .choice(options: ["add", "list", "enable", "disable", "remove", "test"]), defaultValue: "add"),
            WizardField(key: "preset", label: "Destination", kind: .choice(options: ["local-otlp", "otlp", "splunk-o11y", "splunk-hec", "splunk-enterprise", "datadog", "honeycomb", "newrelic", "grafana-cloud", "galileo", "webhook"]), defaultValue: "local-otlp", visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "name", label: "Destination name", kind: .text(placeholder: "name"), visibleWhen: (key: "action", equals: ["add", "enable", "disable", "remove", "test"])),
            WizardField(key: "enabled", label: "Enable destination", kind: .bool, defaultValue: "yes", visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "signals-o11y", label: "Signals", kind: .text(placeholder: "traces,metrics"), defaultValue: "traces,metrics", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["splunk-o11y"])),
            WizardField(key: "signals-galileo", label: "Signals", kind: .choice(options: ["traces"]), defaultValue: "traces", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["galileo"])),
            WizardField(key: "signals-general", label: "Signals", kind: .text(placeholder: "traces,metrics,logs"), defaultValue: "traces,metrics,logs", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["local-otlp", "otlp", "datadog", "honeycomb", "newrelic", "grafana-cloud"])),
            WizardField(key: "realm", label: "Splunk realm", kind: .text(placeholder: "us1"), defaultValue: "us1", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["splunk-o11y"])),
            WizardField(key: "site", label: "Datadog site", kind: .text(placeholder: "us5"), defaultValue: "us5", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["datadog"])),
            WizardField(key: "region", label: "Region / zone", kind: .text(placeholder: "us or prod-us-east-0"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["newrelic", "grafana-cloud"])),
            WizardField(key: "dataset", label: "Honeycomb dataset", kind: .text(placeholder: "defenseclaw"), defaultValue: "defenseclaw", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["honeycomb"])),
            WizardField(key: "endpoint", label: "Endpoint", kind: .text(placeholder: "host:port or URL"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["splunk-enterprise", "galileo", "otlp"])),
            WizardField(key: "protocol", label: "OTLP protocol", kind: .choice(options: ["grpc", "http"]), defaultValue: "grpc", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["otlp"])),
            WizardField(key: "project", label: "Galileo project", kind: .text(placeholder: "project name or ID"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["galileo"])),
            WizardField(key: "logstream", label: "Galileo Log stream", kind: .text(placeholder: "default"), defaultValue: "default", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["galileo"])),
            WizardField(key: "host", label: "Splunk HEC host", kind: .text(placeholder: "localhost"), defaultValue: "localhost", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["splunk-hec"])),
            WizardField(key: "port", label: "Splunk HEC port", kind: .text(placeholder: "8088"), defaultValue: "8088", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["splunk-hec"])),
            WizardField(key: "index", label: "Splunk index", kind: .text(placeholder: "defenseclaw"), defaultValue: "defenseclaw", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["splunk-hec", "splunk-enterprise"])),
            WizardField(key: "source", label: "Splunk source", kind: .text(placeholder: "defenseclaw"), defaultValue: "defenseclaw", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["splunk-hec", "splunk-enterprise"])),
            WizardField(key: "sourcetype", label: "Splunk sourcetype", kind: .text(placeholder: "_json"), defaultValue: "_json", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["splunk-hec", "splunk-enterprise"])),
            WizardField(key: "url", label: "Webhook URL", kind: .text(placeholder: "https://…"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["webhook"])),
            WizardField(key: "method", label: "Webhook method", kind: .choice(options: ["POST", "PUT"]), defaultValue: "POST", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["webhook"])),
            WizardField(key: "url-path", label: "Webhook URL path", kind: .text(placeholder: "/events"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["webhook"])),
            WizardField(key: "verify-tls-hec", label: "Verify HEC TLS", kind: .bool, defaultValue: "no", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["splunk-hec"])),
            WizardField(key: "verify-tls-webhook", label: "Verify webhook TLS", kind: .bool, defaultValue: "yes", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "preset", equals: ["webhook"])),
            WizardField(key: "token", label: "Token / API key", kind: .secure(placeholder: "optional token"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "dry-run", label: "Preview without writing", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "json", label: "JSON output", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "action", equals: ["list"])),
            WizardField(key: "test-timeout", label: "Probe timeout", kind: .text(placeholder: "5"), defaultValue: "5", visibleWhen: (key: "action", equals: ["test"])),
            WizardField(key: "write-probe", label: "Send a content-free probe", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "action", equals: ["test"])),
        ]
    )

    private static let webhooks = WizardDefinition(
        id: "webhooks", title: "Webhooks", icon: "link.badge.plus",
        blurb: "Add, inspect, test, enable, disable, or remove alert notifier webhooks.",
        baseArgs: ["setup", "webhook"], commandBuilder: webhookCommands,
        validation: webhookValidation,
        fields: [
            WizardField(key: "action", label: "Action", kind: .choice(options: ["add", "list", "show", "enable", "disable", "remove", "test"]), defaultValue: "add"),
            WizardField(key: "type", label: "Type", kind: .choice(options: ["slack", "pagerduty", "webex", "generic"]), defaultValue: "slack", visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "name", label: "Destination name", kind: .text(placeholder: "name"), visibleWhen: (key: "action", equals: ["add", "show", "enable", "disable", "remove", "test"])),
            WizardField(key: "url", label: "Webhook URL", kind: .text(placeholder: "https://…"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "slack-secret-env", label: "Slack secret env (optional)", kind: .text(placeholder: "optional env var"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "type", equals: ["slack"])),
            WizardField(key: "pagerduty-secret-env", label: "PagerDuty routing-key env", kind: .text(placeholder: "DEFENSECLAW_PD_ROUTING_KEY"), defaultValue: "DEFENSECLAW_PD_ROUTING_KEY", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "type", equals: ["pagerduty"])),
            WizardField(key: "webex-secret-env", label: "Webex bot-token env", kind: .text(placeholder: "DEFENSECLAW_WEBEX_TOKEN"), defaultValue: "DEFENSECLAW_WEBEX_TOKEN", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "type", equals: ["webex"])),
            WizardField(key: "generic-hmac", label: "Sign with HMAC-SHA256", kind: .bool, defaultValue: "yes", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "type", equals: ["generic"])),
            WizardField(key: "generic-secret-env", label: "HMAC secret env", kind: .text(placeholder: "DEFENSECLAW_WEBHOOK_SECRET"), defaultValue: "DEFENSECLAW_WEBHOOK_SECRET", visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "type", equals: ["generic"]), visibleWhen3: (key: "generic-hmac", equals: ["yes"])),
            WizardField(key: "room-id", label: "Webex room ID", kind: .text(placeholder: "room id"), visibleWhen: (key: "action", equals: ["add"]), visibleWhen2: (key: "type", equals: ["webex"])),
            WizardField(key: "enabled", label: "Enable webhook", kind: .bool, defaultValue: "yes", visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "min-severity", label: "Minimum severity", kind: .choice(options: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), defaultValue: "HIGH", visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "events", label: "Events", kind: .text(placeholder: "block,scan,guardrail,drift,health"), defaultValue: "block,scan,guardrail,drift,health", visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "timeout-seconds", label: "Delivery timeout (seconds)", kind: .text(placeholder: "10"), defaultValue: "10", visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "cooldown-seconds", label: "Dedup cooldown (seconds)", kind: .text(placeholder: "300; 0 disables"), visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "connector", label: "Connector", kind: .choice(options: ["all"] + connectors), defaultValue: "all", visibleWhen: (key: "action", equals: ["add", "list", "enable", "disable", "remove"])),
            WizardField(key: "dry-run-add", label: "Preview without writing", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "action", equals: ["add"])),
            WizardField(key: "json", label: "JSON output", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "action", equals: ["list", "show"])),
            WizardField(key: "test-timeout", label: "Test timeout", kind: .text(placeholder: "5"), defaultValue: "5", visibleWhen: (key: "action", equals: ["test"])),
            WizardField(key: "dry-run-test", label: "Format test payload without delivery", kind: .flagOnly, defaultValue: "no", visibleWhen: (key: "action", equals: ["test"])),
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
        validation: aiDiscoveryValidation,
        liveDefaults: aiDiscoveryLiveDefaults,
        fields: [
            WizardField(key: "enable", label: "Enable", kind: .bool, defaultValue: "yes"),
            WizardField(key: "mode", label: "Mode", kind: .choice(options: ["passive", "enhanced"]), defaultValue: "enhanced", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "scan-interval-min", label: "Scan interval (minutes)", kind: .text(placeholder: "5"), defaultValue: "5", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "process-interval-s", label: "Process poll (seconds)", kind: .text(placeholder: "60"), defaultValue: "60", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "scan-roots", label: "Scan roots", kind: .text(placeholder: "~"), defaultValue: "~", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "max-files-per-scan", label: "Max files per scan", kind: .text(placeholder: "1000"), defaultValue: "1000", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "max-file-bytes", label: "Max bytes per file", kind: .text(placeholder: "524288"), defaultValue: "524288", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "include-shell-history", label: "Include shell history", kind: .bool, defaultValue: "yes", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "include-package-manifests", label: "Include package manifests", kind: .bool, defaultValue: "yes", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "include-env-var-names", label: "Include env var names", kind: .bool, defaultValue: "yes", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "include-network-domains", label: "Include network domains", kind: .bool, defaultValue: "yes", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "allow-workspace-signatures", label: "Honor workspace signatures", kind: .bool, defaultValue: "no", visibleWhen: (key: "enable", equals: ["yes"]), help: "Off by default because workspace-supplied signatures can change discovery results."),
            WizardField(key: "store-raw-local-paths", label: "Store raw local paths", kind: .bool, defaultValue: "no", visibleWhen: (key: "enable", equals: ["yes"])),
            WizardField(key: "restart", label: "Restart gateway", kind: .bool, defaultValue: "yes"),
            WizardField(key: "scan", label: "Scan immediately", kind: .bool, defaultValue: "yes", visibleWhen: (key: "enable", equals: ["yes"])),
        ]
    )

    private static let splunkDashboards = WizardDefinition(
        id: "splunk-dashboards", title: "Splunk Dashboards", icon: "rectangle.3.group.bubble.left",
        blurb: "Apply or destroy the DefenseClaw Splunk O11y dashboards and detectors.",
        baseArgs: ["setup", "splunk", "dashboards"], commandBuilder: splunkDashboardCommands,
        secretEnvironment: { v in
            let token = value(v, "o11y-api-token")
            return token.isEmpty ? [:] : ["SFX_AUTH_TOKEN": token]
        },
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
    static func llmCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
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
        append(v, "timeout", flag: "--timeout", to: &args)
        append(v, "max-retries", flag: "--max-retries", to: &args)
        if value(v, "provider") == "bedrock" {
            append(v, "bedrock-region", flag: "--bedrock-region", to: &args)
            append(v, "bedrock-auth-mode", flag: "--bedrock-auth-mode", to: &args)
        }
        args.append("--non-interactive")
        commands.append(args)
        return commands
    }

    static func llmValidation(_ v: [String: String]) -> String? {
        if value(v, "model").isEmpty { return "Model is required." }
        if !value(v, "api-key").isEmpty, value(v, "api-key-env").isEmpty {
            return "API key env var name is required when supplying an API key."
        }
        if Int(value(v, "timeout", "30")).map({ $0 >= 0 }) != true {
            return "Timeout must be a non-negative integer."
        }
        if Int(value(v, "max-retries", "2")).map({ $0 >= 0 }) != true {
            return "Max retries must be a non-negative integer."
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

    static func providerCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        let action = value(v, "action", "list")
        if action == "list" || action == "show" { return [["setup", "provider", action]] }
        var args = ["setup", "provider", action]
        append(v, "name", flag: "--name", to: &args)
        if action == "add" {
            appendCSV(v, "domain", flag: "--domain", to: &args)
            appendCSV(v, "env-key", flag: "--env-key", to: &args)
            append(v, "profile-id", flag: "--profile-id", to: &args)
            appendCSV(v, "ollama-port", flag: "--ollama-port", to: &args)
            appendCSV(v, "allowed-request", flag: "--allowed-request", to: &args)
            appendCSV(v, "available-model", flag: "--available-model", to: &args)
            appendCSV(v, "request-path-override", flag: "--request-path-override", to: &args)
            append(v, "base-provider-type", flag: "--base-provider-type", to: &args)
            append(v, "base-url", flag: "--base-url", to: &args)
            append(v, "ca-cert-file", flag: "--ca-cert-file", to: &args)
            flag(v, "insecure-skip-verify", "--insecure-skip-verify", to: &args)

            switch value(v, "base-provider-type") {
            case "bedrock":
                append(v, "bedrock-region", flag: "--bedrock-region", to: &args)
                let auth = value(v, "bedrock-auth-mode")
                append(v, "bedrock-auth-mode", flag: "--bedrock-auth-mode", to: &args)
                if auth == "iam_credentials" {
                    append(v, "bedrock-access-key-env", flag: "--bedrock-access-key-env", to: &args)
                    append(v, "bedrock-secret-key-env", flag: "--bedrock-secret-key-env", to: &args)
                    append(v, "bedrock-session-token-env", flag: "--bedrock-session-token-env", to: &args)
                } else if auth == "profile" {
                    append(v, "bedrock-profile-name", flag: "--bedrock-profile-name", to: &args)
                }
                append(v, "bedrock-inference-profile", flag: "--bedrock-inference-profile", to: &args)
                appendCSV(v, "bedrock-deployment", flag: "--bedrock-deployment", to: &args)
            case "vertex_ai":
                append(v, "vertex-project-id", flag: "--vertex-project-id", to: &args)
                append(v, "vertex-region", flag: "--vertex-region", to: &args)
                let auth = value(v, "vertex-auth-mode")
                append(v, "vertex-auth-mode", flag: "--vertex-auth-mode", to: &args)
                if auth == "service_account" {
                    append(v, "vertex-service-account-json-env", flag: "--vertex-service-account-json-env", to: &args)
                }
            case "azure":
                append(v, "azure-endpoint", flag: "--azure-endpoint", to: &args)
                append(v, "azure-api-version", flag: "--azure-api-version", to: &args)
                append(v, "azure-auth-mode", flag: "--azure-auth-mode", to: &args)
                appendCSV(v, "azure-deployment-alias", flag: "--azure-deployment-alias", to: &args)
            default:
                break
            }
        }
        if !yes(v, "reload") { args.append("--no-reload") }
        return [args]
    }

    static func providerValidation(_ v: [String: String]) -> String? {
        let action = value(v, "action", "list")
        if ["add", "remove"].contains(action), value(v, "name").isEmpty {
            return "Provider name is required for \(action)."
        }
        guard action == "add" else { return nil }
        if value(v, "domain").isEmpty, value(v, "base-url").isEmpty {
            return "Supply at least one domain or a base URL."
        }
        let baseURL = value(v, "base-url")
        if !baseURL.isEmpty, !baseURL.contains("://") {
            return "Base URL must include a scheme, such as https://."
        }
        let requestTypes = Set(["chat", "completion", "embedding", "rerank", "image", "audio", "responses"])
        for request in csvValues(v, "allowed-request") where !requestTypes.contains(request.lowercased()) {
            return "Unsupported request type: \(request)."
        }
        for override in csvValues(v, "request-path-override") {
            let pair = override.split(separator: "=", maxSplits: 1).map(String.init)
            guard pair.count == 2,
                  requestTypes.contains(pair[0].lowercased()),
                  pair[1].hasPrefix("/"),
                  pair[1].count > 1 else {
                return "Request path overrides must use a supported type and an absolute path (for example chat=/v1/chat/completions)."
            }
        }
        for key in csvValues(v, "env-key") where !isEnvironmentVariableName(key) {
            return "Invalid API key environment variable name: \(key)."
        }
        for port in csvValues(v, "ollama-port") where Int(port).map({ $0 > 0 }) != true {
            return "Ollama ports must be positive integers."
        }
        let family = value(v, "base-provider-type")
        let aliases = family == "bedrock"
            ? csvValues(v, "bedrock-deployment")
            : family == "azure" ? csvValues(v, "azure-deployment-alias") : []
        for alias in aliases {
            let pair = alias.split(separator: "=", maxSplits: 1).map {
                $0.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            if pair.count != 2 || pair.contains(where: \.isEmpty) {
                return "Deployment aliases must use non-empty name=value pairs."
            }
        }
        let caFile = value(v, "ca-cert-file")
        if !caFile.isEmpty, yes(v, "insecure-skip-verify") {
            return "Choose either a CA certificate or Disable TLS verification, not both."
        }
        if !caFile.isEmpty {
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(atPath: caFile, isDirectory: &isDirectory),
                  !isDirectory.boolValue,
                  let text = try? String(contentsOfFile: caFile, encoding: .utf8),
                  text.split(separator: "\n").first(where: {
                      !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                  })?.contains("BEGIN CERTIFICATE") == true else {
                return "CA certificate must be a readable PEM file whose first nonblank line contains BEGIN CERTIFICATE."
            }
        }
        return nil
    }

    private static func splunkCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        let mode = value(v, "mode", "splunk-o11y")
        let modeFlag = mode == "splunk-o11y" ? "--o11y" : mode == "local-docker" ? "--logs" : "--enterprise"
        var args = ["setup", "splunk", modeFlag, "--non-interactive"]
        append(v, "realm", flag: "--realm", to: &args)
        append(v, "hec-endpoint", flag: "--hec-endpoint", to: &args)
        flag(v, "accept-splunk-license", "--accept-splunk-license", to: &args)
        args.append(yes(v, "traces") ? "--traces" : "--no-traces")
        args.append(yes(v, "metrics") ? "--metrics" : "--no-metrics")
        args.append(yes(v, "logs-export") ? "--logs-export" : "--no-logs-export")
        return [args]
    }

    static func observabilityCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        let action = value(v, "action", "add")
        var args = ["setup", "observability", action]
        if action == "add" {
            let preset = value(v, "preset", "local-otlp")
            args += [preset, "--non-interactive"]
            append(v, "name", flag: "--name", to: &args)
            let signalKey: String? = switch preset {
            case "splunk-o11y": "signals-o11y"
            case "galileo": "signals-galileo"
            case "local-otlp", "otlp", "datadog", "honeycomb", "newrelic", "grafana-cloud":
                "signals-general"
            default: nil
            }
            if let signalKey { append(v, signalKey, flag: "--signals", to: &args) }
            args.append(yes(v, "enabled") ? "--enabled" : "--disabled")
            flag(v, "dry-run", "--dry-run", to: &args)
            let keys: [String]
            switch preset {
            case "splunk-o11y": keys = ["realm"]
            case "splunk-hec": keys = ["host", "port", "index", "source", "sourcetype"]
            case "splunk-enterprise": keys = ["endpoint", "index", "source", "sourcetype"]
            case "datadog": keys = ["site"]
            case "honeycomb": keys = ["dataset"]
            case "newrelic", "grafana-cloud": keys = ["region"]
            case "galileo": keys = ["endpoint", "project", "logstream"]
            case "otlp": keys = ["endpoint", "protocol"]
            case "webhook": keys = ["url", "method", "url-path"]
            default: keys = []
            }
            for key in keys { append(v, key, flag: "--\(key)", to: &args) }
            if preset == "splunk-hec" {
                args.append(yes(v, "verify-tls-hec") ? "--verify-tls" : "--no-verify-tls")
            } else if preset == "webhook" {
                args.append(yes(v, "verify-tls-webhook") ? "--verify-tls" : "--no-verify-tls")
            }
        } else if ["enable", "disable", "remove"].contains(action) {
            let name = value(v, "name")
            if !name.isEmpty { args.append(name) }
            if action == "remove" { args.append("--yes") }
        } else if action == "list" {
            flag(v, "json", "--json", to: &args)
        } else if action == "test" {
            let name = value(v, "name")
            if !name.isEmpty { args.append(name) }
            append(v, "test-timeout", flag: "--timeout", to: &args)
            flag(v, "write-probe", "--write-probe", to: &args)
        }
        return [args]
    }

    static func observabilityValidation(_ v: [String: String]) -> String? {
        let action = value(v, "action", "add")
        if ["enable", "disable", "remove", "test"].contains(action), value(v, "name").isEmpty {
            return "Destination name is required for \(action)."
        }
        if action == "test", Double(value(v, "test-timeout", "5")).map({ $0 > 0 }) != true {
            return "Probe timeout must be a positive number."
        }
        guard action == "add" else { return nil }
        let preset = value(v, "preset", "local-otlp")
        let signalKey: String? = switch preset {
        case "splunk-o11y": "signals-o11y"
        case "galileo": "signals-galileo"
        case "local-otlp", "otlp", "datadog", "honeycomb", "newrelic", "grafana-cloud":
            "signals-general"
        default: nil
        }
        let signals = signalKey.map { csvValues(v, $0) } ?? []
        if signals.contains(where: { !["traces", "metrics", "logs"].contains($0) }) {
            return "Signals may contain only traces, metrics, and logs."
        }
        if preset == "galileo", signals != ["traces"] {
            return "The Galileo preset supports traces only."
        }
        let required: [(String, String)]
        switch preset {
        case "splunk-o11y": required = [("realm", "Splunk realm")]
        case "splunk-hec": required = [("host", "Splunk HEC host"), ("port", "Splunk HEC port")]
        case "splunk-enterprise": required = [("endpoint", "Splunk Enterprise endpoint")]
        case "datadog": required = [("site", "Datadog site")]
        case "honeycomb": required = [("dataset", "Honeycomb dataset")]
        case "newrelic", "grafana-cloud": required = [("region", "Region / zone")]
        case "galileo": required = [
            ("endpoint", "Galileo endpoint"),
            ("project", "Galileo project"),
            ("logstream", "Galileo Log stream"),
        ]
        case "otlp": required = [("endpoint", "OTLP endpoint")]
        case "webhook": required = [("url", "Webhook URL")]
        default: required = []
        }
        if let missing = required.first(where: { value(v, $0.0).isEmpty }) {
            return "\(missing.1) is required."
        }
        if preset == "splunk-hec", Int(value(v, "port")).map({ $0 > 0 }) != true {
            return "Splunk HEC port must be a positive integer."
        }
        return nil
    }

    static func webhookCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        let action = value(v, "action", "add")
        var args = ["setup", "webhook", action]
        if action == "add" {
            let type = value(v, "type", "slack")
            args += [type, "--non-interactive"]
            append(v, "name", flag: "--name", to: &args)
            append(v, "url", flag: "--url", to: &args)
            let secretKey: String? = switch type {
            case "slack": "slack-secret-env"
            case "pagerduty": "pagerduty-secret-env"
            case "webex": "webex-secret-env"
            case "generic" where yes(v, "generic-hmac"): "generic-secret-env"
            default: nil
            }
            if let secretKey { append(v, secretKey, flag: "--secret-env", to: &args) }
            if type == "webex" { append(v, "room-id", flag: "--room-id", to: &args) }
            append(v, "min-severity", flag: "--min-severity", to: &args)
            append(v, "events", flag: "--events", to: &args)
            append(v, "timeout-seconds", flag: "--timeout-seconds", to: &args)
            append(v, "cooldown-seconds", flag: "--cooldown-seconds", to: &args)
            args.append(yes(v, "enabled") ? "--enabled" : "--disabled")
            flag(v, "dry-run-add", "--dry-run", to: &args)
            connector(v, to: &args)
        } else if ["enable", "disable", "remove"].contains(action) {
            let name = value(v, "name")
            if !name.isEmpty { args.append(name) }
            if action == "remove" { args.append("--yes") }
            connector(v, to: &args)
        } else if action == "list" {
            flag(v, "json", "--json", to: &args)
            connector(v, to: &args)
        } else if action == "show" {
            let name = value(v, "name")
            if !name.isEmpty { args.append(name) }
            flag(v, "json", "--json", to: &args)
        } else if action == "test" {
            let name = value(v, "name")
            if !name.isEmpty { args.append(name) }
            flag(v, "dry-run-test", "--dry-run", to: &args)
            append(v, "test-timeout", flag: "--timeout", to: &args)
        }
        return [args]
    }

    static func webhookValidation(_ v: [String: String]) -> String? {
        let action = value(v, "action", "add")
        if ["show", "enable", "disable", "remove", "test"].contains(action), value(v, "name").isEmpty {
            return "Webhook name is required for \(action)."
        }
        if action == "test", Double(value(v, "test-timeout", "5")).map({ $0 > 0 }) != true {
            return "Test timeout must be a positive number."
        }
        guard action == "add" else { return nil }
        if value(v, "url").isEmpty { return "Webhook URL is required for add." }
        let type = value(v, "type", "slack")
        let secretKey: String? = switch type {
        case "pagerduty": "pagerduty-secret-env"
        case "webex": "webex-secret-env"
        case "generic" where yes(v, "generic-hmac"): "generic-secret-env"
        default: nil
        }
        if let secretKey {
            let env = value(v, secretKey)
            if env.isEmpty { return "A secret environment variable is required for \(type)." }
            if !isEnvironmentVariableName(env) { return "Invalid secret environment variable name: \(env)." }
        }
        if type == "webex", value(v, "room-id").isEmpty { return "Webex room ID is required." }
        if Int(value(v, "timeout-seconds", "10")).map({ $0 > 0 }) != true {
            return "Delivery timeout must be a positive integer."
        }
        let cooldown = value(v, "cooldown-seconds")
        if !cooldown.isEmpty, Int(cooldown).map({ $0 >= 0 }) != true {
            return "Dedup cooldown must be a non-negative integer."
        }
        let allowedEvents = Set(["block", "scan", "guardrail", "drift", "health"])
        if csvValues(v, "events").contains(where: { !allowedEvents.contains($0) }) {
            return "Events may contain only block, scan, guardrail, drift, and health."
        }
        return nil
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

    static func aiDiscoveryCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        if !yes(v, "enable") {
            var args = ["agent", "discovery", "disable", "--yes"]
            if !yes(v, "restart") { args.append("--no-restart") }
            return [args]
        }
        var args = ["agent", "discovery", "enable", "--yes"]
        for key in ["mode", "scan-interval-min", "process-interval-s", "scan-roots",
                    "max-files-per-scan", "max-file-bytes"] {
            append(v, key, flag: "--\(key)", to: &args)
        }
        for key in ["include-shell-history", "include-package-manifests", "include-env-var-names",
                    "include-network-domains", "allow-workspace-signatures", "store-raw-local-paths"] {
            args.append(yes(v, key) ? "--\(key)" : "--no-\(key)")
        }
        if !yes(v, "restart") { args.append("--no-restart") }
        if !yes(v, "scan") { args.append("--no-scan") }
        return [args]
    }

    static func aiDiscoveryLiveDefaults(_ raw: YAMLNode) -> [String: String] {
        var out: [String: String] = [:]
        if let enabled = raw["ai_discovery.enabled"]?.bool {
            out["enable"] = enabled ? "yes" : "no"
        }
        if let mode = raw["ai_discovery.mode"]?.string,
           ["passive", "enhanced"].contains(mode) {
            out["mode"] = mode
        }
        for (configKey, fieldKey) in [
            ("scan_interval_min", "scan-interval-min"),
            ("process_interval_s", "process-interval-s"),
            ("max_files_per_scan", "max-files-per-scan"),
            ("max_file_bytes", "max-file-bytes"),
        ] {
            if let number = raw["ai_discovery.\(configKey)"]?.int {
                out[fieldKey] = String(number)
            }
        }
        if let roots = raw["ai_discovery.scan_roots"] {
            switch roots {
            case .scalar(let value) where !value.isEmpty:
                out["scan-roots"] = value
            case .sequence(let items):
                let value = items.compactMap(\.string).joined(separator: ", ")
                if !value.isEmpty { out["scan-roots"] = value }
            default:
                break
            }
        }
        for (configKey, fieldKey) in [
            ("include_shell_history", "include-shell-history"),
            ("include_package_manifests", "include-package-manifests"),
            ("include_env_var_names", "include-env-var-names"),
            ("include_network_domains", "include-network-domains"),
            ("allow_workspace_signatures", "allow-workspace-signatures"),
            ("store_raw_local_paths", "store-raw-local-paths"),
        ] {
            if let enabled = raw["ai_discovery.\(configKey)"]?.bool {
                out[fieldKey] = enabled ? "yes" : "no"
            }
        }
        return out
    }

    static func aiDiscoveryValidation(_ values: [String: String]) -> String? {
        guard yes(values, "enable") else { return nil }
        for (key, label, range) in [
            ("scan-interval-min", "Scan interval", 1...1_440),
            ("process-interval-s", "Process poll", 5...3_600),
            ("max-files-per-scan", "Max files per scan", 10...100_000),
            ("max-file-bytes", "Max bytes per file", 4_096...16_777_216),
        ] {
            let raw = value(values, key)
            guard let number = Int(raw), range.contains(number) else {
                return "\(label) must be an integer from \(range.lowerBound) through \(range.upperBound)."
            }
        }
        return nil
    }

    private static func splunkDashboardCommands(_ v: [String: String], _ mask: Bool) -> [[String]] {
        var args = ["setup", "splunk", "dashboards", value(v, "action", "apply"), "--yes"]
        if yes(v, "with-detectors") {
            args.append("--with-detectors")
            flag(v, "enable-detectors", "--enable-detectors", to: &args)
        }
        append(v, "name-prefix", flag: "--name-prefix", to: &args)
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

    private static func appendCSV(_ values: [String: String], _ key: String, flag: String, to args: inout [String]) {
        csvValues(values, key).forEach { args += [flag, $0] }
    }

    private static func csvValues(_ values: [String: String], _ key: String) -> [String] {
        value(values, key).split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    private static func isEnvironmentVariableName(_ value: String) -> Bool {
        value.range(
            of: #"^[A-Za-z_][A-Za-z0-9_]*$"#,
            options: .regularExpression
        ) != nil
    }

    private static func flag(_ values: [String: String], _ key: String, _ flag: String, to args: inout [String]) {
        if yes(values, key) { args.append(flag) }
    }

    private static func connector(_ values: [String: String], to args: inout [String]) {
        let selected = value(values, "connector", "all")
        if selected != "all" { args += ["--connector", selected] }
    }
}
