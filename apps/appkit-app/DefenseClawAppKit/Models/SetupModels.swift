import Foundation

enum SetupFieldKind: String, Hashable {
    case text
    case integer
    case decimal
    case toggle
    case choice
    case password
}

struct SetupField: Identifiable, Hashable {
    let id: String
    let label: String
    let path: String
    let kind: SetupFieldKind
    let options: [String]
    let placeholder: String
    let help: String
    let secretWriteOnly: Bool

    init(
        _ label: String,
        path: String,
        kind: SetupFieldKind = .text,
        options: [String] = [],
        placeholder: String = "",
        help: String = "",
        secretWriteOnly: Bool = false
    ) {
        self.id = path
        self.label = label
        self.path = path
        self.kind = kind
        self.options = options
        self.placeholder = placeholder
        self.help = help
        self.secretWriteOnly = secretWriteOnly
    }
}

enum SetupWorkflowFieldKind: String, Hashable {
    case text
    case integer
    case toggle
    case choice
    case password
}

struct SetupWorkflowField: Identifiable, Hashable {
    let id: String
    let label: String
    let flag: String
    let noFlag: String?
    let kind: SetupWorkflowFieldKind
    let options: [String]
    let defaultValue: String
    let required: Bool
    let secret: Bool
    let alwaysPass: Bool
    let help: String

    init(
        _ label: String,
        flag: String,
        noFlag: String? = nil,
        kind: SetupWorkflowFieldKind = .text,
        options: [String] = [],
        defaultValue: String = "",
        required: Bool = false,
        secret: Bool = false,
        alwaysPass: Bool = false,
        help: String = ""
    ) {
        self.id = flag.isEmpty ? label : flag
        self.label = label
        self.flag = flag
        self.noFlag = noFlag
        self.kind = kind
        self.options = options
        self.defaultValue = defaultValue
        self.required = required
        self.secret = secret
        self.alwaysPass = alwaysPass
        self.help = help
    }
}

struct SetupWorkflow: Identifiable, Hashable {
    let id: String
    let title: String
    let subtitle: String
    let command: [String]
    let fields: [SetupWorkflowField]

    init(
        id: String,
        title: String,
        subtitle: String,
        command: [String],
        fields: [SetupWorkflowField] = []
    ) {
        self.id = id
        self.title = title
        self.subtitle = subtitle
        self.command = command
        self.fields = fields
    }
}

struct SetupGroup: Identifiable, Hashable {
    let id: String
    let title: String
    let subtitle: String
    let systemImage: String
    let fields: [SetupField]
    let workflows: [SetupWorkflow]
}

enum SetupCatalog {
    static let providerOptions = [
        "anthropic", "openai", "openrouter", "azure", "gemini", "gemini-openai",
        "groq", "mistral", "cohere", "deepseek", "xai", "bedrock", "vertex_ai",
        "ollama", "vllm", "lm_studio"
    ]

    static let groups: [SetupGroup] = [
        SetupGroup(
            id: "llm",
            title: "LLM & Agents",
            subtitle: "Shared DefenseClaw LLM key, model routing, and OpenClaw paths",
            systemImage: "brain.head.profile",
            fields: [
                SetupField("LLM Provider", path: "llm.provider", kind: .choice, options: providerOptions, help: "Shared provider used by scanners and guardrail when no component override is set."),
                SetupField("LLM Model", path: "llm.model", placeholder: "gpt-4o, claude-3-5-sonnet, llama3.1"),
                SetupField("API Key Env", path: "llm.api_key_env", placeholder: "DEFENSECLAW_LLM_KEY", help: "Preferred way to configure the DefenseClaw LLM key without writing the secret into config.yaml."),
                SetupField("Inline API Key", path: "llm.api_key", kind: .password, help: "Write-only. Leave blank to keep the existing value; prefer API Key Env for normal operation.", secretWriteOnly: true),
                SetupField("Base URL", path: "llm.base_url", placeholder: "https://api.example.com"),
                SetupField("Timeout Seconds", path: "llm.timeout", kind: .integer),
                SetupField("Max Retries", path: "llm.max_retries", kind: .integer),
                SetupField("Claw Mode", path: "claw.mode", kind: .choice, options: ["openclaw", "claude-code", "codex", "opencode"], help: "Controls where agent skills, MCPs, and config files are discovered."),
                SetupField("Claw Home Dir", path: "claw.home_dir", placeholder: "~/.openclaw"),
                SetupField("Claw Config File", path: "claw.config_file", placeholder: "~/.openclaw/openclaw.json")
            ],
            workflows: [
                SetupWorkflow(
                    id: "doctor",
                    title: "Run Doctor",
                    subtitle: "Check gateway, scanners, guardrail, observability, Splunk, and sandbox health.",
                    command: ["doctor"]
                )
            ]
        ),
        SetupGroup(
            id: "gateway",
            title: "Gateway & Watchers",
            subtitle: "OpenClaw gateway, REST API bind, filesystem watcher, watchdog",
            systemImage: "network",
            fields: [
                SetupField("Host", path: "gateway.host", placeholder: "localhost"),
                SetupField("WebSocket Port", path: "gateway.port", kind: .integer),
                SetupField("API Port", path: "gateway.api_port", kind: .integer),
                SetupField("API Bind", path: "gateway.api_bind", placeholder: "127.0.0.1"),
                SetupField("Auto Approve Safe", path: "gateway.auto_approve_safe", kind: .toggle),
                SetupField("TLS", path: "gateway.tls", kind: .toggle),
                SetupField("TLS Skip Verify", path: "gateway.tls_skip_verify", kind: .toggle),
                SetupField("Reconnect MS", path: "gateway.reconnect_ms", kind: .integer),
                SetupField("Max Reconnect MS", path: "gateway.max_reconnect_ms", kind: .integer),
                SetupField("Approval Timeout Seconds", path: "gateway.approval_timeout_s", kind: .integer),
                SetupField("Token Env", path: "gateway.token_env", placeholder: "OPENCLAW_GATEWAY_TOKEN"),
                SetupField("Device Key File", path: "gateway.device_key_file", placeholder: "~/.defenseclaw/device.key"),
                SetupField("Watcher Enabled", path: "gateway.watcher.enabled", kind: .toggle),
                SetupField("Watch Skills", path: "gateway.watcher.skill.enabled", kind: .toggle),
                SetupField("Skill Watch Takes Action", path: "gateway.watcher.skill.take_action", kind: .toggle),
                SetupField("Skill Watch Dirs", path: "gateway.watcher.skill.dirs", placeholder: "~/skills,/opt/skills"),
                SetupField("Watch Plugins", path: "gateway.watcher.plugin.enabled", kind: .toggle),
                SetupField("Plugin Watch Takes Action", path: "gateway.watcher.plugin.take_action", kind: .toggle),
                SetupField("Plugin Watch Dirs", path: "gateway.watcher.plugin.dirs", placeholder: "~/.openclaw/plugins"),
                SetupField("MCP Watch Takes Action", path: "gateway.watcher.mcp.take_action", kind: .toggle),
                SetupField("Watchdog Enabled", path: "gateway.watchdog.enabled", kind: .toggle),
                SetupField("Watchdog Interval", path: "gateway.watchdog.interval", kind: .integer),
                SetupField("Watchdog Debounce", path: "gateway.watchdog.debounce", kind: .integer)
            ],
            workflows: [
                SetupWorkflow(
                    id: "gateway-setup",
                    title: "Configure Gateway",
                    subtitle: "Run the same non-interactive gateway setup flow exposed by the TUI.",
                    command: ["setup", "gateway", "--non-interactive"],
                    fields: [
                        SetupWorkflowField("Remote Mode", flag: "--remote", kind: .toggle),
                        SetupWorkflowField("Host", flag: "--host", defaultValue: "localhost"),
                        SetupWorkflowField("Port", flag: "--port", kind: .integer, defaultValue: "9090"),
                        SetupWorkflowField("API Port", flag: "--api-port", kind: .integer, defaultValue: "9099"),
                        SetupWorkflowField("Auth Token", flag: "--token", kind: .password, secret: true),
                        SetupWorkflowField("Verify After Setup", flag: "--verify", noFlag: "--no-verify", kind: .toggle, defaultValue: "true")
                    ]
                )
            ]
        ),
        SetupGroup(
            id: "scanners",
            title: "Scanners",
            subtitle: "Skill scanner, MCP scanner, plugin scanner, CodeGuard",
            systemImage: "magnifyingglass",
            fields: [
                SetupField("Skill Scanner Binary", path: "scanners.skill_scanner.binary", placeholder: "skill-scanner"),
                SetupField("Skill Policy", path: "scanners.skill_scanner.policy", kind: .choice, options: ["strict", "balanced", "permissive", "observe"]),
                SetupField("Lenient Skill Scans", path: "scanners.skill_scanner.lenient", kind: .toggle),
                SetupField("Use LLM", path: "scanners.skill_scanner.use_llm", kind: .toggle),
                SetupField("LLM Consensus Runs", path: "scanners.skill_scanner.llm_consensus_runs", kind: .integer),
                SetupField("Use Behavioral Analyzer", path: "scanners.skill_scanner.use_behavioral", kind: .toggle),
                SetupField("Enable Metadata Analyzer", path: "scanners.skill_scanner.enable_meta", kind: .toggle),
                SetupField("Use Trigger Analyzer", path: "scanners.skill_scanner.use_trigger", kind: .toggle),
                SetupField("Use VirusTotal", path: "scanners.skill_scanner.use_virustotal", kind: .toggle),
                SetupField("VirusTotal Key Env", path: "scanners.skill_scanner.virustotal_api_key_env", placeholder: "VIRUSTOTAL_API_KEY"),
                SetupField("Use Cisco AI Defense", path: "scanners.skill_scanner.use_aidefense", kind: .toggle),
                SetupField("MCP Scanner Binary", path: "scanners.mcp_scanner.binary", placeholder: "mcp-scanner"),
                SetupField("MCP Analyzers", path: "scanners.mcp_scanner.analyzers", placeholder: "yara,api,llm,behavioral,readiness"),
                SetupField("Scan MCP Prompts", path: "scanners.mcp_scanner.scan_prompts", kind: .toggle),
                SetupField("Scan MCP Resources", path: "scanners.mcp_scanner.scan_resources", kind: .toggle),
                SetupField("Scan MCP Instructions", path: "scanners.mcp_scanner.scan_instructions", kind: .toggle),
                SetupField("Plugin Scanner", path: "scanners.plugin_scanner"),
                SetupField("CodeGuard", path: "scanners.codeguard")
            ],
            workflows: [
                SetupWorkflow(
                    id: "skill-scanner",
                    title: "Skill Scanner Setup",
                    subtitle: "Configure behavioral, metadata, trigger, VirusTotal, LLM, and AI Defense analyzers.",
                    command: ["setup", "skill-scanner", "--non-interactive"],
                    fields: [
                        SetupWorkflowField("Behavioral Analyzer", flag: "--use-behavioral", kind: .toggle),
                        SetupWorkflowField("LLM Analyzer", flag: "--use-llm", kind: .toggle),
                        SetupWorkflowField("LLM Provider", flag: "--llm-provider", kind: .choice, options: ["anthropic", "openai"], defaultValue: "anthropic"),
                        SetupWorkflowField("LLM Model", flag: "--llm-model"),
                        SetupWorkflowField("LLM Consensus Runs", flag: "--llm-consensus-runs", kind: .integer, defaultValue: "0"),
                        SetupWorkflowField("Meta Analyzer", flag: "--enable-meta", kind: .toggle),
                        SetupWorkflowField("Trigger Analyzer", flag: "--use-trigger", kind: .toggle),
                        SetupWorkflowField("VirusTotal Scanner", flag: "--use-virustotal", kind: .toggle),
                        SetupWorkflowField("AI Defense Analyzer", flag: "--use-aidefense", kind: .toggle),
                        SetupWorkflowField("Scan Policy", flag: "--policy", kind: .choice, options: ["strict", "balanced", "permissive"], defaultValue: "balanced"),
                        SetupWorkflowField("Lenient Mode", flag: "--lenient", kind: .toggle),
                        SetupWorkflowField("Verify After Setup", flag: "--verify", noFlag: "--no-verify", kind: .toggle, defaultValue: "true")
                    ]
                ),
                SetupWorkflow(
                    id: "mcp-scanner",
                    title: "MCP Scanner Setup",
                    subtitle: "Configure analyzers plus prompt, resource, and instruction scanning.",
                    command: ["setup", "mcp-scanner", "--non-interactive"],
                    fields: [
                        SetupWorkflowField("Analyzers", flag: "--analyzers", defaultValue: "yara,api,llm,behavioral,readiness", alwaysPass: true),
                        SetupWorkflowField("LLM Provider", flag: "--llm-provider", kind: .choice, options: ["anthropic", "openai"], defaultValue: "anthropic"),
                        SetupWorkflowField("LLM Model", flag: "--llm-model"),
                        SetupWorkflowField("Scan Prompts", flag: "--scan-prompts", kind: .toggle),
                        SetupWorkflowField("Scan Resources", flag: "--scan-resources", kind: .toggle),
                        SetupWorkflowField("Scan Instructions", flag: "--scan-instructions", kind: .toggle),
                        SetupWorkflowField("Verify After Setup", flag: "--verify", noFlag: "--no-verify", kind: .toggle, defaultValue: "true")
                    ]
                )
            ]
        ),
        SetupGroup(
            id: "guardrail",
            title: "Guardrail",
            subtitle: "Proxy mode, detection strategy, judge, rule packs, remote AI Defense",
            systemImage: "shield",
            fields: [
                SetupField("Enabled", path: "guardrail.enabled", kind: .toggle),
                SetupField("Mode", path: "guardrail.mode", kind: .choice, options: ["observe", "action"]),
                SetupField("Scanner Mode", path: "guardrail.scanner_mode", kind: .choice, options: ["local", "remote", "both"]),
                SetupField("Host", path: "guardrail.host", placeholder: "127.0.0.1"),
                SetupField("Port", path: "guardrail.port", kind: .integer),
                SetupField("Model", path: "guardrail.model"),
                SetupField("Model Name", path: "guardrail.model_name"),
                SetupField("Original Model", path: "guardrail.original_model"),
                SetupField("API Key Env", path: "guardrail.api_key_env", placeholder: "DEFENSECLAW_LLM_KEY"),
                SetupField("API Base", path: "guardrail.api_base"),
                SetupField("Block Message", path: "guardrail.block_message"),
                SetupField("Retain Judge Bodies", path: "guardrail.retain_judge_bodies", kind: .toggle),
                SetupField("Detection Strategy", path: "guardrail.detection_strategy", kind: .choice, options: ["regex_only", "regex_judge", "judge_first"]),
                SetupField("Prompt Strategy", path: "guardrail.detection_strategy_prompt", kind: .choice, options: ["", "regex_only", "regex_judge", "judge_first"]),
                SetupField("Completion Strategy", path: "guardrail.detection_strategy_completion", kind: .choice, options: ["", "regex_only", "regex_judge", "judge_first"]),
                SetupField("Tool Call Strategy", path: "guardrail.detection_strategy_tool_call", kind: .choice, options: ["", "regex_only", "regex_judge", "judge_first"]),
                SetupField("Stream Buffer Bytes", path: "guardrail.stream_buffer_bytes", kind: .integer),
                SetupField("Rule Pack Dir", path: "guardrail.rule_pack_dir", placeholder: "~/.defenseclaw/policies/guardrail/default"),
                SetupField("Judge Sweep", path: "guardrail.judge_sweep", kind: .toggle),
                SetupField("Judge Enabled", path: "guardrail.judge.enabled", kind: .toggle),
                SetupField("Judge Model", path: "guardrail.judge.model"),
                SetupField("Judge API Key Env", path: "guardrail.judge.api_key_env", placeholder: "DEFENSECLAW_LLM_KEY"),
                SetupField("Judge API Base", path: "guardrail.judge.api_base"),
                SetupField("Judge Timeout", path: "guardrail.judge.timeout", kind: .decimal),
                SetupField("Adjudication Timeout", path: "guardrail.judge.adjudication_timeout", kind: .decimal),
                SetupField("Judge Fallbacks", path: "guardrail.judge.fallbacks", placeholder: "provider/model,provider/model"),
                SetupField("Judge Injection", path: "guardrail.judge.injection", kind: .toggle),
                SetupField("Judge PII", path: "guardrail.judge.pii", kind: .toggle),
                SetupField("Judge PII Prompt", path: "guardrail.judge.pii_prompt", kind: .toggle),
                SetupField("Judge PII Completion", path: "guardrail.judge.pii_completion", kind: .toggle),
                SetupField("Judge Tool Injection", path: "guardrail.judge.tool_injection", kind: .toggle),
                SetupField("Cisco AI Defense Endpoint", path: "cisco_ai_defense.endpoint"),
                SetupField("Cisco AI Defense API Key Env", path: "cisco_ai_defense.api_key_env", placeholder: "CISCO_AI_DEFENSE_API_KEY"),
                SetupField("Cisco AI Defense Timeout MS", path: "cisco_ai_defense.timeout_ms", kind: .integer)
            ],
            workflows: [
                SetupWorkflow(
                    id: "guardrail-setup",
                    title: "Guardrail Setup",
                    subtitle: "Configure local regex/judge scanning and optional remote AI Defense mode.",
                    command: ["setup", "guardrail", "--non-interactive"],
                    fields: [
                        SetupWorkflowField("Mode", flag: "--mode", kind: .choice, options: ["observe", "action"], defaultValue: "observe"),
                        SetupWorkflowField("Scanner Mode", flag: "--scanner-mode", kind: .choice, options: ["local", "remote", "both"], defaultValue: "local"),
                        SetupWorkflowField("Provider", flag: "--provider", kind: .choice, options: providerOptions, defaultValue: "openai"),
                        SetupWorkflowField("Model", flag: "--model"),
                        SetupWorkflowField("API Key Env", flag: "--api-key-env", defaultValue: "DEFENSECLAW_LLM_KEY"),
                        SetupWorkflowField("Judge Enabled", flag: "--judge", kind: .toggle),
                        SetupWorkflowField("Verify After Setup", flag: "--verify", noFlag: "--no-verify", kind: .toggle, defaultValue: "true")
                    ]
                )
            ]
        ),
        observabilityGroup,
        webhookGroup,
        SetupGroup(
            id: "enforcement",
            title: "Enforcement Actions",
            subtitle: "Severity matrices for skill, MCP, and plugin admission gates",
            systemImage: "lock.shield",
            fields: actionFields(prefix: "skill_actions", title: "Skill")
                + actionFields(prefix: "mcp_actions", title: "MCP")
                + actionFields(prefix: "plugin_actions", title: "Plugin")
                + [
                    SetupField("Watch Debounce MS", path: "watch.debounce_ms", kind: .integer),
                    SetupField("Watch Auto Block", path: "watch.auto_block", kind: .toggle),
                    SetupField("Allow List Bypass Scan", path: "watch.allow_list_bypass_scan", kind: .toggle),
                    SetupField("Rescan Enabled", path: "watch.rescan_enabled", kind: .toggle),
                    SetupField("Rescan Interval Minutes", path: "watch.rescan_interval_min", kind: .integer)
                ],
            workflows: []
        ),
        SetupGroup(
            id: "sandbox",
            title: "Sandbox",
            subtitle: "OpenShell policy and runtime toggles; execution remains Linux-only",
            systemImage: "shippingbox",
            fields: [
                SetupField("OpenShell Binary", path: "openshell.binary", placeholder: "openshell"),
                SetupField("Policy Dir", path: "openshell.policy_dir", placeholder: "~/.defenseclaw/openshell-policies"),
                SetupField("Mode", path: "openshell.mode", kind: .choice, options: ["", "docker", "standalone"]),
                SetupField("Version", path: "openshell.version"),
                SetupField("Sandbox Home", path: "openshell.sandbox_home", placeholder: "~/.openshell/sandboxes"),
                SetupField("Auto Pair", path: "openshell.auto_pair", kind: .choice, options: ["", "true", "false"]),
                SetupField("Host Networking", path: "openshell.host_networking", kind: .choice, options: ["", "true", "false"])
            ],
            workflows: [
                SetupWorkflow(
                    id: "sandbox-setup",
                    title: "Sandbox Setup",
                    subtitle: "Write OpenShell policy YAML. Runtime checks are skipped on macOS.",
                    command: ["sandbox", "setup"],
                    fields: [
                        SetupWorkflowField("Sandbox IP", flag: "--sandbox-ip", defaultValue: "10.200.0.2"),
                        SetupWorkflowField("Host IP", flag: "--host-ip", defaultValue: "10.200.0.1"),
                        SetupWorkflowField("Sandbox Home", flag: "--sandbox-home", defaultValue: "/home/sandbox"),
                        SetupWorkflowField("OpenClaw Port", flag: "--openclaw-port", kind: .integer, defaultValue: "18789"),
                        SetupWorkflowField("Policy", flag: "--policy", kind: .choice, options: ["default", "strict", "permissive"], defaultValue: "permissive"),
                        SetupWorkflowField("DNS", flag: "--dns", defaultValue: "8.8.8.8,1.1.1.1"),
                        SetupWorkflowField("No Auto Pair", flag: "--no-auto-pair", kind: .toggle),
                        SetupWorkflowField("No Host Networking", flag: "--no-host-networking", kind: .toggle),
                        SetupWorkflowField("No Guardrail", flag: "--no-guardrail", kind: .toggle),
                        SetupWorkflowField("Disable", flag: "--disable", kind: .toggle)
                    ]
                )
            ]
        )
    ]

    private static var observabilityGroup: SetupGroup {
        SetupGroup(
            id: "observability",
            title: "Observability",
            subtitle: "OTel, audit sinks, Splunk, Datadog, Honeycomb, New Relic, Grafana Cloud",
            systemImage: "waveform.path.ecg",
            fields: [
                SetupField("OTel Enabled", path: "otel.enabled", kind: .toggle),
                SetupField("OTel Protocol", path: "otel.protocol", kind: .choice, options: ["grpc", "http/protobuf"]),
                SetupField("OTel Endpoint", path: "otel.endpoint", placeholder: "https://collector:4317"),
                SetupField("TLS Insecure", path: "otel.tls.insecure", kind: .toggle),
                SetupField("TLS CA Cert", path: "otel.tls.ca_cert"),
                SetupField("Traces Enabled", path: "otel.traces.enabled", kind: .toggle),
                SetupField("Trace Sampler", path: "otel.traces.sampler", kind: .choice, options: ["always_on", "always_off", "traceidratio", "parentbased_always_on", "parentbased_always_off", "parentbased_traceidratio"]),
                SetupField("Trace Sampler Arg", path: "otel.traces.sampler_arg"),
                SetupField("Trace Endpoint", path: "otel.traces.endpoint"),
                SetupField("Trace Protocol", path: "otel.traces.protocol", kind: .choice, options: ["", "grpc", "http/protobuf"]),
                SetupField("Trace URL Path", path: "otel.traces.url_path", placeholder: "/v1/traces"),
                SetupField("Logs Enabled", path: "otel.logs.enabled", kind: .toggle),
                SetupField("Emit Individual Findings", path: "otel.logs.emit_individual_findings", kind: .toggle),
                SetupField("Logs Endpoint", path: "otel.logs.endpoint"),
                SetupField("Logs Protocol", path: "otel.logs.protocol", kind: .choice, options: ["", "grpc", "http/protobuf"]),
                SetupField("Logs URL Path", path: "otel.logs.url_path", placeholder: "/v1/logs"),
                SetupField("Metrics Enabled", path: "otel.metrics.enabled", kind: .toggle),
                SetupField("Metrics Export Interval", path: "otel.metrics.export_interval_s", kind: .integer),
                SetupField("Metrics Temporality", path: "otel.metrics.temporality", kind: .choice, options: ["delta", "cumulative"]),
                SetupField("Metrics Endpoint", path: "otel.metrics.endpoint"),
                SetupField("Metrics Protocol", path: "otel.metrics.protocol", kind: .choice, options: ["", "grpc", "http/protobuf"]),
                SetupField("Metrics URL Path", path: "otel.metrics.url_path", placeholder: "/v1/metrics"),
                SetupField("Max Export Batch Size", path: "otel.batch.max_export_batch_size", kind: .integer),
                SetupField("Scheduled Delay MS", path: "otel.batch.scheduled_delay_ms", kind: .integer),
                SetupField("Max Queue Size", path: "otel.batch.max_queue_size", kind: .integer)
            ],
            workflows: observabilityWorkflows + [
                SetupWorkflow(id: "observability-list", title: "List Destinations", subtitle: "Show OTel plus audit_sinks destinations as JSON.", command: ["setup", "observability", "list", "--json"]),
                SetupWorkflow(id: "observability-migrate-splunk", title: "Migrate Legacy Splunk", subtitle: "Convert old splunk: config into audit_sinks without losing existing sinks.", command: ["setup", "observability", "migrate-splunk", "--apply"])
            ]
        )
    }

    private static var webhookGroup: SetupGroup {
        SetupGroup(
            id: "webhooks",
            title: "Webhooks",
            subtitle: "Slack, PagerDuty, Webex, and generic HMAC notifiers",
            systemImage: "bell.and.waves.left.and.right",
            fields: [],
            workflows: webhookWorkflows + [
                SetupWorkflow(id: "webhook-list", title: "List Webhooks", subtitle: "Show configured notifier webhooks as JSON.", command: ["setup", "webhook", "list", "--json"])
            ]
        )
    }

    private static var observabilityWorkflows: [SetupWorkflow] {
        [
            SetupWorkflow(
                id: "obs-splunk-o11y",
                title: "Splunk Observability Cloud",
                subtitle: "Configure OTLP traces, metrics, and optional logs for Splunk O11y.",
                command: ["setup", "observability", "add", "splunk-o11y", "--non-interactive"],
                fields: [
                    SetupWorkflowField("Name", flag: "--name"),
                    SetupWorkflowField("Enabled", flag: "--enabled", noFlag: "--disabled", kind: .toggle, defaultValue: "true", alwaysPass: true),
                    SetupWorkflowField("Realm", flag: "--realm", defaultValue: "us1", required: true, alwaysPass: true),
                    SetupWorkflowField("Signals", flag: "--signals", defaultValue: "traces,metrics", alwaysPass: true),
                    SetupWorkflowField("Access Token", flag: "--token", kind: .password, secret: true)
                ]
            ),
            SetupWorkflow(
                id: "obs-splunk-hec",
                title: "Splunk HEC Audit Sink",
                subtitle: "Forward audit events to Splunk HEC via audit_sinks.",
                command: ["setup", "observability", "add", "splunk-hec", "--non-interactive"],
                fields: [
                    SetupWorkflowField("Name", flag: "--name"),
                    SetupWorkflowField("Enabled", flag: "--enabled", noFlag: "--disabled", kind: .toggle, defaultValue: "true", alwaysPass: true),
                    SetupWorkflowField("Host", flag: "--host", defaultValue: "localhost", required: true, alwaysPass: true),
                    SetupWorkflowField("Port", flag: "--port", kind: .integer, defaultValue: "8088", required: true, alwaysPass: true),
                    SetupWorkflowField("Index", flag: "--index", defaultValue: "defenseclaw", alwaysPass: true),
                    SetupWorkflowField("Source", flag: "--source", defaultValue: "defenseclaw", alwaysPass: true),
                    SetupWorkflowField("Sourcetype", flag: "--sourcetype", defaultValue: "_json", alwaysPass: true),
                    SetupWorkflowField("Verify TLS", flag: "--verify-tls", noFlag: "--no-verify-tls", kind: .toggle),
                    SetupWorkflowField("HEC Token", flag: "--token", kind: .password, secret: true)
                ]
            ),
            SetupWorkflow(
                id: "obs-datadog",
                title: "Datadog",
                subtitle: "Configure Datadog OTLP exporter with DD_API_KEY fallback.",
                command: ["setup", "observability", "add", "datadog", "--non-interactive"],
                fields: [
                    SetupWorkflowField("Name", flag: "--name"),
                    SetupWorkflowField("Enabled", flag: "--enabled", noFlag: "--disabled", kind: .toggle, defaultValue: "true", alwaysPass: true),
                    SetupWorkflowField("Site", flag: "--site", defaultValue: "us5", required: true, alwaysPass: true),
                    SetupWorkflowField("Signals", flag: "--signals", defaultValue: "traces,metrics,logs", alwaysPass: true),
                    SetupWorkflowField("API Key", flag: "--token", kind: .password, secret: true)
                ]
            ),
            SetupWorkflow(
                id: "obs-honeycomb",
                title: "Honeycomb",
                subtitle: "Configure Honeycomb OTLP export.",
                command: ["setup", "observability", "add", "honeycomb", "--non-interactive"],
                fields: [
                    SetupWorkflowField("Dataset", flag: "--dataset", defaultValue: "defenseclaw", required: true, alwaysPass: true),
                    SetupWorkflowField("Signals", flag: "--signals", defaultValue: "traces,metrics,logs", alwaysPass: true),
                    SetupWorkflowField("API Key", flag: "--token", kind: .password, secret: true)
                ]
            ),
            SetupWorkflow(
                id: "obs-newrelic",
                title: "New Relic",
                subtitle: "Configure New Relic OTLP export.",
                command: ["setup", "observability", "add", "newrelic", "--non-interactive"],
                fields: [
                    SetupWorkflowField("Region", flag: "--region", kind: .choice, options: ["us", "eu"], defaultValue: "us", required: true, alwaysPass: true),
                    SetupWorkflowField("Signals", flag: "--signals", defaultValue: "traces,metrics,logs", alwaysPass: true),
                    SetupWorkflowField("License Key", flag: "--token", kind: .password, secret: true)
                ]
            ),
            SetupWorkflow(
                id: "obs-grafana",
                title: "Grafana Cloud",
                subtitle: "Configure Grafana Cloud OTLP export.",
                command: ["setup", "observability", "add", "grafana-cloud", "--non-interactive"],
                fields: [
                    SetupWorkflowField("Region/Zone", flag: "--region", defaultValue: "prod-us-east-0", required: true, alwaysPass: true),
                    SetupWorkflowField("Signals", flag: "--signals", defaultValue: "traces,metrics,logs", alwaysPass: true),
                    SetupWorkflowField("OTLP Token", flag: "--token", kind: .password, secret: true)
                ]
            ),
            SetupWorkflow(
                id: "obs-otlp",
                title: "Generic OTLP",
                subtitle: "Configure a collector endpoint for OTel or audit_sinks.",
                command: ["setup", "observability", "add", "otlp", "--non-interactive"],
                fields: [
                    SetupWorkflowField("Endpoint", flag: "--endpoint", required: true),
                    SetupWorkflowField("Protocol", flag: "--protocol", kind: .choice, options: ["grpc", "http"], defaultValue: "grpc"),
                    SetupWorkflowField("Target", flag: "--target", kind: .choice, options: ["otel", "audit_sinks"], defaultValue: "otel"),
                    SetupWorkflowField("Signals", flag: "--signals", defaultValue: "traces,metrics,logs")
                ]
            ),
            SetupWorkflow(
                id: "obs-webhook",
                title: "Generic HTTP JSONL Sink",
                subtitle: "Forward audit events to a generic HTTP endpoint.",
                command: ["setup", "observability", "add", "webhook", "--non-interactive"],
                fields: [
                    SetupWorkflowField("URL", flag: "--url", required: true),
                    SetupWorkflowField("Method", flag: "--method", kind: .choice, options: ["POST", "PUT"], defaultValue: "POST"),
                    SetupWorkflowField("Verify TLS", flag: "--verify-tls", noFlag: "--no-verify-tls", kind: .toggle, defaultValue: "true"),
                    SetupWorkflowField("Bearer Token", flag: "--token", kind: .password, secret: true)
                ]
            )
        ]
    }

    private static var webhookWorkflows: [SetupWorkflow] {
        [
            webhookWorkflow("slack", title: "Slack", extraFields: [
                SetupWorkflowField("Secret Env", flag: "--secret-env")
            ]),
            webhookWorkflow("pagerduty", title: "PagerDuty", extraFields: [
                SetupWorkflowField("Routing Key Env", flag: "--secret-env", defaultValue: "DEFENSECLAW_PD_ROUTING_KEY", required: true, alwaysPass: true)
            ]),
            webhookWorkflow("webex", title: "Cisco Webex", extraFields: [
                SetupWorkflowField("Bot Token Env", flag: "--secret-env", defaultValue: "DEFENSECLAW_WEBEX_TOKEN", required: true, alwaysPass: true),
                SetupWorkflowField("Room ID", flag: "--room-id", required: true)
            ]),
            webhookWorkflow("generic", title: "Generic HMAC", extraFields: [
                SetupWorkflowField("HMAC Secret Env", flag: "--secret-env", defaultValue: "DEFENSECLAW_WEBHOOK_SECRET")
            ])
        ]
    }

    private static func webhookWorkflow(_ type: String, title: String, extraFields: [SetupWorkflowField]) -> SetupWorkflow {
        SetupWorkflow(
            id: "webhook-\(type)",
            title: "\(title) Webhook",
            subtitle: "Add or update a \(title) notifier without leaving the app.",
            command: ["setup", "webhook", "add", type, "--non-interactive"],
            fields: [
                SetupWorkflowField("Name", flag: "--name"),
                SetupWorkflowField("URL", flag: "--url", required: true),
                SetupWorkflowField("Enabled", flag: "--enabled", noFlag: "--disabled", kind: .toggle, defaultValue: "true", alwaysPass: true),
                SetupWorkflowField("Min Severity", flag: "--min-severity", kind: .choice, options: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], defaultValue: "HIGH", alwaysPass: true),
                SetupWorkflowField("Events", flag: "--events", defaultValue: "block,scan,guardrail,drift,health", alwaysPass: true),
                SetupWorkflowField("Timeout Seconds", flag: "--timeout-seconds", kind: .integer, defaultValue: "10", alwaysPass: true),
                SetupWorkflowField("Cooldown Seconds", flag: "--cooldown-seconds"),
                SetupWorkflowField("Dry Run", flag: "--dry-run", kind: .toggle)
            ] + extraFields
        )
    }

    private static func actionFields(prefix: String, title: String) -> [SetupField] {
        let severities = ["critical", "high", "medium", "low", "info"]
        return severities.flatMap { severity in
            [
                SetupField("\(title) \(severity.capitalized) File", path: "\(prefix).\(severity).file", kind: .choice, options: ["none", "quarantine"]),
                SetupField("\(title) \(severity.capitalized) Runtime", path: "\(prefix).\(severity).runtime", kind: .choice, options: ["enable", "disable"]),
                SetupField("\(title) \(severity.capitalized) Install", path: "\(prefix).\(severity).install", kind: .choice, options: ["none", "block", "allow"])
            ]
        }
    }
}
