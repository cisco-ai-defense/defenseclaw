import Foundation

public struct AppConfig: Codable, Sendable {
    public var dataDir: String?
    public var auditDb: String?
    public var quarantineDir: String?
    public var pluginDir: String?
    public var policyDir: String?
    public var environment: String?
    public var claw: ClawConfig?
    public var inspectLlm: InspectLLMConfig?
    public var ciscoAiDefense: CiscoAIDefenseConfig?
    public var scanners: ScannersConfig?
    public var openshell: OpenShellConfig?
    public var watch: WatchConfig?
    public var guardrail: GuardrailFullConfig?
    public var splunk: SplunkConfig?
    public var gateway: GatewayFullConfig?
    public var skillActions: SeverityActionsConfig?
    public var mcpActions: SeverityActionsConfig?
    public var pluginActions: SeverityActionsConfig?
    public var otel: OTelConfig?

    public init() {}

    enum CodingKeys: String, CodingKey {
        case dataDir = "data_dir"; case auditDb = "audit_db"; case quarantineDir = "quarantine_dir"
        case pluginDir = "plugin_dir"; case policyDir = "policy_dir"; case environment; case claw
        case inspectLlm = "inspect_llm"; case ciscoAiDefense = "cisco_ai_defense"
        case scanners; case openshell; case watch; case guardrail; case splunk; case gateway
        case skillActions = "skill_actions"; case mcpActions = "mcp_actions"
        case pluginActions = "plugin_actions"; case otel
    }
}

public struct ClawConfig: Codable, Sendable {
    public var mode: String?
    public var homeDir: String?
    public var configFile: String?
    enum CodingKeys: String, CodingKey { case mode; case homeDir = "home_dir"; case configFile = "config_file" }
}

public struct InspectLLMConfig: Codable, Sendable {
    public var provider: String?; public var model: String?; public var apiKey: String?
    public var apiKeyEnv: String?; public var baseUrl: String?; public var timeout: Int?; public var maxRetries: Int?
    enum CodingKeys: String, CodingKey {
        case provider; case model; case timeout; case apiKey = "api_key"; case apiKeyEnv = "api_key_env"
        case baseUrl = "base_url"; case maxRetries = "max_retries"
    }
}

public struct CiscoAIDefenseConfig: Codable, Sendable {
    public var endpoint: String?; public var apiKey: String?; public var apiKeyEnv: String?
    public var timeoutMs: Int?; public var enabledRules: [String]?; public var enabled: Bool?
    enum CodingKeys: String, CodingKey {
        case endpoint; case enabled; case apiKey = "api_key"; case apiKeyEnv = "api_key_env"
        case timeoutMs = "timeout_ms"; case enabledRules = "enabled_rules"
    }
}

public struct SkillScannerConfig: Codable, Sendable {
    public var binary: String?; public var useLlm: Bool?; public var useBehavioral: Bool?
    public var enableMeta: Bool?; public var useTrigger: Bool?; public var useVirustotal: Bool?
    public var useAidefense: Bool?; public var llmConsensusRuns: Int?; public var policy: String?; public var lenient: Bool?
    enum CodingKeys: String, CodingKey {
        case binary; case policy; case lenient; case useLlm = "use_llm"; case useBehavioral = "use_behavioral"
        case enableMeta = "enable_meta"; case useTrigger = "use_trigger"; case useVirustotal = "use_virustotal"
        case useAidefense = "use_aidefense"; case llmConsensusRuns = "llm_consensus_runs"
    }
}

public struct MCPScannerConfig: Codable, Sendable {
    public var binary: String?; public var analyzers: String?
    public var scanPrompts: Bool?; public var scanResources: Bool?; public var scanInstructions: Bool?
    enum CodingKeys: String, CodingKey {
        case binary; case analyzers; case scanPrompts = "scan_prompts"
        case scanResources = "scan_resources"; case scanInstructions = "scan_instructions"
    }
}

public struct ScannersConfig: Codable, Sendable {
    public var skillScanner: SkillScannerConfig?; public var mcpScanner: MCPScannerConfig?
    public var pluginScanner: String?; public var codeguard: String?
    enum CodingKeys: String, CodingKey {
        case skillScanner = "skill_scanner"; case mcpScanner = "mcp_scanner"
        case pluginScanner = "plugin_scanner"; case codeguard
    }
}

public struct OpenShellConfig: Codable, Sendable {
    public var binary: String?; public var policyDir: String?; public var mode: String?
    public var version: String?; public var sandboxHome: String?; public var hostNetworking: Bool?
    enum CodingKeys: String, CodingKey {
        case binary; case mode; case version; case policyDir = "policy_dir"
        case sandboxHome = "sandbox_home"; case hostNetworking = "host_networking"
    }
}

public struct WatchConfig: Codable, Sendable {
    public var debounceMs: Int?; public var autoBlock: Bool?; public var allowListBypassScan: Bool?
    enum CodingKeys: String, CodingKey {
        case debounceMs = "debounce_ms"; case autoBlock = "auto_block"
        case allowListBypassScan = "allow_list_bypass_scan"
    }
}

public struct JudgeConfig: Codable, Sendable {
    public var enabled: Bool?; public var injection: Bool?; public var pii: Bool?
    public var piiPrompt: Bool?; public var piiCompletion: Bool?; public var model: String?
    public var apiKeyEnv: String?; public var apiBase: String?; public var timeout: Double?
    enum CodingKeys: String, CodingKey {
        case enabled; case injection; case pii; case model; case timeout
        case piiPrompt = "pii_prompt"; case piiCompletion = "pii_completion"
        case apiKeyEnv = "api_key_env"; case apiBase = "api_base"
    }
}

public struct GuardrailFullConfig: Codable, Sendable {
    public var enabled: Bool?; public var mode: String?; public var scannerMode: String?
    public var host: String?; public var port: Int?; public var model: String?
    public var modelName: String?; public var apiKeyEnv: String?; public var originalModel: String?
    public var blockMessage: String?; public var judge: JudgeConfig?
    enum CodingKeys: String, CodingKey {
        case enabled; case mode; case host; case port; case model; case judge
        case scannerMode = "scanner_mode"; case modelName = "model_name"
        case apiKeyEnv = "api_key_env"; case originalModel = "original_model"; case blockMessage = "block_message"
    }
}

public struct SplunkConfig: Codable, Sendable {
    public var hecEndpoint: String?; public var hecToken: String?; public var hecTokenEnv: String?
    public var index: String?; public var source: String?; public var sourcetype: String?
    public var verifyTls: Bool?; public var enabled: Bool?; public var batchSize: Int?; public var flushIntervalS: Int?
    enum CodingKeys: String, CodingKey {
        case index; case source; case sourcetype; case enabled
        case hecEndpoint = "hec_endpoint"; case hecToken = "hec_token"; case hecTokenEnv = "hec_token_env"
        case verifyTls = "verify_tls"; case batchSize = "batch_size"; case flushIntervalS = "flush_interval_s"
    }
}

public struct GatewayWatcherSkillConfig: Codable, Sendable {
    public var enabled: Bool?; public var takeAction: Bool?; public var dirs: [String]?
    enum CodingKeys: String, CodingKey { case enabled; case dirs; case takeAction = "take_action" }
}

public struct GatewayWatcherPluginConfig: Codable, Sendable {
    public var enabled: Bool?; public var takeAction: Bool?; public var dirs: [String]?
    enum CodingKeys: String, CodingKey { case enabled; case dirs; case takeAction = "take_action" }
}

public struct GatewayWatcherConfig: Codable, Sendable {
    public var enabled: Bool?; public var skill: GatewayWatcherSkillConfig?; public var plugin: GatewayWatcherPluginConfig?
}

public struct GatewayFullConfig: Codable, Sendable {
    public var host: String?; public var port: Int?; public var token: String?; public var tokenEnv: String?
    public var tls: Bool?; public var tlsSkipVerify: Bool?; public var deviceKeyFile: String?
    public var autoApproveSafe: Bool?; public var reconnectMs: Int?; public var maxReconnectMs: Int?
    public var approvalTimeoutS: Int?; public var apiPort: Int?; public var apiBind: String?
    public var watcher: GatewayWatcherConfig?
    enum CodingKeys: String, CodingKey {
        case host; case port; case token; case tls; case watcher
        case tokenEnv = "token_env"; case tlsSkipVerify = "tls_skip_verify"
        case deviceKeyFile = "device_key_file"; case autoApproveSafe = "auto_approve_safe"
        case reconnectMs = "reconnect_ms"; case maxReconnectMs = "max_reconnect_ms"
        case approvalTimeoutS = "approval_timeout_s"; case apiPort = "api_port"; case apiBind = "api_bind"
    }
}

public struct SeverityAction: Codable, Sendable {
    public var file: String?; public var runtime: String?; public var install: String?
}

public struct SeverityActionsConfig: Codable, Sendable {
    public var critical: SeverityAction?; public var high: SeverityAction?
    public var medium: SeverityAction?; public var low: SeverityAction?; public var info: SeverityAction?
}

public struct OTelConfig: Codable, Sendable {
    public var enabled: Bool?; public var `protocol`: String?; public var endpoint: String?
}
