import Foundation

/// HTTP client for the DefenseClaw sidecar REST API at localhost:18970.
public actor SidecarClient {
    private let baseURL: URL
    private let session: URLSession
    private let decoder: JSONDecoder
    private let authToken: String?

    public init(host: String = "127.0.0.1", port: Int = 18970) {
        self.baseURL = URL(string: "http://\(host):\(port)")!
        // Load gateway token — check multiple sources (matches Go sidecar behavior)
        var token: String? = nil
        do {
            let config = try ConfigManager().load()
            token = config.gateway?.token
            // Support token_env: read token from named environment variable
            if token == nil || token?.isEmpty == true, let envName = config.gateway?.tokenEnv, !envName.isEmpty {
                token = ProcessInfo.processInfo.environment[envName]
            }
        } catch {
            // Config may not exist — sidecar may not require auth
        }
        // Fallback: read from OpenClaw config (~/.openclaw/openclaw.json → gateway.auth.token)
        if token == nil || token?.isEmpty == true {
            token = SidecarClient.readOpenClawGatewayToken()
        }
        self.authToken = token
        let log = AppLogger.shared
        if let t = token, !t.isEmpty {
            log.info("sidecar", "Auth token loaded", details: "len=\(t.count)")
        } else {
            log.warn("sidecar", "No auth token found — sidecar requests will be unauthenticated")
        }
        self.session = URLSession(configuration: .ephemeral)
        let dec = JSONDecoder()
        // Sidecar returns dates like "2026-04-02T21:00:25.796086-07:00"
        // Swift's .iso8601 can't handle fractional seconds, so use a custom strategy
        let fmtWithFrac = ISO8601DateFormatter()
        fmtWithFrac.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let fmtWithout = ISO8601DateFormatter()
        fmtWithout.formatOptions = [.withInternetDateTime]
        dec.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let str = try container.decode(String.self)
            if let d = fmtWithFrac.date(from: str) { return d }
            if let d = fmtWithout.date(from: str) { return d }
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Cannot decode date: \(str)")
        }
        self.decoder = dec
    }

    public func health() async throws -> HealthSnapshot { try await get("/health") }
    public func status() async throws -> [String: AnyCodable] { try await get("/status") }
    public func alerts() async throws -> [Alert] { try await get("/alerts") }
    public func skills() async throws -> [Skill] { try await get("/skills") }
    public func disableSkill(key: String) async throws { try await postVoid("/skill/disable", body: ["skill_key": key]) }
    public func enableSkill(key: String) async throws { try await postVoid("/skill/enable", body: ["skill_key": key]) }
    public func scanSkill(path: String) async throws -> ScanResult { try await post("/v1/skill/scan", body: ["path": path]) }
    public func fetchSkill(url: String) async throws -> [String: AnyCodable] { try await post("/v1/skill/fetch", body: ["url": url]) }
    public func disablePlugin(key: String) async throws { try await postVoid("/plugin/disable", body: ["plugin_key": key]) }
    public func enablePlugin(key: String) async throws { try await postVoid("/plugin/enable", body: ["plugin_key": key]) }
    public func mcpServers() async throws -> [MCPServer] { try await get("/mcps") }
    public func scanMCP(url: String) async throws -> ScanResult { try await post("/v1/mcp/scan", body: ["url": url]) }
    /// Fetch runtime tool catalog from sidecar.
    ///
    /// **Chain**: macOS app → GET /tools/catalog → Go sidecar → WS RPC `tools.catalog` → OpenClaw gateway
    ///
    /// **Expected response** (array of objects):
    /// ```json
    /// [
    ///   { "name": "Bash", "source": "builtin", "description": "Run shell commands", "parameters": {...} },
    ///   { "name": "Read", "source": "builtin", "description": "Read files" }
    /// ]
    /// ```
    /// Fields: `name` (required), `source` (optional: "builtin"|"skill"|"mcp"), `description` (optional),
    /// `parameters` (optional object), `blocked` (optional bool). No `id` field — computed from `name`.
    public func toolsCatalog() async throws -> [ToolEntry] {
        let url = baseURL.appendingPathComponent("/tools/catalog")
        log.info("sidecar", "GET /tools/catalog — fetching tool catalog")
        var request = URLRequest(url: url)
        if let token = authToken { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            let msg = String(data: data, encoding: .utf8) ?? "unknown error"
            log.error("sidecar", "GET /tools/catalog failed", details: "status=\((response as? HTTPURLResponse)?.statusCode ?? 0) body=\(msg.prefix(500))")
            throw SidecarError.requestFailed(endpoint: "/tools/catalog", detail: msg)
        }
        let rawBody = String(data: data, encoding: .utf8) ?? "<non-utf8>"
        log.info("sidecar", "GET /tools/catalog raw response", details: "\(data.count) bytes: \(rawBody.prefix(1000))")
        // Try grouped format first (OpenClaw gateway: { agentId, groups: [{ tools: [...] }] })
        if let catalog = try? decoder.decode(ToolsCatalogResponse.self, from: data) {
            let tools = catalog.flattenedTools()
            log.info("sidecar", "GET /tools/catalog decoded OK (grouped)", details: "\(tools.count) tools from \(catalog.groups?.count ?? 0) groups")
            return tools
        }
        // Fallback: flat array format [{ name, source, ... }]
        do {
            let tools = try decoder.decode([ToolEntry].self, from: data)
            log.info("sidecar", "GET /tools/catalog decoded OK (flat)", details: "\(tools.count) tools")
            return tools
        } catch {
            log.error("sidecar", "GET /tools/catalog DECODE FAILED (tried grouped + flat)", details: "error=\(error) raw=\(rawBody.prefix(500))")
            throw SidecarError.decodingFailed(endpoint: "/tools/catalog", underlying: error)
        }
    }

    /// Inspect a single tool by name via the sidecar.
    ///
    /// **Chain**: macOS app → POST /api/v1/inspect/tool → Go sidecar (local policy + CodeGuard check)
    ///
    /// **Request**: `{ "tool": "<tool-name>" }`
    /// **Response**: Free-form JSON object with policy verdict, findings, etc.
    public func inspectTool(name: String) async throws -> [String: AnyCodable] {
        log.info("sidecar", "POST /api/v1/inspect/tool", details: "tool=\(name)")
        let result: [String: AnyCodable] = try await post("/api/v1/inspect/tool", body: ["tool": name])
        log.info("sidecar", "POST /api/v1/inspect/tool OK", details: "tool=\(name) keys=\(result.keys.sorted())")
        return result
    }
    public func scanCode(path: String) async throws -> ScanResult { try await post("/api/v1/scan/code", body: ["path": path]) }
    public func block(_ request: EnforceRequest) async throws { try await postVoid("/enforce/block", body: request) }
    public func allow(_ request: EnforceRequest) async throws { try await postVoid("/enforce/allow", body: request) }
    public func blockedList() async throws -> [BlockEntry] { try await get("/enforce/blocked") }
    public func allowedList() async throws -> [AllowEntry] { try await get("/enforce/allowed") }
    public func policyEvaluate(input: AdmissionInput) async throws -> AdmissionOutput {
        let resp: PolicyEvaluateResponse = try await post("/policy/evaluate", body: PolicyEvaluateRequest(input: input))
        return resp.data
    }
    public func policyEvaluate(targetType: String, targetName: String) async throws -> AdmissionOutput {
        let input = AdmissionInput(targetType: targetType, targetName: targetName, severity: "MEDIUM", findings: 0)
        let resp: PolicyEvaluateResponse = try await post("/policy/evaluate", body: PolicyEvaluateRequest(input: input))
        return resp.data
    }
    public func policyEvaluateFirewall(input: FirewallInput) async throws -> FirewallOutput { try await post("/policy/evaluate/firewall", body: input) }
    public func policyReload() async throws { try await postVoid("/policy/reload", body: [String: String]()) }
    /// Read the OPA policy data.json from disk (no HTTP endpoint exists for this).
    public func policyShow() async throws -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        var candidates = [
            "\(home)/.defenseclaw/policies/rego/data.json",
            "\(home)/.defenseclaw/policies/data.json",
        ]
        // Also check relative to current working directory (dev mode)
        let cwd = FileManager.default.currentDirectoryPath
        candidates.append("\(cwd)/policies/rego/data.json")
        for path in candidates {
            if FileManager.default.fileExists(atPath: path) {
                let data = try Data(contentsOf: URL(fileURLWithPath: path))
                // Pretty-print the JSON
                if let obj = try? JSONSerialization.jsonObject(with: data),
                   let pretty = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]) {
                    return String(data: pretty, encoding: .utf8) ?? ""
                }
                return String(data: data, encoding: .utf8) ?? ""
            }
        }
        throw SidecarError.requestFailed(endpoint: "policy/show", detail: "No policy data.json found at ~/.defenseclaw/policies/")
    }
    public func guardrailConfig() async throws -> GuardrailConfig { try await get("/v1/guardrail/config") }
    public func updateGuardrailConfig(mode: String? = nil, scannerMode: String? = nil, blockMessage: String? = nil) async throws {
        var body: [String: String] = [:]
        if let m = mode { body["mode"] = m }
        if let s = scannerMode { body["scanner_mode"] = s }
        if let b = blockMessage { body["block_message"] = b }
        var request = URLRequest(url: baseURL.appendingPathComponent("/v1/guardrail/config"))
        request.httpMethod = "PATCH"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("macos-app", forHTTPHeaderField: "X-DefenseClaw-Client")
        if let token = authToken { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        request.httpBody = try JSONEncoder().encode(body)
        log.info("sidecar", "PATCH /v1/guardrail/config", details: "body=\(body)")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            let msg = String(data: data, encoding: .utf8) ?? "unknown"
            log.error("sidecar", "PATCH /v1/guardrail/config failed", details: "status=\((response as? HTTPURLResponse)?.statusCode ?? 0) body=\(msg.prefix(200))")
            throw SidecarError.requestFailed(endpoint: "/v1/guardrail/config", detail: "PATCH failed")
        }
        log.info("sidecar", "PATCH /v1/guardrail/config OK")
    }
    public func guardrailEvaluate(_ request: GuardrailEvalRequest) async throws -> GuardrailEvalResponse { try await post("/v1/guardrail/evaluate", body: request) }
    public func logAuditEvent(action: String, target: String, severity: String, details: String) async throws {
        try await postVoid("/audit/event", body: ["action": action, "target": target, "severity": severity, "details": details])
    }

    private let log = AppLogger.shared

    private func get<T: Decodable>(_ path: String) async throws -> T {
        let url = baseURL.appendingPathComponent(path)
        log.debug("sidecar", "GET \(path)")
        var request = URLRequest(url: url)
        if let token = authToken { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            let msg = String(data: data, encoding: .utf8) ?? "unknown error"
            log.error("sidecar", "GET \(path) failed", details: "status=\((response as? HTTPURLResponse)?.statusCode ?? 0) body=\(msg.prefix(200))")
            throw SidecarError.requestFailed(endpoint: path, detail: msg)
        }
        log.debug("sidecar", "GET \(path) OK", details: "\(data.count) bytes")
        return try decoder.decode(T.self, from: data)
    }

    private func post<B: Encodable, T: Decodable>(_ path: String, body: B) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("macos-app", forHTTPHeaderField: "X-DefenseClaw-Client")
        if let token = authToken { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        request.httpBody = try JSONEncoder().encode(body)
        log.debug("sidecar", "POST \(path)")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            let msg = String(data: data, encoding: .utf8) ?? "unknown error"
            log.error("sidecar", "POST \(path) failed", details: "status=\((response as? HTTPURLResponse)?.statusCode ?? 0) body=\(msg.prefix(200))")
            throw SidecarError.requestFailed(endpoint: path, detail: msg)
        }
        log.debug("sidecar", "POST \(path) OK", details: "\(data.count) bytes")
        return try decoder.decode(T.self, from: data)
    }

    private func postVoid<B: Encodable>(_ path: String, body: B) async throws {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("macos-app", forHTTPHeaderField: "X-DefenseClaw-Client")
        if let token = authToken { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        request.httpBody = try JSONEncoder().encode(body)
        log.debug("sidecar", "POST \(path)")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            let msg = String(data: data, encoding: .utf8) ?? "unknown error"
            log.error("sidecar", "POST \(path) failed", details: "status=\((response as? HTTPURLResponse)?.statusCode ?? 0) body=\(msg.prefix(200))")
            throw SidecarError.requestFailed(endpoint: path, detail: msg)
        }
        log.debug("sidecar", "POST \(path) OK")
    }

    /// Read gateway token from OpenClaw config (~/.openclaw/openclaw.json → gateway.auth.token).
    /// Mirrors the Go implementation in internal/gateway/client.go:readOpenClawGatewayToken.
    static func readOpenClawGatewayToken() -> String? {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let path = "\(home)/.openclaw/openclaw.json"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let gateway = json["gateway"] as? [String: Any],
              let auth = gateway["auth"] as? [String: Any],
              let token = auth["token"] as? String,
              !token.isEmpty else {
            return nil
        }
        return token
    }
}

public enum SidecarError: Error, LocalizedError {
    case requestFailed(endpoint: String, detail: String = "")
    case decodingFailed(endpoint: String, underlying: Error)

    public var errorDescription: String? {
        switch self {
        case .requestFailed(let ep, let detail):
            if detail.isEmpty { return "Sidecar request failed: \(ep)" }
            return "Sidecar \(ep): \(detail)"
        case .decodingFailed(let ep, let err): return "Decoding failed for \(ep): \(err)"
        }
    }
}
