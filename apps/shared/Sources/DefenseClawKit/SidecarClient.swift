import Foundation

/// HTTP client for the DefenseClaw sidecar REST API at localhost:18970.
public actor SidecarClient {
    private let baseURL: URL
    private let session: URLSession
    private let decoder: JSONDecoder

    public init(host: String = "127.0.0.1", port: Int = 18970) {
        self.baseURL = URL(string: "http://\(host):\(port)")!
        self.session = URLSession(configuration: .ephemeral)
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
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
    public func toolsCatalog() async throws -> [ToolEntry] { try await get("/tools/catalog") }
    public func inspectTool(name: String) async throws -> [String: AnyCodable] { try await post("/api/v1/inspect/tool", body: ["tool": name]) }
    public func scanCode(path: String) async throws -> ScanResult { try await post("/api/v1/scan/code", body: ["path": path]) }
    public func block(_ request: EnforceRequest) async throws { try await postVoid("/enforce/block", body: request) }
    public func allow(_ request: EnforceRequest) async throws { try await postVoid("/enforce/allow", body: request) }
    public func blockedList() async throws -> [BlockEntry] { try await get("/enforce/blocked") }
    public func allowedList() async throws -> [AllowEntry] { try await get("/enforce/allowed") }
    public func policyEvaluate(input: AdmissionInput) async throws -> AdmissionOutput { try await post("/policy/evaluate", body: input) }
    public func policyEvaluate(targetType: String, targetName: String) async throws -> AdmissionOutput {
        try await post("/policy/evaluate", body: AdmissionInput(targetType: targetType, targetName: targetName, severity: "MEDIUM", findings: 0))
    }
    public func policyEvaluateFirewall(input: FirewallInput) async throws -> FirewallOutput { try await post("/policy/evaluate/firewall", body: input) }
    public func policyReload() async throws { try await postVoid("/policy/reload", body: [String: String]()) }
    public func policyShow() async throws -> String {
        let url = baseURL.appendingPathComponent("/policy/show")
        let (data, response) = try await session.data(from: url)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw SidecarError.requestFailed(endpoint: "/policy/show")
        }
        return String(data: data, encoding: .utf8) ?? ""
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
        request.httpBody = try JSONEncoder().encode(body)
        let (_, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw SidecarError.requestFailed(endpoint: "/v1/guardrail/config")
        }
    }
    public func guardrailEvaluate(_ request: GuardrailEvalRequest) async throws -> GuardrailEvalResponse { try await post("/v1/guardrail/evaluate", body: request) }
    public func logAuditEvent(action: String, target: String, severity: String, details: String) async throws {
        try await postVoid("/audit/event", body: ["action": action, "target": target, "severity": severity, "details": details])
    }

    private func get<T: Decodable>(_ path: String) async throws -> T {
        let url = baseURL.appendingPathComponent(path)
        let (data, response) = try await session.data(from: url)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw SidecarError.requestFailed(endpoint: path)
        }
        return try decoder.decode(T.self, from: data)
    }

    private func post<B: Encodable, T: Decodable>(_ path: String, body: B) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(body)
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw SidecarError.requestFailed(endpoint: path)
        }
        return try decoder.decode(T.self, from: data)
    }

    private func postVoid<B: Encodable>(_ path: String, body: B) async throws {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(body)
        let (_, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw SidecarError.requestFailed(endpoint: path)
        }
    }
}

public enum SidecarError: Error, LocalizedError {
    case requestFailed(endpoint: String)
    case decodingFailed(endpoint: String, underlying: Error)

    public var errorDescription: String? {
        switch self {
        case .requestFailed(let ep): return "Sidecar request failed: \(ep)"
        case .decodingFailed(let ep, let err): return "Decoding failed for \(ep): \(err)"
        }
    }
}
