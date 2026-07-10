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

// Async REST client for the DefenseClaw Go gateway sidecar (localhost only).
// Endpoint set and timeouts mirror the Python TUI's OrchestratorClient.

import Foundation

actor GatewayClient {
    private var baseURL: URL?
    private var token: String?
    private let session: URLSession

    static let defaultTimeout: TimeInterval = 5
    static let pluginTimeout: TimeInterval = 90
    static let scanTimeout: TimeInterval = 120
    private static let pathSegmentCharacters = CharacterSet.alphanumerics
        .union(CharacterSet(charactersIn: "-._~"))

    init(config: DefenseClawConfig = DefenseClawConfig()) {
        self.baseURL = config.baseURL
        self.token = config.gatewayToken
        let conf = URLSessionConfiguration.ephemeral
        conf.timeoutIntervalForRequest = Self.defaultTimeout
        conf.waitsForConnectivity = false
        self.session = URLSession(configuration: conf)
    }

    func update(config: DefenseClawConfig) {
        baseURL = config.baseURL
        token = config.gatewayToken
    }

    // MARK: - Request plumbing

    private func request(
        _ method: String, _ path: String,
        body: [String: Any]? = nil,
        queryItems: [URLQueryItem] = [],
        timeout: TimeInterval = GatewayClient.defaultTimeout
    ) async throws -> Data {
        guard let baseURL, Self.isLoopback(baseURL) else {
            throw GatewayError.badResponse("refusing non-loopback gateway URL")
        }
        guard let relativeURL = URL(string: path, relativeTo: baseURL),
              var components = URLComponents(url: relativeURL, resolvingAgainstBaseURL: true)
        else {
            throw GatewayError.badResponse("bad path \(path)")
        }
        if !queryItems.isEmpty { components.queryItems = queryItems }
        guard let url = components.url, Self.isLoopback(url) else {
            throw GatewayError.badResponse("refusing non-loopback request URL")
        }
        var req = URLRequest(url: url, timeoutInterval: timeout)
        req.httpMethod = method
        req.setValue("macos-app", forHTTPHeaderField: "X-DefenseClaw-Client")
        if method != "GET" {
            // Token + Content-Type double as CSRF protection on the gateway.
            if let token { req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONSerialization.data(withJSONObject: body ?? [:])
        } else if let token {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: req)
        } catch let err as URLError {
            switch err.code {
            case .cannotConnectToHost, .networkConnectionLost, .cannotFindHost:
                throw GatewayError.offline
            case .timedOut:
                throw GatewayError.timeout
            default:
                throw GatewayError.offline
            }
        }
        guard let http = response as? HTTPURLResponse else {
            throw GatewayError.badResponse("non-HTTP response")
        }
        switch http.statusCode {
        case 200..<300:
            return data
        case 401, 403:
            throw GatewayError.unauthorized
        default:
            throw GatewayError.degraded(status: http.statusCode, body: String(data: data, encoding: .utf8) ?? "")
        }
    }

    private func getJSON(_ path: String, timeout: TimeInterval = GatewayClient.defaultTimeout) async throws -> Any {
        let data = try await request("GET", path, timeout: timeout)
        return try JSONSerialization.jsonObject(with: data)
    }

    private func encodedPathSegment(_ value: String) throws -> String {
        guard let encoded = value.addingPercentEncoding(withAllowedCharacters: Self.pathSegmentCharacters) else {
            throw GatewayError.badResponse("could not encode URL path segment")
        }
        return encoded
    }

    private static func isLoopback(_ url: URL) -> Bool {
        guard ["http", "https"].contains(url.scheme?.lowercased() ?? "") else { return false }
        let host = (url.host ?? "").lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        if host == "localhost" || host == "::1" { return true }
        let octets = host.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4,
              octets.allSatisfy({ part in
                  guard !part.isEmpty, part.allSatisfy(\.isNumber), let value = Int(part) else { return false }
                  return (0...255).contains(value)
              })
        else { return false }
        return octets[0] == "127"
    }

    @discardableResult
    private func post(_ path: String, _ body: [String: Any] = [:], timeout: TimeInterval = GatewayClient.defaultTimeout) async throws -> Any? {
        let data = try await request("POST", path, body: body, timeout: timeout)
        return data.isEmpty ? nil : try? JSONSerialization.jsonObject(with: data)
    }

    // MARK: - Health & status

    func health() async throws -> HealthSnapshot {
        let json = try await getJSON("/health")
        guard let dict = json as? [String: Any] else { throw GatewayError.badResponse("/health not an object") }
        var snap = HealthSnapshot()
        snap.fetchedAt = Date()
        snap.state = (dict["state"] as? String) ?? (dict["status"] as? String) ?? "running"
        snap.uptimeMs = (dict["uptime_ms"] as? Int) ?? (dict["uptimeMs"] as? Int) ?? 0
        snap.lastError = dict["last_error"] as? String ?? dict["lastError"] as? String
        snap.version = dict["version"] as? String

        // Subsystems: any nested object with a state/status field becomes a row.
        let known = ["watcher", "api", "guardrail", "telemetry", "ai_discovery", "sinks", "sandbox", "gateway", "watchdog"]
        for key in known {
            if let sub = dict[key] as? [String: Any],
               let state = (sub["state"] as? String) ?? (sub["status"] as? String) {
                snap.subsystems.append(.init(
                    name: key, state: state,
                    detail: sub["detail"] as? String ?? sub["error"] as? String,
                    details: Self.flattenDetails(sub["details"]),
                    since: DCDates.parse(sub["since"])
                ))
            } else if let state = dict[key] as? String {
                snap.subsystems.append(.init(name: key, state: state, detail: nil))
            }
        }

        // Real /health connector fields: requests, tool_inspections,
        // tool_blocks, subprocess_blocks, errors, since, state. Mode and
        // rule pack live in config (guardrail.connectors.<name>), and
        // last activity / alerts are derived from the audit DB — both are
        // filled in by AppState.pulse() after this returns.
        let connectorList = (dict["connectors"] as? [[String: Any]])
            ?? (dict["connector_health"] as? [[String: Any]])
            ?? []
        snap.connectors = connectorList.map { c in
            ConnectorHealth(
                name: (c["name"] as? String) ?? (c["connector"] as? String) ?? "connector",
                mode: "",
                rulePack: "",
                lastActivity: nil,
                calls: (c["requests"] as? Int) ?? 0,
                blocks: ((c["tool_blocks"] as? Int) ?? 0) + ((c["subprocess_blocks"] as? Int) ?? 0),
                alerts: 0,
                inspections: (c["tool_inspections"] as? Int) ?? 0,
                errors: (c["errors"] as? Int) ?? 0,
                state: (c["state"] as? String) ?? (c["status"] as? String) ?? "active",
                since: DCDates.parse(c["since"])
            )
        }
        // Singular primary connector (drift / zero-requests notices).
        if let primary = dict["connector"] as? [String: Any],
           let name = (primary["name"] as? String)?.nonEmpty {
            snap.primaryConnector = .init(
                name: name,
                state: (primary["state"] as? String) ?? "",
                requests: (primary["requests"] as? Int) ?? 0,
                toolInspectionMode: (primary["tool_inspection_mode"] as? String) ?? "",
                toolBlocks: (primary["tool_blocks"] as? Int) ?? 0,
                subprocessBlocks: (primary["subprocess_blocks"] as? Int) ?? 0,
                since: DCDates.parse(primary["since"])
            )
        }

        // Observability destinations: telemetry.details.destinations (OTel)
        // then sinks.details.sinks (audit) — TUI observability_destination_rows.
        let telemetryDetails = (dict["telemetry"] as? [String: Any])?["details"] as? [String: Any]
        let sinkDetails = (dict["sinks"] as? [String: Any])?["details"] as? [String: Any]
        // Per-item casts so one malformed element can't blank the panel.
        snap.observabilityRows = Self.observabilityRows(
            destinations: ((telemetryDetails?["destinations"] as? [Any]) ?? []).compactMap { $0 as? [String: Any] },
            sinks: ((sinkDetails?["sinks"] as? [Any]) ?? []).compactMap { $0 as? [String: Any] }
        )
        snap.telemetryDetail = Self.telemetrySummary(telemetryDetails)
        return snap
    }

    // MARK: - Observability destinations (TUI overview_state parity)

    private static func observabilityRows(
        destinations: [[String: Any]],
        sinks: [[String: Any]]
    ) -> [ObservabilityDestinationRow] {
        var rows: [ObservabilityDestinationRow] = []
        for item in destinations {
            guard let rawName = (item["name"] as? String)?.nonEmpty else { continue }
            let name = rawName.lowercased() == "galileo" ? "Galileo" : rawName
            let preset = (item["preset"] as? String) ?? ""
            rows.append(ObservabilityDestinationRow(
                name: name,
                target: "otel",
                scope: (item["scope"] as? String)?.nonEmpty ?? "process",
                kind: preset.nonEmpty ?? "otlp",
                state: (item["enabled"] as? Bool ?? false) ? "enabled" : "disabled",
                signals: (item["signals"] as? String)?.nonEmpty ?? "none",
                routing: routingLabel(
                    routing: item["routing"] as? [String: Any],
                    delivery: item["delivery"] as? [String: Any]
                ),
                endpoint: redactEndpoint((item["endpoint"] as? String)?.nonEmpty ?? "—")
            ))
        }
        for item in sinks {
            guard let name = (item["name"] as? String)?.nonEmpty else { continue }
            rows.append(ObservabilityDestinationRow(
                name: name,
                target: "audit_sinks",
                scope: (item["scope"] as? String)?.nonEmpty ?? "global",
                kind: (item["kind"] as? String)?.nonEmpty ?? "unknown",
                state: (item["enabled"] as? Bool ?? false) ? "enabled" : "disabled",
                signals: "audit-events",
                routing: "",
                endpoint: redactEndpoint(
                    (item["endpoint"] as? String)?.nonEmpty ?? (item["url"] as? String)?.nonEmpty ?? "—",
                    hidePath: true
                )
            ))
        }
        return rows
    }

    /// ROUTING column label. Stage 1: eligibility from the routing dict
    /// ("87.5% (7/8)" / "waiting"); stage 2: once delivery has attempted>0 it
    /// REPLACES the label with collector accepted/pending/rejected/failed.
    private static func routingLabel(routing: [String: Any]?, delivery: [String: Any]?) -> String {
        var label = ""
        if let routing {
            let accepted = max(0, looseInt(routing["accepted"]))
            let dropped = max(0, looseInt(routing["dropped"]))
            let total = max(accepted + dropped, looseInt(routing["total"]))
            if total > 0 {
                let pct = looseDouble(routing["eligibility_percentage"])
                    ?? looseDouble(routing["accepted_percentage"])
                    ?? 100.0 * Double(accepted) / Double(total)
                label = String(format: "%.1f%% (%d/%d)", pct, accepted, total)
            } else {
                label = "waiting"
            }
        }
        if let delivery {
            let attempted = max(0, looseInt(delivery["attempted"]))
            if attempted > 0 {
                let delivered = max(0, looseInt(delivery["collector_accepted"] ?? delivery["delivered"]))
                let pending = max(0, looseInt(delivery["pending"]))
                let rejected = max(0, looseInt(delivery["rejected"]))
                let failed = max(0, looseInt(delivery["failed"]))
                label = "collector accepted \(delivered)/\(attempted); pending \(pending); rejected \(rejected); failed \(failed)"
            }
        }
        return label
    }

    /// SERVICES Telemetry row summary (TUI telemetry_detail()): enabled
    /// destinations with delivery/eligibility percentages, prefixed by the
    /// destination count.
    private static func telemetrySummary(_ details: [String: Any]?) -> String {
        guard let details else { return "" }
        guard let rawDestinations = details["destinations"] as? [Any] else {
            // Legacy single-endpoint payloads: "signals, redacted-endpoint".
            let signals = (details["signals"] as? String) ?? ""
            let endpoint = (details["endpoint"] as? String).flatMap {
                $0.isEmpty ? nil : redactEndpoint($0, hidePath: true)
            } ?? ""
            return [signals, endpoint].filter { !$0.isEmpty }.joined(separator: ", ")
        }
        let destinations = rawDestinations.compactMap { $0 as? [String: Any] }
        var names: [String] = []
        for item in destinations {
            guard item["enabled"] as? Bool == true,
                  let rawName = (item["name"] as? String)?.nonEmpty else { continue }
            let preset = ((item["preset"] as? String) ?? "").lowercased()
            var label = (preset == "galileo" || rawName.lowercased() == "galileo") ? "Galileo" : rawName
            if let delivery = item["delivery"] as? [String: Any], looseInt(delivery["attempted"]) > 0 {
                let attempted = max(0, looseInt(delivery["attempted"]))
                let delivered = max(0, looseInt(delivery["collector_accepted"] ?? delivery["delivered"]))
                label += String(format: " (%.1f%% delivered)", 100.0 * Double(delivered) / Double(attempted))
            } else if let routing = item["routing"] as? [String: Any], looseInt(routing["total"]) > 0 {
                let pct = looseDouble(routing["eligibility_percentage"])
                    ?? looseDouble(routing["accepted_percentage"]) ?? 0
                label += String(format: " (%.1f%% eligible; awaiting delivery)", pct)
            }
            names.append(label)
        }
        let count = looseInt(details["destination_count"] ?? destinations.count)
        var summary = "\(count) destination\(count == 1 ? "" : "s")"
        if !names.isEmpty { summary += ": " + names.joined(separator: ", ") }
        return summary
    }

    /// Port of observability/display.redact_endpoint_for_display: drop
    /// userinfo/query/fragment always; collapse the path to "/…" for sinks.
    static func redactEndpoint(_ endpoint: String, hidePath: Bool = false) -> String {
        let value = endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.isEmpty { return "—" }
        if value == "—" { return value }
        let hasScheme = value.contains("://")
        let working = hasScheme ? value : "//" + value
        guard let comps = URLComponents(string: working),
              let host = comps.host?.nonEmpty?.lowercased()
        else { return "<redacted-endpoint>" }
        // URLComponents.host may keep IPv6 brackets — don't double-wrap.
        var hostPart = (host.contains(":") && !host.hasPrefix("[")) ? "[\(host)]" : host
        if let port = comps.port { hostPart += ":\(port)" }
        var path = comps.percentEncodedPath
        if hidePath, !path.isEmpty, path != "/" { path = "/…" }
        if let scheme = comps.scheme, hasScheme {
            return "\(scheme)://\(hostPart)\(path)"
        }
        return "\(hostPart)\(path)"
    }

    private static func looseInt(_ value: Any?) -> Int {
        switch value {
        case let i as Int: return i
        case let n as NSNumber: return n.intValue
        case let s as String: return Int(s) ?? Int(Double(s) ?? 0)
        default: return 0
        }
    }

    private static func looseDouble(_ value: Any?) -> Double? {
        switch value {
        case let d as Double: return d
        case let n as NSNumber: return n.doubleValue
        case let s as String: return Double(s)
        default: return nil
        }
    }

    /// Stringify the scalar entries of a /health subsystem "details" object so
    /// the Services card can read addr/summary/skill_dirs/active_signals/etc.
    /// without dragging non-Sendable `Any` values into the snapshot. Nested
    /// arrays/objects are dropped — the Services details only need scalars.
    static func flattenDetails(_ value: Any?) -> [String: String] {
        guard let dict = value as? [String: Any] else { return [:] }
        var out: [String: String] = [:]
        for (k, v) in dict {
            switch v {
            case let s as String: out[k] = s
            case let i as Int: out[k] = String(i)
            case let b as Bool: out[k] = b ? "true" : "false"
            case let d as Double: out[k] = String(d)
            default: break
            }
        }
        return out
    }

    func status() async throws -> [String: Any] {
        (try await getJSON("/status") as? [String: Any]) ?? [:]
    }

    // MARK: - Catalogs

    func skills() async throws -> [SkillItem] {
        let json = try await getJSON("/skills")
        let rows = (json as? [[String: Any]]) ?? ((json as? [String: Any])?["skills"] as? [[String: Any]]) ?? []
        return rows.map { r in
            SkillItem(
                key: (r["key"] as? String) ?? (r["skillKey"] as? String) ?? (r["name"] as? String) ?? "?",
                name: (r["name"] as? String) ?? (r["key"] as? String) ?? "?",
                version: (r["version"] as? String) ?? "—",
                source: (r["source"] as? String) ?? ((r["bundled"] as? Bool) == true ? "bundled" : "custom"),
                enabled: (r["enabled"] as? Bool) ?? true
            )
        }
    }

    func mcps() async throws -> [MCPItem] {
        let json = try await getJSON("/mcps")
        let rows = (json as? [[String: Any]]) ?? ((json as? [String: Any])?["mcps"] as? [[String: Any]]) ?? []
        return rows.map { r in
            MCPItem(
                name: (r["name"] as? String) ?? "?",
                transport: (r["transport"] as? String) ?? (r["type"] as? String) ?? "stdio",
                endpoint: (r["endpoint"] as? String) ?? (r["url"] as? String) ?? (r["command"] as? String) ?? "—",
                version: (r["version"] as? String) ?? "—",
                enabled: (r["enabled"] as? Bool) ?? true
            )
        }
    }

    func plugins() async throws -> [PluginItem] {
        let dict = try await status()
        let rows = (dict["plugins"] as? [[String: Any]]) ?? []
        return rows.map { r in
            PluginItem(
                name: (r["name"] as? String) ?? "?",
                version: (r["version"] as? String) ?? "—",
                category: (r["category"] as? String) ?? (r["kind"] as? String) ?? "plugin",
                enabled: (r["enabled"] as? Bool) ?? true
            )
        }
    }

    func toolsCatalog() async throws -> [ToolItem] {
        let json = try await getJSON("/tools/catalog")
        let rows = (json as? [[String: Any]]) ?? ((json as? [String: Any])?["tools"] as? [[String: Any]]) ?? []
        return rows.map { r in
            ToolItem(
                name: (r["name"] as? String) ?? "?",
                summary: (r["description"] as? String) ?? "",
                signature: (r["signature"] as? String) ?? (r["schema"] as? String) ?? "",
                state: .allow,
                usageCount: (r["usage_count"] as? Int) ?? (r["usageCount"] as? Int) ?? 0
            )
        }
    }

    // MARK: - Mutations (parity with TUI write actions)

    func setSkill(key: String, enabled: Bool) async throws {
        try await post(enabled ? "/skill/enable" : "/skill/disable", ["skillKey": key])
    }

    func setMCP(name: String, enabled: Bool) async throws {
        try await post(enabled ? "/mcp/enable" : "/mcp/disable", ["name": name])
    }

    func setPlugin(name: String, enabled: Bool) async throws {
        try await post(enabled ? "/plugin/enable" : "/plugin/disable",
                       ["pluginName": name], timeout: Self.pluginTimeout)
    }

    func enforceBlock(targetType: String, targetName: String, reason: String) async throws {
        try await post("/enforce/block",
                       ["targetType": targetType, "targetName": targetName, "reason": reason])
    }

    func enforceAllow(targetType: String, targetName: String, reason: String) async throws {
        try await post("/enforce/allow",
                       ["targetType": targetType, "targetName": targetName, "reason": reason])
    }

    func reloadPolicy() async throws {
        try await post("/policy/reload")
    }

    func scanSkills() async throws {
        try await post("/v1/skill/scan", timeout: Self.scanTimeout)
    }

    func scanMCPs() async throws {
        try await post("/v1/mcp/scan", timeout: Self.scanTimeout)
    }

    // MARK: - AI usage / discovery

    func aiUsage() async throws -> AIUsageSnapshot {
        let json = try await getJSON("/api/v1/ai-usage")
        // Throw on malformed payloads so callers keep the last good snapshot.
        guard let dict = json as? [String: Any] else {
            throw GatewayError.badResponse("/api/v1/ai-usage not an object")
        }
        var snap = AIUsageSnapshot()
        let summary = (dict["summary"] as? [String: Any]) ?? dict
        snap.totalDetected = (summary["total_signals"] as? Int)
            ?? (summary["active_signals"] as? Int)
            ?? (summary["total_detected"] as? Int) ?? 0
        snap.activeSignals = (summary["active_signals"] as? Int) ?? 0
        snap.filesScanned = (summary["files_scanned"] as? Int) ?? 0
        // TUI: bool(raw.get("enabled")) — a missing key means disabled.
        snap.enabled = (dict["enabled"] as? Bool) ?? (summary["enabled"] as? Bool) ?? false
        snap.newSignals = (summary["new_signals"] as? Int) ?? 0
        snap.changedSignals = (summary["changed_signals"] as? Int) ?? 0
        snap.goneSignals = (summary["gone_signals"] as? Int) ?? 0
        snap.privacyMode = (summary["privacy_mode"] as? String) ?? (summary["mode"] as? String) ?? ""
        snap.lastScan = DCDates.parse(summary["scanned_at"] ?? summary["last_scan"] ?? summary["lastScan"])
        let signals = (dict["signals"] as? [[String: Any]]) ?? (dict["components"] as? [[String: Any]]) ?? []
        snap.signals = signals.map(decodeSignal)
        snap.components = signals.map(decodeComponent)
        if snap.totalDetected == 0 { snap.totalDetected = snap.signals.count }
        snap.averageConfidence = normalizeConfidence(summary["avg_confidence"] ?? summary["average_confidence"])
        if snap.averageConfidence == 0, !snap.signals.isEmpty {
            snap.averageConfidence = snap.signals.map(\.confidence).reduce(0, +) / Double(snap.signals.count)
        }
        return snap
    }

    private func decodeSignal(_ r: [String: Any]) -> AISignal {
        let component = r["component"] as? [String: Any]
        return AISignal(
            state: (r["state"] as? String) ?? "",
            product: (r["product"] as? String) ?? (r["name"] as? String) ?? "?",
            vendor: (r["vendor"] as? String) ?? "",
            category: (r["category"] as? String) ?? "",
            detector: (r["detector"] as? String) ?? "",
            version: (component?["version"] as? String) ?? (r["version"] as? String) ?? "",
            ecosystem: (component?["ecosystem"] as? String) ?? "",
            componentName: (component?["name"] as? String) ?? "",
            source: (r["source"] as? String) ?? "",
            confidence: normalizeConfidence(r["confidence"]),
            identityScore: normalizeConfidence(r["identity_score"]),
            identityBand: (r["identity_band"] as? String) ?? "",
            presenceScore: normalizeConfidence(r["presence_score"]),
            presenceBand: (r["presence_band"] as? String) ?? "",
            firstSeen: DCDates.parse(r["first_seen"]),
            lastSeen: DCDates.parse(r["last_seen"]),
            lastActive: DCDates.parse(r["last_active_at"]),
            name: (r["name"] as? String) ?? "",
            supportedConnector: (r["supported_connector"] as? String) ?? "",
            signalID: (r["signal_id"] as? String) ?? (r["id"] as? String) ?? "",
            signatureID: (r["signature_id"] as? String) ?? ""
        )
    }

    func aiComponents() async throws -> [AIComponent] {
        let json = try await getJSON("/api/v1/ai-usage/components")
        let rows = (json as? [[String: Any]]) ?? ((json as? [String: Any])?["components"] as? [[String: Any]]) ?? []
        return rows.map(decodeComponent)
    }

    func aiComponentLocations(ecosystem: String, name: String) async throws -> [String] {
        let ecosystemSegment = try encodedPathSegment(ecosystem)
        let nameSegment = try encodedPathSegment(name)
        let json = try await getJSON("/api/v1/ai-usage/components/\(ecosystemSegment)/\(nameSegment)/locations")
        if let arr = json as? [String] { return arr }
        let rows = ((json as? [String: Any])?["locations"] as? [Any]) ?? (json as? [Any]) ?? []
        return rows.compactMap { ($0 as? String) ?? ($0 as? [String: Any])?["path"] as? String }
    }

    func aiComponentHistory(ecosystem: String, name: String) async throws -> [ConfidencePoint] {
        let ecosystemSegment = try encodedPathSegment(ecosystem)
        let nameSegment = try encodedPathSegment(name)
        let json = try await getJSON("/api/v1/ai-usage/components/\(ecosystemSegment)/\(nameSegment)/history")
        let rows = (json as? [[String: Any]]) ?? ((json as? [String: Any])?["history"] as? [[String: Any]]) ?? []
        return rows.compactMap { r in
            guard let ts = DCDates.parse(r["timestamp"] ?? r["captured_at"]) else { return nil }
            return ConfidencePoint(timestamp: ts, confidence: normalizeConfidence(r["confidence"]))
        }
    }

    func aiScan() async throws {
        try await post("/api/v1/ai-usage/scan", timeout: Self.scanTimeout)
    }

    func confidencePolicy(source: String = "merged") async throws -> String {
        let data = try await request(
            "GET",
            "/api/v1/ai-usage/confidence/policy",
            queryItems: [URLQueryItem(name: "source", value: source)]
        )
        return String(data: data, encoding: .utf8) ?? ""
    }

    func validateConfidencePolicy(yaml: String) async throws -> Bool {
        let result = try await post("/api/v1/ai-usage/confidence/policy/validate", ["policy": yaml])
        return ((result as? [String: Any])?["valid"] as? Bool) ?? true
    }

    private func decodeComponent(_ r: [String: Any]) -> AIComponent {
        // Gateway signal shape: name/vendor/product/category/confidence/state/
        // detector/source (see /api/v1/ai-usage); older shapes used
        // ecosystem/version/last_seen — accept both.
        AIComponent(
            ecosystem: (r["ecosystem"] as? String) ?? (r["vendor"] as? String) ?? (r["category"] as? String) ?? "unknown",
            name: (r["name"] as? String) ?? (r["product"] as? String) ?? "?",
            version: (r["version"] as? String) ?? "—",
            confidence: normalizeConfidence(r["confidence"]),
            state: (r["state"] as? String) ?? "detected",
            lastSeen: DCDates.parse(r["last_seen"] ?? r["lastSeen"] ?? r["observed_at"]),
            locations: (r["locations"] as? [String]) ?? [(r["source"] as? String)].compactMap { $0 }
        )
    }

    private func normalizeConfidence(_ raw: Any?) -> Double {
        let value = (raw as? Double) ?? (raw as? Int).map(Double.init) ?? 0
        return value > 1 ? value / 100 : value // accept 0–100 or 0–1
    }
}
