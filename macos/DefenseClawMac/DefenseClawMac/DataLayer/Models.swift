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

// DefenseClaw for macOS — data models mirroring the TUI's service-layer dataclasses.
// Apache-2.0; companion to cisco-ai-defense/defenseclaw.

import Foundation

// MARK: - Severity / state

enum Severity: String, CaseIterable, Codable, Comparable, Identifiable {
    case critical = "CRITICAL"
    case high = "HIGH"
    case medium = "MEDIUM"
    case low = "LOW"
    case info = "INFO"

    var id: String { rawValue }

    private var rank: Int {
        switch self {
        case .critical: 4
        case .high: 3
        case .medium: 2
        case .low: 1
        case .info: 0
        }
    }

    static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rank < rhs.rank }

    /// Mirrors the TUI's _severity_bucket: WARNING folds into MEDIUM;
    /// anything unrecognized (ERROR, ACK, …) is INFO and never alert-counted.
    static func parse(_ raw: String?) -> Severity {
        guard let raw else { return .info }
        let upper = raw.uppercased()
        if upper == "WARNING" { return .medium }
        return Severity(rawValue: upper) ?? .info
    }
}

/// Runtime state buckets matching the TUI's STATE_STYLES groups.
enum EntityState: String {
    case active, blocked, warn, quarantined, disabled

    static func classify(_ raw: String) -> EntityState {
        switch raw.lowercased() {
        case "active", "running", "enabled", "clean", "pass", "ok", "healthy", "allow", "allowed", "connected":
            return .active
        case "blocked", "error", "rejected", "stopped", "fail", "failed", "block", "offline":
            return .blocked
        case "warn", "warning", "reconnecting", "starting", "stale", "degraded", "observe", "not configured", "unconfigured":
            return .warn
        case "quarantined":
            return .quarantined
        default:
            return .disabled
        }
    }
}

// MARK: - Gateway /health

struct HealthSnapshot: Sendable {
    var state: String = "offline"
    var uptimeMs: Int = 0
    var lastError: String?
    var subsystems: [Subsystem] = []
    var connectors: [ConnectorHealth] = []
    var version: String?
    var fetchedAt: Date = .distantPast
    /// Runtime-loaded OTel destinations + audit sinks (Overview
    /// OBSERVABILITY DESTINATIONS · RUNTIME box), otel rows first.
    var observabilityRows: [ObservabilityDestinationRow] = []
    /// The SERVICES Telemetry row detail (TUI telemetry_detail()), e.g.
    /// "1 destination: splunk-o11y (99.9% delivered)".
    var telemetryDetail: String = ""
    /// The singular primary "connector" object from /health — drives the
    /// connector-drift and zero-requests notices (distinct from connectors[]).
    var primaryConnector: PrimaryConnectorHealth?

    struct PrimaryConnectorHealth: Sendable {
        var name: String
        var state: String
        var requests: Int
        var toolInspectionMode: String = ""
        var toolBlocks: Int = 0
        var subprocessBlocks: Int = 0
        var since: Date?
    }

    struct Subsystem: Identifiable, Sendable {
        var name: String
        var state: String
        var detail: String?
        /// Stringified scalar values from the /health subsystem's nested
        /// "details" object (e.g. skill_dirs, active_signals, addr, summary).
        var details: [String: String] = [:]
        var since: Date?
        var id: String { name }
    }

    /// Look up a parsed subsystem by its /health key.
    func subsystem(_ key: String) -> Subsystem? {
        subsystems.first { $0.name == key }
    }
}

/// One row of the Overview SERVICES card — mirrors the TUI's ServiceCard
/// (gateway, agent, watchdog, guardrail, api, sinks, telemetry, ai_discovery,
/// sandbox), each with a runtime state and a one-line detail.
struct ServiceStatus: Identifiable, Sendable {
    var key: String
    var name: String
    var state: String
    var detail: String
    var id: String { key }
}

/// One row of the Overview OBSERVABILITY DESTINATIONS · RUNTIME table —
/// mirrors the TUI's ObservabilityDestinationRow (overview_state.py).
struct ObservabilityDestinationRow: Identifiable, Sendable {
    var name: String
    var target: String      // "otel" | "audit_sinks"
    var scope: String
    var kind: String        // preset or sink kind
    var state: String       // "enabled" | "disabled"
    var signals: String
    var routing: String     // "" renders as "—"
    var endpoint: String    // pre-redacted for display
    var id: String { "\(target)/\(name)" }
}

struct ConnectorHealth: Identifiable, Sendable {
    var name: String
    var mode: String          // from config guardrail.connectors.<name>.mode
    var rulePack: String      // from config …rule_pack_dir (basename)
    var lastActivity: Date?   // derived from audit events (connector= kv)
    var calls: Int            // /health requests, audit fallback for hook connectors
    var blocks: Int           // tool_blocks + subprocess_blocks, audit fallback
    var alerts: Int           // severity-bearing audit rows for this connector
    var inspections: Int = 0  // /health tool_inspections
    var errors: Int = 0
    var state: String
    /// Gateway-session start for this connector (/health connectors[].since) —
    /// drives the TUI's live-window test and session-scoped counts.
    var since: Date?
    var id: String { name }
}

/// A locally detected DefenseClaw-capable agent that is not registered in the
/// active gateway roster. Detection is informational; registration always
/// requires an explicit user action.
struct ConnectorRegistrationCandidate: Identifiable, Sendable, Hashable {
    var name: String
    var confidence: Double
    var lastSeen: Date?
    var canConfigureInline: Bool
    var id: String { name }
}

struct OverviewEnforcementMetrics: Sendable, Equatable {
    var hookCalls: Int = 0
    var blocks: Int = 0
    var findings: Int = 0
    var updatedAt: Date = .distantPast
}

/// One "What needs attention" line (TUI OverviewNotice): level info|warn|error.
struct OverviewNotice: Identifiable, Sendable, Equatable {
    enum Level: String, Sendable { case info, warn, error }
    var level: Level
    var message: String
    var id: String { "\(level.rawValue)-\(message)" }
}

/// One label/value row of the Overview CONFIGURATION box (parity with the
/// TUI's global configuration lines).
struct ConfigurationRow: Identifiable, Sendable {
    var label: String
    var value: String
    var id: String { label }
}

/// Per-connector aibom coverage shown in the filtered ENFORCEMENT/SCANNERS
/// boxes — computed from `aibom scan --json --connector <name>` exactly like
/// the TUI's `_connector_scan_metrics`.
struct ConnectorScanMetrics: Sendable, Equatable {
    var skills = 0
    var skillsBlocked = 0
    var skillsAllowed = 0
    var mcps = 0
    var scanned = 0
    var scannable = 0
}

/// Display name for a connector wire name, mirroring the TUI's
/// `friendly_connector_name` (overview_state.py).
func friendlyConnectorName(_ connector: String) -> String {
    switch connector.trimmingCharacters(in: .whitespaces).lowercased() {
    case "openclaw": return "OpenClaw"
    case "zeptoclaw": return "ZeptoClaw"
    case "claudecode": return "Claude Code"
    case "codex": return "Codex"
    case "hermes": return "Hermes"
    case "cursor": return "Cursor"
    case "windsurf": return "Windsurf"
    case "geminicli": return "Gemini CLI"
    case "copilot": return "GitHub Copilot CLI"
    case "openhands": return "OpenHands"
    case "antigravity": return "Antigravity"
    case "opencode": return "OpenCode"
    case "omnigent": return "OmniGent"
    case let value where !value.isEmpty:
        return value.prefix(1).uppercased() + value.dropFirst()
    default: return "No connector"
    }
}

extension String {
    /// self when non-empty, otherwise nil — for `?? fallback` chains.
    var nonEmpty: String? { isEmpty ? nil : self }
}

// MARK: - Catalog items (skills / MCPs / plugins / tools)

struct CatalogScanState: Sendable {
    var clean: Bool = true
    var maxSeverity: String = ""
    var totalFindings: Int = 0
    var target: String = ""

    var summary: String {
        guard totalFindings > 0 else { return clean ? "Clean" : "Not scanned" }
        let severity = maxSeverity.isEmpty ? "finding" : maxSeverity.uppercased()
        return "\(totalFindings) \(severity) finding\(totalFindings == 1 ? "" : "s")"
    }
}

struct SkillItem: Identifiable, Sendable {
    var key: String
    var name: String
    var version: String
    var source: String
    var enabled: Bool                 // gateway rows: enabled; filesystem rows: eligible/ready
    var skillDescription: String = ""
    var connector: String = ""
    var fromFilesystem: Bool = false  // listed by SkillScanner, read-only
    var status: String = "inactive"
    var verdict: String = "-"
    var scan: CatalogScanState?
    var id: String { key }
}

struct MCPItem: Identifiable, Sendable {
    var name: String
    var transport: String
    var endpoint: String
    var version: String
    var enabled: Bool
    var source: String = ""           // registry file the entry came from (filesystem rows)
    var connector: String = ""
    var fromFilesystem: Bool = false  // discovered by MCPScanner, read-only
    var status: String = "active"
    var verdict: String = "-"
    var scan: CatalogScanState?
    var id: String { connector.isEmpty ? name : "\(connector)/\(name)" }
}

struct PluginItem: Identifiable, Sendable {
    var name: String
    var version: String
    var category: String              // gateway rows: kind; filesystem rows: manifest file or "no manifest"
    var enabled: Bool
    var source: String = ""           // plugin dir the entry came from (filesystem rows)
    var connector: String = ""
    var fromFilesystem: Bool = false  // discovered by PluginScanner, read-only
    var hasManifest: Bool = true
    var commandID: String = ""
    var status: String = ""
    var verdict: String = "-"
    var scan: CatalogScanState?
    var id: String { connector.isEmpty ? (commandID.nonEmpty ?? name) : "\(connector)/\(commandID.nonEmpty ?? name)" }
}

enum ToolState: String, CaseIterable, Identifiable {
    case allow, observe, block
    var id: String { rawValue }
}

struct ToolItem: Identifiable, Sendable {
    var name: String
    var summary: String
    var signature: String
    var state: ToolState
    var usageCount: Int
    var connector: String = ""
    var scope: String = ""
    var commandTarget: String = ""
    var status: String {
        switch state {
        case .allow: "allowed"
        case .observe: "active"
        case .block: "blocked"
        }
    }
    var id: String { connector.isEmpty ? name : "\(connector)/\(name)" }
}

// MARK: - Audit / alerts

struct AuditEvent: Identifiable, Sendable, Hashable {
    var id: String
    var timestamp: Date
    var action: String
    var eventType: String
    var connector: String
    var target: String
    var actor: String
    var details: String
    var structuredJSON: String
    var severity: Severity
    var runID: String

    var isBlockClass: Bool {
        let a = action.lowercased()
        return a.contains("block") || a.contains("reject") || a.contains("enforce") || a.contains("quarantine")
    }
}

struct ScanFindingEvent: Identifiable, Sendable, Hashable {
    var id: String
    var timestamp: Date
    var scanner: String
    var target: String
    var title: String
    var detail: String
    var location: String
    var remediation: String
    var severity: Severity
    var runID: String
    var connector: String = ""
}

struct EgressEvent: Identifiable, Sendable, Hashable {
    var id: String
    var timestamp: Date
    var target: String        // egress.target_host
    var decision: String
    var reason: String
    var looksLikeLLM: Bool
    var branch: String
    var severity: Severity
    var connector: String = ""
    var targetPath: String = ""   // egress.target_path
    var bodyShape: String = ""    // egress.body_shape
    var source: String = ""       // egress.source
    /// False when the row's ts failed to parse (timestamp is ingest time) —
    /// such rows are excluded from the silent-bypass window like the TUI.
    var timestampParsed = true

    /// The TUI's synthetic egress detail line (alerts.synthetic_egress_event).
    var detailLine: String {
        var parts = [
            "host=\(target.isEmpty ? "(unknown)" : target)",
            "path=\(targetPath)",
            "branch=\(branch)",
            "decision=\(decision)",
            "shape=\(bodyShape)",
            "looks_like_llm=\(looksLikeLLM)",
            "source=\(source)",
        ]
        if !reason.isEmpty { parts.append("reason=\(reason)") }
        return parts.joined(separator: " ")
    }
}

/// A scan summary block grouped by scan_id from gateway.jsonl — the unit the
/// TUI's Alerts panel counts (one row per scan; nested findings expand).
struct ScanBlockEvent: Identifiable, Sendable, Hashable {
    var scanID: String
    var timestamp: Date
    var scanner: String
    var target: String
    var severity: Severity   // scan.severity_max
    var verdict: String
    var findingCount: Int
    var findingTitles: [String]
    var connector: String = ""
    var id: String { "scan-\(scanID)" }
}

/// Unified alert row (audit ∪ scan blocks ∪ findings ∪ egress) — parity with AlertRowKind.
enum AlertRow: Identifiable, Hashable {
    case audit(AuditEvent)
    case scan(ScanBlockEvent)
    case finding(ScanFindingEvent)
    case egress(EgressEvent)

    var id: String {
        switch self {
        case .audit(let e): "audit-\(e.id)"
        case .scan(let e): e.id
        case .finding(let e): "finding-\(e.id)"
        case .egress(let e): "egress-\(e.id)"
        }
    }
    var kind: String {
        switch self {
        case .audit: "audit"
        case .scan: "scan"
        case .finding: "scan finding"
        case .egress: "egress"
        }
    }
    /// Attributed connector for the connector filter ("" = unattributed).
    var connectorName: String {
        switch self {
        case .audit(let e): e.connector
        case .scan(let e): e.connector
        case .finding(let e): e.connector
        case .egress(let e): e.connector
        }
    }
    var timestamp: Date {
        switch self {
        case .audit(let e): e.timestamp
        case .scan(let e): e.timestamp
        case .finding(let e): e.timestamp
        case .egress(let e): e.timestamp
        }
    }
    var severity: Severity {
        switch self {
        case .audit(let e): e.severity
        case .scan(let e): e.severity
        case .finding(let e): e.severity
        case .egress(let e): e.severity
        }
    }
    var action: String {
        switch self {
        case .audit(let e): e.action
        case .scan(let e): e.verdict.isEmpty ? "scan" : e.verdict
        case .finding: "finding"
        case .egress(let e): e.decision
        }
    }
    var target: String {
        switch self {
        case .audit(let e): e.target
        case .scan(let e): e.target
        case .finding(let e): e.target
        case .egress(let e): e.target
        }
    }
    var details: String {
        switch self {
        case .audit(let e): e.details
        case .scan(let e):
            ([e.scanner, "\(e.findingCount) finding(s)"] + e.findingTitles.prefix(2))
                .filter { !$0.isEmpty }.joined(separator: " · ")
        case .finding(let e): [e.title, e.detail].filter { !$0.isEmpty }.joined(separator: " — ")
        case .egress(let e): e.detailLine
        }
    }
    var runID: String {
        switch self {
        case .audit(let e): e.runID
        case .scan: ""
        case .finding(let e): e.runID
        case .egress: ""
        }
    }
}

// MARK: - Activity (config mutations)

struct ActivityMutation: Identifiable, Sendable, Hashable {
    var id: String
    var timestamp: Date
    var actor: String
    var action: String
    var targetType: String
    var targetID: String
    var reason: String
    var versionFrom: String
    var versionTo: String
    var beforeJSON: String
    var afterJSON: String
    var connector: String = ""
}

enum StructuredDetailParser {
    static func pairs(_ details: String) -> [(String, String)] {
        details.split(whereSeparator: \.isWhitespace).compactMap { token in
            let components = token.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard components.count == 2 else { return nil }
            let key = String(components[0])
            let value = String(components[1])
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"'`"))
            guard !key.isEmpty, !value.isEmpty else { return nil }
            return (label(key), value)
        }
    }

    static func prettyJSON(_ raw: String) -> String {
        guard let data = raw.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              JSONSerialization.isValidJSONObject(object),
              let pretty = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]),
              let text = String(data: pretty, encoding: .utf8)
        else { return raw }
        return text
    }

    static func label(_ key: String) -> String {
        key.split(separator: "_").map { $0.capitalized }.joined(separator: " ")
    }
}

// MARK: - Logs

enum LogStream: String, CaseIterable, Identifiable {
    case gateway, verdicts, otel, watchdog
    var id: String { rawValue }
    var title: String { rawValue.capitalized }
}

struct LogRow: Identifiable, Sendable {
    var id: String
    var timestamp: Date
    var stream: LogStream
    var severity: Severity
    var action: String
    var eventType: String
    var message: String
    var rawJSON: String
    var connector: String = ""
}

/// Filter presets ported from the TUI's FILTER_PRESETS.
enum LogPreset: String, CaseIterable, Identifiable {
    case all, noNoise = "no-noise", important, errors, warningsPlus = "warnings+",
         scan, drift, guardrail, hooks
    var id: String { rawValue }

    private static let noisePatterns = [
        "event tick seq=", "event health seq=", "payload_len=20",
        "mallocstacklogging", "event sessions.changed", "content-length=0",
    ]
    private static let importantKeywords = [
        "error", "fatal", "panic", "warn", "block", "allow", "reject", "quarantine",
        "scan", "drift", "verdict", "guardrail", "connected", "disconnected",
        "started", "stopped",
    ]

    func matches(_ row: LogRow) -> Bool {
        let msg = row.message.lowercased()
        switch self {
        case .all: return true
        case .noNoise: return !Self.noisePatterns.contains { msg.contains($0) }
        case .important: return Self.importantKeywords.contains { msg.contains($0) }
        case .errors: return row.severity >= .high
        case .warningsPlus: return row.severity >= .medium
        case .scan: return row.eventType == "scan" || msg.contains("scan")
        case .drift: return msg.contains("drift")
        case .guardrail: return msg.contains("guardrail") || msg.contains("verdict") || msg.contains("judge")
        case .hooks: return row.eventType == "hook" || msg.contains("hook")
        }
    }
}

// MARK: - AI discovery

enum DCSafeNumbers {
    /// Swift traps when converting a non-finite or out-of-range floating-point
    /// value to Int. Return nil instead while preserving normal truncation.
    static func intTruncating(_ value: Double) -> Int? {
        guard value.isFinite else { return nil }
        return Int(exactly: value.rounded(.towardZero))
    }
}

/// Normalizes gateway confidence values and keeps display conversions safe.
/// Gateway payloads may use either a 0...1 fraction or a 0...100 percent.
enum AIConfidence {
    static func normalize(_ raw: Any?) -> Double {
        let value = (raw as? Double) ?? (raw as? Int).map(Double.init) ?? 0
        guard value.isFinite else { return 0 }
        return clampedUnit(value > 1 ? value / 100 : value)
    }

    static func clampedUnit(_ value: Double) -> Double {
        guard value.isFinite else { return 0 }
        return min(max(value, 0), 1)
    }

    static func percent(
        _ value: Double,
        roundingRule: FloatingPointRoundingRule = .towardZero
    ) -> Int {
        DCSafeNumbers.intTruncating((clampedUnit(value) * 100).rounded(roundingRule)) ?? 0
    }
}

enum AIPresenceAxis {
    /// Current gateways omit an exact numeric zero but still send its
    /// non-empty confidence band. Compatible gateways may send the zero
    /// explicitly. Only a missing/null score with no band means the axis was
    /// unavailable on an older payload.
    static func wasReported(rawScore: Any?, band: String) -> Bool {
        if !band.isEmpty { return true }
        guard let rawScore else { return false }
        return !(rawScore is NSNull)
    }
}

struct AIUsageSnapshot: Sendable {
    var totalDetected: Int = 0
    var activeSignals: Int = 0
    var filesScanned: Int = 0
    var averageConfidence: Double = 0
    var lastScan: Date?
    var components: [AIComponent] = []
    var signals: [AISignal] = []
    // Overview box inputs (TUI ai_discovery_box)
    var enabled: Bool = true
    /// Runtime opt-in reported by the currently running gateway generation.
    var lookupModelProvenanceOnline: Bool = false
    var newSignals: Int = 0
    var changedSignals: Int = 0
    var goneSignals: Int = 0
    var privacyMode: String = ""

    /// Non-model discoveries stay in the existing one-row-per-product table.
    var rows: [AIDiscoveryRow] { AIDiscoveryGrouping.rows(from: signals) }

    /// TUI `header_parts`: a reported zero remains `active=0`; churn counters
    /// only appear when non-zero.
    var discoveryHeaderParts: [String] {
        var parts = ["active=\(activeSignals)"]
        if newSignals != 0 { parts.append("new=\(newSignals)") }
        if changedSignals != 0 { parts.append("changed=\(changedSignals)") }
        if goneSignals != 0 { parts.append("gone=\(goneSignals)") }
        parts.append("files=\(filesScanned)")
        parts.append("model-lookup=\(lookupModelProvenanceOnline ? "online" : "offline")")
        return parts
    }

    /// Local model signals use a dedicated compact table so high-cardinality
    /// model IDs and lineage metadata do not crowd the product inventory.
    var modelRows: [AIModelDiscoveryRow] { AIDiscoveryGrouping.modelRows(from: signals) }
}

struct AIComponent: Identifiable, Sendable, Hashable {
    var ecosystem: String
    var name: String
    var version: String
    var confidence: Double // 0...1
    var state: String      // detected / uncertain / trusted
    var lastSeen: Date?
    var locations: [String]
    var id: String { "\(ecosystem)/\(name)@\(version)" }
}

/// Curated lineage for one locally observed model. Flags are intentionally
/// derived by clients from the ISO country code instead of crossing the wire.
struct AIModelProvenance: Sendable, Hashable {
    var publisher: String = ""
    var countryCode: String = ""
    var rootModel: String = ""
    var baseModels: [String] = []
    /// nil means the catalog could not establish whether this is quantized.
    var quantized: Bool? = nil
    var quantization: String = ""
    /// nil means the catalog could not establish whether this is distilled.
    var distilled: Bool? = nil
    var derivation: String = ""
    var source: String = ""
    var confidence: String = ""

    static func fromMapping(_ raw: [String: Any]?) -> AIModelProvenance? {
        guard let raw, !raw.isEmpty else { return nil }
        let bases: [String]
        if let values = raw["base_models"] as? [String] {
            bases = values.filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        } else if let values = raw["base_models"] as? [Any] {
            bases = values.compactMap { $0 as? String }
                .filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        } else if let value = raw["base_models"] as? String,
                  !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            bases = [value]
        } else {
            bases = []
        }
        return AIModelProvenance(
            publisher: (raw["publisher"] as? String) ?? "",
            countryCode: normalizedCountryCode((raw["country_code"] as? String) ?? ""),
            rootModel: (raw["root_model"] as? String) ?? "",
            baseModels: bases,
            quantized: optionalBool(raw["quantized"]),
            quantization: (raw["quantization"] as? String) ?? "",
            distilled: optionalBool(raw["distilled"]),
            derivation: (raw["derivation"] as? String) ?? "",
            source: (raw["source"] as? String) ?? "",
            confidence: (raw["confidence"] as? String) ?? ""
        )
    }

    /// Text remains useful when the platform cannot render the flag glyph.
    var countryDisplay: String {
        guard !countryCode.isEmpty else { return "" }
        let flag = countryFlag
        return flag.isEmpty ? countryCode : "\(countryCode) \(flag)"
    }

    var countryFlag: String {
        guard countryCode.unicodeScalars.count == 2 else { return "" }
        let regionalIndicatorOffset: UInt32 = 127_397
        return countryCode.unicodeScalars.compactMap { scalar in
            UnicodeScalar(regionalIndicatorOffset + scalar.value)
        }.map { String($0) }.joined()
    }

    var rootDisplay: String {
        if !rootModel.isEmpty { return rootModel }
        if !baseModels.isEmpty { return "ambiguous (\(baseModels.count))" }
        return ""
    }

    var derivationDisplay: String {
        var parts: [String] = []
        if !derivation.isEmpty {
            parts.append(derivation)
        } else if quantized == true, distilled == true {
            parts.append("distilled+quantized")
        } else if quantized == true {
            parts.append("quantized")
        } else if distilled == true {
            parts.append("distilled")
        } else if quantized == false, distilled == false {
            parts.append("base")
        }
        if !quantization.isEmpty,
           !parts.contains(where: { $0.caseInsensitiveCompare(quantization) == .orderedSame }) {
            parts.append(quantization)
        }
        return parts.joined(separator: " · ")
    }

    private static func normalizedCountryCode(_ raw: String) -> String {
        let code = raw.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard code.unicodeScalars.count == 2,
              code.unicodeScalars.allSatisfy({ (65...90).contains(Int($0.value)) })
        else { return "" }
        return code
    }

    private static func optionalBool(_ raw: Any?) -> Bool? {
        if let value = raw as? Bool { return value }
        if let value = raw as? NSNumber, value.doubleValue == 0 || value.doubleValue == 1 {
            return value.boolValue
        }
        if let value = raw as? String {
            switch value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case "true", "1", "yes", "on": return true
            case "false", "0", "no", "off": return false
            default: return nil
            }
        }
        return nil
    }
}

/// Model metadata emitted by the local model API and artifact detectors.
struct AIUsageModel: Sendable, Hashable {
    var id: String = ""
    var status: String = ""
    var format: String = ""
    var provider: String = ""
    var recipe: String = ""
    var modality: String = ""
    var device: String = ""
    var sizeBytes: Int64 = 0
    var pinned: Bool = false
    var provenance: AIModelProvenance? = nil

    static func fromMapping(_ raw: [String: Any]?) -> AIUsageModel? {
        guard let raw, !raw.isEmpty else { return nil }
        return AIUsageModel(
            id: (raw["id"] as? String) ?? "",
            status: (raw["status"] as? String) ?? "",
            format: (raw["format"] as? String) ?? "",
            provider: (raw["provider"] as? String) ?? "",
            recipe: (raw["recipe"] as? String) ?? "",
            modality: (raw["modality"] as? String) ?? "",
            device: (raw["device"] as? String) ?? "",
            sizeBytes: AIUsageValueDecoding.nonnegativeInt64(raw["size_bytes"]),
            pinned: AIUsageValueDecoding.boolean(raw["pinned"]),
            provenance: AIModelProvenance.fromMapping(raw["provenance"] as? [String: Any])
        )
    }
}

private enum AIUsageValueDecoding {
    static func nonnegativeInt64(_ raw: Any?) -> Int64 {
        // JSON booleans bridge through NSNumber, so reject Bool first.
        if raw is Bool { return 0 }
        let value: Int64?
        switch raw {
        case let number as Int:
            value = Int64(exactly: number)
        case let number as Int64:
            value = number
        case let number as NSNumber:
            let double = number.doubleValue
            guard double.isFinite, let exact = Int64(exactly: double) else { return 0 }
            value = exact
        case let text as String:
            value = Int64(text.trimmingCharacters(in: .whitespacesAndNewlines))
        default:
            value = nil
        }
        guard let value, value >= 0 else { return 0 }
        return value
    }

    static func boolean(_ raw: Any?) -> Bool {
        if let value = raw as? Bool { return value }
        if let value = raw as? NSNumber {
            if value == 0 { return false }
            if value == 1 { return true }
            return false
        }
        guard let text = raw as? String else { return false }
        switch text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "true", "1", "yes", "on": return true
        default: return false
        }
    }
}

struct ConfidencePoint: Identifiable, Sendable {
    var timestamp: Date
    var confidence: Double
    var id: Date { timestamp }
}

/// Sanitized process metadata for a discovered AI runtime. The gateway never
/// includes argv, prompts, or workspace paths in this block.
struct AIUsageRuntime: Sendable, Hashable {
    var pid: Int = 0
    var ppid: Int = 0
    var startedAt: Date?
    var uptimeSeconds: Int64 = 0
    var user: String = ""
    var command: String = ""
}

/// One raw detection signal from /api/v1/ai-usage (ai_discovery_state.AIUsageSignal).
struct AISignal: Sendable, Hashable {
    var state: String
    var product: String
    var vendor: String
    var category: String
    var detector: String
    var version: String
    var ecosystem: String       // component.ecosystem when present
    var componentName: String   // component.name when present
    var source: String
    var confidence: Double
    var identityScore: Double
    var identityBand: String
    var presenceScore: Double
    var presenceBand: String
    /// True when the gateway supplied the presence axis. Older gateways omit
    /// both presence fields; a reported score of zero must remain distinct
    /// because it means the signal is confidently no longer present.
    var presenceAxisReported: Bool = false
    var firstSeen: Date?
    var lastSeen: Date?
    var lastActive: Date?
    // Overview-box row inputs (TUI display/dedup keys)
    var name: String = ""
    var supportedConnector: String = ""
    var signalID: String = ""
    var signatureID: String = ""
    var model: AIUsageModel? = nil
    var runtime: AIUsageRuntime? = nil
    var evidenceTypes: [String] = []

    func hasEligiblePresence(minimum: Double) -> Bool {
        !presenceAxisReported || presenceScore >= minimum
    }
}

/// Pure decoding shared by the gateway client and focused Swift harnesses.
/// Keeping JSON coercion here prevents view code from reinterpreting the wire
/// format and mirrors the TUI's `AIUsageSignal.from_mapping` boundary.
enum AISignalDecoding {
    /// Decode array members independently. A single malformed compatible-
    /// gateway row must not erase every valid discovery signal in the batch.
    static func signalMappings(from raw: Any?) -> [[String: Any]] {
        (raw as? [Any])?.compactMap { $0 as? [String: Any] } ?? []
    }

    static func decode(_ raw: [String: Any]) -> AISignal {
        let component = nonemptyDictionary(raw["component"])
        let model = decodeModel(nonemptyDictionary(raw["model"]))
        let runtime = decodeRuntime(nonemptyDictionary(raw["runtime"]))
        let presenceBand = string(raw["presence_band"])
        let presenceAxisReported = AIPresenceAxis.wasReported(
            rawScore: raw["presence_score"],
            band: presenceBand
        )

        return AISignal(
            state: string(raw["state"]),
            product: string(raw["product"]),
            vendor: string(raw["vendor"]),
            category: string(raw["category"]),
            detector: string(raw["detector"]),
            version: string(component?["version"]).nonEmpty ?? string(raw["version"]),
            ecosystem: string(component?["ecosystem"]),
            componentName: string(component?["name"]),
            source: string(raw["source"]),
            confidence: AIConfidence.normalize(raw["confidence"]),
            identityScore: AIConfidence.normalize(raw["identity_score"]),
            identityBand: string(raw["identity_band"]),
            presenceScore: AIConfidence.normalize(raw["presence_score"]),
            presenceBand: presenceBand,
            presenceAxisReported: presenceAxisReported,
            firstSeen: DCDates.parse(raw["first_seen"]),
            lastSeen: DCDates.parse(raw["last_seen"]),
            lastActive: DCDates.parse(raw["last_active_at"]),
            name: string(raw["name"]),
            supportedConnector: string(raw["supported_connector"]),
            signalID: string(raw["signal_id"]).nonEmpty ?? string(raw["id"]),
            signatureID: string(raw["signature_id"]),
            model: model,
            runtime: runtime,
            evidenceTypes: stringList(raw["evidence_types"])
        )
    }

    private static func decodeModel(_ raw: [String: Any]?) -> AIUsageModel? {
        AIUsageModel.fromMapping(raw)
    }

    private static func decodeRuntime(_ raw: [String: Any]?) -> AIUsageRuntime? {
        guard let raw else { return nil }
        return AIUsageRuntime(
            pid: Int(clamping: AIUsageValueDecoding.nonnegativeInt64(raw["pid"])),
            ppid: Int(clamping: AIUsageValueDecoding.nonnegativeInt64(raw["ppid"])),
            startedAt: DCDates.parse(raw["started_at"]),
            uptimeSeconds: AIUsageValueDecoding.nonnegativeInt64(raw["uptime_sec"]),
            user: string(raw["user"]),
            command: string(raw["comm"])
        )
    }

    private static func nonemptyDictionary(_ raw: Any?) -> [String: Any]? {
        guard let value = raw as? [String: Any], !value.isEmpty else { return nil }
        return value
    }

    private static func string(_ raw: Any?) -> String {
        raw as? String ?? ""
    }

    private static func stringList(_ raw: Any?) -> [String] {
        if let value = raw as? String { return value.isEmpty ? [] : [value] }
        return (raw as? [Any])?.compactMap { $0 as? String } ?? []
    }

}

/// Grouped product row — exact port of the TUI's AIDiscoveryRow (_rebuild()).
struct AIDiscoveryRow: Identifiable, Sendable, Hashable {
    var state: String
    var product: String
    var vendor: String
    var ecosystem: String
    var component: String
    var version: String
    var model: String
    var modelStatuses: [String]
    var modelFormats: [String]
    var categories: [String]
    var detectors: [String]
    var count: Int
    var identityScore: Double
    var identityBand: String
    var presenceScore: Double
    var presenceBand: String
    var lastActive: Date?
    var signals: [AISignal]

    /// Length-prefix every user-controlled field so embedded separators cannot
    /// make two different rows share a SwiftUI selection identity.
    var id: String {
        [state, product, vendor, ecosystem, component, version, model]
            .map { "\($0.utf8.count):\($0)" }
            .joined()
    }

    var maxConfidence: Double { signals.map(\.confidence).max() ?? 0 }

    var componentLabel: String {
        if !ecosystem.isEmpty, !component.isEmpty { return "\(component) (\(ecosystem))" }
        return component
    }
}

struct AIModelDiscoveryRowID: Sendable, Hashable {
    var normalizedModelID: String
}

/// A model-centric row aggregated across artifact, API, and runtime sources.
struct AIModelDiscoveryRow: Identifiable, Sendable, Hashable {
    var state: String
    var modelID: String
    var statuses: [String]
    var formats: [String]
    var providers: [String]
    var products: [String]
    var vendors: [String]
    var detectors: [String]
    var count: Int
    var provenance: AIModelProvenance?
    var lastActive: Date?
    var signals: [AISignal]

    var id: AIModelDiscoveryRowID {
        AIModelDiscoveryRowID(
            normalizedModelID: AIDiscoveryGrouping.normalizedModelID(modelID)
        )
    }

    var maxSizeBytes: Int64 { signals.compactMap(\.model).map(\.sizeBytes).max() ?? 0 }
    var isPinned: Bool { signals.compactMap(\.model).contains { $0.pinned } }

    func matches(_ query: String) -> Bool {
        guard !query.isEmpty else { return true }
        let provenanceParts = provenance.map {
            [$0.publisher, $0.countryCode, $0.countryDisplay, $0.rootModel, $0.quantization,
             $0.derivation, $0.source, $0.confidence] + $0.baseModels
        } ?? []
        var parts = [state, modelID]
        parts.append(contentsOf: statuses)
        parts.append(contentsOf: formats)
        parts.append(contentsOf: providers)
        parts.append(contentsOf: products)
        parts.append(contentsOf: vendors)
        parts.append(contentsOf: detectors)
        parts.append(contentsOf: provenanceParts)
        return parts.joined(separator: " ").localizedCaseInsensitiveContains(query)
    }
}

enum AIDiscoveryGrouping {
    static let detailSignalLimit = 50

    private struct GroupKey: Hashable {
        var state: String
        var product: String
        var vendor: String
        var ecosystem: String
        var component: String
        var version: String
        var model: String
    }

    /// TUI state_weight(): new < changed < active < seen < gone < other.
    static func stateWeight(_ state: String) -> Int {
        switch state.trimmingCharacters(in: .whitespaces).lowercased() {
        case "new": 0
        case "changed": 1
        case "active": 2
        case "seen": 3
        case "gone": 4
        default: 9
        }
    }

    /// TUI format_csv_truncated(items, 2) → "a, b (+3)".
    static func csvTruncated(_ items: [String], limit: Int = 2) -> String {
        guard !items.isEmpty else { return "" }
        guard limit > 0, limit < items.count else { return items.joined(separator: ", ") }
        return items.prefix(limit).joined(separator: ", ") + " (+\(items.count - limit))"
    }

    /// TUI format_confidence(): "band (NN%)".
    static func formatConfidence(score: Double, band: String) -> String {
        let band = band.trimmingCharacters(in: .whitespaces)
        let normalizedScore = AIConfidence.clampedUnit(score)
        if band.isEmpty && normalizedScore == 0 { return "" }
        let pct = AIConfidence.percent(normalizedScore, roundingRule: .toNearestOrAwayFromZero)
        return band.isEmpty ? "\(pct)%" : "\(band) (\(pct)%)"
    }

    static func hasModels(in rows: [AIDiscoveryRow]) -> Bool {
        rows.contains { !$0.model.isEmpty }
    }

    /// TUI `_apply_filter`: model identity participates in search, while
    /// status/format remain presentation-only aggregate columns.
    static func matches(_ row: AIDiscoveryRow, query: String) -> Bool {
        guard !query.isEmpty else { return true }
        let haystack = ([
            row.state, row.product, row.vendor, row.ecosystem, row.component,
            row.version, row.model, row.identityBand, row.presenceBand,
        ] + row.categories + row.detectors).joined(separator: " ").lowercased()
        return haystack.contains(query.lowercased())
    }

    static func signalIdentifier(_ signal: AISignal) -> String {
        for candidate in [signal.signatureID, signal.name, signal.signalID] {
            let value = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
            if !value.isEmpty { return value }
        }
        return "(unknown)"
    }

    static func modelDetail(_ model: AIUsageModel) -> String {
        let modelID = model.id.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty ?? "(unknown)"
        var parts = ["model: id=\(modelID)"]
        for (label, value) in [
            ("status", model.status), ("format", model.format),
            ("recipe", model.recipe), ("modality", model.modality),
            ("device", model.device),
        ] {
            let value = value.trimmingCharacters(in: .whitespacesAndNewlines)
            if !value.isEmpty { parts.append("\(label)=\(value)") }
        }
        if model.sizeBytes > 0 { parts.append("size_bytes=\(model.sizeBytes)") }
        if model.pinned { parts.append("pinned=true") }
        return parts.joined(separator: " ")
    }

    static func runtimeDetail(_ runtime: AIUsageRuntime) -> String {
        guard runtime.pid > 0 else { return "" }
        var parts = ["runtime: pid=\(runtime.pid)"]
        let user = runtime.user.trimmingCharacters(in: .whitespacesAndNewlines)
        if !user.isEmpty { parts.append("user=\(user)") }
        if runtime.uptimeSeconds > 0 {
            parts.append("up=\(humanizeDuration(seconds: runtime.uptimeSeconds))")
        }
        let command = runtime.command.trimmingCharacters(in: .whitespacesAndNewlines)
        if !command.isEmpty { parts.append("comm=\(command)") }
        return parts.joined(separator: " ")
    }

    static func activityDetail(_ signal: AISignal, now: Date = Date()) -> String {
        if let lastActive = signal.lastActive,
           let seconds = safeElapsedSeconds(from: lastActive, to: now) {
            return "last active: \(humanizeDuration(seconds: seconds)) ago"
        }
        if let lastSeen = signal.lastSeen,
           let seconds = safeElapsedSeconds(from: lastSeen, to: now) {
            return "last seen: \(humanizeDuration(seconds: seconds)) ago"
        }
        return ""
    }

    static func humanizeDuration(seconds rawSeconds: Int64) -> String {
        let seconds = max(rawSeconds, 0)
        if seconds < 1 { return "0s" }
        if seconds < 60 { return "\(seconds)s" }
        let minutes = seconds / 60
        if minutes < 60 { return "\(minutes)m" }
        let hours = minutes / 60
        if hours < 24 {
            let remainder = minutes - hours * 60
            return remainder == 0 ? "\(hours)h" : "\(hours)h\(remainder)m"
        }
        let days = hours / 24
        let remainder = hours % 24
        return remainder == 0 ? "\(days)d" : "\(days)d\(remainder)h"
    }

    private static func safeElapsedSeconds(from date: Date, to now: Date) -> Int64? {
        let delta = abs(now.timeIntervalSince(date))
        guard let seconds = DCSafeNumbers.intTruncating(delta) else { return nil }
        return Int64(exactly: seconds)
    }

    /// Port of AIDiscoveryPanelModel._rebuild(): group non-model signals by
    /// (state, product, vendor, ecosystem, component, version); aggregate
    /// unique categories/detectors in first-seen order; sort by state
    /// weight, then count desc, then product. Identified `local_model` signals
    /// move to `modelRows(from:)`; compatible non-local signals that happen to
    /// carry model metadata remain product rows.
    static func rows(from signals: [AISignal]) -> [AIDiscoveryRow] {
        var groups: [GroupKey: AIDiscoveryRow] = [:]
        var order: [GroupKey] = []
        for signal in signals {
            if signal.category == "local_model",
               let model = signal.model,
               !model.id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                continue
            }
            let modelID = ""
            let key = GroupKey(
                state: signal.state,
                product: signal.product,
                vendor: signal.vendor,
                ecosystem: signal.ecosystem.lowercased(),
                component: signal.componentName.lowercased(),
                version: signal.version,
                model: modelID
            )
            var row = groups[key] ?? AIDiscoveryRow(
                state: signal.state, product: signal.product, vendor: signal.vendor,
                ecosystem: signal.ecosystem, component: signal.componentName,
                version: signal.version, model: modelID, modelStatuses: [], modelFormats: [],
                categories: [], detectors: [], count: 0,
                identityScore: 0, identityBand: "", presenceScore: 0, presenceBand: "",
                lastActive: nil, signals: []
            )
            if groups[key] == nil { order.append(key) }
            row.count += 1
            row.signals.append(signal)
            if !signal.category.isEmpty, !row.categories.contains(signal.category) {
                row.categories.append(signal.category)
            }
            if !signal.detector.isEmpty, !row.detectors.contains(signal.detector) {
                row.detectors.append(signal.detector)
            }
            if let model = signal.model {
                if !model.status.isEmpty, !row.modelStatuses.contains(model.status) {
                    row.modelStatuses.append(model.status)
                }
                if !model.format.isEmpty, !row.modelFormats.contains(model.format) {
                    row.modelFormats.append(model.format)
                }
            }
            if row.identityBand.isEmpty, !signal.identityBand.isEmpty {
                row.identityBand = signal.identityBand
                row.identityScore = signal.identityScore
            }
            if row.presenceBand.isEmpty, !signal.presenceBand.isEmpty {
                row.presenceBand = signal.presenceBand
                row.presenceScore = signal.presenceScore
            }
            if let active = signal.lastActive, row.lastActive.map({ active > $0 }) ?? true {
                row.lastActive = active
            }
            groups[key] = row
        }
        return order.enumerated().compactMap { offset, key in
            groups[key].map { (offset, $0) }
        }.sorted { lhs, rhs in
            let lhsKey = (stateWeight(lhs.1.state), -lhs.1.count, lhs.1.product, lhs.1.model)
            let rhsKey = (stateWeight(rhs.1.state), -rhs.1.count, rhs.1.product, rhs.1.model)
            return lhsKey == rhsKey ? lhs.0 < rhs.0 : lhsKey < rhsKey
        }.map(\.1)
    }
}

/// TUI-equivalent ordering and evidence deduplication for the Overview card.
/// The card is explicitly agent-only; local models stay visible in the full
/// AI Discovery table and never consume its eight-row agent cap.
enum AIOverviewGrouping {
    private struct OverviewKey: Hashable {
        var kind: String
        var value: String
    }

    static func agentSignals(from signals: [AISignal]) -> [AISignal] {
        signals.filter { $0.category != "local_model" }
    }

    static func summaryParts(
        from signals: [AISignal],
        lastScan: Date?,
        privacyMode: String,
        now: Date = Date()
    ) -> [String] {
        let agents = agentSignals(from: signals)
        let states = agents.map {
            $0.state.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }
        var parts = ["\(states.filter { $0 != "gone" }.count) active"]
        let newCount = states.filter { $0 == "new" }.count
        let changedCount = states.filter { $0 == "changed" }.count
        let goneCount = states.filter { $0 == "gone" }.count
        if newCount != 0 { parts.append("\(newCount) new") }
        if changedCount != 0 { parts.append("\(changedCount) changed") }
        if goneCount != 0 { parts.append("\(goneCount) gone") }
        if let lastScan { parts.append("scanned \(formatScanAge(lastScan, now: now))") }
        if let mode = trimmed(privacyMode).nonEmpty { parts.append("mode \(mode)") }
        return parts
    }

    static func sortedSignals(_ signals: [AISignal]) -> [AISignal] {
        signals.enumerated().sorted { lhsEntry, rhsEntry in
            let lhs = lhsEntry.element
            let rhs = rhsEntry.element
            let lhsState = stateRank(lhs.state)
            let rhsState = stateRank(rhs.state)
            if lhsState != rhsState { return lhsState < rhsState }

            let lhsModel = lhs.model?.status == "loaded" ? 0 : 1
            let rhsModel = rhs.model?.status == "loaded" ? 0 : 1
            if lhsModel != rhsModel { return lhsModel < rhsModel }
            if lhs.confidence != rhs.confidence { return lhs.confidence > rhs.confidence }

            let lhsSeen = lhs.lastSeen?.timeIntervalSince1970 ?? 0
            let rhsSeen = rhs.lastSeen?.timeIntervalSince1970 ?? 0
            if lhsSeen != rhsSeen { return lhsSeen > rhsSeen }
            let lhsName = displayName(lhs).lowercased()
            let rhsName = displayName(rhs).lowercased()
            return lhsName == rhsName ? lhsEntry.offset < rhsEntry.offset : lhsName < rhsName
        }.map(\.element)
    }

    static func uniqueSignals(_ signals: [AISignal]) -> [AISignal] {
        var seen = Set<OverviewKey>()
        var rows: [AISignal] = []
        for signal in signals {
            guard seen.insert(key(for: signal)).inserted else { continue }
            rows.append(signal)
        }
        return rows
    }

    static func displayName(_ signal: AISignal) -> String {
        for candidate in [
            signal.model?.id ?? "", signal.name, signal.product,
            signal.signatureID, signal.signalID,
        ] {
            let value = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
            if !value.isEmpty { return value }
        }
        return "(unknown)"
    }

    static func displayVendor(_ signal: AISignal) -> String {
        let vendor = trimmed(signal.vendor).nonEmpty ?? trimmed(signal.category).nonEmpty ?? "-"
        var label = signal.version.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty
            .map { "\(vendor) \($0)" } ?? vendor
        if let connector = trimmed(signal.supportedConnector).nonEmpty {
            label += " (\(connector))"
        }
        if let model = signal.model {
            let details = [trimmed(model.status), trimmed(model.format)].filter { !$0.isEmpty }
            if !details.isEmpty { label += " (\(details.joined(separator: ", ")))" }
        }
        return label
    }

    static func rowID(_ signal: AISignal) -> String {
        let identity = key(for: signal)
        return [identity.kind, identity.value]
            .map { "\($0.utf8.count):\($0)" }
            .joined()
    }

    private static func stateRank(_ state: String) -> Int {
        switch trimmed(state).lowercased() {
        case "new": 0
        case "changed": 1
        case "active", "": 2
        case "gone": 3
        default: 4
        }
    }

    private static func formatScanAge(_ date: Date, now: Date) -> String {
        let delta = now.timeIntervalSince(date)
        guard delta.isFinite else { return "-" }
        if delta < 0 { return "now" }
        guard let seconds = DCSafeNumbers.intTruncating(delta) else { return "-" }
        if seconds < 60 { return "\(seconds)s ago" }
        let minutes = seconds / 60
        if minutes < 60 { return "\(minutes)m ago" }
        let hours = minutes / 60
        if hours < 24 { return "\(hours)h ago" }
        return "\(hours / 24)d ago"
    }

    private static func key(for signal: AISignal) -> OverviewKey {
        if let connector = trimmed(signal.supportedConnector).nonEmpty {
            return OverviewKey(kind: "connector", value: connector.lowercased())
        }
        let ecosystem = trimmed(signal.ecosystem).lowercased()
        let component = trimmed(signal.componentName).lowercased()
        if !ecosystem.isEmpty || !component.isEmpty {
            return OverviewKey(kind: "component", value: identityValue([ecosystem, component]))
        }
        if let model = signal.model, let modelID = trimmed(model.id).nonEmpty {
            let provider = trimmed(model.provider).nonEmpty ?? trimmed(signal.vendor)
            return OverviewKey(
                kind: "model",
                value: identityValue([provider.lowercased(), modelID.lowercased()])
            )
        }
        return OverviewKey(
            kind: "display",
            value: identityValue([
                displayVendor(signal).lowercased(),
                displayName(signal).lowercased(),
            ])
        )
    }

    private static func identityValue(_ fields: [String]) -> String {
        fields.map { "\($0.utf8.count):\($0)" }.joined()
    }

    private static func trimmed(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

}

extension AIDiscoveryGrouping {

    /// Collapse case variants of the same local-model ID across file, API, and
    /// runtime detectors, surfacing the most actionable lifecycle state.
    static func modelRows(from signals: [AISignal]) -> [AIModelDiscoveryRow] {
        var groups: [AIModelDiscoveryRowID: AIModelDiscoveryRow] = [:]
        var order: [AIModelDiscoveryRowID] = []
        for signal in signals {
            guard signal.category == "local_model",
                  let model = signal.model
            else { continue }
            let modelID = model.id.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !modelID.isEmpty else { continue }
            let key = AIModelDiscoveryRowID(
                normalizedModelID: normalizedModelID(modelID)
            )
            var row = groups[key] ?? AIModelDiscoveryRow(
                state: signal.state,
                modelID: modelID,
                statuses: [], formats: [], providers: [], products: [], vendors: [], detectors: [],
                count: 0, provenance: nil, lastActive: nil, signals: []
            )
            if groups[key] == nil { order.append(key) }
            if stateWeight(signal.state) < stateWeight(row.state) {
                row.state = signal.state
            }
            row.count += 1
            row.signals.append(signal)
            appendUnique(model.status, to: &row.statuses)
            appendUnique(model.format, to: &row.formats)
            appendUnique(model.provider, to: &row.providers)
            appendUnique(signal.product, to: &row.products)
            appendUnique(signal.vendor, to: &row.vendors)
            appendUnique(signal.detector, to: &row.detectors)
            if prefersModelProvenance(model.provenance, over: row.provenance) {
                let provenance = model.provenance
                row.provenance = provenance
            }
            if let active = signal.lastActive, row.lastActive.map({ active > $0 }) ?? true {
                row.lastActive = active
            }
            groups[key] = row
        }
        return order.compactMap { groups[$0] }.sorted {
            (stateWeight($0.state), normalizedModelID($0.modelID))
                < (stateWeight($1.state), normalizedModelID($1.modelID))
        }
    }

    static func normalizedModelID(_ value: String) -> String {
        value.folding(
            options: [.caseInsensitive],
            locale: Locale(identifier: "en_US_POSIX")
        ).lowercased()
    }

    private static func appendUnique(_ value: String, to values: inout [String]) {
        guard !value.isEmpty, !values.contains(value) else { return }
        values.append(value)
    }

    private static func prefersModelProvenance(
        _ candidate: AIModelProvenance?,
        over current: AIModelProvenance?
    ) -> Bool {
        guard let candidate else { return false }
        guard let current else { return true }
        let confidenceRank = ["low": 1, "medium": 2, "high": 3]
        func score(_ provenance: AIModelProvenance) -> (Int, Int) {
            let populated = [
                !provenance.publisher.isEmpty,
                !provenance.countryCode.isEmpty,
                !provenance.rootModel.isEmpty,
                !provenance.baseModels.isEmpty,
                !provenance.quantization.isEmpty,
                !provenance.derivation.isEmpty,
                !provenance.source.isEmpty,
            ].filter { $0 }.count
            return (confidenceRank[provenance.confidence.lowercased(), default: 0], populated)
        }
        return score(candidate) > score(current)
    }
}

// MARK: - Inventory

enum InventoryCategory: String, CaseIterable, Identifiable {
    case agents = "Agents", mcps = "MCPs", plugins = "Plugins",
         skills = "Skills", tools = "Tools", memories = "Memories", providers = "Models"
    var id: String { rawValue }
}

struct InventoryField: Identifiable, Sendable, Hashable {
    var label: String
    var value: String
    var id: String { label }
}

struct InventoryItem: Identifiable, Sendable {
    var category: InventoryCategory
    var name: String
    var version: String
    var path: String
    var detail: String
    var connector: String = ""
    var verdict: String = ""   // aibom policy_verdict (rejected/approved/unscanned/…)
    var status: String = ""
    var fields: [InventoryField] = []
    var id: String { "\(category.rawValue)/\(connector)/\(name)/\(path)" }
}

struct InventoryConnectorSummary: Identifiable, Sendable {
    var connector: String
    var version: String
    var generatedAt: String
    var home: String
    var config: String
    var live: Bool
    var errors: Int
    var counts: [InventoryCategory: Int]
    var id: String { connector.isEmpty ? "default" : connector }

    var total: Int { counts.values.reduce(0, +) }
}

// MARK: - Registries

struct RegistrySource: Identifiable, Sendable, Hashable {
    var id: String
    var kind: String
    var content: String
    var url: String
    var authEnv: String
    var enabled: Bool
    var autoSync: Bool
    var syncIntervalHours: Int
    var lastSync: String
    var lastStatus: String
    var fetchedAt: String = ""
    var publisher: String = ""
    var entryCount: Int = 0
    var cleanCount: Int = 0
    var warningCount: Int = 0
    var blockedCount: Int = 0
    var errorCount: Int = 0
    var indexError: String?
}

struct RegistryEntry: Identifiable, Sendable, Hashable {
    var sourceID: String
    var type: String
    var name: String
    var status: String
    var severity: String
    var findings: Int
    var approved: Bool
    var rejected: Bool
    var transport: String
    var command: String
    var arguments: [String]
    var url: String
    var sourceURL: String

    var id: String { "\(sourceID)/\(type)/\(name)/\(location)" }

    var approvalMarker: String {
        if approved { return "Approved" }
        if rejected { return "Rejected" }
        return "Unreviewed"
    }

    var location: String {
        if !url.isEmpty { return url }
        if !command.isEmpty { return command }
        return sourceURL
    }
}

struct RegistrySnapshot: Sendable {
    var sources: [RegistrySource] = []
    var entries: [RegistryEntry] = []
}

// MARK: - Doctor

struct DoctorCheck: Identifiable, Sendable {
    enum Result: String { case pass, warn, fail }
    var name: String
    var result: Result
    var detail: String
    var id: String { name }
}

// MARK: - Gateway errors

enum GatewayError: LocalizedError {
    case offline
    case unauthorized
    case degraded(status: Int, body: String)
    case timeout
    case badResponse(String)

    var errorDescription: String? {
        switch self {
        case .offline: "Gateway unreachable — is the DefenseClaw gateway running?"
        case .unauthorized: "Gateway token rejected. The token in config.yaml may have been rotated."
        case .degraded(let status, _):
            status == 502
                ? "The gateway could not reach the connector agent (HTTP 502). Skill and tool catalogs need a running OpenClaw agent."
                : "Gateway error (HTTP \(status))."
        case .timeout: "Gateway request timed out."
        case .badResponse(let why): "Unexpected gateway response: \(why)"
        }
    }
}

// MARK: - Shared helpers

enum ConnectorAttribution {
    /// Extract the `connector=<name>` value from an audit event's kv details
    /// (matches the TUI's parse_kv_details(...).get("connector")).
    static func fromDetails(_ details: String) -> String {
        guard let range = details.range(of: "connector=") else { return "" }
        return String(details[range.upperBound...].prefix { !$0.isWhitespace && $0 != "," })
    }

    /// Hook scan targets are "<connector>:<event>" (e.g. "claudecode:PostToolUse"),
    /// so the connector is the prefix before the first colon. Filesystem-path
    /// targets ("/Users/…") and URLs are connector-agnostic and return "".
    static func fromTarget(_ target: String) -> String {
        guard !target.contains("/"), let colon = target.firstIndex(of: ":") else { return "" }
        let prefix = String(target[..<colon])
        // A bare connector token: letters/digits/_/- only (rules out schemes
        // and hosts, which carry dots or aren't followed by an event name).
        guard !prefix.isEmpty,
              prefix.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" })
        else { return "" }
        return prefix
    }
}

enum ActiveConnectorRoster {
    /// Configured names lead, then live list entries, then the singular health
    /// primary connector. Matching is case-insensitive while preserving the
    /// spelling and order of the first occurrence.
    static func names(
        configured: [String],
        legacy: String?,
        live: [String],
        primary: String?
    ) -> [String] {
        var names = configured
        if names.isEmpty, let legacy = legacy?.nonEmpty {
            names.append(legacy)
        }

        var seen = Set(names.map { $0.lowercased() })
        for candidate in live + [primary].compactMap({ $0 }) {
            guard !candidate.isEmpty,
                  seen.insert(candidate.lowercased()).inserted else { continue }
            names.append(candidate)
        }
        return names
    }
}

enum DCDates {
    static let iso: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()
    static let isoNoFrac: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    static func parse(_ raw: Any?) -> Date? {
        if let s = raw as? String {
            return iso.date(from: s) ?? isoNoFrac.date(from: s)
        }
        if let n = raw as? Double {
            guard n.isFinite else { return nil }
            // Heuristic: epoch seconds vs milliseconds.
            return Date(timeIntervalSince1970: n > 1e12 ? n / 1000 : n)
        }
        if let n = raw as? Int {
            return parse(Double(n))
        }
        return nil
    }

    static func relative(_ date: Date?) -> String {
        guard let date else { return "never" }
        if abs(date.timeIntervalSinceNow) < 2 { return "just now" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .abbreviated
        return f.localizedString(for: date, relativeTo: Date())
    }
}

extension Date {
    /// TUI STALENESS_WINDOW = 15 minutes.
    var isStale: Bool { Date().timeIntervalSince(self) > 15 * 60 }
}
