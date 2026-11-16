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

// Read-only policy and monitoring projections. No credentials or raw documents
// are retained; unknown fields are displayed through bounded redacted rows.
import Foundation
import CoreFoundation

struct SandboxInspectionTarget: Equatable, Sendable {
    let sandbox: String
    let gateway: String
    let workspace: String

    static func validName(_ value: String) -> Bool {
        !value.isEmpty && value.count <= 160 && value.first != "-"
            && value.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) || "-_.".unicodeScalars.contains($0) }
    }
    var valid: Bool { Self.validName(sandbox) && Self.validName(gateway) && Self.validName(workspace) }
    var openShellArguments: [String] { ["--gateway", gateway, "--workspace", workspace, "--color", "never"] }
}

struct SandboxInspectionField: Identifiable, Equatable, Sendable {
    var key: String
    var value: String
    var source = ""
    var id: String { key }
}

struct SandboxPolicyDocument: Sendable {
    var fields: [SandboxInspectionField]
    var version: Int?
    var activeVersion: Int?
    var status: String
    var source: String
    var scope: String
    var hash: String

    var enforcement: String {
        guard !status.isEmpty else { return "Unverified: no enforcement status returned" }
        let state = status.lowercased()
        if state.contains("reject") || state.contains("fail") { return "Rejected (\(status))" }
        if state.contains("pending") { return "Pending" }
        if state == "effective", let version, let activeVersion, version == activeVersion {
            return "Applied: revision \(version)"
        }
        return "Reported status: \(status); active revision \(activeVersion.map(String.init) ?? "unavailable")"
    }
}

struct SandboxPolicyRevision: Identifiable, Sendable {
    var version: Int
    var status: String
    var created: Date?
    var loaded: Date?
    var hash: String
    var id: Int { version }
}

struct SandboxPolicyHistory: Sendable {
    var revisions: [SandboxPolicyRevision]
    var nextPageToken: String
}

struct SandboxDestination: Identifiable, Sendable {
    var host: String
    var fields: [SandboxInspectionField]
    var id: String { fields.first?.key ?? host }
}

struct SandboxInspectionEvent: Identifiable, Equatable, Sendable {
    var id: String
    var time: Date?
    var source: String
    var severity: String
    var decision: String
    var message: String
    var host: String = ""
    var rule: String = ""

    static func activity(_ event: SandboxActivity) -> Self {
        let message = SandboxInspectionDecoding.safe(event.summary)
        return Self(id: "dc|" + event.id, time: event.time, source: "DefenseClaw",
                    severity: level(event.severity.isEmpty ? event.kind + " " + event.reason + " " + message : event.severity),
                    decision: decision(event.kind), message: message,
                    host: SandboxInspectionDecoding.safe(event.host), rule: SandboxInspectionDecoding.safe(event.rule))
    }

    static func level(_ text: String) -> String {
        let s = text.lowercased()
        if ["error", "fatal", "crit", "high", "failed", "failure"].contains(where: s.contains) { return "Error" }
        if ["warn", "med", "denied", "block", "finding"].contains(where: s.contains) { return "Warning" }
        return "Info"
    }
    static func decision(_ text: String) -> String {
        let s = text.lowercased()
        if s.contains("unblocked") { return "Unblocked" }
        if s.contains("blocked") || s.contains("denied") || s.contains("reject") { return "Blocked" }
        if s.contains("allowed") || s.contains("approved") || s.contains("egress.allowed") { return "Allowed" }
        return "Other"
    }

    func matches(query: String, source filterSource: String, severity filterSeverity: String,
                 decision filterDecision: String, since: Date?) -> Bool {
        (filterSource == "All" || source == filterSource)
            && (filterSeverity == "All" || severity == filterSeverity)
            && (filterDecision == "All" || decision == filterDecision)
            && (since == nil || time.map { $0 >= since! } == true)
            && (query.isEmpty || (message + " " + host + " " + rule).localizedCaseInsensitiveContains(query))
    }
}

enum SandboxInspectionError: LocalizedError {
    case invalid(String)
    var errorDescription: String? { if case .invalid(let text) = self { return text }; return nil }
}

enum SandboxDiagnosticsExport {
    static func data(target: SandboxInspectionTarget, events: [SandboxInspectionEvent],
                     sandboxLogStatus: String, gatewayLogStatus: String, date: Date = Date()) throws -> Data {
        let iso = ISO8601DateFormatter()
        let safe = { SandboxInspectionDecoding.safe($0) }
        let object: [String: Any] = [
            "sandbox": safe(target.sandbox), "gateway": safe(target.gateway), "workspace": safe(target.workspace),
            "exported_at": iso.string(from: date),
            "coverage": "Bounded display projection, not complete audit history. Secrets and payloads are omitted where recognized.",
            "sandbox_logs": safe(sandboxLogStatus), "gateway_logs": safe(gatewayLogStatus),
            "events": events.map { event in [
                "time": event.time.map { iso.string(from: $0) } ?? "unknown", "source": safe(event.source),
                "severity": safe(event.severity), "decision": safe(event.decision), "message": safe(event.message),
                "host": safe(event.host), "rule": safe(event.rule)
            ] }
        ]
        return try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    }
}

enum SandboxInspectionDecoding {
    static func safe(_ value: String, limit: Int = 2048) -> String {
        var text = value.replacingOccurrences(of: #"\u001B\[[0-?]*[ -/]*[@-~]"#, with: "", options: .regularExpression)
        // Logs are untrusted: omit payload-bearing lines, private keys, and
        // environment/command dumps instead of trying to enumerate their secrets.
        if text.range(of: #"(?i)(BEGIN .{0,20}PRIVATE KEY|request[_ ]?body|response[_ ]?body|\bprompt\s*[=:]|\benv(?:ironment)?\s*[=:]|\bcredentials?\s*[=:])"#, options: .regularExpression) != nil {
            return "[sensitive diagnostic omitted]"
        }
        text = text.replacingOccurrences(of: #"(?i)([\"']?(?:authorization|cookie|set-cookie|api[_-]?key|password|secret|access[_-]?token|refresh[_-]?token|token)[\"']?\s*[:=]\s*)("(?:\\.|[^"\\])*(?:"|$)|'(?:\\.|[^'\\])*(?:'|$)|[^\s,;]+)"#, with: "$1[redacted]", options: .regularExpression)
        text = text.replacingOccurrences(of: #"(?i)(https?://)[^/\s@]+@"#, with: "$1[redacted]@", options: .regularExpression)
        text = text.replacingOccurrences(of: #"(https?://[^\s?#]+)[?#][^\s]*"#, with: "$1?[redacted]", options: .regularExpression)
        return DisplayRedaction.text(text, limit: limit)
    }

    static func object(_ text: String) throws -> [String: Any] {
        guard text.utf8.count <= 1_048_576, let data = text.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw SandboxInspectionError.invalid("The command did not return a supported JSON response.")
        }
        return object
    }

    static func fields(_ value: Any, prefix: String = "", depth: Int = 0) -> [SandboxInspectionField] {
        guard depth < 12 else { return [.init(key: prefix, value: "[nested fields omitted]")] }
        if let dict = value as? [String: Any] {
            return Array(dict.keys.sorted().prefix(300).flatMap { key -> [SandboxInspectionField] in
                let path = prefix.isEmpty ? key : prefix + "." + key
                if DisplayRedaction.isSensitiveKey(key) || ["env", "environment", "credentials", "command_line"].contains(key.lowercased()) {
                    return [.init(key: safe(path), value: "[redacted]")]
                }
                return fields(dict[key]!, prefix: path, depth: depth + 1)
            }.prefix(600))
        }
        if let values = value as? [Any] {
            if values.isEmpty { return [.init(key: safe(prefix), value: "[]")] }
            return Array(values.prefix(100).enumerated().flatMap { index, item in
                fields(item, prefix: "\(prefix)[\(index)]", depth: depth + 1)
            }.prefix(600))
        }
        if let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() {
            return [.init(key: safe(prefix), value: number.boolValue ? "true" : "false")]
        }
        return [.init(key: safe(prefix), value: safe(String(describing: value)))]
    }

    static func defensePolicy(_ text: String) throws -> [SandboxInspectionField] {
        let obj = try object(text)
        guard obj["pack"] is String, let settings = obj["settings"] as? [[String: Any]] else {
            throw SandboxInspectionError.invalid("Resolved DefenseClaw policy is unavailable in this runtime response.")
        }
        var rows = fields(obj.filter { ["pack", "pack_source", "pack_digest", "profile", "network_mode", "approvals", "admin", "workspace", "violations"].contains($0.key) })
        rows += settings.prefix(400).enumerated().map { index, row in
            let key = row["key"] as? String ?? "setting \(index)"
            return SandboxInspectionField(key: "settings[\(index)]." + safe(key),
                value: DisplayRedaction.isSensitiveKey(key) ? "[redacted]" : safe(row["value"] as? String ?? "Unavailable"),
                source: safe([row["source"], row["origin"]].compactMap { $0 as? String }.joined(separator: " · ")))
        }
        return rows
    }

    static func policy(_ text: String, sandbox: String, global: Bool = false) throws -> SandboxPolicyDocument {
        let obj = try object(text)
        guard let policy = obj["policy"] as? [String: Any], !policy.isEmpty,
              global ? obj["scope"] as? String == "global" : obj["sandbox"] as? String == sandbox else {
            throw SandboxInspectionError.invalid("No matching policy document was returned for this scope.")
        }
        return SandboxPolicyDocument(fields: fields(policy), version: obj["version"] as? Int,
            activeVersion: obj["active_version"] as? Int, status: safe(obj["status"] as? String ?? ""),
            source: safe(obj["policy_source"] as? String ?? "Unavailable"), scope: safe(obj["scope"] as? String ?? "Unavailable"),
            hash: safe(obj["hash"] as? String ?? "Unavailable"))
    }

    static func history(_ text: String, sandbox: String) throws -> SandboxPolicyHistory {
        let obj = try object(text)
        guard let rows = obj["revisions"] as? [[String: Any]] else {
            throw SandboxInspectionError.invalid("Policy history is unavailable in this OpenShell response.")
        }
        var seen = Set<Int>()
        let revisions = try rows.prefix(100).map { row -> SandboxPolicyRevision in
            guard row["sandbox"] as? String == sandbox, let version = row["version"] as? Int,
                  version > 0, seen.insert(version).inserted else {
                throw SandboxInspectionError.invalid("Policy history contained an invalid or mismatched revision.")
            }
            func date(_ key: String) -> Date? {
                guard let ms = row[key] as? Double, ms > 0 else { return nil }
                return Date(timeIntervalSince1970: ms / 1000)
            }
            return .init(version: version, status: safe(row["status"] as? String ?? "Unavailable"),
                         created: date("created_at_ms"), loaded: date("loaded_at_ms"), hash: safe(row["hash"] as? String ?? "Unavailable"))
        }
        let token = obj["next_page_token"] as? String ?? ""
        guard token.utf8.count <= 4096 else { throw SandboxInspectionError.invalid("Invalid history continuation token.") }
        return .init(revisions: revisions, nextPageToken: token)
    }

    static func destinations(_ text: String, sandbox: String) throws -> [SandboxDestination] {
        let obj = try object(text)
        guard obj["name"] as? String == sandbox, let rows = obj["destinations"] as? [[String: Any]] else {
            throw SandboxInspectionError.invalid("No matching destination list was returned.")
        }
        return try rows.prefix(500).enumerated().map { index, row in
            guard let host = row["host"] as? String, !host.isEmpty else {
                throw SandboxInspectionError.invalid("Destination response has no host.")
            }
            return .init(host: safe(host), fields: fields(row, prefix: "destination[\(index)]"))
        }
    }

    static func difference(_ old: [SandboxInspectionField], _ new: [SandboxInspectionField]) -> [SandboxInspectionField] {
        let a = Dictionary(old.map { ($0.key, $0.value) }, uniquingKeysWith: { _, last in last })
        let b = Dictionary(new.map { ($0.key, $0.value) }, uniquingKeysWith: { _, last in last })
        return Set(a.keys).union(b.keys).sorted().compactMap { key in
            guard a[key] != b[key] else { return nil }
            return .init(key: key, value: "\(a[key] ?? "[absent]") → \(b[key] ?? "[absent]")")
        }
    }

    static func logs(_ text: String, source: String) -> [SandboxInspectionEvent] {
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let sanitizedBlocks = text.replacingOccurrences(of: #"(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)"#, with: "[private key omitted]", options: .regularExpression)
        return sanitizedBlocks.split(separator: "\n").suffix(200).enumerated().compactMap { index, raw in
            if let data = String(raw).data(using: .utf8), let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                // OCSF JSON is projected through an allowlist; bodies, command
                // lines, credentials and unknown payloads never reach the view.
                let values = object.filter { ["class_name", "activity_name", "status", "status_detail", "severity"].contains($0.key) }
                let message = fields(values).map { "\($0.key): \($0.value)" }.joined(separator: " · ")
                let timestamp = (object["time"] as? Double).map { Date(timeIntervalSince1970: $0 / 1000) }
                let endpoint = object["dst_endpoint"] as? [String: Any] ?? [:]
                let host = safe(endpoint["hostname"] as? String ?? "")
                let level = object["severity"] as? String ?? ""
                let severityID = object["severity_id"] as? Int ?? 0
                return .init(id: "\(source)|\(index)|\(message)", time: timestamp, source: source,
                    severity: severityID >= 4 ? "Error" : severityID == 3 ? "Warning" : SandboxInspectionEvent.level(level),
                    decision: SandboxInspectionEvent.decision(object["status"] as? String ?? ""),
                    message: message.isEmpty ? "[unrecognized structured event omitted]" : message, host: host)
            }
            let line = safe(String(raw), limit: 4096)
            // CLI warnings are coverage information, not sandbox events.
            guard !line.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
            let prefix = line.split(separator: " ").first.map(String.init) ?? ""
            let epoch = prefix.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            let date = Double(epoch).map { Date(timeIntervalSince1970: $0) } ?? iso.date(from: prefix) ?? ISO8601DateFormatter().date(from: prefix)
            func capture(_ pattern: String) -> String {
                guard let regex = try? NSRegularExpression(pattern: pattern),
                      let match = regex.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)),
                      let range = Range(match.range(at: 1), in: line) else { return "" }
                return String(line[range])
            }
            let endpoint = capture(#"->\s+([^\s\[]+)"#)
            let host = URLComponents(string: "https://" + endpoint)?.host ?? ""
            let rule = capture(#"\[policy:([^\s\]]+)"#)
            let disposition = capture(#"(?i)\b(ALLOWED|DENIED|BLOCKED|UNBLOCKED)\b"#)
            let explicitLevel = capture(#"(?i)\[(ERROR|WARN|INFO|HIGH|MED|LOW|CRIT|FATAL|DEBUG|TRACE)\s*\]"#)
            return .init(id: "\(source)|\(index)|\(line)", time: date, source: source,
                         severity: SandboxInspectionEvent.level(explicitLevel.isEmpty ? disposition : explicitLevel), decision: SandboxInspectionEvent.decision(disposition), message: line,
                         host: safe(host), rule: rule == "-" ? "" : safe(rule))
        }
    }
}
