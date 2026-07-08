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

// Read-only access to ~/.defenseclaw/audit.db via the SDK's SQLite3 module.
// The gateway owns all writes; this store never opens the DB writable.
// Schema-tolerant: missing tables/columns degrade features, never crash.

import Foundation
import SQLite3

private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

actor AuditStore {
    private var db: OpaquePointer?
    private let path: String

    init(url: URL = ConfigStore.auditDBURL) {
        self.path = url.path
    }

    var isAvailable: Bool {
        ensureOpen()
        return db != nil
    }

    private func ensureOpen() {
        guard db == nil else { return }
        guard FileManager.default.fileExists(atPath: path) else { return }
        var handle: OpaquePointer?
        // Read-only; gateway writes via WAL so allow shared access.
        if sqlite3_open_v2(path, &handle, SQLITE_OPEN_READONLY, nil) == SQLITE_OK {
            db = handle
            sqlite3_busy_timeout(db, 500)
        } else {
            sqlite3_close(handle)
        }
    }

    private func tableExists(_ name: String) -> Bool {
        ensureOpen()
        guard db != nil else { return false }
        let rows = query("SELECT name FROM sqlite_master WHERE type='table' AND name=?", binds: [name])
        return !rows.isEmpty
    }

    /// Runs a query, returning rows as [column: value] dictionaries.
    private func query(_ sql: String, binds: [Any] = []) -> [[String: Any]] {
        ensureOpen()
        guard let db else { return [] }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }

        for (i, bind) in binds.enumerated() {
            let idx = Int32(i + 1)
            switch bind {
            case let v as String: sqlite3_bind_text(stmt, idx, v, -1, SQLITE_TRANSIENT)
            case let v as Int: sqlite3_bind_int64(stmt, idx, Int64(v))
            case let v as Double: sqlite3_bind_double(stmt, idx, v)
            default: sqlite3_bind_null(stmt, idx)
            }
        }

        var rows: [[String: Any]] = []
        var attempts = 0
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_ROW {
                var row: [String: Any] = [:]
                for col in 0..<sqlite3_column_count(stmt) {
                    let name = String(cString: sqlite3_column_name(stmt, col))
                    switch sqlite3_column_type(stmt, col) {
                    case SQLITE_INTEGER: row[name] = Int(sqlite3_column_int64(stmt, col))
                    case SQLITE_FLOAT: row[name] = sqlite3_column_double(stmt, col)
                    case SQLITE_TEXT:
                        if let text = sqlite3_column_text(stmt, col) { row[name] = String(cString: text) }
                    default: break
                    }
                }
                rows.append(row)
            } else if rc == SQLITE_BUSY && attempts < 5 {
                attempts += 1
                usleep(50_000)
                continue
            } else {
                break
            }
        }
        return rows
    }

    private func decodeAuditEvent(_ r: [String: Any]) -> AuditEvent {
        let details = (r["details"] as? String) ?? ""
        let target = (r["target"] as? String) ?? ""
        // Connector attribution: the `connector=` kv in details (the TUI's
        // parse_kv_details), else the "<connector>:<event>" target prefix —
        // not the actor, which is the hook name.
        let connector = {
            let kv = ConnectorAttribution.fromDetails(details)
            return kv.isEmpty ? ConnectorAttribution.fromTarget(target) : kv
        }()
        return AuditEvent(
            id: (r["id"] as? String) ?? String(describing: r["id"] ?? UUID().uuidString),
            timestamp: DCDates.parse(r["timestamp"]) ?? Date(timeIntervalSince1970: 0),
            action: (r["action"] as? String) ?? "",
            eventType: (r["event_type"] as? String) ?? (r["type"] as? String) ?? "audit",
            connector: connector.isEmpty ? ((r["connector"] as? String) ?? "") : connector,
            target: target,
            actor: (r["actor"] as? String) ?? "",
            details: details,
            structuredJSON: (r["structured_json"] as? String) ?? "",
            severity: Severity.parse(r["severity"] as? String),
            runID: (r["run_id"] as? String) ?? ""
        )
    }

    // MARK: - Queries used by panels

    func recentEvents(limit: Int, offset: Int = 0, search: String? = nil,
                      severities: [Severity]? = nil, actionLike: [String]? = nil) -> [AuditEvent] {
        guard tableExists("audit_events") else { return [] }
        var sql = "SELECT * FROM audit_events"
        var conds: [String] = []
        var binds: [Any] = []
        if let search, !search.isEmpty {
            conds.append("(action LIKE ? OR target LIKE ? OR details LIKE ?)")
            let like = "%\(search)%"
            binds.append(contentsOf: [like, like, like])
        }
        if let severities, !severities.isEmpty {
            conds.append("UPPER(severity) IN (\(severities.map { _ in "?" }.joined(separator: ",")))")
            binds.append(contentsOf: severities.map(\.rawValue))
        }
        if let actionLike, !actionLike.isEmpty {
            conds.append("(" + actionLike.map { _ in "(action LIKE ? OR details LIKE ?)" }.joined(separator: " OR ") + ")")
            for pattern in actionLike {
                let like = "%\(pattern)%"
                binds.append(contentsOf: [like, like])
            }
        }
        if !conds.isEmpty { sql += " WHERE " + conds.joined(separator: " AND ") }
        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        binds.append(contentsOf: [limit, offset])
        return query(sql, binds: binds).map(decodeAuditEvent)
    }

    func blockClassEvents(limit: Int) -> [AuditEvent] {
        recentEvents(limit: limit, actionLike: ["block", "reject", "quarantine", "enforce"])
    }

    func relatedEvents(target: String? = nil, runID: String? = nil, limit: Int = 20) -> [AuditEvent] {
        guard tableExists("audit_events") else { return [] }
        var conditions: [String] = []
        var binds: [Any] = []
        if let target, !target.isEmpty {
            conditions.append("target = ?")
            binds.append(target)
        }
        if let runID, !runID.isEmpty {
            conditions.append("run_id = ?")
            binds.append(runID)
        }
        guard !conditions.isEmpty else { return [] }
        binds.append(limit)
        return query(
            "SELECT * FROM audit_events WHERE \(conditions.joined(separator: " AND ")) ORDER BY timestamp DESC LIMIT ?",
            binds: binds
        ).map(decodeAuditEvent)
    }

    func scanFindings(runID: String? = nil, target: String? = nil, limit: Int = 20) -> [ScanFindingEvent] {
        guard tableExists("scan_results") else { return [] }
        var conditions = ["raw_json IS NOT NULL", "raw_json != ''"]
        var binds: [Any] = []
        if let runID, !runID.isEmpty {
            conditions.append("run_id = ?")
            binds.append(runID)
        } else if let target, !target.isEmpty {
            conditions.append("target = ?")
            binds.append(target)
        }
        binds.append(limit)
        let rows = query(
            "SELECT * FROM scan_results WHERE \(conditions.joined(separator: " AND ")) ORDER BY timestamp DESC LIMIT ?",
            binds: binds
        )
        return rows.flatMap { row -> [ScanFindingEvent] in
            guard let raw = row["raw_json"] as? String,
                  let data = raw.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let findings = object["findings"] as? [[String: Any]]
            else { return [] }
            let scanID = (row["id"] as? String) ?? UUID().uuidString
            let timestamp = DCDates.parse(row["timestamp"]) ?? .distantPast
            let scanner = (row["scanner"] as? String) ?? ""
            let scanTarget = (row["target"] as? String) ?? ""
            let eventRunID = (row["run_id"] as? String) ?? ""
            return findings.enumerated().map { index, finding in
                ScanFindingEvent(
                    id: "\(scanID)-\((finding["id"] as? String) ?? String(index))",
                    timestamp: timestamp,
                    scanner: (finding["scanner"] as? String) ?? scanner,
                    target: scanTarget,
                    title: (finding["title"] as? String) ?? "Finding \(index + 1)",
                    detail: (finding["description"] as? String) ?? "",
                    location: (finding["location"] as? String) ?? "",
                    remediation: (finding["remediation"] as? String) ?? "",
                    severity: Severity.parse(finding["severity"] as? String),
                    runID: eventRunID,
                    connector: (object["connector"] as? String) ?? ""
                )
            }
        }
    }

    /// The TUI's alert queue: db.py::list_alerts(500) loads the last 500
    /// non-ACK rows of ANY listed severity, and the panel then counts only
    /// the CRITICAL/HIGH/MEDIUM/LOW buckets in memory. Older severity-bearing
    /// rows that scrolled out of the 500-row window do NOT count — replicate
    /// that exactly: window first, filter second.
    func alertQueueEvents(limit: Int = 500) -> [AuditEvent] {
        guard tableExists("audit_events") else { return [] }
        let rows = query("""
            SELECT * FROM audit_events
            WHERE UPPER(severity) IN ('CRITICAL','HIGH','MEDIUM','LOW','WARNING','ERROR','INFO')
              AND action NOT LIKE 'dismiss%'
            ORDER BY timestamp DESC LIMIT ?
            """, binds: [limit])
        return rows.map(decodeAuditEvent)
            .filter { $0.severity != .info } // bucket filter: C/H/M/L only (WARNING→MEDIUM)
    }

    /// db.py::get_counts — Overview ENFORCEMENT summary.
    func enforcementSummary() -> (blockedSkills: Int, allowedSkills: Int, blockedMCPs: Int, allowedMCPs: Int, totalScans: Int, activeAlerts: Int) {
        func count(_ sql: String) -> Int {
            (query(sql).first?["n"] as? Int) ?? 0
        }
        let qSkill = "SELECT COUNT(*) AS n FROM actions WHERE target_type='skill' AND json_extract(actions_json,'$.install')="
        let qMCP = "SELECT COUNT(*) AS n FROM actions WHERE target_type='mcp' AND json_extract(actions_json,'$.install')="
        let hasActions = tableExists("actions")
        let hasScans = tableExists("scan_results")
        let hasAudit = tableExists("audit_events")
        return (
            blockedSkills: hasActions ? count(qSkill + "'block'") : 0,
            allowedSkills: hasActions ? count(qSkill + "'allow'") : 0,
            blockedMCPs: hasActions ? count(qMCP + "'block'") : 0,
            allowedMCPs: hasActions ? count(qMCP + "'allow'") : 0,
            totalScans: hasScans ? count("SELECT COUNT(*) AS n FROM scan_results") : 0,
            activeAlerts: hasAudit ? count("SELECT COUNT(*) AS n FROM audit_events WHERE UPPER(severity) IN ('CRITICAL','HIGH','MEDIUM','LOW')") : 0
        )
    }

    /// db.py::connector_hook_event_stats — ALL-TIME per-connector totals for
    /// the Connectors table's no-live-window fallback, so CALLS doesn't
    /// freeze at the recent-window size (the TUI calls this out explicitly).
    /// Requires the audit_events.connector column (schema v7+); returns [:]
    /// on older schemas and callers fall back to the windowed stats.
    func connectorStatsAllTime() -> [String: ConnectorStats] {
        guard tableExists("audit_events") else { return [:] }
        let rows = query("""
            SELECT connector, COUNT(*) AS calls,
                   SUM(CASE WHEN ' '||COALESCE(details,'')||' ' LIKE '% action=block %'
                              OR ' '||COALESCE(details,'')||' ' LIKE '% action=deny %'
                       THEN 1 ELSE 0 END) AS blocks,
                   SUM(CASE WHEN ' '||COALESCE(details,'')||' ' LIKE '% action=alert %'
                              OR ' '||COALESCE(details,'')||' ' LIKE '% action=warn %'
                       THEN 1 ELSE 0 END) AS alerts,
                   MAX(timestamp) AS newest
            FROM audit_events
            WHERE action = 'connector-hook' AND connector <> ''
            GROUP BY connector
            """)
        var out: [String: ConnectorStats] = [:]
        for row in rows {
            guard let name = row["connector"] as? String, !name.isEmpty else { continue }
            let calls = (row["calls"] as? Int) ?? 0
            out[name] = ConnectorStats(
                hookCalls: calls,
                blocks: min((row["blocks"] as? Int) ?? 0, calls),
                alerts: min((row["alerts"] as? Int) ?? 0, calls),
                lastActivity: DCDates.parse(row["newest"])
            )
        }
        return out
    }

    /// db.py::count_scan_results_since — the ACTIVITY card's session-scoped
    /// "Total scans". nil since = all-time.
    func countScanResultsSince(_ since: Date?) -> Int {
        guard tableExists("scan_results") else { return 0 }
        guard let since else {
            return (query("SELECT COUNT(*) AS n FROM scan_results").first?["n"] as? Int) ?? 0
        }
        let iso = ISO8601DateFormatter().string(from: since)
        return (query(
            "SELECT COUNT(*) AS n FROM scan_results WHERE datetime(timestamp) >= datetime(?)",
            binds: [iso]
        ).first?["n"] as? Int) ?? 0
    }

    /// Connector breakdown parity with the TUI:
    /// `AuditPanelModel.refresh()` loads the latest 500 audit rows, and the
    /// hook-call tile's `_connector_hook_breakdown()` scans `items[-200:]`.
    /// The descending DB sort means that is the oldest 200 rows within the
    /// loaded 500-row window. Mirroring that keeps per-connector stats aligned
    /// with the TUI instead of showing a much larger 24h total.
    func overviewHookBreakdown(limit: Int = 500, breakdownWindow: Int = 200) -> (allow: Int, alert: Int, block: Int) {
        guard tableExists("audit_events") else { return (0, 0, 0) }
        let rows = query("""
            SELECT action, details FROM audit_events
            ORDER BY timestamp DESC, rowid DESC LIMIT ?
            """, binds: [limit])
        let window = rows.suffix(max(breakdownWindow, 1))
        var allow = 0
        var alert = 0
        var block = 0
        for row in window {
            guard ((row["action"] as? String) ?? "") == "connector-hook" else { continue }
            switch detailValue("action", in: (row["details"] as? String) ?? "").lowercased() {
            case "allow":
                allow += 1
            case "alert", "warn":
                alert += 1
            case "block", "deny":
                block += 1
            default:
                break
            }
        }
        return (allow, alert, block)
    }

    /// TUI Hook Calls tile parity: `_hook_event_timestamps()` counts every
    /// connector-hook event in the latest loaded 500 audit rows.
    func overviewHookCallCount(limit: Int = 500) -> Int {
        guard tableExists("audit_events") else { return 0 }
        let rows = query("""
            SELECT action FROM audit_events
            ORDER BY timestamp DESC, rowid DESC LIMIT ?
            """, binds: [limit])
        return rows.reduce(0) { total, row in
            total + (((row["action"] as? String) == "connector-hook") ? 1 : 0)
        }
    }

    /// TUI Blocks tile parity: `_block_event_timestamps()` scans the latest
    /// loaded 500 audit rows and treats block-class actions or hook details
    /// with `action=block|deny` as block events.
    func overviewBlockCount(limit: Int = 500) -> Int {
        guard tableExists("audit_events") else { return 0 }
        let rows = query("""
            SELECT action, details FROM audit_events
            ORDER BY timestamp DESC, rowid DESC LIMIT ?
            """, binds: [limit])
        return rows.reduce(0) { total, row in
            let action = ((row["action"] as? String) ?? "").lowercased()
            let decision = detailValue("action", in: (row["details"] as? String) ?? "").lowercased()
            let isBlock = ["block", "guardrail-block", "deny", "quarantine"].contains(action)
                || decision == "block"
                || decision == "deny"
            return total + (isBlock ? 1 : 0)
        }
    }

    /// Hourly allowed/blocked histogram for the last 24h (Overview enhancement).
    func hourlyEnforcement24h() -> [(hour: Date, action: String, count: Int)] {
        guard tableExists("audit_events") else { return [] }
        let since = DCDates.iso.string(from: Date().addingTimeInterval(-24 * 3600))
        let rows = query("""
            SELECT substr(timestamp, 1, 13) AS hour_bucket,
                   CASE WHEN action LIKE '%block%' OR action LIKE '%reject%' THEN 'blocked' ELSE 'allowed' END AS klass,
                   COUNT(*) AS n
            FROM audit_events WHERE timestamp >= ?
            GROUP BY hour_bucket, klass ORDER BY hour_bucket
            """, binds: [since])
        let hourFormat = DateFormatter()
        hourFormat.dateFormat = "yyyy-MM-dd'T'HH"
        hourFormat.timeZone = TimeZone(identifier: "UTC")
        return rows.compactMap { r in
            guard let bucket = r["hour_bucket"] as? String,
                  let date = hourFormat.date(from: bucket),
                  let klass = r["klass"] as? String,
                  let n = r["n"] as? Int else { return nil }
            return (date, klass, n)
        }
    }

    func countBySeverity(blockClassOnly: Bool) -> [Severity: Int] {
        guard tableExists("audit_events") else { return [:] }
        var sql = "SELECT UPPER(severity) AS sev, COUNT(*) AS n FROM audit_events"
        if blockClassOnly {
            sql += " WHERE action LIKE '%block%' OR action LIKE '%reject%' OR action LIKE '%quarantine%'"
        }
        sql += " GROUP BY sev"
        var out: [Severity: Int] = [:]
        for r in query(sql) {
            if let sev = r["sev"] as? String, let n = r["n"] as? Int {
                out[Severity.parse(sev)] = n
            }
        }
        return out
    }

    /// Full tool override rows (actions table) — the data the Tools panel
    /// governs. In hook mode this is the only tool surface: the catalog
    /// endpoint needs an OpenClaw agent, but overrides still enforce.
    func toolOverrideRows() -> [ToolItem] {
        guard tableExists("actions") else { return [] }
        let rows = query("""
            SELECT target_name, actions_json, reason, updated_at
            FROM actions WHERE target_type = 'tool' ORDER BY target_name
            """)
        return rows.compactMap { r in
            guard let name = r["target_name"] as? String else { return nil }
            let json = (r["actions_json"] as? String ?? "").lowercased()
            let state: ToolState = json.contains("block") ? .block
                : json.contains("observe") ? .observe : .allow
            let reason = (r["reason"] as? String) ?? ""
            let updated = (r["updated_at"] as? String) ?? ""
            return ToolItem(
                name: name,
                summary: reason.isEmpty ? "override" : reason,
                signature: updated.isEmpty ? "" : "updated \(updated)",
                state: state,
                usageCount: 0
            )
        }
    }

    /// Tool allow/block overrides from the actions table.
    func toolOverrides() -> [String: ToolState] {
        guard tableExists("actions") else { return [:] }
        let rows = query("SELECT target_name, actions_json FROM actions WHERE target_type = 'tool'")
        var out: [String: ToolState] = [:]
        for r in rows {
            guard let name = r["target_name"] as? String else { continue }
            let json = (r["actions_json"] as? String ?? "").lowercased()
            if json.contains("block") { out[name] = .block }
            else if json.contains("observe") { out[name] = .observe }
            else { out[name] = .allow }
        }
        return out
    }

    func activityEvents(limit: Int) -> [ActivityMutation] {
        guard tableExists("activity_events") else { return [] }
        return query("SELECT * FROM activity_events ORDER BY timestamp DESC LIMIT ?", binds: [limit]).map { r in
            ActivityMutation(
                id: (r["id"] as? String) ?? String(describing: r["id"] ?? UUID().uuidString),
                timestamp: DCDates.parse(r["timestamp"]) ?? Date(timeIntervalSince1970: 0),
                actor: (r["actor"] as? String) ?? "",
                action: (r["action"] as? String) ?? "",
                targetType: (r["target_type"] as? String) ?? "",
                targetID: (r["target_id"] as? String) ?? "",
                reason: (r["reason"] as? String) ?? "",
                versionFrom: (r["version_from"] as? String) ?? "",
                versionTo: (r["version_to"] as? String) ?? "",
                beforeJSON: (r["before_json"] as? String) ?? "",
                afterJSON: (r["after_json"] as? String) ?? "",
                connector: (r["connector"] as? String) ?? ConnectorAttribution.fromDetails((r["reason"] as? String) ?? "")
            )
        }
    }

    func egressEvents(limit: Int) -> [EgressEvent] {
        guard tableExists("network_egress_events") else { return [] }
        return query("SELECT * FROM network_egress_events ORDER BY timestamp DESC LIMIT ?", binds: [limit]).map { r in
            let blocked = ((r["blocked"] as? Int) ?? 0) == 1
            return EgressEvent(
                id: (r["id"] as? String) ?? String(describing: r["id"] ?? UUID().uuidString),
                timestamp: DCDates.parse(r["timestamp"]) ?? Date(timeIntervalSince1970: 0),
                target: (r["hostname"] as? String) ?? (r["url"] as? String) ?? "",
                decision: blocked ? "blocked" : ((r["policy_outcome"] as? String) ?? "allowed"),
                reason: (r["details"] as? String) ?? (r["decision_code"] as? String) ?? "",
                looksLikeLLM: false,
                branch: (r["protocol"] as? String) ?? "",
                severity: Severity.parse(r["severity"] as? String)
            )
        }
    }

    struct ConnectorStats {
        var hookCalls = 0
        var blocks = 0
        var alerts = 0
        var lastActivity: Date?
    }

    /// Per-connector activity derived from recent audit events — the TUI's
    /// fallback for hook connectors, whose calls arrive out-of-band of the
    /// gateway's request counters. Connector attribution comes from the
    /// `connector=<name>` kv token in each event's details.
    func connectorStats(window: Int = 500, breakdownWindow: Int = 200) -> [String: ConnectorStats] {
        guard tableExists("audit_events") else { return [:] }
        let rows = query("""
            SELECT action, severity, timestamp, details FROM audit_events
            ORDER BY timestamp DESC, rowid DESC LIMIT ?
            """, binds: [window])
        var stats: [String: ConnectorStats] = [:]
        for r in rows {
            let details = (r["details"] as? String) ?? ""
            let name = ConnectorAttribution.fromDetails(details)
            guard !name.isEmpty else { continue }
            var s = stats[name] ?? ConnectorStats()
            if let ts = DCDates.parse(r["timestamp"]), ts > (s.lastActivity ?? .distantPast) {
                s.lastActivity = ts
            }
            stats[name] = s
        }
        for r in rows.suffix(max(breakdownWindow, 1)) {
            let details = (r["details"] as? String) ?? ""
            let name = ConnectorAttribution.fromDetails(details)
            guard !name.isEmpty, ((r["action"] as? String) ?? "") == "connector-hook" else { continue }
            var s = stats[name] ?? ConnectorStats()
            switch detailValue("action", in: details).lowercased() {
            case "allow":
                s.hookCalls += 1
            case "alert", "warn":
                s.hookCalls += 1
                s.alerts += 1
            case "block", "deny":
                s.hookCalls += 1
                s.blocks += 1
            default:
                break
            }
            stats[name] = s
        }
        return stats
    }

    private func detailValue(_ key: String, in details: String) -> String {
        let prefix = "\(key)="
        for token in details.split(whereSeparator: { $0.isWhitespace || $0 == "," || $0 == ";" }) {
            guard token.hasPrefix(prefix) else { continue }
            return String(token.dropFirst(prefix.count))
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"'`"))
        }
        return ""
    }

    /// Newest block-class event timestamp — used for new-alert detection.
    func latestBlockTimestamp() -> Date? {
        guard tableExists("audit_events") else { return nil }
        let rows = query("""
            SELECT timestamp FROM audit_events
            WHERE action LIKE '%block%' OR action LIKE '%reject%'
            ORDER BY timestamp DESC LIMIT 1
            """)
        return DCDates.parse(rows.first?["timestamp"])
    }
}
