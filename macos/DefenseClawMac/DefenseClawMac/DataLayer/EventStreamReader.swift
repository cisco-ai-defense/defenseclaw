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

// Incremental tailer for ~/.defenseclaw/gateway.jsonl.
// Remembers byte offset, handles truncation/rotation (falls back to the last
// 512 KiB — the same budget the Go reader and TUI use), classifies rows into
// the four TUI log streams, and extracts scan findings / activity / egress rows.

import Foundation

struct StreamDelta: Sendable {
    var logRows: [LogRow] = []
    var findings: [ScanFindingEvent] = []
    var activity: [ActivityMutation] = []
    var egress: [EgressEvent] = []
}

actor EventStreamReader {
    static let tailBudget = 512 * 1024
    static let tailLineLimit = 2_000

    private let url: URL
    private let gatewayLogURL: URL
    private let watchdogLogURL: URL
    private var offset: UInt64 = 0
    private var gatewayLogOffset: UInt64 = 0
    private var watchdogLogOffset: UInt64 = 0
    private var rowCounter = 0
    private var plainLogCounter = 0

    private(set) var logBuffers: [LogStream: [LogRow]] = [:]
    private(set) var findings: [ScanFindingEvent] = []
    private(set) var activity: [ActivityMutation] = []
    private(set) var egress: [EgressEvent] = []

    /// Scan blocks grouped by scan_id — mirrors load_gateway_scan_blocks,
    /// which reads the bounded gateway.jsonl tail (512 KiB / 2,000 lines).
    private var scanBlockMap: [String: ScanBlockEvent] = [:]
    private var scanSummaryCounts: [String: Int] = [:]
    private var observedFindingCounts: [String: Int] = [:]

    var scanBlocks: [ScanBlockEvent] {
        scanBlockMap.values.sorted { $0.timestamp > $1.timestamp }
    }

    private let bufferCap = 20_000

    init(
        url: URL = ConfigStore.gatewayJSONLURL,
        gatewayLogURL: URL = ConfigStore.gatewayLogURL,
        watchdogLogURL: URL = ConfigStore.watchdogLogURL
    ) {
        self.url = url
        self.gatewayLogURL = gatewayLogURL
        self.watchdogLogURL = watchdogLogURL
    }

    /// Reload scan/scan_finding rows from the same bounded tail the TUI uses.
    /// This keeps the Findings tile current and prevents stale historical
    /// gateway.jsonl rows from inflating the live alert count.
    private func refreshScanBlocksFromTail() {
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            scanBlockMap = [:]
            scanSummaryCounts = [:]
            observedFindingCounts = [:]
            return
        }
        defer { try? handle.close() }

        let size = (try? handle.seekToEnd()) ?? 0
        let readSize = min(size, UInt64(Self.tailBudget))
        let start = size - readSize
        try? handle.seek(toOffset: start)
        guard let data = try? handle.read(upToCount: Int(readSize)), !data.isEmpty else {
            scanBlockMap = [:]
            scanSummaryCounts = [:]
            observedFindingCounts = [:]
            return
        }

        var text = String(decoding: data, as: UTF8.self)
        if start > 0 {
            if let newline = text.firstIndex(of: "\n") {
                text = String(text[text.index(after: newline)...])
            } else {
                text = ""
            }
        }

        scanBlockMap = [:]
        scanSummaryCounts = [:]
        observedFindingCounts = [:]
        for line in text.split(separator: "\n", omittingEmptySubsequences: false).suffix(Self.tailLineLimit) {
            guard line.contains("\"event_type\":\"scan") || line.contains("\"event_type\": \"scan") else { continue }
            guard let lineData = line.data(using: .utf8),
                  let obj = try? JSONSerialization.jsonObject(with: lineData) as? [String: Any]
            else { continue }
            ingestScanBlock(obj)
        }
    }

    private func ingestScanBlock(_ obj: [String: Any]) {
        let eventType = (obj["event_type"] as? String) ?? ""
        let ts = DCDates.parse(obj["ts"] ?? obj["timestamp"]) ?? Date()
        let connector = (obj["connector"] as? String) ?? ""
        if eventType == "scan", let scan = obj["scan"] as? [String: Any],
           let scanID = scan["scan_id"].map({ String(describing: $0) }), !scanID.isEmpty {
            var block = scanBlockMap[scanID] ?? ScanBlockEvent(
                scanID: scanID, timestamp: ts, scanner: "", target: "",
                severity: .info, verdict: "", findingCount: 0, findingTitles: []
            )
            block.scanner = (scan["scanner"] as? String) ?? block.scanner
            block.target = (scan["target"] as? String) ?? block.target
            let summarySeverity = Severity.parse((scan["severity_max"] as? String) ?? (obj["severity"] as? String))
            if summarySeverity > block.severity { block.severity = summarySeverity }
            block.verdict = (scan["verdict"] as? String) ?? block.verdict
            block.timestamp = max(block.timestamp, ts)
            // Hook scans carry the connector in the target prefix
            // ("claudecode:PostToolUse"), not a top-level field.
            let resolved = !connector.isEmpty ? connector : ConnectorAttribution.fromTarget(block.target)
            if !resolved.isEmpty { block.connector = resolved }
            if let total = scan["total_count"] as? Int {
                scanSummaryCounts[scanID] = total
                block.findingCount = max(total, observedFindingCounts[scanID] ?? 0)
            }
            scanBlockMap[scanID] = block
        } else if eventType == "scan_finding", let finding = obj["scan_finding"] as? [String: Any],
                  let scanID = finding["scan_id"].map({ String(describing: $0) }), !scanID.isEmpty {
            var block = scanBlockMap[scanID] ?? ScanBlockEvent(
                scanID: scanID, timestamp: ts,
                scanner: (finding["scanner"] as? String) ?? "",
                target: (finding["target"] as? String) ?? "",
                severity: Severity.parse(obj["severity"] as? String),
                verdict: "", findingCount: 0, findingTitles: []
            )
            observedFindingCounts[scanID, default: 0] += 1
            block.findingCount = max(
                scanSummaryCounts[scanID] ?? 0,
                observedFindingCounts[scanID] ?? 0
            )
            let findingSeverity = Severity.parse((finding["severity"] as? String) ?? (obj["severity"] as? String))
            if findingSeverity > block.severity { block.severity = findingSeverity }
            if let title = finding["title"] as? String, block.findingTitles.count < 5 {
                block.findingTitles.append(title)
            }
            block.timestamp = max(block.timestamp, ts)
            let resolved = !connector.isEmpty ? connector : ConnectorAttribution.fromTarget(block.target)
            if !resolved.isEmpty { block.connector = resolved }
            scanBlockMap[scanID] = block
        }
    }

    var fileExists: Bool {
        FileManager.default.fileExists(atPath: url.path)
    }

    /// Reads any new bytes appended since the last call; first call reads the tail budget.
    func poll() -> StreamDelta {
        refreshScanBlocksFromTail()
        var delta = StreamDelta()
        if let handle = try? FileHandle(forReadingFrom: url) {
            defer { try? handle.close() }
            let size = (try? handle.seekToEnd()) ?? 0

            if offset == 0 || offset > size {
                // First read, or the file was truncated/rotated: read tail budget only.
                offset = size > UInt64(Self.tailBudget) ? size - UInt64(Self.tailBudget) : 0
            }
            if size > offset {
                if size - offset > UInt64(Self.tailBudget) {
                    offset = size - UInt64(Self.tailBudget)
                }
                try? handle.seek(toOffset: offset)
                let requested = Int(size - offset)
                if let data = try? handle.read(upToCount: requested),
                   let complete = completeLinePrefix(data), !complete.isEmpty {
                    offset += UInt64(complete.count)
                    let text = String(decoding: complete, as: UTF8.self)
                    for line in text.split(separator: "\n") {
                        guard let lineData = line.data(using: .utf8),
                              let obj = try? JSONSerialization.jsonObject(with: lineData) as? [String: Any]
                        else { continue }
                        ingest(obj, raw: String(line), into: &delta)
                    }
                }
            }
        }
        ingestPlainLog(gatewayLogURL, stream: .gateway, offset: &gatewayLogOffset, into: &delta)
        ingestPlainLog(watchdogLogURL, stream: .watchdog, offset: &watchdogLogOffset, into: &delta)

        for row in delta.logRows {
            logBuffers[row.stream, default: []].append(row)
            if logBuffers[row.stream]!.count > bufferCap {
                logBuffers[row.stream]!.removeFirst(logBuffers[row.stream]!.count - bufferCap)
            }
        }
        findings.append(contentsOf: delta.findings)
        activity.append(contentsOf: delta.activity)
        egress.append(contentsOf: delta.egress)
        if findings.count > bufferCap { findings.removeFirst(findings.count - bufferCap) }
        if activity.count > bufferCap { activity.removeFirst(activity.count - bufferCap) }
        if egress.count > bufferCap { egress.removeFirst(egress.count - bufferCap) }
        return delta
    }

    /// Reset and re-read the tail (the Logs panel's "reload from disk").
    func reload() -> StreamDelta {
        offset = 0
        logBuffers = [:]
        findings = []
        activity = []
        egress = []
        scanBlockMap = [:]
        scanSummaryCounts = [:]
        observedFindingCounts = [:]
        gatewayLogOffset = 0
        watchdogLogOffset = 0
        return poll()
    }

    private func ingestPlainLog(_ url: URL, stream: LogStream, offset: inout UInt64, into delta: inout StreamDelta) {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        if offset == 0 || offset > size {
            offset = size > UInt64(Self.tailBudget) ? size - UInt64(Self.tailBudget) : 0
        }
        guard size > offset else { return }
        if size - offset > UInt64(Self.tailBudget) {
            offset = size - UInt64(Self.tailBudget)
        }

        try? handle.seek(toOffset: offset)
        let requested = Int(size - offset)
        guard let data = try? handle.read(upToCount: requested),
              let complete = completeLinePrefix(data), !complete.isEmpty
        else { return }
        offset += UInt64(complete.count)

        let text = String(decoding: complete, as: UTF8.self)
        for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let raw = String(line)
            guard !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { continue }
            delta.logRows.append(plainLogRow(raw, stream: stream))
        }
    }

    /// Return only newline-terminated bytes. A writer may be midway through a
    /// JSON/log line when the size is sampled; leaving that suffix unconsumed
    /// makes the next poll re-read and complete it instead of dropping it.
    private func completeLinePrefix(_ data: Data) -> Data? {
        guard let newline = data.lastIndex(of: 0x0A) else { return nil }
        return data.prefix(through: newline)
    }

    private func plainLogRow(_ line: String, stream: LogStream) -> LogRow {
        plainLogCounter += 1
        let metadata = parsePlainLogMetadata(line, stream: stream)
        return LogRow(
            id: "plain-\(stream.rawValue)-\(plainLogCounter)",
            timestamp: metadata.timestamp ?? Date(),
            stream: stream,
            severity: metadata.severity,
            action: metadata.action,
            eventType: metadata.eventType,
            message: line,
            rawJSON: line,
            connector: metadata.connector
        )
    }

    private func parsePlainLogMetadata(_ line: String, stream: LogStream) -> (
        timestamp: Date?, severity: Severity, action: String, eventType: String, connector: String
    ) {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        let timestamp = parsePlainLogTimestamp(trimmed)
        let lower = trimmed.lowercased()
        let severity: Severity
        if lower.contains("critical") || lower.contains("fatal") {
            severity = .critical
        } else if lower.contains("error") || lower.contains("http 4") || lower.contains("http 5") {
            severity = .high
        } else if lower.contains("warn") {
            severity = .medium
        } else {
            severity = .info
        }

        var eventType = stream.rawValue
        var connector = ""
        if let open = trimmed.firstIndex(of: "["), let close = trimmed[open...].firstIndex(of: "]") {
            let tag = String(trimmed[trimmed.index(after: open)..<close])
            let parts = tag.split(separator: ":", maxSplits: 1).map(String.init)
            eventType = parts.first?.lowercased() ?? eventType
            if parts.count == 2 { connector = parts[1].lowercased() }
        }

        let action = firstPlainLogValue("phase", in: trimmed)
            ?? firstPlainLogValue("action", in: trimmed)
            ?? (lower.contains("completed") ? "completed" : "")
        return (timestamp, severity, action, eventType, connector)
    }

    private func firstPlainLogValue(_ key: String, in line: String) -> String? {
        guard let range = line.range(of: "\(key)=") else { return nil }
        let value = line[range.upperBound...].prefix { !$0.isWhitespace }
        return value.isEmpty ? nil : String(value)
    }

    private func parsePlainLogTimestamp(_ line: String) -> Date? {
        guard line.count >= 12 else { return nil }
        let prefix = String(line.prefix(12))
        guard prefix.range(of: #"^\d{2}:\d{2}:\d{2}\.\d{3}$"#, options: .regularExpression) != nil else {
            return nil
        }
        let parts = prefix.split { $0 == ":" || $0 == "." }.compactMap { Int($0) }
        guard parts.count == 4 else { return nil }
        var components = Calendar(identifier: .gregorian).dateComponents(in: TimeZone(secondsFromGMT: 0)!, from: Date())
        components.hour = parts[0]
        components.minute = parts[1]
        components.second = parts[2]
        components.nanosecond = parts[3] * 1_000_000
        components.timeZone = TimeZone(secondsFromGMT: 0)
        return Calendar(identifier: .gregorian).date(from: components)
    }

    private func nextID(_ obj: [String: Any], _ kind: String) -> String {
        if let id = obj["id"] as? String { return id }
        rowCounter += 1
        return "\(kind)-\(rowCounter)"
    }

    private func ingest(_ obj: [String: Any], raw: String, into delta: inout StreamDelta) {
        // Gateway rows carry their kind in "event_type" (scan / scan_finding / activity).
        let rowType = (obj["event_type"] as? String) ?? (obj["type"] as? String) ?? (obj["row_type"] as? String) ?? "event"
        let ts = DCDates.parse(obj["ts"] ?? obj["timestamp"] ?? obj["time"]) ?? Date()
        let severity = Severity.parse(obj["severity"] as? String)
        let parsed = parseLogFields(obj, rowType: rowType)
        let action = parsed.action
        let eventType = parsed.eventType
        let target = parsed.target
        let details = parsed.details
        // Gateway JSONL rows carry the attributed connector at top level or in
        // nested lifecycle/audit payloads; fall back to connector= kv details.
        let connector = parsed.connector.isEmpty
            ? ConnectorAttribution.fromDetails(details)
            : parsed.connector

        switch rowType {
        case "scan_finding":
            let finding = (obj["scan_finding"] as? [String: Any]) ?? obj
            let findingTarget = (finding["target"] as? String) ?? target
            delta.findings.append(ScanFindingEvent(
                id: nextID(obj, "finding"),
                timestamp: ts,
                scanner: (finding["scanner"] as? String) ?? "scanner",
                target: findingTarget,
                title: (finding["title"] as? String) ?? action,
                detail: (finding["description"] as? String) ?? details,
                location: (finding["location"] as? String) ?? "",
                remediation: (finding["remediation"] as? String) ?? "",
                severity: severity,
                runID: (obj["run_id"] as? String) ?? "",
                connector: connector.isEmpty ? ConnectorAttribution.fromTarget(findingTarget) : connector
            ))
        case "activity":
            // Mutation fields are nested under "activity" (gateway_events.py
            // load_gateway_activity); top level is a fallback for older rows.
            let act = (obj["activity"] as? [String: Any]) ?? obj
            let before = jsonString(act["before_json"] ?? act["before"] ?? obj["before_json"] ?? obj["before"])
            var after = jsonString(act["after_json"] ?? act["after"] ?? obj["after_json"] ?? obj["after"])
            if before.isEmpty, after.isEmpty,
               let diff = act["diff"] as? [[String: Any]], !diff.isEmpty {
                after = jsonString(diff) // JSON-patch style op/path entries
            }
            delta.activity.append(ActivityMutation(
                id: nextID(obj, "activity"),
                timestamp: ts,
                actor: firstString(act["actor"], obj["actor"], "system"),
                action: firstString(act["action"], action, eventType),
                targetType: firstString(act["target_type"], obj["target_type"]),
                targetID: firstString(act["target_id"], obj["target_id"], target),
                reason: firstString(act["reason"], obj["reason"], details),
                versionFrom: firstString(act["version_from"], obj["version_from"]),
                versionTo: firstString(act["version_to"], obj["version_to"]),
                beforeJSON: before,
                afterJSON: after,
                connector: connector
            ))
        case "egress":
            // Egress fields are nested under "egress"; the TUI's
            // load_gateway_egress skips rows without that dict, and its
            // synthetic_egress_event derives severity purely from
            // decision/branch/shape — the envelope's top-level severity is
            // deliberately ignored, so ours must be too.
            guard let egress = obj["egress"] as? [String: Any] else { break }
            let decision = firstString(egress["decision"])
            let branch = firstString(egress["branch"])
            let looksLikeLLM = (egress["looks_like_llm"] as? Bool) ?? false
            // WARNING (-> MEDIUM bucket) for blocked or LLM-shaped bypass
            // traffic; everything else INFO.
            let synthesized: Severity = (decision == "block" || (branch == "shape" && looksLikeLLM))
                ? .medium : .info
            let tsParsed = DCDates.parse(obj["ts"] ?? obj["timestamp"] ?? obj["time"]) != nil
            delta.egress.append(EgressEvent(
                id: nextID(obj, "egress"),
                timestamp: ts,
                target: firstString(egress["target_host"]),
                decision: decision,
                reason: firstString(egress["reason"]),
                looksLikeLLM: looksLikeLLM,
                branch: branch,
                severity: synthesized,
                connector: connector,
                targetPath: firstString(egress["target_path"]),
                bodyShape: firstString(egress["body_shape"]),
                source: firstString(egress["source"]),
                timestampParsed: tsParsed
            ))
        default:
            break
        }

        // Every row also lands in a log stream (parity with load_gateway_log_views).
        let stream = classifyStream(parsed)
        let message = displayMessage(for: parsed, severity: severity, raw: raw)
        // The TUI's Gateway and Watchdog tabs are backed by gateway.log and
        // watchdog.log. JSONL rows feed the structured tabs and counters.
        if stream != .gateway && stream != .watchdog {
            delta.logRows.append(LogRow(
                id: nextID(obj, "log"),
                timestamp: ts,
                stream: stream,
                severity: severity,
                action: action,
                eventType: eventType,
                message: message.isEmpty ? raw : message,
                rawJSON: raw,
                connector: connector
            ))
        }
    }

    private struct ParsedLogFields {
        var rowType = ""
        var eventType = ""
        var action = ""
        var target = ""
        var rawDetails = ""
        var details = ""
        var lifecycleDetails: [String: String] = [:]
        var actor = ""
        var connector = ""
        var subsystem = ""
        var transition = ""
        var scanner = ""
        var verdict = ""
        var findingTitle = ""
        var findingRuleID = ""
        var findingLocation = ""
        var findingCount: Int?
        var errorSubsystem = ""
        var errorCode = ""
        var errorMessage = ""
        var errorCause = ""
        var diagnosticComponent = ""
        var diagnosticMessage = ""
        var activityAction = ""
        var activityTarget = ""
        var versionFrom = ""
        var versionTo = ""
        // verdict / judge payloads (gateway_log_views._with_verdict/_with_judge)
        var stage = ""
        var direction = ""
        var model = ""
        var reason = ""
        var categories: [String] = []
        var latencyMs = 0
        var judgeKind = ""
        var judgeInputBytes = 0
        var judgeParseError = ""
    }

    private func parseLogFields(_ obj: [String: Any], rowType: String) -> ParsedLogFields {
        let lifecycle = obj["lifecycle"] as? [String: Any]
        let lifecycleDetails = lifecycle?["details"] as? [String: Any]
        let scan = obj["scan"] as? [String: Any]
        let finding = obj["scan_finding"] as? [String: Any]
        let audit = obj["audit"] as? [String: Any]
        let payload = obj["payload"] as? [String: Any]
        let error = obj["error"] as? [String: Any]
        let diagnostic = obj["diagnostic"] as? [String: Any]
        let activity = obj["activity"] as? [String: Any]
        let verdict = obj["verdict"] as? [String: Any]
        let judge = obj["judge"] as? [String: Any]

        let eventType = firstString(
            obj["event_type"], obj["event"], obj["type"], obj["row_type"], rowType
        )
        var action = firstString(
            obj["action"],
            verdict?["action"],
            judge?["action"],
            lifecycleDetails?["action"],
            audit?["action"],
            payload?["action"],
            scan?["action"],
            finding?["action"],
            error?["code"],
            activity?["action"]
        )
        // _with_scan/_with_scan_finding force action="scan"/"finding" so the
        // Verdicts action filter can select them; finding wins when both exist.
        if scan != nil { action = "scan" }
        if finding != nil { action = "finding" }
        let target = firstString(
            obj["target"],
            lifecycleDetails?["target"],
            audit?["target"],
            payload?["target"],
            scan?["target"],
            finding?["target"],
            activityTarget(activity)
        )
        let rawDetails = firstString(
            obj["details"],
            obj["message"],
            obj["msg"],
            obj["content"],
            lifecycleDetails?["details"],
            lifecycleDetails?["content"],
            audit?["details"],
            audit?["content"],
            payload?["details"],
            payload?["content"],
            finding?["description"],
            finding?["content"],
            scan?["details"],
            scan?["content"]
        )
        let details = sanitizeLogDetails(rawDetails)
        let connector = firstString(
            obj["connector"],
            lifecycleDetails?["connector"],
            audit?["connector"],
            payload?["connector"],
            scan?["connector"],
            finding?["connector"],
            ConnectorAttribution.fromTarget(target),
            ConnectorAttribution.fromDetails(rawDetails),
            ConnectorAttribution.fromDetails(details)
        )
        return ParsedLogFields(
            rowType: rowType,
            eventType: eventType,
            action: action,
            target: target,
            rawDetails: rawDetails,
            details: details,
            lifecycleDetails: stringMap(lifecycleDetails),
            actor: firstString(obj["actor"], lifecycleDetails?["actor"], audit?["actor"], payload?["actor"]),
            connector: connector,
            subsystem: firstString(lifecycle?["subsystem"], obj["subsystem"], payload?["subsystem"]),
            transition: firstString(lifecycle?["transition"], obj["transition"], payload?["transition"]),
            scanner: firstString(scan?["scanner"], finding?["scanner"], obj["scanner"]),
            verdict: firstString(scan?["verdict"], obj["verdict"] as? String, payload?["verdict"]),
            findingTitle: firstString(finding?["title"], obj["title"]),
            findingRuleID: firstString(finding?["rule_id"], obj["rule_id"]),
            findingLocation: firstString(finding?["location"], obj["location"]),
            findingCount: firstInt(scan?["total_count"], scan?["finding_count"], obj["finding_count"]),
            errorSubsystem: firstString(error?["subsystem"]),
            errorCode: firstString(error?["code"]),
            errorMessage: firstString(error?["message"]),
            errorCause: firstString(error?["cause"]),
            diagnosticComponent: firstString(diagnostic?["component"]),
            diagnosticMessage: firstString(diagnostic?["message"]),
            activityAction: firstString(activity?["action"]),
            activityTarget: activityTarget(activity),
            versionFrom: firstString(activity?["version_from"]),
            versionTo: firstString(activity?["version_to"]),
            stage: firstString(verdict?["stage"]),
            direction: firstString(obj["direction"]),
            model: firstString(obj["model"]),
            reason: firstString(verdict?["reason"]),
            categories: ((verdict?["categories"] as? [Any]) ?? []).map { firstString($0) },
            latencyMs: firstInt(verdict?["latency_ms"], judge?["latency_ms"], scan?["duration_ms"]) ?? 0,
            judgeKind: firstString(judge?["kind"]),
            judgeInputBytes: firstInt(judge?["input_bytes"]) ?? 0,
            judgeParseError: firstString(judge?["parse_error"])
        )
    }

    private func displayMessage(for row: ParsedLogFields, severity: Severity, raw: String) -> String {
        switch row.eventType {
        case "verdict":
            // TUI: VERDICT <ACTION> <SEV> <stage> <dir> <model> -- <reason> [cats] (Nms)
            var suffix = truncateLogText(row.reason, limit: 100)
            if !row.categories.isEmpty {
                // trim_categories: first 2, then a "+Nmore" overflow marker.
                var cats = Array(row.categories.prefix(2))
                if row.categories.count > 2 { cats.append("+\(row.categories.count - 2)more") }
                suffix += " [" + cats.joined(separator: ",") + "]"
            }
            if row.latencyMs > 0 { suffix += " (\(row.latencyMs)ms)" }
            return joinedWords(
                "VERDICT",
                nonEmpty(row.action, "none").uppercased(),
                severity.rawValue.uppercased(),
                nonEmpty(row.stage, "-"),
                nonEmpty(row.direction, "-"),
                nonEmpty(row.model, "-"),
                "--",
                suffix.trimmingCharacters(in: .whitespaces)
            )
        case "judge":
            // TUI: JUDGE <ACTION> <SEV> kind= dir= model= in=NB Nms parse=error
            var suffix = ""
            if row.judgeInputBytes > 0 { suffix += " in=\(row.judgeInputBytes)B" }
            if row.latencyMs > 0 { suffix += " \(row.latencyMs)ms" }
            if !row.judgeParseError.isEmpty { suffix += " parse=error" }
            return joinedWords(
                "JUDGE",
                nonEmpty(row.action, "none").uppercased(),
                severity.rawValue.uppercased(),
                "kind=\(nonEmpty(row.judgeKind, "-"))",
                "dir=\(nonEmpty(row.direction, "-"))",
                "model=\(nonEmpty(row.model, "-"))" + suffix
            )
        case "lifecycle":
            if row.lifecycleDetails["action"] == "connector-hook" {
                return renderHookLifecycleLine(row, severity: severity)
            }
            let subject = [row.subsystem, row.transition].filter { !$0.isEmpty }.joined(separator: " ")
            return joinedWords("LIFECYCLE", subject.uppercased(), renderInlineDetails(row.lifecycleDetails, limit: 3))
        case "error":
            let message = truncateLogText(sanitizeLogDetails(row.errorMessage), limit: 120)
            let cause = truncateLogText(sanitizeLogDetails(row.errorCause), limit: 80)
            return joinedWords(
                "ERROR",
                row.errorSubsystem.uppercased(),
                row.errorCode.isEmpty ? "" : "code=\(row.errorCode)",
                message.isEmpty ? "" : "msg=\(message)",
                cause.isEmpty ? "" : "cause=\(cause)"
            )
        case "diagnostic":
            return joinedWords(
                "DIAG",
                row.diagnosticComponent.uppercased(),
                truncateLogText(sanitizeLogDetails(row.diagnosticMessage), limit: 120)
            )
        case "scan":
            let findingText = row.findingCount.map { "\($0) finding\($0 == 1 ? "" : "s")" } ?? ""
            return joinedWords(
                "SCAN",
                severity.rawValue.uppercased(),
                "scanner=\(nonEmpty(row.scanner, "-"))",
                "target=\(truncateLogText(row.target, limit: 40))",
                "verdict=\(nonEmpty(row.verdict, "-"))",
                findingText
            )
        case "scan_finding":
            return joinedWords(
                "FINDING",
                severity.rawValue.uppercased(),
                "rule=\(nonEmpty(row.findingRuleID, "-"))",
                truncateLogText(row.findingTitle.isEmpty ? row.target : row.findingTitle, limit: 80)
            )
        case "activity":
            return joinedWords(
                "ACT",
                severity.rawValue.uppercased(),
                "actor=\(nonEmpty(row.actor, "-"))",
                "action=\(nonEmpty(row.activityAction, row.action.isEmpty ? "-" : row.action))",
                "target=\(truncateLogText(nonEmpty(row.activityTarget, "-"), limit: 36))",
                "\(nonEmpty(row.versionFrom, "empty"))->\(nonEmpty(row.versionTo, "empty"))"
            )
        default:
            let headline = joinedWords(row.action, row.eventType == "event" ? "" : row.eventType)
            return joinedParts(headline, actorTarget(row.actor, row.target), row.details, fallback: raw)
        }
    }

    private func renderHookLifecycleLine(_ row: ParsedLogFields, severity: Severity) -> String {
        let parsed = parseLogKeyValues(row.rawDetails)
        let connector = parsed["connector"] ?? row.connector
        let decision = parsed["action"] ?? parsed["decision"] ?? ""
        let decisionSeverity = parsed["severity"] ?? ""
        let mode = parsed["mode"] ?? ""
        let head = truncateLogText(joinedWords(connector, row.target), limit: 36)
        var pieces: [String] = []
        if !decision.isEmpty { pieces.append(decision) }
        if !decisionSeverity.isEmpty, decisionSeverity.uppercased() != "NONE" {
            pieces.append(decisionSeverity.uppercased())
        }
        if !mode.isEmpty, mode != "observe" { pieces.append(mode) }
        return joinedWords("HOOK", severity.rawValue.uppercased(), nonEmpty(head, "-"), pieces.joined(separator: " · "))
    }

    private func actorTarget(_ actor: String, _ target: String) -> String {
        if !actor.isEmpty && !target.isEmpty { return "\(actor) -> \(target)" }
        return actor.isEmpty ? target : actor
    }

    private func joinedWords(_ parts: String...) -> String {
        parts.filter { !$0.isEmpty }.joined(separator: " ")
    }

    private func joinedParts(_ parts: String..., fallback: String) -> String {
        let message = parts
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: " · ")
        return message.isEmpty ? fallback : message
    }

    private func firstString(_ values: Any?...) -> String {
        for value in values {
            if let string = value as? String {
                let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty { return trimmed }
            } else if let value {
                let string = String(describing: value).trimmingCharacters(in: .whitespacesAndNewlines)
                if !string.isEmpty { return string }
            }
        }
        return ""
    }

    private func firstInt(_ values: Any?...) -> Int? {
        for value in values {
            if let int = value as? Int { return int }
            if let string = value as? String, let int = Int(string) { return int }
        }
        return nil
    }

    private func activityTarget(_ activity: [String: Any]?) -> String {
        let targetType = firstString(activity?["target_type"])
        let targetID = firstString(activity?["target_id"])
        if targetType.isEmpty { return targetID }
        return "\(targetType):\(targetID)"
    }

    private func stringMap(_ values: [String: Any]?) -> [String: String] {
        guard let values else { return [:] }
        return values.reduce(into: [:]) { result, item in
            let value = firstString(item.value)
            if !value.isEmpty { result[item.key] = value }
        }
    }

    private func renderInlineDetails(_ details: [String: String], limit: Int) -> String {
        guard limit > 0, !details.isEmpty else { return "" }
        return details.keys.sorted()
            .compactMap { key in humanLogDetailToken("\(key)=\(details[key] ?? "")") }
            .prefix(limit)
            .joined(separator: " ")
    }

    private func nonEmpty(_ value: String, _ fallback: String) -> String {
        value.isEmpty ? fallback : value
    }

    private func truncateLogText(_ value: String, limit: Int) -> String {
        guard limit > 0 else { return "" }
        guard value.count > limit else { return value }
        if limit <= 3 { return String(repeating: ".", count: limit) }
        return String(value.prefix(limit - 3)) + "..."
    }

    private func sanitizeLogDetails(_ details: String) -> String {
        let tokens = logDetailTokens(from: removeRedactedMetadataSegments(from: details))
            .compactMap(humanLogDetailToken)
        return tokens.joined(separator: " ")
    }

    private func removeRedactedMetadataSegments(from text: String) -> String {
        var result = ""
        var index = text.startIndex
        while index < text.endIndex {
            if text[index] == "<" {
                if let close = text[index...].firstIndex(of: ">") {
                    let segment = String(text[index...close]).lowercased()
                    if isRedactedMetadata(segment) {
                        index = text.index(after: close)
                        continue
                    }
                } else {
                    let tail = String(text[index...]).lowercased()
                    if isRedactedMetadata(tail) { break }
                }
            }
            result.append(text[index])
            index = text.index(after: index)
        }
        return result
    }

    private func logDetailTokens(from text: String) -> [String] {
        var tokens: [String] = []
        var current = ""
        var angleDepth = 0

        func appendCurrent() {
            let trimmed = current.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty { tokens.append(trimmed) }
            current = ""
        }

        for character in text {
            if character == "<" {
                angleDepth += 1
                current.append(character)
            } else if character == ">" {
                if angleDepth > 0 { angleDepth -= 1 }
                current.append(character)
            } else if isWhitespace(character), angleDepth == 0 {
                appendCurrent()
            } else {
                current.append(character)
            }
        }
        appendCurrent()
        return tokens
    }

    private func humanLogDetailToken(_ token: String) -> String? {
        guard !isNoisyLogDetailToken(token) else { return nil }

        let trimmed = token.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = splitLogDetailToken(trimmed)
        guard let key = parts.key, let value = parts.value else { return trimmed }

        switch key {
        case "action", "decision", "verdict":
            return value
        case "mode":
            return "\(value) mode"
        case "would_block":
            return boolValue(value) == true ? "would block" : nil
        case "result":
            return value == "ok" || value == "success" ? nil : "result=\(value)"
        default:
            return trimmed
        }
    }

    private func isNoisyLogDetailToken(_ token: String) -> Bool {
        let trimmed = token.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = trimmed.trimmingCharacters(in: CharacterSet(charactersIn: ",;")).lowercased()
        guard !lower.isEmpty else { return true }

        if isRedactedMetadata(lower) {
            return true
        }

        let parts = splitLogDetailToken(lower)
        let key = parts.key ?? lower
        let value = parts.value ?? ""
        let hasValue = parts.value != nil

        if !hasValue {
            if lower.contains("<redacted"), lower.contains("len=") || lower.contains("sha=") {
                return true
            }
            return isLikelyHashValue(lower)
        }
        if key.contains("hash") || key.contains("hmac") || key.contains("checksum") || key.contains("digest") {
            return true
        }
        if key == "id" || key.hasSuffix("_id") || key == "session" || key == "call" {
            return true
        }
        if key == "connector" || key == "severity" || key == "raw_origin" || key.hasPrefix("raw_") {
            return true
        }
        if key == "len" || key.hasSuffix("_len") || key.hasSuffix("_length") || key == "length" {
            return true
        }
        if key == "hook_compatibility_status" || key == "hook_script_version" {
            return true
        }
        if key == "sha" || key.hasPrefix("sha") || key.hasSuffix("_sha") {
            return true
        }
        if key.contains("elapsed") || key.contains("duration") || key.contains("latency") || key == "took" || key == "took_ms" {
            return true
        }
        if key.contains("bytes") || key == "byte" || key == "size" ||
            key == "content-length" || key == "content_length" ||
            key == "payload_len" || key == "body_len" ||
            key == "request_len" || key == "response_len" ||
            key == "body_bytes" || key == "request_bytes" || key == "response_bytes" {
            return true
        }
        if key == "result", value == "ok" || value == "success" {
            return true
        }
        if value.contains("<redacted"), value.contains("len=") || value.contains("sha=") {
            return true
        }
        if isLikelyHashValue(value) {
            return true
        }
        return false
    }

    private func isRedactedMetadata(_ value: String) -> Bool {
        value.contains("<redacted") && (value.contains("len=") || value.contains("sha="))
    }

    private func splitLogDetailToken(_ token: String) -> (key: String?, value: String?) {
        let parts = token.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2 else { return (nil, nil) }
        let key = String(parts[0]).trimmingCharacters(in: CharacterSet(charactersIn: "\"'` "))
        let value = String(parts[1]).trimmingCharacters(in: CharacterSet(charactersIn: "\"'`,; "))
        guard !key.isEmpty, !value.isEmpty else { return (nil, nil) }
        return (key.lowercased(), value)
    }

    private func parseLogKeyValues(_ text: String) -> [String: String] {
        var pairs: [String: String] = [:]
        var index = text.startIndex

        func skipWhitespace() {
            while index < text.endIndex, text[index].isWhitespace {
                index = text.index(after: index)
            }
        }

        while index < text.endIndex {
            skipWhitespace()
            let keyStart = index
            while index < text.endIndex, text[index] != "=", !text[index].isWhitespace {
                index = text.index(after: index)
            }
            guard index < text.endIndex, text[index] == "=" else { break }
            let key = String(text[keyStart..<index]).lowercased()
            index = text.index(after: index)

            let valueStart = index
            if index < text.endIndex, text[index] == "\"" {
                index = text.index(after: index)
                let quotedStart = index
                while index < text.endIndex, text[index] != "\"" {
                    if text[index] == "\\", text.index(after: index) < text.endIndex {
                        index = text.index(index, offsetBy: 2)
                    } else {
                        index = text.index(after: index)
                    }
                }
                pairs[key] = String(text[quotedStart..<index])
                if index < text.endIndex { index = text.index(after: index) }
                continue
            }
            if index < text.endIndex, text[index] == "<" {
                var depth = 0
                while index < text.endIndex {
                    if text[index] == "<" {
                        depth += 1
                    } else if text[index] == ">" {
                        depth -= 1
                        if depth == 0 {
                            index = text.index(after: index)
                            break
                        }
                    }
                    index = text.index(after: index)
                }
            } else {
                while index < text.endIndex, !text[index].isWhitespace {
                    index = text.index(after: index)
                }
            }
            let value = String(text[valueStart..<index])
            if !key.isEmpty, !value.isEmpty { pairs[key] = value }
        }
        return pairs
    }

    private func boolValue(_ value: String) -> Bool? {
        switch value.lowercased() {
        case "true", "yes", "1": return true
        case "false", "no", "0": return false
        default: return nil
        }
    }

    private func isLikelyHashValue(_ value: String) -> Bool {
        let candidate = value.trimmingCharacters(in: CharacterSet(charactersIn: "\"'`,;<>"))
        guard candidate.count >= 16 else { return false }
        return candidate.unicodeScalars.allSatisfy { scalar in
            ("0"..."9").contains(Character(scalar)) ||
                ("a"..."f").contains(Character(scalar)) ||
                ("A"..."F").contains(Character(scalar))
        }
    }

    private func isWhitespace(_ character: Character) -> Bool {
        character.unicodeScalars.allSatisfy { CharacterSet.whitespacesAndNewlines.contains($0) }
    }

    private func classifyStream(_ row: ParsedLogFields) -> LogStream {
        if isOtelLogRow(row) { return .otel }
        let type = row.eventType.lowercased()
        if [
            "verdict", "judge", "lifecycle", "error", "diagnostic",
            "scan", "scan_finding", "activity",
        ].contains(type) {
            return .verdicts
        }
        let haystack = "\(row.rowType) \(row.eventType) \(row.action) \(row.details)".lowercased()
        if haystack.contains("watchdog") || haystack.contains("health probe") {
            return .watchdog
        }
        return .gateway
    }

    private func isOtelLogRow(_ row: ParsedLogFields) -> Bool {
        let action = (row.activityAction.isEmpty ? row.lifecycleDetails["action"] ?? "" : row.activityAction)
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        if action.hasPrefix("otel.ingest.")
            || action.hasPrefix("codex.notify.")
            || ["otel.ingest", "codex.notify", "connector-hook"].contains(action) {
            return true
        }
        let subsystem = row.subsystem.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let component = row.diagnosticComponent.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return ["otel", "telemetry"].contains(subsystem) || ["otel", "telemetry"].contains(component)
    }

    private func jsonString(_ value: Any?) -> String {
        guard let value else { return "" }
        if let s = value as? String { return s }
        if JSONSerialization.isValidJSONObject(value),
           let data = try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys]) {
            return String(decoding: data, as: UTF8.self)
        }
        return String(describing: value)
    }
}
