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
import SQLite3

@main
struct CanonicalEventHistoryTests {
    static func main() async throws {
        func check(_ value: Bool, _ message: String) { precondition(value, message) }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let dbURL = root.appendingPathComponent("audit.db")
        let store = AuditStore(url: dbURL)
        if case .unavailable = await store.canonicalHistory() {} else { fatalError("missing DB") }
        check(!FileManager.default.fileExists(atPath: dbURL.path), "read must not create database")
        var db: OpaquePointer?
        check(sqlite3_open(dbURL.path, &db) == SQLITE_OK, "create fixture")
        defer { sqlite3_close(db) }
        func sql(_ value: String) {
            check(sqlite3_exec(db, value, nil, nil, nil) == SQLITE_OK, "fixture SQL failed")
        }
        sql("""
            CREATE TABLE audit_events (id TEXT, timestamp TEXT, bucket TEXT, event_name TEXT,
                source TEXT, signal TEXT, severity TEXT, action TEXT, actor TEXT, details TEXT,
                connector TEXT, payload_json TEXT, projected_record_json TEXT);
            """)
        func insert(_ id: String, _ bucket: String, payload: String = "{}", signal: String = "logs") {
            var stmt: OpaquePointer?
            check(sqlite3_prepare_v2(db, "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", -1, &stmt, nil) == SQLITE_OK, "prepare insert")
            defer { sqlite3_finalize(stmt) }
            let values = [id, "2026-09-18T12:00:00Z", bucket, "test.observed", "fixture", signal,
                          "HIGH", "block", "operator", "token=fixture-secret safe summary", "codex", payload, #"{"outcome":"block"}"#]
            for (index, value) in values.enumerated() {
                sqlite3_bind_text(stmt, Int32(index + 1), value, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            }
            check(sqlite3_step(stmt) == SQLITE_DONE, "insert")
        }
        insert("verdict", "guardrail.evaluation", payload: #"{"defenseclaw.guardrail.decision":"block","api_key":"do-not-display","request.body":"private text","token":"plain-token-placeholder","apiKey":"camel-key-placeholder","note":"Authorization: Bearer header-placeholder"}"#)
        insert("otel", "telemetry.ingest")
        insert("mutation", "compliance.activity", payload: #"{"defenseclaw.config.path":"guardrail.mode","defenseclaw.config.generation":2}"#)
        insert("egress", "network.egress", payload: #"{"defenseclaw.network.decision":"allow","defenseclaw.network.branch":"shape","defenseclaw.network.looks_like_llm":true}"#)
        insert("metric", "telemetry.ingest", signal: "metrics")
        insert("huge", "security.finding", payload: String(repeating: "é", count: 40_000))
        let gatewayLogURL = root.appendingPathComponent("gateway.log")
        try "old log line\n".write(to: gatewayLogURL, atomically: true, encoding: .utf8)
        let reader = EventStreamReader(
            url: root.appendingPathComponent("retired.jsonl"),
            gatewayLogURL: gatewayLogURL,
            watchdogLogURL: root.appendingPathComponent("watchdog.log")
        )
        guard case .available(let rows) = await store.canonicalHistory() else { fatalError("canonical schema") }
        check(rows.count == 5, "logs only")
        check(rows.first?.payloadOmitted == true && rows.first?.payloadJSON == "", "byte bound before decode")
        _ = await reader.poll(canonicalHistory: .available(rows))
        let logs = await reader.logBuffers
        check(logs[.otel]?.count == 5 && logs[.verdicts]?.count == 3, "TUI stream routing")
        let rendered = logs.values.flatMap { $0 }.map { $0.rawJSON + $0.message }.joined()
        check(!rendered.contains("do-not-display") && !rendered.contains("private text"), "sensitive keys redacted")
        check(!rendered.contains("fixture-secret"), "summary credentials redacted")
        check(!rendered.contains("plain-token-placeholder") && !rendered.contains("camel-key-placeholder"), "all credential key forms redacted")
        check(!rendered.contains("header-placeholder"), "authorization scheme and credential redacted")
        for key in ["token", "apiKey", "api-key", "auth.accessToken", "clientSecret"] {
            check(DisplayRedaction.isSensitiveKey(key), "credential key spelling")
        }
        check(!DisplayRedaction.isSensitiveKey("input_tokens"), "token counters remain useful")
        for text in [
            "Authorization: Basic sample-value", "Authorization: Bearer sample-value",
            "--token sample-value", "--api-key='sample-value with spaces'",
            "refresh_token=sample-value", "secret=\"sample-value with spaces",
            "password=\"" + String(repeating: "sample-value ", count: 400) + "\"",
        ] {
            check(!DisplayRedaction.text(text).contains("sample-value"), "credential text forms")
        }
        check(await reader.activity.count == 1, "canonical mutations")
        check(await reader.egress.first?.looksLikeLLM == true, "canonical egress")
        check(await reader.scanBlocks.isEmpty, "canonical findings must not duplicate alert blocks")
        let ids = logs[.otel]!.map(\.id)
        _ = await reader.poll(canonicalHistory: .available(rows))
        check(await reader.logBuffers[.otel]!.map(\.id) == ids, "stable IDs and no duplicates")
        _ = await reader.poll(canonicalHistory: .unavailable)
        check(await reader.logBuffers[.otel]!.map(\.id) == ids, "unavailable retains last good")
        check(await reader.structuredError != nil, "unavailable is visible")
        try "new log line\n".write(to: gatewayLogURL, atomically: true, encoding: .utf8)
        _ = await reader.reload(canonicalHistory: .unavailable)
        check(await reader.logBuffers[.otel]!.map(\.id) == ids, "failed manual refresh retains last good")
        let reloadedGateway = await reader.logBuffers[.gateway] ?? []
        check(reloadedGateway.count == 1 && reloadedGateway[0].message.contains("new log line"), "plain logs reload independently of the database")
        _ = await reader.poll(canonicalHistory: .available([]))
        check(await reader.logBuffers[.otel]?.isEmpty == true, "valid empty clears stale events")
        guard case .available(let bounded) = await store.canonicalHistory(limit: 2) else { fatalError() }
        check(bounded.count == 2, "row limit")
        sql("BEGIN;")
        for index in 0..<90 {
            insert("budget-\(index)", "telemetry.ingest", payload: #"{"safe":""# + String(repeating: "x", count: 60_000) + #""}"#)
        }
        sql("COMMIT;")
        guard case .available(let budgeted) = await store.canonicalHistory(limit: Int.max) else { fatalError() }
        check(budgeted.count > 0 && budgeted.count < 90, "aggregate materialization is bounded")
        check(budgeted.reduce(0) { $0 + $1.payloadJSON.utf8.count + $1.projectionJSON.utf8.count } <= 4 * 1024 * 1024, "four MiB input budget")
        let limitedReader = EventStreamReader(
            url: root.appendingPathComponent("retired.jsonl"),
            gatewayLogURL: root.appendingPathComponent("gateway.log"),
            watchdogLogURL: root.appendingPathComponent("watchdog.log"),
            bufferCap: 2, maximumRecordBytes: 128, maximumRetainedBytes: 256
        )
        _ = await limitedReader.poll(canonicalHistory: .available(rows))
        check(await limitedReader.retainedBufferBytes <= 256, "canonical retained budget")
        check(await limitedReader.logBuffers.values.allSatisfy { $0.count <= 2 }, "canonical count budget")
        sql("DROP TABLE audit_events; CREATE TABLE audit_events (id TEXT);")
        if case .unsupported = await store.canonicalHistory() {} else { fatalError("partial schema must fall back") }
        sql("ALTER TABLE audit_events ADD COLUMN bucket TEXT;")
        if case .unavailable = await store.canonicalHistory() {} else { fatalError("partial v8 must not revive legacy data") }
        await store.close()
        print("Canonical event history tests passed")

        if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--live-audit" {
            let live = AuditStore(url: URL(fileURLWithPath: CommandLine.arguments[2]))
            guard case .available(let rows) = await live.canonicalHistory() else { fatalError("live canonical history unavailable") }
            _ = await reader.poll(canonicalHistory: .available(rows))
            let buffers = await reader.logBuffers
            print("Live canonical read: \(rows.count) events; Verdicts \(buffers[.verdicts]?.count ?? 0); Otel \(buffers[.otel]?.count ?? 0)")
            await live.close()
        }
    }
}
