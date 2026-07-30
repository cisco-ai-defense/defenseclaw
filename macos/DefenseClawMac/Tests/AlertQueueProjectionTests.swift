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

enum ConfigStore {
    static let auditDBURL = URL(fileURLWithPath: "/dev/null")
}

@main
enum AlertQueueProjectionTests {
    static func main() async {
        await currentSchemaExcludesAcknowledgedAndNonFindingRows()
        await legacySchemaRemainsReadable()
        print("AlertQueueProjectionTests passed")
    }

    private static func currentSchemaExcludesAcknowledgedAndNonFindingRows() async {
        let url = temporaryDatabaseURL("current")
        defer { try? FileManager.default.removeItem(at: url) }
        execute(url, """
            CREATE TABLE audit_events (
                id TEXT, timestamp TEXT, action TEXT, target TEXT, actor TEXT,
                details TEXT, severity TEXT, run_id TEXT, structured_json TEXT,
                connector TEXT, bucket TEXT, event_name TEXT
            );
            CREATE TABLE alert_acknowledgement_projection (alert_id TEXT);
            INSERT INTO audit_events VALUES
                ('active', '2026-07-22T12:00:00Z', 'scan', '', '', '', 'HIGH', '', '', '', NULL, NULL),
                ('observed', '2026-07-22T12:01:00Z', 'scan', '', '', '', 'HIGH', '', '', '', 'security.finding', 'finding.observed'),
                ('acked', '2026-07-22T12:02:00Z', 'scan', '', '', '', 'HIGH', '', '', '', NULL, NULL),
                ('telemetry', '2026-07-22T12:03:00Z', 'scan', '', '', '', 'HIGH', '', '', '', 'telemetry', 'span.received'),
                ('warning', '2026-07-22T12:04:00Z', 'scan', '', '', '', 'WARNING', '', '', '', NULL, NULL),
                ('dismissed', '2026-07-22T12:05:00Z', 'dismiss-alert', '', '', '', 'HIGH', '', '', '', NULL, NULL);
            INSERT INTO alert_acknowledgement_projection VALUES ('acked');
            """)

        let rows = await AuditStore(url: url).alertQueueEvents(limit: 500)
        expect(Set(rows.map(\.id)) == ["active", "observed"], "v8 queue matches the canonical active projection")
    }

    private static func legacySchemaRemainsReadable() async {
        let url = temporaryDatabaseURL("legacy")
        defer { try? FileManager.default.removeItem(at: url) }
        execute(url, """
            CREATE TABLE audit_events (
                id TEXT, timestamp TEXT, action TEXT, target TEXT, actor TEXT,
                details TEXT, severity TEXT, run_id TEXT, structured_json TEXT,
                connector TEXT
            );
            INSERT INTO audit_events VALUES
                ('legacy', '2026-07-22T12:00:00Z', 'scan-finding', '', '', '', 'HIGH', '', '', '');
            """)

        let rows = await AuditStore(url: url).alertQueueEvents(limit: 500)
        expect(rows.map(\.id) == ["legacy"], "legacy queue remains available without v8 projection columns")
    }

    private static func temporaryDatabaseURL(_ suffix: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("DefenseClaw-alert-queue-\(suffix)-\(UUID().uuidString).db")
    }

    private static func execute(_ url: URL, _ sql: String) {
        var database: OpaquePointer?
        guard sqlite3_open(url.path, &database) == SQLITE_OK, let database else {
            fatalError("could not create test database")
        }
        defer { sqlite3_close(database) }
        var error: UnsafeMutablePointer<CChar>?
        guard sqlite3_exec(database, sql, nil, nil, &error) == SQLITE_OK else {
            let detail = error.map { String(cString: $0) } ?? "unknown SQLite error"
            sqlite3_free(error)
            fatalError(detail)
        }
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() {
            fputs("FAIL: \(message)\n", stderr)
            exit(1)
        }
    }
}
