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

// Minimal standalone-test dependency for InventoryOutputParser. The app target
// supplies the production limit from DataLayer/CLIRunner.swift.
enum CLIOutputLimits {
    static let maximumOutputBytes = 16 * 1024 * 1024
}

@main
struct InventoryCapabilityWarningTests {
    static func main() {
        filtersCapabilityNotesAcrossConnectors()
        preservesRealFailuresAndDiagnostics()
        rejectsNearMatches()
        supportsLegacySummaryCounts()
        print("InventoryCapabilityWarningTests passed")
    }

    private static func filtersCapabilityNotesAcrossConnectors() {
        let connectors = ["antigravity", "claudecode", "codex", "cursor", "opencode"]
        let documents = connectors.map(capabilityDocument)
        let warning = Array(
            repeating: "Warning: 4 connector inventory command(s) failed",
            count: connectors.count
        ).joined(separator: "\n")

        let data = try? JSONSerialization.data(withJSONObject: documents, options: [.sortedKeys])
        let output = warning + "\n" + (data.flatMap { String(data: $0, encoding: .utf8) } ?? "")
        guard let parsed = InventoryOutputParser.parse(output) else {
            fail("multi-connector inventory output should parse")
        }

        expect(parsed.documents.count == connectors.count, "all connector documents are retained")
        expect(
            parsed.documents.allSatisfy { InventoryOutputParser.actionableErrorCount(in: $0) == 0 },
            "expected connector capability notes are not counted as failures"
        )
        expect(
            InventoryOutputParser.userFacingDiagnostics(from: parsed).isEmpty,
            "capability-only aggregate warnings are removed"
        )
    }

    private static func preservesRealFailuresAndDiagnostics() {
        var document = capabilityDocument("codex")
        var errors = document["errors"] as? [[String: Any]] ?? []
        errors.append(["command": "codex:skills", "error": "permission denied"])
        document["errors"] = errors

        let result = InventoryOutputParseResult(
            documents: [document],
            diagnostics: "Warning: 5 connector inventory command(s) failed\nscanner cache is stale"
        )
        expect(
            InventoryOutputParser.actionableErrorCount(in: document) == 1,
            "real inventory failures remain actionable"
        )
        expect(
            InventoryOutputParser.userFacingDiagnostics(from: result)
                == "Warning: 1 connector inventory command(s) failed\nscanner cache is stale",
            "real failures are deduplicated and unrelated diagnostics are preserved"
        )
    }

    private static func rejectsNearMatches() {
        var document = capabilityDocument("codex")
        document["errors"] = [[
            "command": "codex:skills",
            "error": "agents are not a first-class concept on this connector",
        ]]
        expect(
            InventoryOutputParser.actionableErrorCount(in: document) == 1,
            "capability text under the wrong command remains actionable"
        )

        document["errors"] = [[
            "command": "codex:agents",
            "error": "agent inventory timed out",
        ]]
        expect(
            InventoryOutputParser.actionableErrorCount(in: document) == 1,
            "unknown errors remain actionable"
        )
    }

    private static func supportsLegacySummaryCounts() {
        let document: [String: Any] = [
            "connector": "codex",
            "summary": ["errors": 3],
        ]
        expect(
            InventoryOutputParser.actionableErrorCount(in: document) == 3,
            "legacy payloads without structured errors retain their summary count"
        )
    }

    private static func capabilityDocument(_ connector: String) -> [String: Any] {
        [
            "connector": connector,
            "errors": [
                [
                    "command": "\(connector):agents",
                    "error": "agents are not a first-class concept on this connector",
                ],
                [
                    "command": "\(connector):tools",
                    "error": "tool registry is owned by each plugin's manifest",
                ],
                [
                    "command": "\(connector):models",
                    "error": "model providers are configured inside the framework",
                ],
                [
                    "command": "\(connector):memory",
                    "error": "memory backend is private to the framework",
                ],
            ],
            "summary": ["errors": 4],
        ]
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else { fail(message) }
    }

    private static func fail(_ message: String) -> Never {
        fputs("FAILED: \(message)\n", stderr)
        exit(1)
    }
}
