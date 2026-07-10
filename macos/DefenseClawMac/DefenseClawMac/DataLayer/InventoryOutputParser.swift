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

struct InventoryOutputParseResult {
    var documents: [[String: Any]]
    var diagnostics: String
}

enum InventoryOutputParser {
    static let maximumInputBytes = CLIOutputLimits.maximumOutputBytes
    static let maximumCandidateCount = 64
    private static let maximumNestingDepth = 512
    private static let maximumScanWork = maximumInputBytes * 2

    /// First syntactically valid top-level JSON array in mixed CLI output.
    /// Diagnostics may contain stray brackets before the real payload.
    static func firstJSONArrayData(in output: String) -> Data? {
        guard output.utf8.count <= maximumInputBytes else { return nil }
        let bytes = Array(output.utf8)
        var budget = ScanBudget()
        for start in bytes.indices where bytes[start] == 0x5B {
            guard budget.canTryCandidate else { return nil }
            budget.candidates += 1
            guard let end = matchingJSONEnd(in: bytes, from: start, budget: &budget) else {
                continue
            }
            let data = Data(bytes[start...end])
            if (try? JSONSerialization.jsonObject(with: data)) is [Any] { return data }
        }
        return nil
    }

    /// DefenseClaw emits one object for a single connector and an array for
    /// multiple connectors. CLI diagnostics may surround that JSON because the
    /// app combines stdout and stderr for Activity output.
    static func parse(_ output: String) -> InventoryOutputParseResult? {
        guard output.utf8.count <= maximumInputBytes else { return nil }
        let bytes = Array(output.utf8)
        var candidateStart = 0
        var budget = ScanBudget()

        while candidateStart < bytes.count {
            guard bytes[candidateStart] == 0x7B || bytes[candidateStart] == 0x5B else {
                candidateStart += 1
                continue
            }
            guard budget.canTryCandidate else { return nil }
            budget.candidates += 1
            guard let candidateEnd = matchingJSONEnd(
                in: bytes,
                from: candidateStart,
                budget: &budget
            ) else {
                candidateStart += 1
                continue
            }

            let data = Data(bytes[candidateStart...candidateEnd])
            if let value = try? JSONSerialization.jsonObject(with: data),
               let documents = normalizedDocuments(from: value) {
                let before = String(decoding: bytes[..<candidateStart], as: UTF8.self)
                let afterStart = candidateEnd + 1
                let after = afterStart < bytes.count
                    ? String(decoding: bytes[afterStart...], as: UTF8.self)
                    : ""
                let diagnostics = [before, after]
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter { !$0.isEmpty }
                    .joined(separator: "\n")
                return InventoryOutputParseResult(documents: documents, diagnostics: diagnostics)
            }
            candidateStart += 1
        }
        return nil
    }

    private static func normalizedDocuments(from value: Any) -> [[String: Any]]? {
        if let document = value as? [String: Any], isInventoryDocument(document) {
            return [document]
        }
        if let documents = value as? [[String: Any]],
           documents.allSatisfy(isInventoryDocument) {
            return documents
        }
        return nil
    }

    private static func isInventoryDocument(_ document: [String: Any]) -> Bool {
        document["connector"] != nil
            || document["claw_mode"] != nil
            || document["summary"] != nil
    }

    private struct ScanBudget {
        var candidates = 0
        var remainingWork = maximumScanWork

        var canTryCandidate: Bool {
            candidates < maximumCandidateCount && remainingWork > 0
        }
    }

    private static func matchingJSONEnd(
        in bytes: [UInt8],
        from start: Int,
        budget: inout ScanBudget
    ) -> Int? {
        var expectedClosers: [UInt8] = []
        var inString = false
        var escaped = false

        for index in start..<bytes.count {
            guard budget.remainingWork > 0 else { return nil }
            budget.remainingWork -= 1
            let byte = bytes[index]
            if inString {
                if escaped {
                    escaped = false
                } else if byte == 0x5C {
                    escaped = true
                } else if byte == 0x22 {
                    inString = false
                }
                continue
            }

            switch byte {
            case 0x22:
                inString = true
            case 0x7B:
                expectedClosers.append(0x7D)
            case 0x5B:
                expectedClosers.append(0x5D)
            case 0x7D, 0x5D:
                guard expectedClosers.last == byte else { return nil }
                expectedClosers.removeLast()
                if expectedClosers.isEmpty { return index }
            default:
                break
            }
            guard expectedClosers.count <= maximumNestingDepth else { return nil }
        }
        return nil
    }
}
