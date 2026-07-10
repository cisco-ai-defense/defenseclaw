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

    /// First syntactically valid top-level JSON array in mixed CLI output.
    /// Diagnostics may contain stray brackets before the real payload.
    static func firstJSONArrayData(in output: String) -> Data? {
        guard output.utf8.count <= maximumInputBytes else { return nil }
        let bytes = Array(output.utf8)
        for candidate in candidateRanges(in: bytes) where bytes[candidate.start] == 0x5B {
            let data = Data(bytes[candidate.start...candidate.end])
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
        for candidate in candidateRanges(in: bytes) {
            let data = Data(bytes[candidate.start...candidate.end])
            if let value = try? JSONSerialization.jsonObject(with: data),
               let documents = normalizedDocuments(from: value) {
                let before = String(decoding: bytes[..<candidate.start], as: UTF8.self)
                let afterStart = candidate.end + 1
                let after = afterStart < bytes.count
                    ? String(decoding: bytes[afterStart...], as: UTF8.self)
                    : ""
                let diagnostics = [before, after]
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter { !$0.isEmpty }
                    .joined(separator: "\n")
                return InventoryOutputParseResult(documents: documents, diagnostics: diagnostics)
            }
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

    private struct CandidateRange {
        var start: Int
        var end: Int
    }

    private struct JSONFrame {
        var start: Int
        var closer: UInt8
    }

    /// Finds balanced object/array ranges in one byte traversal. Nested ranges
    /// are retained so valid JSON after unmatched diagnostic openers remains
    /// discoverable without rescanning the same suffix for every opener.
    private static func candidateRanges(in bytes: [UInt8]) -> [CandidateRange] {
        var stack: [JSONFrame] = []
        var candidates: [CandidateRange] = []
        var largestCandidateStart = -1
        var largestCandidateIndex = 0
        var inString = false
        var escaped = false

        func retain(_ candidate: CandidateRange) {
            if candidates.count < maximumCandidateCount {
                candidates.append(candidate)
                if candidate.start > largestCandidateStart {
                    largestCandidateStart = candidate.start
                    largestCandidateIndex = candidates.count - 1
                }
                return
            }
            guard candidate.start < largestCandidateStart else { return }
            candidates[largestCandidateIndex] = candidate
            if let replacement = candidates.indices.max(by: {
                candidates[$0].start < candidates[$1].start
            }) {
                largestCandidateIndex = replacement
                largestCandidateStart = candidates[replacement].start
            }
        }

        for index in bytes.indices {
            let byte = bytes[index]
            if stack.isEmpty {
                switch byte {
                case 0x7B:
                    stack.append(JSONFrame(start: index, closer: 0x7D))
                case 0x5B:
                    stack.append(JSONFrame(start: index, closer: 0x5D))
                default:
                    continue
                }
                inString = false
                escaped = false
                continue
            }

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
                guard stack.count < maximumNestingDepth else {
                    stack = [JSONFrame(start: index, closer: 0x7D)]
                    inString = false
                    escaped = false
                    continue
                }
                stack.append(JSONFrame(start: index, closer: 0x7D))
            case 0x5B:
                guard stack.count < maximumNestingDepth else {
                    stack = [JSONFrame(start: index, closer: 0x5D)]
                    inString = false
                    escaped = false
                    continue
                }
                stack.append(JSONFrame(start: index, closer: 0x5D))
            case 0x7D, 0x5D:
                guard stack.last?.closer == byte, let frame = stack.popLast() else {
                    stack.removeAll(keepingCapacity: true)
                    inString = false
                    escaped = false
                    continue
                }
                retain(CandidateRange(start: frame.start, end: index))
            default:
                break
            }
        }
        return candidates.sorted {
            $0.start == $1.start ? $0.end > $1.end : $0.start < $1.start
        }
    }
}
