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

/// Parses the gateway's human-readable `key=value` detail format without
/// mistaking metadata inside `<redacted ...>` placeholders for event fields.
enum StructuredDetailParser {
    private static let safeMetadataKeys: Set<String> = [
        "action", "connector", "decision", "evaluation_id", "finding_count",
        "findings", "max_severity", "rule_ids", "scan_id", "scanner",
    ]

    /// Parses a contiguous structured record. If the record starts with prose
    /// or a redaction placeholder, callers should preserve it as raw text.
    static func pairs(_ details: String) -> [(String, String)] {
        let characters = Array(details)
        var index = skipWhitespace(in: characters, from: 0)
        var result: [(String, String)] = []

        while index < characters.count {
            guard let pair = parsePair(in: characters, from: index) else { break }
            result.append((label(pair.key), displayValue(pair.value)))
            index = skipWhitespace(in: characters, from: pair.nextIndex)
        }
        return result
    }

    /// Extracts only useful top-level metadata from an otherwise raw record.
    /// Angle-bracket placeholders are skipped as a unit, so their `len` and
    /// `sha` attributes can never become inspector rows.
    static func safeMetadataPairs(_ details: String) -> [(String, String)] {
        let characters = Array(details)
        var index = 0
        var seen = Set<String>()
        var result: [(String, String)] = []

        while index < characters.count {
            index = skipWhitespace(in: characters, from: index)
            guard index < characters.count else { break }

            if characters[index] == "<" {
                index = skipAngleGroup(in: characters, from: index)
                continue
            }

            if let pair = parsePair(in: characters, from: index) {
                let normalizedKey = pair.key.lowercased()
                if safeMetadataKeys.contains(normalizedKey), seen.insert(normalizedKey).inserted {
                    result.append((label(normalizedKey), displayValue(pair.value)))
                }
                index = pair.nextIndex
            } else {
                index = skipToken(in: characters, from: index)
            }
        }
        return result
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
        switch key.lowercased() {
        case "evaluation_id": return "Evaluation ID"
        case "rule_ids": return "Rule IDs"
        case "scan_id": return "Scan ID"
        default:
            return key.split(separator: "_").map { $0.capitalized }.joined(separator: " ")
        }
    }

    private static func parsePair(
        in characters: [Character],
        from startIndex: Int
    ) -> (key: String, value: String, nextIndex: Int)? {
        var index = startIndex
        let keyStart = index
        while index < characters.count,
              characters[index] != "=",
              !characters[index].isWhitespace {
            if characters[index] == "<" || characters[index] == ">" { return nil }
            index += 1
        }
        guard index > keyStart, index < characters.count, characters[index] == "=" else { return nil }

        let key = String(characters[keyStart..<index])
        index += 1
        guard index < characters.count else { return nil }

        let valueStart = index
        if characters[index] == "\"" || characters[index] == "'" || characters[index] == "`" {
            let quote = characters[index]
            index += 1
            var value: [Character] = []
            var escaped = false
            while index < characters.count {
                let character = characters[index]
                index += 1
                if escaped {
                    value.append(character)
                    escaped = false
                } else if character == "\\" {
                    escaped = true
                } else if character == quote {
                    return (key, String(value), index)
                } else {
                    value.append(character)
                }
            }
            return nil
        }

        if characters[index] == "<" {
            let nextIndex = skipAngleGroup(in: characters, from: index)
            guard nextIndex > index, characters[nextIndex - 1] == ">" else { return nil }
            return (key, String(characters[index..<nextIndex]), nextIndex)
        }

        while index < characters.count, !characters[index].isWhitespace { index += 1 }
        guard index > valueStart else { return nil }
        return (key, String(characters[valueStart..<index]), index)
    }

    private static func displayValue(_ value: String) -> String {
        guard value.hasPrefix("<redacted"), value.hasSuffix(">") else { return value }
        let body = value.dropFirst().dropLast()
        let attributes = pairs(String(body.dropFirst("redacted".count)))
        let length = attributes.first { $0.0 == "Len" }?.1
        let digest = attributes.first { $0.0 == "Sha" }?.1
        return [
            "redacted",
            length.map { "\($0) bytes" },
            digest.map { "sha:\($0)" },
        ].compactMap { $0 }.joined(separator: " · ")
    }

    private static func skipWhitespace(in characters: [Character], from startIndex: Int) -> Int {
        var index = startIndex
        while index < characters.count, characters[index].isWhitespace { index += 1 }
        return index
    }

    private static func skipToken(in characters: [Character], from startIndex: Int) -> Int {
        var index = startIndex
        while index < characters.count, !characters[index].isWhitespace { index += 1 }
        return index
    }

    private static func skipAngleGroup(in characters: [Character], from startIndex: Int) -> Int {
        var index = startIndex
        var depth = 0
        while index < characters.count {
            if characters[index] == "<" { depth += 1 }
            if characters[index] == ">" {
                depth -= 1
                if depth == 0 { return index + 1 }
            }
            index += 1
        }
        return index
    }
}
