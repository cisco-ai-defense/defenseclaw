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

// Reads the InstallationContext-selected config.yaml — the same source of
// truth the CLI/TUI use.
// Minimal YAML subset parser (nested block mappings, scalars, simple lists),
// sufficient for the keys the app consumes. Writes never go through this
// store; they go via the gateway (/config/patch) or the defenseclaw CLI.

import Darwin
import Foundation

struct DefenseClawConfig: Sendable {
    var gatewayHost: String = "127.0.0.1"
    var gatewayPort: Int = 18970
    var gatewayToken: String?
    var connectorName: String?
    var connectorMode: String?
    var connectors: [String] = []
    var connectorModes: [String: String] = [:]
    var connectorRulePacks: [String: String] = [:]
    /// Connectors whose guardrail is explicitly killed
    /// (guardrail.connectors.<name>.enabled: false) — TUI effective_enabled.
    var connectorDisabled: Set<String> = []
    /// claw.mode with the runtime loader's "openclaw" default — the drift
    /// notice's "configured" side (distinct from connectorMode's chain).
    var clawMode = "openclaw"
    /// Non-empty when guardrail.connectors exists but failed to parse — the
    /// TUI's roster-degraded error notice.
    var rosterError = ""
    /// Last config read failure. The last-good snapshot remains active while
    /// this is non-empty so a transient filesystem error cannot wipe tokens.
    var loadError = ""
    var guardrailEnabled = false
    var guardrailMode: String?
    var guardrailPort: Int?
    var guardrailRulePack: String = "default"
    // Global posture surfaced in the Overview CONFIGURATION box.
    // Empty means the source key is absent. It must stay distinct from the
    // valid, deliberately permissive profile named "none".
    var redactionDefaultProfile = ""         // observability.defaults.redaction_profile
    var hiltEnabled = false                  // hilt.enabled (human-in-the-loop approval)
    var hiltMinSeverity = "HIGH"             // hilt.min_severity
    var environment: String?                 // environment
    var policyDir: String?                   // policy_dir
    var dataDir: String?                     // data_dir
    var llmProvider: String?                 // llm.provider (→ inspect_llm.provider)
    var llmModel: String?                    // llm.model (→ inspect_llm.model)
    var aiDefenseEndpoint: String?           // cisco_ai_defense.endpoint
    var registrySources: [RegistrySourceConfig] = []
    var registryRequiredByType: [String: Bool] = [:]
    var raw: YAMLNode = .mapping([:])

    struct RegistrySourceConfig: Sendable {
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
    }

    var baseURL: URL? {
        var components = URLComponents()
        components.scheme = "http"
        components.host = gatewayHost
        components.port = gatewayPort
        // URLComponents brackets IPv6 hosts correctly. Invalid configured
        // hosts stay on the loopback fallback and are reported by health.
        // Invalid operator-controlled values become nil and are rejected by
        // GatewayClient before any token-bearing request is constructed.
        return components.url
    }
}

/// Very small YAML representation: enough for config.yaml's block style.
indirect enum YAMLNode: Sendable {
    case scalar(String)
    case mapping([String: YAMLNode])
    case sequence([YAMLNode])

    subscript(path: String) -> YAMLNode? {
        var node: YAMLNode = self
        for key in path.split(separator: ".").map(String.init) {
            guard case .mapping(let m) = node, let next = m[key] else { return nil }
            node = next
        }
        return node
    }

    var string: String? {
        if case .scalar(let s) = self { return s.isEmpty ? nil : s }
        return nil
    }
    var int: Int? { string.flatMap(Int.init) }
    var bool: Bool? {
        guard let s = string?.lowercased() else { return nil }
        if ["true", "yes", "on"].contains(s) { return true }
        if ["false", "no", "off"].contains(s) { return false }
        return nil
    }
    var mapping: [String: YAMLNode]? {
        if case .mapping(let m) = self { return m }
        return nil
    }
    var sequence: [YAMLNode]? {
        if case .sequence(let s) = self { return s }
        return nil
    }
}

enum MiniYAML {
    private static let maximumSourceBytes = 4 * 1024 * 1024
    private static let maximumNodes = 65_536

    /// Parses block-style YAML mappings/sequences with plain or quoted scalars.
    /// Supports the nested flow collections emitted by DefenseClaw's
    /// style-preserving config writer and ignores document markers and anchors.
    static func parse(_ text: String) -> YAMLNode {
        guard text.utf8.count <= maximumSourceBytes else {
            return .scalar("")
        }
        let lines = logicalLines(from: text)
        var index = 0
        let root = parseBlock(lines: lines, index: &index, indent: 0)
        guard boundedNodeCount(root) != nil else { return .scalar("") }
        return root
    }

    private enum FlowLineState {
        case open
        case complete
        case invalid
    }

    private struct PendingFlowLine {
        var indent: Int
        var parts: [String]
        var balance: FlowBalance

        var content: String { parts.joined() }
    }

    private struct FlowBalance {
        private var stack: [Character] = []
        private var inSingle = false
        private var inDouble = false
        private var escaped = false
        private var invalid = false

        var state: FlowLineState {
            if invalid { return .invalid }
            if !stack.isEmpty || inSingle || inDouble { return .open }
            return .complete
        }

        var isInsideQuote: Bool { inSingle || inDouble }

        /// YAML folds ordinary quoted line breaks to a space. A trailing
        /// backslash in a double-quoted scalar escapes the line break instead.
        mutating func foldedLineBreakEscapesWhitespace() -> Bool {
            guard inDouble, escaped else { return false }
            escaped = false
            return true
        }

        var quoteState: (inSingle: Bool, inDouble: Bool) {
            (inSingle, inDouble)
        }

        mutating func consume(_ value: String) {
            let characters = Array(value)
            var index = 0
            while index < characters.count, !invalid {
                let character = characters[index]
                if inDouble {
                    if escaped {
                        escaped = false
                    } else if character == "\\" {
                        escaped = true
                    } else if character == "\"" {
                        inDouble = false
                    }
                    index += 1
                    continue
                }
                if inSingle {
                    if character == "'" {
                        if index + 1 < characters.count, characters[index + 1] == "'" {
                            index += 2
                            continue
                        }
                        inSingle = false
                    }
                    index += 1
                    continue
                }

                switch character {
                case "\"":
                    inDouble = true
                case "'":
                    inSingle = true
                case "{":
                    stack.append("}")
                case "[":
                    stack.append("]")
                case "}", "]":
                    if stack.last == character {
                        stack.removeLast()
                    } else {
                        invalid = true
                    }
                default:
                    break
                }
                index += 1
            }
        }
    }

    /// PyYAML wraps large flow collections at its configured width. Rejoin
    /// only lines that begin with a mapping/sequence value and have balanced
    /// flow delimiters; ordinary block YAML retains its physical line shape.
    private static func logicalLines(from text: String) -> [(indent: Int, content: String)] {
        var lines: [(indent: Int, content: String)] = []
        var pending: PendingFlowLine?

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(rawLine)
            let stripped = line.trimmingCharacters(in: .whitespaces)

            if var continuation = pending {
                if !continuation.balance.isInsideQuote,
                   stripped.isEmpty || stripped.hasPrefix("#") {
                    continue
                }
                let escapedLineBreak = continuation.balance.foldedLineBreakEscapesWhitespace()
                if escapedLineBreak {
                    if let last = continuation.parts.indices.last,
                       continuation.parts[last].last == "\\" {
                        continuation.parts[last].removeLast()
                    }
                } else {
                    continuation.parts.append(" ")
                    continuation.balance.consume(" ")
                }
                let quoteState = continuation.balance.quoteState
                let content = stripInlineComment(
                    stripped,
                    startingInSingle: quoteState.inSingle,
                    startingInDouble: quoteState.inDouble
                ).trimmingCharacters(in: .whitespaces)
                continuation.parts.append(content)
                continuation.balance.consume(content)
                switch continuation.balance.state {
                case .open:
                    pending = continuation
                case .complete, .invalid:
                    lines.append((continuation.indent, continuation.content))
                    pending = nil
                }
                continue
            }

            if stripped.isEmpty || stripped.hasPrefix("#") || stripped == "---" { continue }
            let indent = line.prefix { $0 == " " }.count
            let content = stripInlineComment(stripped).trimmingCharacters(in: .whitespaces)
            guard !content.isEmpty else { continue }

            guard let candidate = flowCandidate(in: content) else {
                lines.append((indent, content))
                continue
            }
            var balance = FlowBalance()
            balance.consume(candidate)
            if balance.state == .open {
                pending = PendingFlowLine(indent: indent, parts: [content], balance: balance)
            } else {
                lines.append((indent, content))
            }
        }
        if let pending { lines.append((pending.indent, pending.content)) }
        return lines
    }

    private static func flowCandidate(in content: String) -> String? {
        if content.hasPrefix("- ") {
            let candidate = String(content.dropFirst(2)).trimmingCharacters(in: .whitespaces)
            return candidate.first == "{" || candidate.first == "[" ? candidate : nil
        } else if let colon = findColon(content) {
            let candidate = String(content[content.index(after: colon)...])
                .trimmingCharacters(in: .whitespaces)
            return candidate.first == "{" || candidate.first == "[" ? candidate : nil
        }
        return nil
    }

    private static func parseBlock(lines: [(indent: Int, content: String)], index: inout Int, indent: Int) -> YAMLNode {
        var map: [String: YAMLNode] = [:]
        var seq: [YAMLNode] = []
        var isSequence: Bool?

        while index < lines.count {
            let (lineIndent, content) = lines[index]
            if lineIndent < indent { break }
            if lineIndent > indent { // shouldn't happen at well-formed entry point; skip
                index += 1
                continue
            }
            if content.hasPrefix("- ") || content == "-" {
                if isSequence == false { break }
                isSequence = true
                let inline = String(content.dropFirst(2)).trimmingCharacters(in: .whitespaces)
                index += 1
                if inline.isEmpty {
                    seq.append(parseBlock(lines: lines, index: &index, indent: nextIndent(lines, index, greaterThan: indent)))
                } else if inline.hasPrefix("{") || inline.hasPrefix("[") {
                    seq.append(inlineNode(inline))
                } else if let colon = findColon(inline) {
                    // "- key: value" — sequence of mappings; gather subsequent deeper keys
                    var item: [String: YAMLNode] = [:]
                    let key = unquote(String(inline[..<colon]))
                    let value = String(inline[inline.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                    item[key] = value.isEmpty
                        ? parseBlock(lines: lines, index: &index, indent: nextIndent(lines, index, greaterThan: indent))
                        : inlineNode(value)
                    while index < lines.count, lines[index].indent > indent, !lines[index].content.hasPrefix("- ") {
                        let sub = lines[index]
                        if let c = findColon(sub.content) {
                            let k = unquote(String(sub.content[..<c]))
                            let v = String(sub.content[sub.content.index(after: c)...]).trimmingCharacters(in: .whitespaces)
                            index += 1
                            item[k] = v.isEmpty
                                ? parseBlock(lines: lines, index: &index, indent: nextIndent(lines, index, greaterThan: sub.indent))
                                : inlineNode(v)
                        } else { index += 1 }
                    }
                    seq.append(.mapping(item))
                } else {
                    seq.append(inlineNode(inline))
                }
            } else if let colon = findColon(content) {
                if isSequence == true { break }
                isSequence = false
                let key = unquote(String(content[..<colon]))
                let value = String(content[content.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                index += 1
                if value.isEmpty {
                    map[key] = parseBlock(lines: lines, index: &index, indent: nextIndent(lines, index, greaterThan: indent))
                } else {
                    map[key] = inlineNode(value)
                }
            } else {
                index += 1 // unrecognized line — skip
            }
        }
        if isSequence == true { return .sequence(seq) }
        return .mapping(map)
    }

    /// DefenseClaw preserves compact flow style when it expands seed values
    /// such as `observability: {}`. Parse those generated collections while
    /// leaving quoted values such as `"{}"` as ordinary strings.
    private static func inlineNode(_ raw: String) -> YAMLNode {
        let value = raw.trimmingCharacters(in: .whitespaces)
        let syntax = stripInlineComment(value).trimmingCharacters(in: .whitespaces)
        let isQuoted = (syntax.hasPrefix("\"") && syntax.hasSuffix("\""))
            || (syntax.hasPrefix("'") && syntax.hasSuffix("'"))
        if !isQuoted {
            var parser = FlowParser(syntax)
            if let node = parser.parse() { return node }
        }
        return .scalar(unquote(value))
    }

    /// Bounded parser for the flow mappings/sequences produced by the runtime.
    /// A collection is accepted only when the complete value parses, so a
    /// truncated config remains a scalar and InstallationContext fails closed.
    private struct FlowParser {
        private static let maximumDepth = 32
        private static let maximumSourceBytes = 4 * 1024 * 1024
        private static let maximumNodes = 65_536
        private static let maximumMappingEntries = 1_024

        private let characters: [Character]
        private let sourceByteCount: Int
        private var index = 0
        private var nodeCount = 0

        init(_ value: String) {
            characters = Array(value)
            sourceByteCount = value.utf8.count
        }

        mutating func parse() -> YAMLNode? {
            guard sourceByteCount <= Self.maximumSourceBytes else { return nil }
            skipWhitespace()
            guard let first = peek(), first == "{" || first == "[",
                  let node = parseValue(depth: 0)
            else { return nil }
            skipWhitespace()
            return index == characters.count ? node : nil
        }

        private mutating func parseValue(depth: Int) -> YAMLNode? {
            guard depth <= Self.maximumDepth, nodeCount < Self.maximumNodes else { return nil }
            nodeCount += 1
            skipWhitespace()
            guard let character = peek() else { return nil }
            switch character {
            case "{":
                return parseMapping(depth: depth)
            case "[":
                return parseSequence(depth: depth)
            case "\"", "'":
                return parseQuotedScalar().map(YAMLNode.scalar)
            default:
                return parsePlainScalar().map(YAMLNode.scalar)
            }
        }

        private mutating func parseMapping(depth: Int) -> YAMLNode? {
            guard consume("{") else { return nil }
            skipWhitespace()
            if consume("}") { return .mapping([:]) }

            var mapping: [String: YAMLNode] = [:]
            while true {
                let quotedKey = peek() == "\"" || peek() == "'"
                guard let key = parseMappingKey() else { return nil }
                guard key != "<<", nodeCount < Self.maximumNodes else { return nil }
                nodeCount += 1
                if !quotedKey, !plainMappingKeyIsString(key) { return nil }
                skipWhitespace()
                guard consume(":") else { return nil }
                if !quotedKey, let next = peek(),
                   !next.isWhitespace && next != "{" && next != "[" {
                    return nil
                }
                guard let value = parseValue(depth: depth + 1) else { return nil }
                guard mapping[key] == nil,
                      mapping.count < Self.maximumMappingEntries
                else { return nil }
                mapping[key] = value
                skipWhitespace()
                if consume("}") { return .mapping(mapping) }
                guard consume(",") else { return nil }
                skipWhitespace()
                if consume("}") { return .mapping(mapping) }
            }
        }

        private mutating func parseSequence(depth: Int) -> YAMLNode? {
            guard consume("[") else { return nil }
            skipWhitespace()
            if consume("]") { return .sequence([]) }

            var sequence: [YAMLNode] = []
            while true {
                guard sequence.count < Self.maximumNodes else { return nil }
                guard let value = parseValue(depth: depth + 1) else { return nil }
                sequence.append(value)
                skipWhitespace()
                if consume("]") { return .sequence(sequence) }
                guard consume(",") else { return nil }
                skipWhitespace()
                if consume("]") { return .sequence(sequence) }
            }
        }

        private mutating func parseMappingKey() -> String? {
            skipWhitespace()
            if peek() == "\"" || peek() == "'" {
                return parseQuotedScalar()
            }

            var key = ""
            while let character = peek(), character != ":" {
                guard !["{", "}", "[", "]", ","].contains(character) else { return nil }
                key.append(character)
                index += 1
            }
            let trimmed = key.trimmingCharacters(in: .whitespaces)
            return trimmed.isEmpty ? nil : trimmed
        }

        private func plainMappingKeyIsString(_ key: String) -> Bool {
            let lowercased = key.lowercased()
            if ["<<", "=", "~", "null", "true", "false", "yes", "no", "on", "off"].contains(lowercased) {
                return false
            }
            if key.hasPrefix("!") || key.hasPrefix("&") || key.hasPrefix("*") {
                return false
            }

            if isImplicitYAMLNumber(key) { return false }
            if key.range(
                of: #"^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:$|[Tt \t])"#,
                options: .regularExpression
            ) != nil {
                return false
            }
            return true
        }

        private func isImplicitYAMLNumber(_ value: String) -> Bool {
            // Match PyYAML's YAML 1.1 implicit int/float resolvers. Swift's
            // Double parser is intentionally not used: values such as `1e2`,
            // `inf`, and `Infinity` are valid unquoted string keys in YAML.
            let integer = #"^[+-]?(?:0|[1-9][0-9_]*|0b[0-1_]+|0[0-7_]+|0x[0-9a-fA-F_]+|[1-9][0-9_]*(?::[0-5]?[0-9])+)$"#
            let float = #"^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?:[eE][-+][0-9]+)|[-+]?\.[0-9_]+(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$"#
            return value.range(of: integer, options: .regularExpression) != nil
                || value.range(of: float, options: .regularExpression) != nil
        }

        private mutating func parseQuotedScalar() -> String? {
            guard let quote = peek(), quote == "\"" || quote == "'" else { return nil }
            index += 1
            var value = ""

            while let character = peek() {
                index += 1
                if character == quote {
                    if quote == "'", peek() == "'" {
                        value.append("'")
                        index += 1
                        continue
                    }
                    return value
                }
                if character == "\\", quote == "\"" {
                    guard let escaped = parseDoubleQuotedEscape() else { return nil }
                    value.append(escaped)
                    continue
                }
                value.append(character)
            }
            return nil
        }

        private mutating func parseDoubleQuotedEscape() -> String? {
            guard let escape = peek() else { return nil }
            index += 1
            switch escape {
            case "0": return "\0"
            case "a": return "\u{0007}"
            case "b": return "\u{0008}"
            case "t": return "\t"
            case "n": return "\n"
            case "v": return "\u{000B}"
            case "f": return "\u{000C}"
            case "r": return "\r"
            case "e": return "\u{001B}"
            case " ": return " "
            case "\"": return "\""
            case "/": return "/"
            case "\\": return "\\"
            case "N": return "\u{0085}"
            case "_": return "\u{00A0}"
            case "L": return "\u{2028}"
            case "P": return "\u{2029}"
            case "x": return parseUnicodeEscape(digitCount: 2)
            case "u": return parseUnicodeEscape(digitCount: 4)
            case "U": return parseUnicodeEscape(digitCount: 8)
            default: return nil
            }
        }

        private mutating func parseUnicodeEscape(digitCount: Int) -> String? {
            guard index + digitCount <= characters.count else { return nil }
            let digits = String(characters[index..<(index + digitCount)])
            guard digits.allSatisfy(\.isHexDigit),
                  let value = UInt32(digits, radix: 16),
                  let scalar = UnicodeScalar(value)
            else { return nil }
            index += digitCount
            return String(scalar)
        }

        private mutating func parsePlainScalar() -> String? {
            var value = ""
            while let character = peek(), ![",", "]", "}"].contains(character) {
                if character == ":", let next = peek(offset: 1),
                   next.isWhitespace || [",", "]", "}"].contains(next) {
                    return nil
                }
                value.append(character)
                index += 1
            }
            let trimmed = value.trimmingCharacters(in: .whitespaces)
            return trimmed.isEmpty ? nil : trimmed
        }

        private mutating func skipWhitespace() {
            while peek()?.isWhitespace == true { index += 1 }
        }

        private func peek(offset: Int = 0) -> Character? {
            let target = index + offset
            guard characters.indices.contains(target) else { return nil }
            return characters[target]
        }

        private mutating func consume(_ expected: Character) -> Bool {
            guard peek() == expected else { return false }
            index += 1
            return true
        }
    }

    private static func stripInlineComment(
        _ value: String,
        startingInSingle: Bool = false,
        startingInDouble: Bool = false
    ) -> String {
        let characters = Array(value)
        var inSingle = startingInSingle
        var inDouble = startingInDouble
        var escaped = false
        var previous: Character?
        var index = 0
        while index < characters.count {
            let character = characters[index]
            if inDouble {
                if escaped {
                    escaped = false
                } else if character == "\\" {
                    escaped = true
                } else if character == "\"" {
                    inDouble = false
                }
            } else if inSingle {
                if character == "'" {
                    if index + 1 < characters.count, characters[index + 1] == "'" {
                        previous = "'"
                        index += 2
                        continue
                    }
                    inSingle = false
                }
            } else if character == "'" {
                inSingle = true
            } else if character == "\"" {
                inDouble = true
            } else if character == "#", previous?.isWhitespace == true {
                return String(characters[..<index])
            }
            previous = character
            index += 1
        }
        return value
    }

    private static func boundedNodeCount(_ root: YAMLNode) -> Int? {
        var count = 0
        var pending = [root]
        while let node = pending.popLast() {
            count += 1
            guard count <= maximumNodes else { return nil }
            switch node {
            case .scalar:
                break
            case .sequence(let values):
                pending.append(contentsOf: values)
            case .mapping(let values):
                // The runtime's node budget includes mapping-key scalar nodes.
                count += values.count
                guard count <= maximumNodes else { return nil }
                pending.append(contentsOf: values.values)
            }
        }
        return count
    }

    private static func nextIndent(_ lines: [(indent: Int, content: String)], _ index: Int, greaterThan indent: Int) -> Int {
        guard index < lines.count, lines[index].indent > indent else { return indent + 2 }
        return lines[index].indent
    }

    /// First colon that terminates a key (colon followed by space or EOL), outside quotes.
    private static func findColon(_ s: String) -> String.Index? {
        var inSingle = false, inDouble = false
        var i = s.startIndex
        while i < s.endIndex {
            let ch = s[i]
            if ch == "'" && !inDouble { inSingle.toggle() }
            if ch == "\"" && !inSingle { inDouble.toggle() }
            if ch == ":" && !inSingle && !inDouble {
                let next = s.index(after: i)
                if next == s.endIndex || s[next] == " " { return i }
            }
            i = s.index(after: i)
        }
        return nil
    }

    private static func unquote(_ s: String) -> String {
        var t = ""
        var inSingle = false
        var inDouble = false
        var escaped = false
        for character in s {
            if escaped {
                t.append(character)
                escaped = false
                continue
            }
            if character == "\\" && inDouble {
                t.append(character)
                escaped = true
                continue
            }
            if character == "'" && !inDouble { inSingle.toggle() }
            if character == "\"" && !inSingle { inDouble.toggle() }
            if character == "#" && !inSingle && !inDouble,
               t.last?.isWhitespace == true {
                break
            }
            t.append(character)
        }
        t = t.trimmingCharacters(in: .whitespaces)
        if t.count >= 2, (t.hasPrefix("\"") && t.hasSuffix("\"")) || (t.hasPrefix("'") && t.hasSuffix("'")) {
            t = String(t.dropFirst().dropLast())
        }
        return t
    }
}

/// Writes sensitive exports without ever installing a permissive inode at the
/// destination path. The complete payload is prepared in the destination
/// directory with mode 0600, then atomically renamed into place.
enum SecureFileWriter {
    enum WriteError: LocalizedError {
        case parentIsNotDirectory(String)
        case couldNotCreateTemporaryFile(String)
        case insecurePreparedFile(String)
        case insecureExtendedACL(String)

        var errorDescription: String? {
            switch self {
            case .parentIsNotDirectory(let path):
                "Secure output parent is not a directory: \(path)"
            case .couldNotCreateTemporaryFile(let path):
                "Could not create secure temporary file: \(path)"
            case .insecurePreparedFile(let path):
                "Refusing to install a temporary file without mode 0600: \(path)"
            case .insecureExtendedACL(let path):
                "Refusing secure output because an extended ACL is present: \(path)"
            }
        }
    }

    static func write(_ contents: String, to target: URL) throws {
        try write(Data(contents.utf8), to: target)
    }

    /// `preparedFileCheck` is a regression-test seam invoked after the file is
    /// fully written and synced, immediately before its atomic installation.
    static func write(
        _ data: Data,
        to target: URL,
        fileManager: FileManager = .default,
        preparedFileCheck: ((URL) throws -> Void)? = nil
    ) throws {
        let parent = target.deletingLastPathComponent()
        var isDirectory: ObjCBool = false
        if fileManager.fileExists(atPath: parent.path, isDirectory: &isDirectory) {
            guard isDirectory.boolValue else {
                throw WriteError.parentIsNotDirectory(parent.path)
            }
        } else {
            try fileManager.createDirectory(
                at: parent,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        // Existing DefenseClaw data directories may predate the secure-export
        // path, so tighten them before the temporary file is created.
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: parent.path)
        guard try !hasExtendedACL(at: parent) else {
            throw WriteError.insecureExtendedACL(parent.path)
        }

        let temporary = parent.appendingPathComponent(
            ".\(target.lastPathComponent).\(UUID().uuidString).tmp",
            isDirectory: false
        )
        defer { try? fileManager.removeItem(at: temporary) }

        guard fileManager.createFile(
            atPath: temporary.path,
            contents: nil,
            attributes: [.posixPermissions: 0o600]
        ) else {
            throw WriteError.couldNotCreateTemporaryFile(temporary.path)
        }
        // A concurrently introduced inheritable ACL must not survive on the
        // prepared inode even though the parent was checked immediately above.
        try clearExtendedACL(at: temporary)

        let handle = try FileHandle(forWritingTo: temporary)
        do {
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            throw error
        }

        let attributes = try fileManager.attributesOfItem(atPath: temporary.path)
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue
        guard permissions == 0o600 else {
            throw WriteError.insecurePreparedFile(temporary.path)
        }
        guard try !hasExtendedACL(at: temporary) else {
            throw WriteError.insecureExtendedACL(temporary.path)
        }
        try preparedFileCheck?(temporary)

        if fileManager.fileExists(atPath: target.path) {
            _ = try fileManager.replaceItemAt(
                target,
                withItemAt: temporary,
                backupItemName: nil,
                options: [.usingNewMetadataOnly]
            )
        } else {
            try fileManager.moveItem(at: temporary, to: target)
        }
    }

    private static func hasExtendedACL(at url: URL) throws -> Bool {
        let (acl, capturedErrno) = url.path.withCString { path in
            errno = 0
            let value = acl_get_file(path, ACL_TYPE_EXTENDED)
            return (value, errno)
        }
        guard let acl else {
            if capturedErrno == ENOENT || capturedErrno == EOPNOTSUPP { return false }
            throw posixError(code: capturedErrno, operation: "inspect ACL", path: url.path)
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        return true
    }

    private static func clearExtendedACL(at url: URL) throws {
        errno = 0
        let allocatedACL = acl_init(0)
        let allocationErrno = errno
        guard let emptyACL = allocatedACL else {
            throw posixError(code: allocationErrno, operation: "allocate empty ACL", path: url.path)
        }
        defer { acl_free(UnsafeMutableRawPointer(emptyACL)) }

        let (result, capturedErrno) = url.path.withCString { path in
            errno = 0
            let value = acl_set_file(path, ACL_TYPE_EXTENDED, emptyACL)
            return (value, errno)
        }
        guard result == 0 || capturedErrno == EOPNOTSUPP else {
            throw posixError(code: capturedErrno, operation: "clear ACL", path: url.path)
        }
    }

    private static func posixError(code: Int32, operation: String, path: String) -> NSError {
        NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(code),
            userInfo: [NSLocalizedDescriptionKey: "Could not \(operation) for \(path): \(String(cString: strerror(code)))"]
        )
    }
}

actor ConfigStore {
    private(set) var context: InstallationContext
    private(set) var config = DefenseClawConfig()

    init(context: InstallationContext) {
        self.context = context
    }

    /// Rebinding clears the last-good snapshot. Carrying a token or endpoint
    /// from the previous installation across a path change would be worse than
    /// briefly showing the new installation as unavailable.
    func rebind(to context: InstallationContext) {
        guard self.context != context else { return }
        self.context = context
        config = DefenseClawConfig()
    }

    var installPresent: Bool {
        FileManager.default.fileExists(atPath: context.configURL.path)
    }

    /// KEY=VALUE pairs from ~/.defenseclaw/.env — written by the Go gateway on
    /// first boot (firstboot.go::EnsureGatewayToken). The Python CLI loads this
    /// into os.environ before resolving the token; a GUI app inherits no shell
    /// environment, so we read the file directly. Process env still wins.
    private func loadDotEnv() -> [String: String] {
        let url = context.environmentURL
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [:] }
        var out: [String: String] = [:]
        for rawLine in text.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#"), let eq = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
            var value = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            if value.count >= 2, (value.hasPrefix("\"") && value.hasSuffix("\"")) || (value.hasPrefix("'") && value.hasSuffix("'")) {
                value = String(value.dropFirst().dropLast())
            }
            out[key] = value
        }
        return out
    }

    /// Upstream precedence ladder (config.py::resolved_token):
    /// 1. env var named by gateway.token_env  2. DEFENSECLAW_GATEWAY_TOKEN
    /// 3. OPENCLAW_GATEWAY_TOKEN              4. literal gateway.token
    private func resolveToken(root: YAMLNode, dotenv: [String: String]) -> String? {
        func env(_ key: String) -> String? {
            if let v = ProcessInfo.processInfo.environment[key], !v.isEmpty { return v }
            if let v = dotenv[key], !v.isEmpty { return v }
            return nil
        }
        if let name = root["gateway.token_env"]?.string, let v = env(name) { return v }
        if let v = env("DEFENSECLAW_GATEWAY_TOKEN") { return v }
        if let v = env("OPENCLAW_GATEWAY_TOKEN") { return v }
        return root["gateway.token"]?.string
    }

    @discardableResult
    func reload() -> DefenseClawConfig {
        let configURL = context.configURL
        guard let text = try? String(contentsOf: configURL, encoding: .utf8) else {
            // A temporary permission/read race must not wipe the last-good
            // token and endpoint. Reset only when the config was actually
            // removed (the normal first-run/uninstall state).
            if FileManager.default.fileExists(atPath: configURL.path) {
                config.loadError = "config.yaml exists but could not be read as UTF-8; using the last-good configuration"
                return config
            }
            config = DefenseClawConfig()
            return config
        }
        let root = MiniYAML.parse(text)
        var c = DefenseClawConfig()
        c.raw = root
        c.gatewayHost = root["gateway.host"]?.string ?? "127.0.0.1"
        c.gatewayPort = root["gateway.api_port"]?.int ?? root["gateway.port"]?.int ?? 18970
        c.gatewayToken = resolveToken(root: root, dotenv: loadDotEnv())
        c.connectorName = root["connector.name"]?.string ?? root["guardrail.connector"]?.string ?? root["connector"]?.string
        c.connectorMode = root["connector.mode"]?.string ?? root["claw.mode"]?.string ?? root["mode"]?.string
        c.guardrailEnabled = root["guardrail.enabled"]?.bool ?? false
        c.guardrailMode = root["guardrail.mode"]?.string
        c.guardrailPort = root["guardrail.port"]?.int
        if let packDir = root["guardrail.rule_pack_dir"]?.string, !packDir.isEmpty {
            c.guardrailRulePack = (packDir as NSString).lastPathComponent
        }
        // Source baseline only. Bucket and route overrides belong to the
        // runtime's canonical redaction-policy surface, not this YAML reader.
        c.redactionDefaultProfile = root["observability.defaults.redaction_profile"]?.string ?? ""
        c.hiltEnabled = root["hilt.enabled"]?.bool ?? false
        c.hiltMinSeverity = root["hilt.min_severity"]?.string ?? "HIGH"
        c.environment = root["environment"]?.string
        c.policyDir = root["policy_dir"]?.string
        c.dataDir = root["data_dir"]?.string
        c.llmProvider = root["llm.provider"]?.string ?? root["inspect_llm.provider"]?.string
        c.llmModel = root["llm.model"]?.string ?? root["inspect_llm.model"]?.string
        c.aiDefenseEndpoint = root["cisco_ai_defense.endpoint"]?.string
        c.clawMode = root["claw.mode"]?.string ?? "openclaw"
        // Multi-connector roster (guardrail.connectors: {codex: {...}, ...}),
        // plus each connector's mode and rule pack for the Overview table.
        if root["guardrail.connectors"] != nil, root["guardrail.connectors"]?.mapping == nil {
            c.rosterError = "guardrail.connectors is not a mapping"
        }
        if let roster = root["guardrail.connectors"]?.mapping {
            c.connectors = roster.keys.sorted()
            for (name, node) in roster {
                guard let fields = node.mapping else { continue }
                c.connectorModes[name] = fields["mode"]?.string ?? ""
                if let packDir = fields["rule_pack_dir"]?.string, !packDir.isEmpty {
                    c.connectorRulePacks[name] = (packDir as NSString).lastPathComponent
                }
                // Only an explicit false disables (default true).
                if fields["enabled"]?.bool == false {
                    c.connectorDisabled.insert(name)
                }
            }
        }
        if let sources = root["registries.sources"]?.sequence ?? root["registries"]?.sequence {
            var parsedSources: [DefenseClawConfig.RegistrySourceConfig] = []
            for node in sources {
                guard let fields = node.mapping else { continue }
                let id = fields["id"]?.string?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                guard !id.isEmpty else { continue }
                let source = DefenseClawConfig.RegistrySourceConfig(
                    id: id,
                    kind: fields["kind"]?.string ?? "http_yaml",
                    content: fields["content"]?.string ?? "skill",
                    url: fields["url"]?.string ?? "",
                    authEnv: fields["auth_env"]?.string ?? "",
                    enabled: fields["enabled"]?.bool ?? true,
                    autoSync: fields["auto_sync"]?.bool ?? false,
                    syncIntervalHours: fields["sync_interval_hours"]?.int ?? 24,
                    lastSync: fields["last_sync"]?.string ?? "",
                    lastStatus: fields["last_status"]?.string ?? ""
                )
                parsedSources.append(source)
            }
            c.registrySources = parsedSources
        }
        for type in ["skill", "mcp", "plugin"] {
            c.registryRequiredByType[type] = root["asset_policy.\(type).registry_required"]?.bool ?? false
        }
        // Loopback only — refuse non-local gateway hosts (spec §11).
        if !["127.0.0.1", "localhost", "::1"].contains(c.gatewayHost) {
            c.gatewayHost = "127.0.0.1"
        }
        config = c
        return c
    }
}
