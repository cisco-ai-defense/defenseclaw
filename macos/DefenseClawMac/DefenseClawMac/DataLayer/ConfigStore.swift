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

// Reads ~/.defenseclaw/config.yaml — the same source of truth the TUI uses.
// Minimal YAML subset parser (nested block mappings, scalars, simple lists),
// sufficient for the keys the app consumes. Writes never go through this
// store; they go via the gateway (/config/patch) or the defenseclaw CLI.

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
    var redactionEnabled = true              // privacy.disable_redaction (inverted)
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
    /// Parses block-style YAML mappings/sequences with plain or quoted scalars.
    /// Ignores comments, documents markers, anchors, and flow collections —
    /// adequate for defenseclaw's generated config.yaml.
    static func parse(_ text: String) -> YAMLNode {
        var lines: [(indent: Int, content: String)] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(rawLine)
            let stripped = line.trimmingCharacters(in: .whitespaces)
            if stripped.isEmpty || stripped.hasPrefix("#") || stripped == "---" { continue }
            let indent = line.prefix { $0 == " " }.count
            lines.append((indent, stripped))
        }
        var index = 0
        return parseBlock(lines: lines, index: &index, indent: 0)
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
                } else if let colon = findColon(inline) {
                    // "- key: value" — sequence of mappings; gather subsequent deeper keys
                    var item: [String: YAMLNode] = [:]
                    let key = unquote(String(inline[..<colon]))
                    let value = String(inline[inline.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                    item[key] = value.isEmpty
                        ? parseBlock(lines: lines, index: &index, indent: nextIndent(lines, index, greaterThan: indent))
                        : .scalar(unquote(value))
                    while index < lines.count, lines[index].indent > indent, !lines[index].content.hasPrefix("- ") {
                        let sub = lines[index]
                        if let c = findColon(sub.content) {
                            let k = unquote(String(sub.content[..<c]))
                            let v = String(sub.content[sub.content.index(after: c)...]).trimmingCharacters(in: .whitespaces)
                            index += 1
                            item[k] = v.isEmpty
                                ? parseBlock(lines: lines, index: &index, indent: nextIndent(lines, index, greaterThan: sub.indent))
                                : .scalar(unquote(v))
                        } else { index += 1 }
                    }
                    seq.append(.mapping(item))
                } else {
                    seq.append(.scalar(unquote(inline)))
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
                    map[key] = .scalar(unquote(value))
                }
            } else {
                index += 1 // unrecognized line — skip
            }
        }
        if isSequence == true { return .sequence(seq) }
        return .mapping(map)
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

        var errorDescription: String? {
            switch self {
            case .parentIsNotDirectory(let path):
                "Secure output parent is not a directory: \(path)"
            case .couldNotCreateTemporaryFile(let path):
                "Could not create secure temporary file: \(path)"
            case .insecurePreparedFile(let path):
                "Refusing to install a temporary file without mode 0600: \(path)"
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
}

actor ConfigStore {
    static let dataDirectory = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".defenseclaw")

    /// Cheap change signature over config.yaml + .env (mtime/size) so the
    /// pulse can re-resolve the gateway token and config when either file
    /// changes out-of-band (token rotation, setup commands, the TUI).
    static var diskSignature: String {
        [configURL, dataDirectory.appendingPathComponent(".env")].map { url in
            let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
            let mtime = (attrs?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
            let size = (attrs?[.size] as? Int) ?? 0
            return "\(url.lastPathComponent):\(mtime):\(size)"
        }.joined(separator: "|")
    }
    static let configURL = dataDirectory.appendingPathComponent("config.yaml")
    static let auditDBURL = dataDirectory.appendingPathComponent("audit.db")
    static let gatewayJSONLURL = dataDirectory.appendingPathComponent("gateway.jsonl")
    static let gatewayLogURL = dataDirectory.appendingPathComponent("gateway.log")
    static let watchdogLogURL = dataDirectory.appendingPathComponent("watchdog.log")

    private(set) var config = DefenseClawConfig()

    var installPresent: Bool {
        FileManager.default.fileExists(atPath: Self.configURL.path)
    }

    /// KEY=VALUE pairs from ~/.defenseclaw/.env — written by the Go gateway on
    /// first boot (firstboot.go::EnsureGatewayToken). The Python CLI loads this
    /// into os.environ before resolving the token; a GUI app inherits no shell
    /// environment, so we read the file directly. Process env still wins.
    private func loadDotEnv() -> [String: String] {
        let url = Self.dataDirectory.appendingPathComponent(".env")
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
        guard let text = try? String(contentsOf: Self.configURL, encoding: .utf8) else {
            // A temporary permission/read race must not wipe the last-good
            // token and endpoint. Reset only when the config was actually
            // removed (the normal first-run/uninstall state).
            if FileManager.default.fileExists(atPath: Self.configURL.path) {
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
        // Global posture for the Overview CONFIGURATION box.
        c.redactionEnabled = !(root["privacy.disable_redaction"]?.bool ?? false)
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
