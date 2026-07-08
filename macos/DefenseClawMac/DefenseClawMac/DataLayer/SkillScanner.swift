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

// Filesystem connector catalogs — ports of the CLI's canonical discovery:
// skills from skill_list.py + connector_paths.skill_dirs, MCP servers from
// connector_paths.mcp_servers. Used when the gateway catalogs are
// unavailable: hook-based connectors (claudecode, codex, cursor, …) have no
// OpenClaw agent behind the gateway, so /skills and /mcps don't answer and
// the TUI/CLI read these per-connector files instead.

import Foundation

enum SkillScanner {
    /// Home-relative skill directories per connector (connector_paths.skill_dirs).
    /// Workspace-relative variants are omitted — the app has no project cwd.
    static func skillDirs(connector: String) -> [String] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        func p(_ parts: String...) -> String { ([home] + parts).joined(separator: "/") }
        switch connector.lowercased().replacingOccurrences(of: "-", with: "") {
        case "claudecode": return [p(".claude", "skills")]
        case "codex": return [p(".codex", "skills")]
        case "zeptoclaw": return [p(".zeptoclaw", "skills")]
        case "hermes": return [p(".hermes", "skills")]
        case "cursor": return [p(".cursor", "skills"), p(".agents", "skills")]
        case "geminicli": return [p(".gemini", "skills")]
        case "copilot": return [p(".copilot", "skills")]
        case "openhands":
            return [p(".agents", "skills"), p(".openhands", "skills"),
                    p(".openhands", "microagents"),
                    p(".openhands", "skills", "installed")]
        case "openclaw": return [p(".openclaw", "workspace", "skills")]
        default: return [] // windsurf, antigravity: no skills surface
        }
    }

    /// Walk every connector's skill dirs; one row per immediate subdirectory,
    /// deduped by name within a connector (parity with skill_list.py).
    static func scan(connectors: [String]) -> (items: [SkillItem], checkedDirs: [String]) {
        let fm = FileManager.default
        var items: [SkillItem] = []
        var checked: [String] = []
        for connector in connectors {
            var seen = Set<String>()
            for dir in skillDirs(connector: connector) {
                checked.append(dir)
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: dir, isDirectory: &isDir), isDir.boolValue,
                      let entries = try? fm.contentsOfDirectory(atPath: dir)
                else { continue }
                for entry in entries.sorted() {
                    // Parity with skill_list.py: dot-directories (e.g. .system)
                    // are listed too; only the openhands "installed" container
                    // is special-cased upstream, which we don't scan here.
                    let full = dir + "/" + entry
                    guard fm.fileExists(atPath: full, isDirectory: &isDir), isDir.boolValue,
                          seen.insert(entry).inserted
                    else { continue }
                    items.append(SkillItem(
                        key: "\(connector)/\(entry)",
                        name: entry,
                        version: "—",
                        source: dir,
                        enabled: isEligible(at: full),
                        skillDescription: readDescription(at: full),
                        connector: connector,
                        fromFilesystem: true
                    ))
                }
            }
        }
        return (items, checked)
    }

    /// skill_list._skill_dir_is_eligible: any recognized marker file.
    static func isEligible(at path: String) -> Bool {
        let fm = FileManager.default
        return ["SKILL.md", "skill.json", "README.md"].contains {
            fm.fileExists(atPath: path + "/" + $0)
        }
    }

    /// skill_list._read_skill_description: frontmatter `description:` from
    /// SKILL.md/README.md, else first non-empty line; bounded to 2 KiB.
    static func readDescription(at path: String) -> String {
        for marker in ["SKILL.md", "README.md"] {
            guard let handle = FileHandle(forReadingAtPath: path + "/" + marker) else { continue }
            defer { try? handle.close() }
            guard let data = try? handle.read(upToCount: 2048) else { continue }
            let text = String(decoding: data, as: UTF8.self)
            if let desc = frontmatterDescription(text), !desc.isEmpty {
                return String(desc.prefix(200))
            }
            for line in contentWithoutFrontmatter(text).split(separator: "\n") {
                let stripped = line.trimmingCharacters(in: .whitespaces)
                    .drop { $0 == "#" }
                    .trimmingCharacters(in: .whitespaces)
                if !stripped.isEmpty { return String(stripped.prefix(200)) }
            }
        }
        return ""
    }

    private static func frontmatterDescription(_ text: String) -> String? {
        guard text.hasPrefix("---"), let end = text.range(of: "\n---", range: text.index(text.startIndex, offsetBy: 3)..<text.endIndex)
        else { return nil }
        for line in text[text.index(text.startIndex, offsetBy: 3)..<end.lowerBound].split(separator: "\n") {
            guard let colon = line.firstIndex(of: ":") else { continue }
            if line[..<colon].trimmingCharacters(in: .whitespaces) == "description" {
                return line[line.index(after: colon)...]
                    .trimmingCharacters(in: .whitespaces)
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            }
        }
        return nil
    }

    private static func contentWithoutFrontmatter(_ text: String) -> Substring {
        guard text.hasPrefix("---"),
              let end = text.range(
                  of: "\n---",
                  range: text.index(text.startIndex, offsetBy: 3)..<text.endIndex
              )
        else { return text[...] }
        let bodyStart = text.index(end.upperBound, offsetBy: 0)
        return text[bodyStart...]
    }
}

// MARK: - MCP server discovery (connector_paths.mcp_servers)

enum MCPScanner {
    enum Format {
        case dotMCPJSON                  // {"mcpServers": {...}} or top-level name → server
        case settingsJSON([[String]])    // JSON file, servers under one of these key paths
        case codexTOML                   // [mcp_servers.<name>] tables
        case yaml([[String]])            // YAML file, servers under one of these key paths
    }

    /// Per-connector MCP registries (home-based; workspace files omitted).
    static func sources(connector: String) -> [(path: String, format: Format)] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        func p(_ parts: String...) -> String { ([home] + parts).joined(separator: "/") }
        switch connector.lowercased().replacingOccurrences(of: "-", with: "") {
        case "claudecode":
            return [(p(".claude", "settings.json"), .settingsJSON([["mcpServers"]]))]
        case "codex":
            return [(p(".codex", "config.toml"), .codexTOML)]
        case "zeptoclaw":
            return [(p(".zeptoclaw", "config.json"), .settingsJSON([["mcp", "servers"], ["mcpServers"]]))]
        case "hermes":
            return [(p(".hermes", "config.yaml"), .yaml([["mcp", "servers"], ["mcpServers"]]))]
        case "cursor":
            return [(p(".cursor", "mcp.json"), .dotMCPJSON)]
        case "windsurf":
            return [(p(".codeium", "windsurf", "mcp_config.json"), .dotMCPJSON)]
        case "geminicli":
            return [(p(".gemini", "settings.json"), .settingsJSON([["mcpServers"]]))]
        case "copilot":
            return [(p(".copilot", "mcp-config.json"), .dotMCPJSON)]
        case "openhands":
            return [(p(".openhands", "mcp.json"), .dotMCPJSON)]
        case "openclaw":
            return [(p(".openclaw", "openclaw.json"), .settingsJSON([["mcp", "servers"], ["mcpServers"]]))]
        default:
            return [] // antigravity: no documented MCP surface
        }
    }

    static func scan(connectors: [String]) -> (items: [MCPItem], checkedFiles: [String]) {
        var items: [MCPItem] = []
        var checked: [String] = []
        for connector in connectors {
            var seen = Set<String>()
            for source in sources(connector: connector) {
                checked.append(source.path)
                let servers: [String: [String: Any]]
                switch source.format {
                case .dotMCPJSON:
                    servers = readJSONServers(source.path, keyPaths: [["mcpServers"], []])
                case .settingsJSON(let keyPaths):
                    servers = readJSONServers(source.path, keyPaths: keyPaths)
                case .codexTOML:
                    servers = readCodexTOML(source.path)
                case .yaml(let keyPaths):
                    servers = readYAMLServers(source.path, keyPaths: keyPaths)
                }
                for (name, cfg) in servers.sorted(by: { $0.key < $1.key }) where seen.insert(name).inserted {
                    let command = (cfg["command"] as? String) ?? ""
                    let args = (cfg["args"] as? [String]) ?? []
                    let url = (cfg["url"] as? String) ?? ""
                    var transport = (cfg["transport"] as? String) ?? (cfg["type"] as? String) ?? ""
                    if transport.isEmpty { transport = url.isEmpty ? "stdio" : "http" }
                    let endpoint = url.isEmpty
                        ? ([command] + args).filter { !$0.isEmpty }.joined(separator: " ")
                        : url
                    items.append(MCPItem(
                        name: name,
                        transport: transport,
                        endpoint: endpoint.isEmpty ? "—" : endpoint,
                        version: "—",
                        enabled: true,
                        source: source.path,
                        connector: connector,
                        fromFilesystem: true
                    ))
                }
            }
        }
        return (items, checked)
    }

    /// JSON registries: try each key path (empty path = whole document is the
    /// name → server mapping, the bare .mcp.json convention).
    private static func readJSONServers(_ path: String, keyPaths: [[String]]) -> [String: [String: Any]] {
        guard let data = FileManager.default.contents(atPath: path),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return [:] }
        for keyPath in keyPaths {
            var node: Any = root
            for key in keyPath {
                guard let dict = node as? [String: Any], let next = dict[key] else { node = [:] ; break }
                node = next
            }
            if let mapping = node as? [String: [String: Any]], !mapping.isEmpty {
                // Bare-document form: only accept entries that look like servers.
                if keyPath.isEmpty {
                    let plausible = mapping.filter { $0.value["command"] != nil || $0.value["url"] != nil }
                    if !plausible.isEmpty { return plausible }
                } else {
                    return mapping
                }
            }
        }
        return [:]
    }

    /// Minimal TOML subset for Codex's documented schema:
    /// [mcp_servers.<name>] sections with command/url/transport strings and
    /// an args string-array. Inline env tables are ignored.
    private static func readCodexTOML(_ path: String) -> [String: [String: Any]] {
        guard let data = FileManager.default.contents(atPath: path) else { return [:] }
        let text = String(decoding: data, as: UTF8.self)
        var servers: [String: [String: Any]] = [:]
        var current: String?
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("["), line.hasSuffix("]") {
                let section = line.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
                if section.hasPrefix("mcp_servers.") {
                    let name = String(section.dropFirst("mcp_servers.".count))
                        .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                    // [mcp_servers.<name>.env] etc. are sub-tables of a server,
                    // not servers themselves — tomllib nests these upstream.
                    if name.contains(".") {
                        current = nil
                    } else {
                        current = name
                        if servers[name] == nil { servers[name] = [:] }
                    }
                } else {
                    current = nil
                }
                continue
            }
            guard let current, let eq = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
            let rawValue = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            if rawValue.hasPrefix("[") {
                // String array: args = ["-y", "server"]
                let inner = rawValue.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
                let parts = inner.split(separator: ",").map {
                    $0.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                }
                servers[current]?[key] = parts.filter { !$0.isEmpty }
            } else if rawValue.hasPrefix("\"") || rawValue.hasPrefix("'") {
                servers[current]?[key] = rawValue.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            }
        }
        return servers
    }

    /// Hermes-style YAML registries via the built-in MiniYAML parser.
    private static func readYAMLServers(_ path: String, keyPaths: [[String]]) -> [String: [String: Any]] {
        guard let data = FileManager.default.contents(atPath: path) else { return [:] }
        let root = MiniYAML.parse(String(decoding: data, as: UTF8.self))
        for keyPath in keyPaths {
            guard let node = root[keyPath.joined(separator: ".")], let mapping = node.mapping else { continue }
            var out: [String: [String: Any]] = [:]
            for (name, server) in mapping {
                guard let fields = server.mapping else { continue }
                var cfg: [String: Any] = [:]
                for key in ["command", "url", "transport", "type"] {
                    if let value = fields[key]?.string { cfg[key] = value }
                }
                if let args = fields["args"]?.sequence {
                    cfg["args"] = args.compactMap(\.string)
                }
                out[name] = cfg
            }
            if !out.isEmpty { return out }
        }
        return [:]
    }
}

// MARK: - Plugin discovery (connector_paths.plugin_dirs +
// claw_inventory._enumerate_plugins_filesystem)

enum PluginScanner {
    /// Per-connector plugin/extension directories (home-based).
    static func pluginDirs(connector: String) -> [String] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        func p(_ parts: String...) -> String { ([home] + parts).joined(separator: "/") }
        switch connector.lowercased().replacingOccurrences(of: "-", with: "") {
        case "claudecode": return [p(".claude", "plugins")]
        case "codex": return [p(".codex", "plugins"), p(".codex", "plugins", "cache")]
        case "zeptoclaw": return [p(".zeptoclaw", "plugins"), p(".zeptoclaw", "plugins", "cache")]
        case "hermes": return [p(".hermes", "plugins")]
        case "geminicli": return [p(".gemini", "extensions")]
        case "openclaw": return [p(".openclaw", "extensions")]
        default: return [] // cursor, windsurf, copilot, openhands, antigravity: no plugin surface
        }
    }

    /// Manifest names recognized upstream (plugin_scanner._MANIFEST_CANDIDATES).
    private static let manifestFiles = [
        "package.json", "manifest.json", "plugin.json", "openclaw.plugin.json",
        ".codex-plugin/plugin.json", ".claude-plugin/plugin.json",
    ]

    static func scan(connectors: [String]) -> (items: [PluginItem], checkedDirs: [String]) {
        let fm = FileManager.default
        var items: [PluginItem] = []
        var checked: [String] = []
        for connector in connectors {
            var seen = Set<String>()
            for dir in pluginDirs(connector: connector) {
                checked.append(dir)
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: dir, isDirectory: &isDir), isDir.boolValue,
                      let entries = try? fm.contentsOfDirectory(atPath: dir)
                else { continue }
                for entry in entries.sorted() {
                    // "cache" siblings hold transient downloads, not plugins.
                    guard entry != "cache" else { continue }
                    let full = dir + "/" + entry
                    guard fm.fileExists(atPath: full, isDirectory: &isDir), isDir.boolValue,
                          seen.insert(entry).inserted
                    else { continue }
                    let manifest = manifestFiles.first { fm.fileExists(atPath: full + "/" + $0) }
                    items.append(PluginItem(
                        name: entry,
                        version: manifestVersion(at: full, manifest: manifest) ?? "—",
                        category: manifest ?? "no manifest",
                        enabled: true,
                        source: dir,
                        connector: connector,
                        fromFilesystem: true,
                        hasManifest: manifest != nil
                    ))
                }
            }
        }
        return (items, checked)
    }

    private static func manifestVersion(at path: String, manifest: String?) -> String? {
        guard let manifest, manifest.hasSuffix(".json"),
              let data = FileManager.default.contents(atPath: path + "/" + manifest),
              data.count < 256 * 1024,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return obj["version"] as? String
    }
}
