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

enum CatalogCLIError: LocalizedError {
    case commandFailed(String)
    case invalidJSON(String)

    var errorDescription: String? {
        switch self {
        case .commandFailed(let message): message
        case .invalidJSON(let message): "DefenseClaw returned invalid catalog JSON: \(message)"
        }
    }
}

enum CatalogCLI {
    static func skills(using cli: CLIRunner) async throws -> [SkillItem] {
        let groups = try await rows(resource: "skill", collection: "skills", using: cli)
        return groups.map { group, row in
            let connector = string(row["connector"]).nonEmpty ?? group
            let name = string(row["name"])
            let status = effectiveStatus(
                raw: string(row["status"]).nonEmpty ?? "inactive",
                actions: stringDict(row["actions"])
            )
            return SkillItem(
                key: connector.isEmpty ? name : "\(connector)/\(name)",
                name: name,
                version: string(row["version"]),
                source: string(row["source"]),
                enabled: bool(row["eligible"]) && !bool(row["disabled"]),
                skillDescription: string(row["description"]),
                connector: connector,
                status: status,
                verdict: string(row["verdict"]).nonEmpty ?? "-",
                scan: scan(row["scan"])
            )
        }
    }

    static func mcps(using cli: CLIRunner) async throws -> [MCPItem] {
        let groups = try await rows(resource: "mcp", collection: "mcp_servers", using: cli)
        return groups.map { group, row in
            let connector = string(row["connector"]).nonEmpty ?? group
            let endpoint = string(row["server_url"]).nonEmpty
                ?? string(row["url"]).nonEmpty
                ?? string(row["command"])
            // `mcp list --json` rows carry NO status field — governance state
            // lives solely in the actions dict (cmd_mcp._mcp_list_json_items).
            let status = effectiveStatus(
                raw: string(row["status"]).nonEmpty ?? "active",
                actions: stringDict(row["actions"])
            )
            return MCPItem(
                name: string(row["name"]),
                transport: string(row["transport"]).nonEmpty ?? (endpoint.hasPrefix("http") ? "http" : "stdio"),
                endpoint: endpoint,
                version: string(row["version"]),
                enabled: status != "disabled",
                source: string(row["source"]),
                connector: connector,
                status: status,
                verdict: string(row["verdict"]).nonEmpty ?? "-",
                scan: scan(row["scan"])
            )
        }
    }

    static func plugins(using cli: CLIRunner) async throws -> [PluginItem] {
        let groups = try await rows(resource: "plugin", collection: "plugins", using: cli)
        return groups.map { group, row in
            let connector = string(row["connector"]).nonEmpty ?? group
            let commandID = string(row["id"]).nonEmpty ?? string(row["name"])
            return PluginItem(
                name: string(row["name"]).nonEmpty ?? commandID,
                version: string(row["version"]),
                category: string(row["origin"]),
                enabled: bool(row["enabled"]),
                source: string(row["source"]),
                connector: connector,
                commandID: commandID,
                status: string(row["status"]),
                verdict: string(row["verdict"]).nonEmpty ?? "-",
                scan: scan(row["scan"])
            )
        }
    }

    static func tools(using cli: CLIRunner) async throws -> [ToolItem] {
        let groups = try await rows(resource: "tool", collection: "tools", using: cli)
        return groups.map { group, row in
            let connector = string(row["connector"]).nonEmpty ?? group
            let status = string(row["status"]).nonEmpty ?? "active"
            let name = string(row["name"]).nonEmpty ?? string(row["target_name"])
            return ToolItem(
                name: name,
                summary: string(row["reason"]),
                signature: "",
                state: toolState(status),
                usageCount: int(row["usage_count"]),
                connector: connector,
                scope: string(row["scope"]),
                commandTarget: string(row["target_name"]).nonEmpty ?? name
            )
        }
    }

    private static func rows(
        resource: String,
        collection: String,
        using cli: CLIRunner
    ) async throws -> [(String, [String: Any])] {
        let result = await cli.run(arguments: [resource, "list", "--json"])
        guard result.succeeded else {
            throw CatalogCLIError.commandFailed(result.output.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        let data = try jsonData(from: result.output)
        guard let payload = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            throw CatalogCLIError.invalidJSON("expected a top-level array")
        }

        var flattened: [(String, [String: Any])] = []
        for group in payload {
            let connector = string(group["connector"])
            if let nested = group[collection] as? [[String: Any]] {
                flattened += nested.map { (connector, $0) }
            } else if group["name"] != nil || group["target_name"] != nil {
                flattened.append((connector, group))
            }
        }
        return flattened
    }

    private static func jsonData(from output: String) throws -> Data {
        guard let start = output.firstIndex(of: "["), let end = output.lastIndex(of: "]"), start <= end else {
            throw CatalogCLIError.invalidJSON(String(output.prefix(240)))
        }
        return Data(output[start...end].utf8)
    }

    private static func scan(_ value: Any?) -> CatalogScanState? {
        guard let value = value as? [String: Any] else { return nil }
        return CatalogScanState(
            clean: bool(value["clean"]),
            maxSeverity: string(value["max_severity"]),
            totalFindings: int(value["total_findings"]),
            target: string(value["target"])
        )
    }

    private static func string(_ value: Any?) -> String {
        if let value = value as? String { return value }
        if let value { return String(describing: value) }
        return ""
    }

    private static func bool(_ value: Any?) -> Bool {
        if let value = value as? Bool { return value }
        if let value = value as? NSNumber { return value.boolValue }
        return ["true", "yes", "1", "enabled", "active"].contains(string(value).lowercased())
    }

    private static func int(_ value: Any?) -> Int {
        if let value = value as? Int { return value }
        if let value = value as? NSNumber { return value.intValue }
        return Int(string(value)) ?? 0
    }

    private static func toolState(_ status: String) -> ToolState {
        switch status.lowercased() {
        case "blocked", "block": .block
        case "allowed", "allow": .allow
        default: .observe
        }
    }

    /// Effective governance state for the Status column and action menus,
    /// mirroring the CLI's `_skill_status_display` precedence: the raw roster
    /// status (disabled flag / allowlist block) wins, then explicit action
    /// entries in `compute_verdict` order — quarantine > block > disable >
    /// allow. Skills' raw status is only disabled/blocked/active/inactive and
    /// MCP rows have no raw status at all, so quarantined/allowed can ONLY
    /// come from the actions dict.
    private static func effectiveStatus(raw: String, actions: [String: String]) -> String {
        let rawStatus = raw.lowercased()
        if rawStatus == "disabled" || rawStatus == "blocked" { return rawStatus }
        if actions["file"] == "quarantine" { return "quarantined" }
        if actions["install"] == "block" { return "blocked" }
        if actions["runtime"] == "disable" { return "disabled" }
        if actions["install"] == "allow" { return "allowed" }
        return raw
    }

    private static func stringDict(_ value: Any?) -> [String: String] {
        guard let value = value as? [String: Any] else { return [:] }
        return value.reduce(into: [:]) { result, item in
            let text = string(item.value)
            if !text.isEmpty { result[item.key] = text }
        }
    }
}

struct CatalogResourceAction: Identifiable, Hashable {
    var verb: String
    var label: String
    var detail: String
    var systemImage: String
    var readOnly: Bool = false
    var destructive: Bool = false
    var id: String { verb }
}

struct CatalogInvocation: Identifiable {
    var id = UUID()
    var title: String
    var arguments: [String]
    var detail: String
    var requiresConfirmation: Bool
    var destructive: Bool

    var displayCommand: String {
        (["defenseclaw"] + arguments).map(Self.quote).joined(separator: " ")
    }

    private static func quote(_ value: String) -> String {
        guard value.contains(where: { $0.isWhitespace || "'\"\\".contains($0) }) else { return value }
        return "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}

enum CatalogActions {
    static func skills(_ item: SkillItem) -> [CatalogResourceAction] {
        var actions = [
            action("scan", "Scan", "Run the skill security scan", "shield.lefthalf.filled", readOnly: true),
            action("info", "Info", "Show full skill details", "info.circle", readOnly: true),
        ]
        switch item.status.lowercased() {
        case "blocked":
            actions += [action("unblock", "Unblock", "Remove from the block list", "lock.open"),
                        action("allow", "Allow", "Pin as allow-listed", "checkmark.shield")]
        case "allowed":
            actions += [action("block", "Block", "Add to the block list", "nosign"),
                        action("disable", "Disable", "Disable at runtime", "pause.circle")]
        case "quarantined":
            actions += [action("restore", "Restore", "Restore from quarantine", "arrow.uturn.backward")]
        case "disabled":
            actions += [action("enable", "Enable", "Enable at runtime", "play.circle"),
                        action("block", "Block", "Add to the block list", "nosign")]
        default:
            actions += [
                action("block", "Block", "Add to the block list", "nosign"),
                action("allow", "Allow", "Add to the allow list", "checkmark.shield"),
                action("disable", "Disable", "Disable at runtime", "pause.circle"),
                action("quarantine", "Quarantine", "Move files to quarantine", "shippingbox.and.arrow.backward", destructive: true),
                action("install", "Install", "Install through ClawHub", "square.and.arrow.down"),
            ]
        }
        return actions
    }

    static func mcps(_ item: MCPItem) -> [CatalogResourceAction] {
        var actions = [
            action("scan", "Scan", "Run the MCP security scan", "shield.lefthalf.filled", readOnly: true),
            action("info", "Info", "Show MCP list details", "info.circle", readOnly: true),
        ]
        switch item.status.lowercased() {
        case "blocked":
            actions += [action("unblock", "Unblock", "Remove from the block list", "lock.open"),
                        action("unset", "Unset", "Remove from the connector configuration", "minus.circle", destructive: true)]
        case "allowed":
            actions += [action("block", "Block", "Add to the block list", "nosign"),
                        action("unset", "Unset", "Remove from the connector configuration", "minus.circle", destructive: true)]
        default:
            actions += [action("block", "Block", "Add to the block list", "nosign"),
                        action("allow", "Allow", "Add to the allow list", "checkmark.shield")]
        }
        return actions
    }

    static func plugins(_ item: PluginItem) -> [CatalogResourceAction] {
        var actions = [
            action("scan", "Scan", "Run the plugin security scan", "shield.lefthalf.filled", readOnly: true),
            action("info", "Info", "Show full plugin details", "info.circle", readOnly: true),
        ]
        if item.verdict.lowercased() == "blocked" {
            actions.append(action("unblock", "Unblock", "Remove from the block list", "lock.open"))
        } else if item.verdict.lowercased() == "allowed" {
            actions.append(action("block", "Block", "Add to the install block list", "nosign"))
        } else {
            actions += [action("block", "Block", "Add to the install block list", "nosign"),
                        action("allow", "Allow", "Add to the install allow list", "checkmark.shield")]
        }
        actions.append(item.enabled
            ? action("disable", "Disable", "Disable at runtime", "pause.circle")
            : action("enable", "Enable", "Enable at runtime", "play.circle"))
        actions.append(item.status.lowercased().contains("quarantine")
            ? action("restore", "Restore", "Restore from quarantine", "arrow.uturn.backward")
            : action("quarantine", "Quarantine", "Move files to quarantine", "shippingbox.and.arrow.backward", destructive: true))
        actions.append(action("remove", "Remove", "Delete plugin files from disk", "trash", destructive: true))
        return actions
    }

    static func tools(_ item: ToolItem) -> [CatalogResourceAction] {
        var actions = [action("status", "Info", "Show tool policy status", "info.circle", readOnly: true)]
        switch item.status.lowercased() {
        case "blocked":
            actions += [action("unblock", "Unblock", "Remove from block and allow lists", "lock.open"),
                        action("allow", "Allow", "Pin as allow-listed", "checkmark.shield")]
        case "allowed":
            actions += [action("unblock", "Unblock", "Remove from block and allow lists", "lock.open"),
                        action("block", "Block", "Add to the tool block list", "nosign")]
        default:
            actions += [action("block", "Block", "Add to the tool block list", "nosign"),
                        action("allow", "Allow", "Pin as allow-listed", "checkmark.shield")]
        }
        return actions
    }

    static func invocation(_ action: CatalogResourceAction, skill: SkillItem) -> CatalogInvocation {
        invocation(action, resource: "skill", target: skill.name, connector: skill.connector)
    }

    static func invocation(_ action: CatalogResourceAction, mcp: MCPItem) -> CatalogInvocation {
        if action.verb == "info" {
            var args = ["mcp", "list"]
            appendConnector(mcp.connector, to: &args)
            return make(action, arguments: args, target: mcp.name)
        }
        return invocation(action, resource: "mcp", target: mcp.name, connector: mcp.connector)
    }

    static func invocation(_ action: CatalogResourceAction, plugin: PluginItem) -> CatalogInvocation {
        let verb = action.verb == "unblock" ? "allow" : action.verb
        return invocation(action, resource: "plugin", verb: verb,
                          target: plugin.commandID.nonEmpty ?? plugin.name, connector: plugin.connector)
    }

    static func invocation(_ action: CatalogResourceAction, tool: ToolItem) -> CatalogInvocation {
        invocation(action, resource: "tool", target: tool.commandTarget.nonEmpty ?? tool.name, connector: tool.connector)
    }

    private static func invocation(
        _ action: CatalogResourceAction,
        resource: String,
        verb: String? = nil,
        target: String,
        connector: String
    ) -> CatalogInvocation {
        var args = [resource, verb ?? action.verb, target]
        appendConnector(connector, to: &args)
        return make(action, arguments: args, target: target)
    }

    private static func appendConnector(_ connector: String, to args: inout [String]) {
        if !connector.isEmpty { args += ["--connector", connector] }
    }

    private static func make(
        _ action: CatalogResourceAction,
        arguments: [String],
        target: String
    ) -> CatalogInvocation {
        CatalogInvocation(
            title: "\(action.label) \(target)",
            arguments: arguments,
            detail: action.detail,
            requiresConfirmation: !action.readOnly,
            destructive: action.destructive
        )
    }

    private static func action(
        _ verb: String,
        _ label: String,
        _ detail: String,
        _ image: String,
        readOnly: Bool = false,
        destructive: Bool = false
    ) -> CatalogResourceAction {
        CatalogResourceAction(verb: verb, label: label, detail: detail, systemImage: image,
                              readOnly: readOnly, destructive: destructive)
    }
}
