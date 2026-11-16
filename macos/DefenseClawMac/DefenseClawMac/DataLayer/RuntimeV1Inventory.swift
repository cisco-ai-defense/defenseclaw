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

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
import Foundation

/// Bounded read-only projections of the 1.0 TUI's IDE and agent identity rows.
enum RuntimeV1Inventory {
    /// Enabled cell for an IDE plugin row, as `defenseclaw agent ide-plugins`
    /// and the TUI word it (inventory_state.IDE_PLUGIN_ENABLED_LABELS).
    static let idePluginEnabledLabels = [
        "enabled": "yes", "disabled": "no", "client_side_unknown": "client side", "unknown": "unknown",
    ]
    /// IDE cell suffix for a plugin of a remote install (IDE_REMOTE_LABELS).
    static let ideRemoteLabels = ["ssh_server": "ssh", "jetbrains_remote_dev": "remote dev"]

    static func idePluginEnabledLabel(_ raw: String) -> String {
        raw.isEmpty ? "unknown" : (idePluginEnabledLabels[raw] ?? raw)
    }

    /// "<product> <version> (<location>)" (the TUI's IDEPluginRow.ide_label).
    static func ideLabel(product: String, version: String, scope: String, remoteKind: String) -> String {
        var label = version.isEmpty ? product : "\(product) \(version)"
        let location = remoteKind.isEmpty ? (scope == "remote" ? "remote" : "") : (ideRemoteLabels[remoteKind] ?? "remote")
        if !location.isEmpty { label += " (\(location))" }
        return label
    }

    static func ideRows(_ document: [String: Any]) -> [InventoryItem] {
        ((document["ide_plugins"] as? [[String: Any]]) ?? []).prefix(10_000).map { row in
            let name = text(row, "plugin_id", "display_name")
            let user = text(row, "user", "user_name", "user_id")
            let product = text(row, "ide_product", "ide_family")
            let ide = ideLabel(product: product, version: text(row, "ide_version"), scope: text(row, "scope"), remoteKind: text(row, "remote_kind"))
            let fields = projectedFields(row, keys: ["plugin_id", "display_name", "publisher", "version", "user", "user_name", "user_id", "ide_family", "ide_product", "ide_version", "enabled", "enabled_source", "scope", "remote_kind", "is_ai", "ai_signature_id", "installed_at", "last_seen", "fingerprint"])
            return InventoryItem(category: .idePlugins, name: name, version: text(row, "version"),
                path: [user, product, text(row, "scope"), text(row, "fingerprint")].joined(separator: "/"),
                detail: [ide, user, (row["is_ai"] as? Bool) == true ? "AI extension" : ""].filter { !$0.isEmpty }.joined(separator: " · "),
                status: idePluginEnabledLabel(text(row, "enabled")), fields: fields)
        }
    }

    /// Whether a document's IDE plugin inventory stopped at its bound
    /// (summary.ide_plugins.partial): the tab count reads "N+".
    static func idePluginsPartial(_ document: [String: Any]) -> Bool {
        (((document["summary"] as? [String: Any])?["ide_plugins"] as? [String: Any])?["partial"] as? Bool) ?? false
    }

    /// The summary's IDE plugin line, "N (X AI, Y disabled, Z users)"
    /// (inventory_state._ide_count_summary).
    static func ideCountSummary(_ rows: [InventoryItem]) -> String {
        let plugins = rows.filter { $0.category == .idePlugins }
        let ai = plugins.filter { $0.detail.contains("AI extension") }.count
        let disabled = plugins.filter { $0.status == "no" }.count
        let users = Set(plugins.compactMap { item in
            ["User", "User Name", "User Id"].lazy.compactMap { label in item.fields.first { $0.label == label }?.value }.first { !$0.isEmpty }
        }).count
        return "\(plugins.count) (\(ai) AI, \(disabled) disabled, \(users) user\(users == 1 ? "" : "s"))"
    }

    static func agentRows(_ output: String) -> (items: [InventoryItem], note: String)? {
        guard let object = InventoryOutputParser.firstJSONObject(in: output),
              let rows = object["identities"] as? [[String: Any]] else { return nil }
        let items = rows.prefix(1000).compactMap { row -> InventoryItem? in
            let id = text(row, "agent_id")
            guard !id.isEmpty else { return nil }
            return InventoryItem(category: .agents, name: id, version: "", path: "agent identity",
                detail: text(row, "user", "user_name", "user_id"), connector: text(row, "connector"), status: "observed",
                fields: projectedFields(row, keys: ["agent_id", "connector", "user", "user_name", "user_id", "first_seen", "last_seen", "sessions_seen"]))
        }
        let total = (object["total"] as? Int) ?? rows.count
        let note = total > items.count ? "Showing \(items.count) of \(total) agent identities (bounded to 1,000)." : ""
        return (items, note)
    }

    private static func text(_ row: [String: Any], _ keys: String...) -> String {
        keys.compactMap { row[$0] as? String }.first(where: { !$0.isEmpty }) ?? ""
    }

    private static func projectedFields(_ row: [String: Any], keys: [String]) -> [InventoryField] {
        keys.compactMap { key in
            guard let value = row[key], !(value is NSNull), value is String || value is NSNumber else { return nil }
            return InventoryField(label: key.replacingOccurrences(of: "_", with: " ").capitalized,
                                  value: String(describing: value))
        }
    }
}
