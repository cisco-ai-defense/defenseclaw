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

// Operator block/allow lists in config.yaml `asset_policy` — the runtime's
// cli/defenseclaw/enforce/asset_lists.py.
//
// Since config_version 9 (runtime 1.0.x) `asset_policy.<type>.denied/allowed`
// (and `asset_policy.tool`) are the only operator block/allow source: `skill
// block`, `mcp allow`, `tool block` and the catalog actions write config.yaml,
// not audit.db. The audit.db `actions` table is the enforcement journal (scan
// verdicts, quarantine, runtime disable). Secure Client hosts keep the actions
// table unchanged, so every reader folds the lists in only when the install
// is not Secure Client (asset_lists.merge_operator_entries, install_counts,
// enforce/policy.py tool_rule_entries).

import Foundation

/// One `asset_policy.<type>.allowed/denied` rule (config.py AssetPolicyRule;
/// only the keys the list readers use).
struct OperatorAssetRule: Sendable, Hashable {
    var name: String
    var connector: String
    var reason: String
}

/// An audit.db `actions` row reduced to what the install counts need.
struct InstallJournalRow: Sendable, Hashable {
    var name: String
    var connector: String
    /// `actions_json.install`: "block", "allow", or "" when the row carries
    /// no install decision.
    var install: String
}

struct OperatorAssetLists: Sendable, Hashable {
    static let assetTypes = ["skill", "mcp", "plugin", "tool"]

    /// Secure Client hosts keep the audit.db rows as the decision source.
    var secureClient: Bool
    var allowed: [String: [OperatorAssetRule]]
    var denied: [String: [OperatorAssetRule]]

    /// admission.asset_name_key: skill, MCP and plugin names compare trimmed,
    /// Unicode NFC and lower-cased; tool names compare exactly.
    static func assetNameKey(_ name: String, targetType: String) -> String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if targetType == "tool" { return trimmed }
        return trimmed.precomposedStringWithCanonicalMapping.lowercased()
    }

    /// asset_lists._connector_key: "" for an unscoped rule or row, otherwise
    /// connector_paths.normalize (the canonical lowercase name). An unscoped
    /// rule never matches an openclaw-scoped row, as in the runtime.
    static func connectorKey(_ connector: String) -> String {
        let name = connector.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        switch name {
        case "": return ""
        case "open-hands", "open_hands": return "openhands"
        case "claude-code", "claude_code": return "claudecode"
        default: return name
        }
    }

    /// asset_lists.merge_operator_entries: each named rule sets the install
    /// decision of the journal row with the same name and connector, or
    /// becomes a row of its own. Secure Client keeps the journal as is.
    func mergedInstalls(journal: [InstallJournalRow], targetType: String) -> [InstallJournalRow] {
        var out = journal
        guard !secureClient else { return out }
        for (decision, rules) in [("allow", allowed[targetType] ?? []), ("block", denied[targetType] ?? [])] {
            for rule in rules {
                let nameKey = Self.assetNameKey(rule.name, targetType: targetType)
                let connectorKey = Self.connectorKey(rule.connector)
                if let index = out.firstIndex(where: {
                    Self.assetNameKey($0.name, targetType: targetType) == nameKey
                        && Self.connectorKey($0.connector) == connectorKey
                }) {
                    out[index].install = decision
                } else {
                    out.append(InstallJournalRow(name: rule.name, connector: rule.connector, install: decision))
                }
            }
        }
        return out
    }

    /// asset_lists.install_counts: (blocked skills, allowed skills, blocked
    /// MCPs, allowed MCPs) as the list views count them.
    func installCounts(
        skills: [InstallJournalRow],
        mcps: [InstallJournalRow]
    ) -> (blockedSkills: Int, allowedSkills: Int, blockedMCPs: Int, allowedMCPs: Int) {
        let mergedSkills = mergedInstalls(journal: skills, targetType: "skill")
        let mergedMCPs = mergedInstalls(journal: mcps, targetType: "mcp")
        return (
            blockedSkills: mergedSkills.filter { $0.install == "block" }.count,
            allowedSkills: mergedSkills.filter { $0.install == "allow" }.count,
            blockedMCPs: mergedMCPs.filter { $0.install == "block" }.count,
            allowedMCPs: mergedMCPs.filter { $0.install == "allow" }.count
        )
    }

    /// enforce/policy.py _tool_policy_entries: the `asset_policy.tool` rules
    /// as Tools rows. A rule scoped to a connector is shown as
    /// `@<connector>/<name>`; config.yaml stores no time for a rule, so the
    /// row carries no "updated" signature.
    func toolRuleEntries() -> [ToolItem] {
        var out: [ToolItem] = []
        for (decision, rules) in [(ToolState.block, denied["tool"] ?? []), (ToolState.allow, allowed["tool"] ?? [])] {
            for rule in rules {
                let target = rule.connector.isEmpty ? rule.name : "@\(rule.connector)/\(rule.name)"
                out.append(ToolItem(
                    name: target,
                    summary: rule.reason,
                    signature: "",
                    state: decision,
                    usageCount: 0,
                    connector: rule.connector,
                    scope: rule.connector.isEmpty ? "global" : "connector",
                    commandTarget: target
                ))
            }
        }
        return out
    }
}
