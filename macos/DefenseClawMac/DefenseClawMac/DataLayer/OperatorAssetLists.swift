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
    /// Unicode NFC and case-folded the way Go `strings.EqualFold` folds
    /// (runtime 1.0.4+: final sigma, capital sigma and sigma are one letter,
    /// the Kelvin sign is a k); tool names compare exactly.
    static func assetNameKey(_ name: String, targetType: String) -> String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if targetType == "tool" { return trimmed }
        return GoCaseFold.fold(trimmed.precomposedStringWithCanonicalMapping)
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

/// Go's `strings.EqualFold` folding, scalar by scalar, as the runtime's
/// `admission.asset_name_key` applies it through `_asset_name_fold.py`
/// (generated from Go's unicode tables, Unicode 15.0.0). Foundation's
/// `folding(options: .caseInsensitive)` is full case folding (ß → ss,
/// ﬁ → fi, İ → i̇), which Go never does: a rule and a journal row would
/// match here but not in the gateway, so the simple table is used instead.
enum GoCaseFold {
    /// start:count:stride:delta runs (start in hex): count code points from
    /// start, stride apart, each folding to itself plus delta. Keep identical
    /// to the runtime's FOLD_RUNS.
    static let runs = """
    41:26:1:32 c0:23:1:32 d8:7:1:32 100:24:2:1 132:3:2:1 139:8:2:1 14a:23:2:1 178:1:1:-121 179:3:2:1
    17f:1:1:-268 181:1:1:210 182:2:2:1 186:1:1:206 187:1:1:1 189:2:1:205 18b:1:1:1 18e:1:1:79
    18f:1:1:202 190:1:1:203 191:1:1:1 193:1:1:205 194:1:1:207 196:1:1:211 197:1:1:209 198:1:1:1
    19c:1:1:211 19d:1:1:213 19f:1:1:214 1a0:3:2:1 1a6:1:1:218 1a7:1:1:1 1a9:1:1:218 1ac:1:1:1
    1ae:1:1:218 1af:1:1:1 1b1:2:1:217 1b3:2:2:1 1b7:1:1:219 1b8:2:4:1 1c4:1:1:2 1c5:1:1:1 1c7:1:1:2
    1c8:1:1:1 1ca:1:1:2 1cb:9:2:1 1de:9:2:1 1f1:1:1:2 1f2:2:2:1 1f6:1:1:-97 1f7:1:1:-56 1f8:20:2:1
    220:1:1:-130 222:9:2:1 23a:1:1:10795 23b:1:1:1 23d:1:1:-163 23e:1:1:10792 241:1:1:1 243:1:1:-195
    244:1:1:69 245:1:1:71 246:5:2:1 370:2:2:1 376:1:1:1 37f:1:1:116 386:1:1:38 388:3:1:37 38c:1:1:64
    38e:2:1:63 391:8:1:32 399:1:1:-84 39a:2:1:32 39c:1:1:-743 39d:5:1:32 3a3:9:1:32 3b9:1:1:-116
    3bc:1:1:-775 3c2:1:1:1 3cf:1:1:8 3d0:1:1:-30 3d1:1:1:-25 3d5:1:1:-15 3d6:1:1:-22 3d8:12:2:1
    3f0:1:1:-54 3f1:1:1:-48 3f4:1:1:-60 3f5:1:1:-64 3f7:1:1:1 3f9:1:1:-7 3fa:1:1:1 3fd:3:1:-130
    400:16:1:80 410:32:1:32 460:17:2:1 48a:27:2:1 4c0:1:1:15 4c1:7:2:1 4d0:48:2:1 531:38:1:48
    10a0:38:1:7264 10c7:2:6:7264 13a0:80:1:38864 13f0:6:1:8 1c80:1:1:-6222 1c81:1:1:-6221 1c82:1:1:-6212
    1c83:2:1:-6210 1c85:1:1:-6211 1c86:1:1:-6204 1c87:1:1:-6180 1c90:43:1:-3008 1cbd:3:1:-3008
    1e00:75:2:1 1e9b:1:1:-58 1e9e:1:1:-7615 1ea0:48:2:1 1f08:8:1:-8 1f18:6:1:-8 1f28:8:1:-8 1f38:8:1:-8
    1f48:6:1:-8 1f59:4:2:-8 1f68:8:1:-8 1f88:8:1:-8 1f98:8:1:-8 1fa8:8:1:-8 1fb8:2:1:-8 1fba:2:1:-74
    1fbc:1:1:-9 1fbe:1:1:-7289 1fc8:4:1:-86 1fcc:1:1:-9 1fd8:2:1:-8 1fda:2:1:-100 1fe8:2:1:-8
    1fea:2:1:-112 1fec:1:1:-7 1ff8:2:1:-128 1ffa:2:1:-126 1ffc:1:1:-9 2126:1:1:-7517 212a:1:1:-8383
    212b:1:1:-8262 2132:1:1:28 2160:16:1:16 2183:1:1:1 24b6:26:1:26 2c00:48:1:48 2c60:1:1:1
    2c62:1:1:-10743 2c63:1:1:-3814 2c64:1:1:-10727 2c67:3:2:1 2c6d:1:1:-10780 2c6e:1:1:-10749
    2c6f:1:1:-10783 2c70:1:1:-10782 2c72:2:3:1 2c7e:2:1:-10815 2c80:50:2:1 2ceb:2:2:1 2cf2:2:31054:1
    a642:4:2:1 a64a:1:1:-35266 a64b:1:1:-35267 a64c:17:2:1 a680:14:2:1 a722:7:2:1 a732:31:2:1 a779:2:2:1
    a77d:1:1:-35332 a77e:5:2:1 a78b:1:1:1 a78d:1:1:-42280 a790:2:2:1 a796:10:2:1 a7aa:1:1:-42308
    a7ab:1:1:-42319 a7ac:1:1:-42315 a7ad:1:1:-42305 a7ae:1:1:-42308 a7b0:1:1:-42258 a7b1:1:1:-42282
    a7b2:1:1:-42261 a7b3:1:1:928 a7b4:8:2:1 a7c4:1:1:-48 a7c5:1:1:-42307 a7c6:1:1:-35384 a7c7:2:2:1
    a7d0:2:6:1 a7d8:2:29:1 ff21:26:1:32 10400:40:1:40 104b0:36:1:40 10570:11:1:39 1057c:15:1:39
    1058c:7:1:39 10594:2:1:39 10c80:51:1:64 118a0:32:1:32 16e40:32:1:32 1e900:34:1:34
    """

    static let table: [UInt32: UInt32] = {
        var fold: [UInt32: UInt32] = [:]
        for run in runs.split(whereSeparator: { $0 == " " || $0 == "\n" }) {
            let parts = run.split(separator: ":")
            guard parts.count == 4,
                  let start = UInt32(parts[0], radix: 16),
                  let count = Int(parts[1]), let stride = Int(parts[2]), let delta = Int(parts[3]) else { continue }
            for i in 0..<count {
                let code = Int(start) + i * stride
                fold[UInt32(code)] = UInt32(code + delta)
            }
        }
        return fold
    }()

    static func fold(_ text: String) -> String {
        var scalars = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            if let mapped = table[scalar.value], let folded = Unicode.Scalar(mapped) {
                scalars.append(folded)
            } else {
                scalars.append(scalar)
            }
        }
        return String(scalars)
    }
}
