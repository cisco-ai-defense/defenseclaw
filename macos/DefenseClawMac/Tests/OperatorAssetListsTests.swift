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

// Mirrors cli/defenseclaw/enforce/asset_lists.py (install_counts,
// merge_operator_entries) and enforce/policy.py (_tool_policy_entries,
// tool_rule_entries) on runtime 1.0.3.

import Foundation

@main
struct OperatorAssetListsTests {
    static func main() {
        operatorDecisionsAreCountedWithTheJournal()
        namesMatchTheRuntimeComparison()
        secureClientKeepsTheJournalOnly()
        enterpriseProfileFollowsTheRuntimeLadder()
        toolRulesComeFromConfigYAML()
        malformedListsAreIgnored()
        print("Operator asset list tests passed")
    }

    private static let config = MiniYAML.parse("""
    deployment_mode: unmanaged_byod
    asset_policy:
      enabled: true
      skill:
        default: allow
        denied:
          - name: Evil-Skill
            reason: scanner verdict
          - name: pentest
            connector: claude-code
            reason: operator block
        allowed:
          - name: trusted
      mcp:
        denied:
          - name: shady-mcp
        allowed:
          - name: filesystem
            connector: codex
          - name: ''
      tool:
        denied:
          - name: Bash
            reason: no shells
          - name: WebFetch
            connector: codex
        allowed:
          - name: Read
    """)

    private static func operatorDecisionsAreCountedWithTheJournal() {
        let lists = OperatorAssetLists.read(raw: config, environment: [:])
        expect(!lists.secureClient, "an unmanaged install folds the operator lists in")
        // Journal: a scan-verdict block that the operator later allowed by
        // name, plus an unrelated quarantine row with no install decision.
        let skills = [
            InstallJournalRow(name: "trusted", connector: "", install: "block"),
            InstallJournalRow(name: "quarantined", connector: "", install: ""),
        ]
        let mcps = [InstallJournalRow(name: "filesystem", connector: "codex", install: "block")]
        let counts = lists.installCounts(skills: skills, mcps: mcps)
        // Skills: Evil-Skill + pentest@claudecode blocked; trusted re-decided
        // to allow (one row, not two).
        expect(counts.blockedSkills == 2, "blocked skills fold the denied list: \(counts.blockedSkills)")
        expect(counts.allowedSkills == 1, "an allow rule re-decides the journal row: \(counts.allowedSkills)")
        // MCPs: shady-mcp blocked; filesystem@codex journal block overridden
        // by the allow rule; the unnamed rule is ignored.
        expect(counts.blockedMCPs == 1, "blocked MCPs: \(counts.blockedMCPs)")
        expect(counts.allowedMCPs == 1, "allowed MCPs: \(counts.allowedMCPs)")

        let journalOnly = OperatorAssetLists(secureClient: true, allowed: [:], denied: [:])
            .installCounts(skills: skills, mcps: mcps)
        expect(journalOnly.blockedSkills == 1 && journalOnly.allowedSkills == 0, "the bare journal counts stay the 0.x numbers")
    }

    private static func namesMatchTheRuntimeComparison() {
        let lists = OperatorAssetLists.read(raw: config, environment: [:])
        // asset_name_key: trimmed, NFC, lower-cased for skills/MCPs; the
        // connector compares through connector_paths.normalize.
        let merged = lists.mergedInstalls(
            journal: [InstallJournalRow(name: "evil-skill", connector: "", install: ""),
                      InstallJournalRow(name: "PENTEST", connector: "claudecode", install: "allow")],
            targetType: "skill"
        )
        expect(merged.count == 3, "case-insensitive matches merge instead of duplicating: \(merged.count)")
        expect(merged.first { $0.name == "evil-skill" }?.install == "block", "the denied rule sets the journal row's install")
        expect(merged.first { $0.name == "PENTEST" }?.install == "block", "claude-code and claudecode are the same connector")
        expect(OperatorAssetLists.assetNameKey("Caf\u{0065}\u{0301}", targetType: "skill") == "café", "NFC folding")
        expect(OperatorAssetLists.assetNameKey("Bash", targetType: "tool") == "Bash", "tool names compare exactly")
        expect(OperatorAssetLists.connectorKey("") == "", "an unscoped rule or row keys as empty (asset_lists._connector_key)")
        let unscoped = lists.mergedInstalls(
            journal: [InstallJournalRow(name: "trusted", connector: "openclaw", install: "block")], targetType: "skill")
        expect(unscoped.filter { $0.name.lowercased() == "trusted" }.count == 2, "an unscoped allow rule never re-decides an openclaw-scoped row: \(unscoped)")
        expect(OperatorAssetLists.connectorKey("Open-Hands") == "openhands", "connector aliases normalize")
    }

    private static func secureClientKeepsTheJournalOnly() {
        let secure = MiniYAML.parse("""
        deployment_mode: managed_enterprise
        enterprise:
          profile: secure_client
        asset_policy:
          skill:
            denied:
              - name: blocked-by-config
        """)
        let lists = OperatorAssetLists.read(raw: secure, environment: [:])
        expect(lists.secureClient, "secure_client is read from enterprise.profile")
        let counts = lists.installCounts(skills: [], mcps: [])
        expect(counts.blockedSkills == 0, "Secure Client keeps the actions table as the decision source")
        expect(lists.mergedInstalls(journal: [], targetType: "skill").isEmpty, "no fold on Secure Client")
    }

    private static func enterpriseProfileFollowsTheRuntimeLadder() {
        func profile(_ yaml: String, env: [String: String] = [:]) -> String {
            OperatorAssetLists.enterpriseProfile(raw: MiniYAML.parse(yaml), environment: env)
        }
        expect(profile("deployment_mode: unmanaged_byod") == "", "unmanaged installs have no profile")
        expect(profile("deployment_mode: managed_enterprise") == "secure_client", "macOS default profile is secure_client")
        expect(profile("deployment_mode: managed_enterprise\nenterprise:\n  profile: standalone") == "standalone", "the config's profile wins")
        expect(profile("deployment_mode: managed_enterprise", env: ["DEFENSECLAW_ENTERPRISE_PROFILE": "standalone"]) == "standalone", "the pin applies when nothing is configured")
        expect(profile("deployment_mode: managed_enterprise\nenterprise:\n  profile: secure_client",
                       env: ["DEFENSECLAW_ENTERPRISE_PROFILE": "standalone"]) == "secure_client",
               "a pin that contradicts the declared profile is ignored")
        expect(profile("deployment_mode: unmanaged_byod", env: ["DEFENSECLAW_ENTERPRISE_PROFILE": "secure_client"]) == "",
               "a pin cannot reclassify an unmanaged host")
    }

    private static func toolRulesComeFromConfigYAML() {
        let lists = OperatorAssetLists.read(raw: config, environment: [:])
        let rows = lists.toolRuleEntries()
        expect(rows.map(\.name) == ["Bash", "@codex/WebFetch", "Read"], "denied first, connector-scoped as @connector/name: \(rows.map(\.name))")
        expect(rows[0].state == .block && rows[0].summary == "no shells" && rows[0].scope == "global", "a global block keeps its reason")
        expect(rows[1].state == .block && rows[1].connector == "codex" && rows[1].scope == "connector", "a scoped rule names its connector")
        expect(rows[2].state == .allow && rows[2].signature.isEmpty, "config.yaml stores no time for a rule")
        expect(rows.allSatisfy { $0.usageCount == 0 }, "rules carry no usage")
        expect(OperatorAssetLists.read(raw: MiniYAML.parse("gateway:\n  port: 1"), environment: [:]).toolRuleEntries().isEmpty,
               "no asset_policy means no rules")
    }

    private static func malformedListsAreIgnored() {
        let odd = MiniYAML.parse("""
        asset_policy:
          skill:
            denied: not-a-list
            allowed:
              - just-a-string
              - name: ok
          mcp: 7
        """)
        let lists = OperatorAssetLists.read(raw: odd, environment: [:])
        expect(lists.denied["skill"]?.isEmpty == true, "a scalar where a list belongs yields no rules")
        expect(lists.allowed["skill"]?.map(\.name) == ["ok"], "entries that are not mappings are skipped")
        expect(lists.allowed["mcp"]?.isEmpty == true && lists.denied["mcp"]?.isEmpty == true, "a scalar type policy yields no rules")
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ label: String) {
        guard condition() else {
            fputs("FAILED: \(label)\n", stderr)
            exit(1)
        }
    }
}
