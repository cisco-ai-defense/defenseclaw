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

@main
struct ConnectorInventoryCompatibilityTests {
    static func main() {
        runtimeV1Inventory()
        skillDirectoriesMatchCurrentConnectors()
        mcpSourcesMatchCurrentConnectors()
        print("ConnectorInventoryCompatibilityTests passed")
    }

    private static func runtimeV1Inventory() {
        let alerts = RuntimeV1Alerts.parse(#"[{"id":"compat","timestamp":"2026-10-12T12:00:00Z","action":"tool-result-pii-alert","severity":"ERROR","target":"tool","agent_identity_id":"agent-1","decision":"result withheld","secret":"never project"}]"#)
        expect(alerts?.first?.severity == .high && alerts?.first?.target == "tool", "canonical compatibility alerts retain actionable severity and target")
        expect(alerts?.first?.runtimeFacts.contains { $0.value == "agent-1" } == true, "canonical alert agent attribution is retained")
        expect(alerts?.first?.runtimeFacts.contains { $0.value == "never project" } == false, "alert projection omits unlisted metadata")
        let blocked = RuntimeV1Alerts.parse(#"[{"id":"finding","timestamp":"2026-10-12T12:00:00Z","action":"scan-finding","severity":"HIGH","decision":"blocked (action mode)"}]"#)!.first!
        expect(blocked.isBlockClass && AlertRow.audit(blocked).kind == "scan", "canonical findings retain scan and block filters")
        expect(RuntimeV1Alerts.parse("[]")?.isEmpty == true, "valid empty alert queue")
        expect(RuntimeV1Alerts.parse(#"[{"id":"broken"}]"#) == nil, "malformed alerts are not clean success")
        let rows = RuntimeV1Inventory.ideRows(["ide_plugins": [["plugin_id": "fixture.ai", "ide_product": "Code", "user_name": "fixture", "enabled": "disabled", "is_ai": true, "version": "2.0", "secret": "never project"]]])
        expect(rows.count == 1 && rows[0].category == .idePlugins, "IDE-only scan is represented")
        // Enablement reads as `defenseclaw agent ide-plugins` words it (yes / no / client side / unknown).
        expect(rows[0].status == "no" && rows[0].detail.contains("AI extension"), "IDE filter fields retain enablement and AI classification: \(rows[0].status)")
        let remote = RuntimeV1Inventory.ideRows(["ide_plugins": [["plugin_id": "x", "ide_product": "PyCharm", "ide_version": "2026.2", "remote_kind": "jetbrains_remote_dev", "enabled": "client_side_unknown", "user": "a"],
                                                                 ["plugin_id": "y", "ide_product": "Code", "scope": "remote", "user": "b"]],
                                                 "summary": ["ide_plugins": ["partial": true]]])
        expect(remote[0].status == "client side" && remote[0].detail.hasPrefix("PyCharm 2026.2 (remote dev)"), "a remote-dev plugin names its IDE, version and location: \(remote[0].detail)")
        expect(remote[1].status == "unknown" && remote[1].detail.hasPrefix("Code (remote)"), "a remote scope without a kind reads remote: \(remote[1].detail)")
        expect(RuntimeV1Inventory.idePluginsPartial(["summary": ["ide_plugins": ["partial": true]]]) && !RuntimeV1Inventory.idePluginsPartial([:]), "a bounded scan is partial")
        expect(RuntimeV1Inventory.ideCountSummary(rows + remote) == "3 (1 AI, 1 disabled, 3 users)", "IDE count summary: \(RuntimeV1Inventory.ideCountSummary(rows + remote))")
        expect(rows[0].fields.contains { $0.value == "fixture" }, "IDE user identity is retained")
        expect(!rows[0].fields.contains { $0.value == "never project" }, "only allowlisted IDE fields are displayed")
        let result = RuntimeV1Inventory.agentRows(#"{"identities":[{"agent_id":"agent-1","connector":"codex","user_id":"fixture","sessions_seen":3}],"total":20,"next_cursor":"next"}"#)
        expect(result?.items.first?.name == "agent-1" && result?.items.first?.connector == "codex", "stable agent ids retain connector scope")
        expect(result?.note.contains("1 of 20") == true, "bounded identity lists disclose omitted rows")
        expect(RuntimeV1Inventory.agentRows("not JSON") == nil, "malformed identities are not empty success")
        expect(RuntimeV1Inventory.agentRows(#"{"identities":[]}"#)?.items.isEmpty == true, "empty valid identity inventory is accepted")
    }

    private static func skillDirectoriesMatchCurrentConnectors() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        expect(
            SkillScanner.skillDirs(connector: "devin")
                == ["\(home)/.config/devin/skills", "\(home)/.agents/skills"],
            "Devin skill directories match the current runtime contract"
        )
        expect(
            SkillScanner.skillDirs(connector: "antigravity")
                == ["\(home)/.gemini/config/skills", "\(home)/.gemini/antigravity-cli/skills"],
            "Antigravity skill directories match the current runtime contract"
        )
        expect(
            SkillScanner.skillDirs(connector: "amp")
                == [
                    "\(home)/.config/agents/skills",
                    "\(home)/.agents/skills",
                    "\(home)/.config/amp/skills",
                    "\(home)/.claude/skills",
                ],
            "Amp skill directories match the current runtime contract"
        )
        let codex = SkillScanner.skillDirs(connector: "codex")
        expect(codex.first == "\(home)/.agents/skills", "Codex shared skill directory is retained")
        expect(codex.count == 2 && codex.last?.hasSuffix("/skills") == true, "Codex home skill directory is retained")
    }

    private static func mcpSourcesMatchCurrentConnectors() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        expect(
            MCPScanner.sources(connector: "devin").map(\.path)
                == [
                    "\(home)/.config/devin/mcp_config.json",
                    "\(home)/.config/devin/config.json",
                ],
            "Devin MCP sources match the current runtime contract"
        )
        expect(
            MCPScanner.sources(connector: "antigravity").map(\.path)
                == ["\(home)/.gemini/config/mcp_config.json"],
            "Antigravity MCP source matches the current runtime contract"
        )
        expect(
            MCPScanner.sources(connector: "amp").map(\.path)
                == [
                    "\(home)/.config/amp/settings.json",
                    "\(home)/.config/amp/settings.jsonc",
                ],
            "Amp MCP sources match the current runtime contract"
        )
        let opencode = MCPScanner.sources(connector: "opencode").map(\.path)
        expect(
            opencode == [
                "\(home)/.config/opencode/config.json",
                "\(home)/.config/opencode/opencode.json",
                "\(home)/.config/opencode/opencode.jsonc",
                "\(home)/.opencode/opencode.json",
                "\(home)/.opencode/opencode.jsonc",
            ],
            "OpenCode MCP sources match the current runtime contract"
        )
        expect(
            MCPScanner.sources(connector: "codex").first?.path.hasSuffix("/.codex/config.toml") == true,
            "Codex MCP source uses config.toml"
        )
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else {
            fputs("FAILED: \(message)\n", stderr)
            exit(1)
        }
    }
}
