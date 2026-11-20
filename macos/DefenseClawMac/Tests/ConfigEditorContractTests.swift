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

// Config editor contracts against runtime 1.0.3: config_writer.restart_required
// (config_diff.py save_label), tui/panels/setup.py _rebase_config_draft, and
// tui/app.py _config_error_summary.

import Foundation

@main
struct ConfigEditorContractTests {
    static func main() {
        expect(ConfigEditorCatalog.connectors == ["openclaw", "zeptoclaw", "codex", "claudecode", "hermes", "cursor", "devin", "copilot", "antigravity", "opencode", "amp", "kiro"],
               "offline connector choices match runtime 1.0.5")
        decisionModelFieldsValidateLikeTheRuntime()
        gatewayTokenLadderSkipsSecretRefText()
        activeConnectorFollowsTheRuntimeRule()
        unlinkedScannersCountAsInstalled()
        runtimeOverviewSummaryParsesBoundedOutput()
        clawModeNamesOpenClawOnlyWhenItIsInstalled()
        restartIsQueuedOnlyForKeysTheGatewayReadsAtStart()
        anOpenDraftSurvivesADiskGeneration()
        invalidConfigIsNamedWithItsLine()
        print("Config editor contract tests passed")
    }

    private static func decisionModelFieldsValidateLikeTheRuntime() {
        expect(ConfigRestartPolicy.restartRequired(["guardrail.protected_files"]) == ["guardrail.protected_files"], "1.0.7 adds guardrail.protected_files to RESTART_KEYS")
        let section = ConfigEditorCatalog.sections(activeConnectors: ["codex"], config: .mapping([:])).first { $0.name == "Decision Model" }
        expect(section?.fields.map(\.key).contains("decision_model.base_url") == true, "the offline catalog offers the Decision Model section")
        func check(_ key: String, _ value: String) -> String? {
            let field = ConfigEditorField(label: key, key: key, kind: .string)
            let result = ConfigFieldValidation.validate(field, value: value)
            return result.isError ? result.message : nil
        }
        expect(check("decision_model.allow_threshold", "0.3") == nil && check("decision_model.allow_threshold", "1.5") != nil && check("decision_model.timeout", "12") == nil
               && check("decision_model.timeout", "31") != nil && check("decision_model.block_threshold", "x") != nil, "fractions and seconds are range-checked like setup_state")
        expect(check("decision_model.base_url", "https://model.example/v1") == nil && check("decision_model.base_url", "http://127.0.0.1:8000/v1") == nil
               && check("decision_model.base_url", "http://model.example/v1") != nil, "http is loopback-only for the decision model endpoint")
    }

    /// config.py::resolved_token (1.0.7): SecretRef text a 1.0.5/1.0.6 build
    /// saved as a token is never one, at any rung of the ladder.
    private static func gatewayTokenLadderSkipsSecretRefText() {
        let secretRef = "{'source': 'env', 'name': 'TOKEN'}"
        expect(GatewayTokenLadder.isSecretRefText(secretRef), "the Python repr of a SecretRef is never a token")
        expect(GatewayTokenLadder.isSecretRefText(#"{"name": "X", "source" : "keychain"}"#), "the JSON form in any key order, spaces before the colon")
        expect(!GatewayTokenLadder.isSecretRefText("dc_live_source:abc"), "a token that mentions source is a token")
        expect(!GatewayTokenLadder.isSecretRefText("{abc}"), "braces alone are not a SecretRef")
        var env = ["OPENCLAW_GATEWAY_TOKEN": secretRef]
        expect(GatewayTokenLadder.resolve(tokenEnvName: nil, literal: "literal-token") { env[$0] } == "literal-token",
               "SecretRef text in .env falls through to the next rung")
        env["DEFENSECLAW_GATEWAY_TOKEN"] = "real-token"
        expect(GatewayTokenLadder.resolve(tokenEnvName: "MY_TOKEN", literal: nil) { env[$0] } == "real-token",
               "an unset gateway.token_env name falls through to the canonical name")
        env["MY_TOKEN"] = "pinned"
        expect(GatewayTokenLadder.resolve(tokenEnvName: "MY_TOKEN", literal: nil) { env[$0] } == "pinned", "gateway.token_env always wins")
        expect(GatewayTokenLadder.resolve(tokenEnvName: nil, literal: secretRef) { _ in nil } == nil,
               "a SecretRef saved as gateway.token is unauthenticated, not a token")
        expect(GatewayTokenLadder.resolve(tokenEnvName: nil, literal: "") { _ in nil } == nil, "an empty literal is no token")
    }

    /// config.active_connector() (1.0.7): guardrail.connector → roster → claw.mode.
    private static func activeConnectorFollowsTheRuntimeRule() {
        var config = DefenseClawConfig()
        expect(config.activeConnector == "", "an unconfigured install selects no connector")
        config.clawMode = " Claude-Code "
        expect(config.activeConnector == "claudecode", "claw.mode is normalized like connector_paths.normalize")
        config.connectors = ["kiro", "codex"]
        expect(config.activeConnector == "codex", "a roster that does not list claw.mode picks its first sorted name")
        config.clawMode = "kiro"
        expect(config.activeConnector == "kiro", "claw.mode wins when the roster lists it")
        config.raw = MiniYAML.parse("guardrail:\n  connector: Cursor\n")
        expect(config.activeConnector == "cursor", "guardrail.connector outranks the roster")
        config.connectorModes = ["kiro": "action"]
        config.guardrailMode = "observe"
        expect(config.effectiveGuardrailMode(for: "kiro") == "action" && config.effectiveGuardrailMode(for: "codex") == "observe",
               "the connector wizard seeds a connector's effective mode (override, else global)")
        config.guardrailMode = nil
        expect(config.effectiveGuardrailMode(for: "codex") == "observe", "no mode anywhere means observe")
    }

    /// 1.0.7 resolve_scanner_binary: the runtime runs the venv copy next to its
    /// own entry point even when nothing linked it into PATH.
    private static func unlinkedScannersCountAsInstalled() {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("dc-scanner-\(getpid())")
        defer { try? FileManager.default.removeItem(at: dir) }
        let name = "dc-test-scanner-\(getpid())"
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            for file in ["defenseclaw", name] {
                let url = dir.appendingPathComponent(file)
                try "#!/bin/sh\n".write(to: url, atomically: true, encoding: .utf8)
                try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
            }
        } catch {
            expect(false, "scanner fixture is writable: \(error)")
            return
        }
        let cli = dir.appendingPathComponent("defenseclaw").path
        expect(ScannerProbe.locate(name, cliPath: cli) == .unlinked(dir.appendingPathComponent(name).path), "the venv sibling is found next to the CLI")
        expect(ScannerProbe.available(name, cliPath: cli, shellFound: []), "the runtime runs its venv copy, so it is available")
        expect(!ScannerProbe.available(name, cliPath: nil, shellFound: []), "no CLI, no venv copy")
        expect(ScannerProbe.available(name, cliPath: nil, shellFound: [name]), "a shell-resolved copy is available")
    }

    /// Config.has_connector_configured / _mark_openclaw_not_installed (GAP-0568):
    /// the loader's "openclaw" default names a connector only while OpenClaw is
    /// on the machine; the roster, guardrail.connector or any other mode always do.
    private static func clawModeNamesOpenClawOnlyWhenItIsInstalled() {
        var config = DefenseClawConfig()
        config.clawMode = "openclaw"
        expect(config.hasConnectorConfigured && config.activeConnector == "openclaw" && config.displayClawMode == "openclaw",
               "the loader default names OpenClaw while OpenClaw is installed")
        config.openclawNotInstalled = true
        expect(!config.hasConnectorConfigured && config.activeConnector == "" && config.displayClawMode == "",
               "a claw.mode that only implies an absent OpenClaw configures nothing")
        config.raw = MiniYAML.parse("guardrail:\n  connector: openclaw\n")
        expect(config.hasConnectorConfigured && config.activeConnector == "openclaw",
               "setup openclaw pins guardrail.connector, which keeps the connector")
        config.raw = .mapping([:])
        config.connectors = ["codex"]
        expect(config.activeConnector == "codex" && config.displayClawMode == "openclaw", "a roster keeps the connector")
        config.connectors = []
        config.clawMode = "codex"
        expect(config.hasConnectorConfigured && config.activeConnector == "codex", "an explicit non-OpenClaw mode is never gated")
        config.clawMode = ""
        expect(!config.hasConnectorConfigured && config.activeConnector == "", "setup remove leaves claw.mode empty: no connector")

        expect(!OpenClawPresence.fleetLinkConfigured(fleetMode: nil, host: "127.0.0.1"), "auto + loopback is no fleet link")
        expect(OpenClawPresence.fleetLinkConfigured(fleetMode: "auto", host: "10.0.0.5"), "a remote gateway host keeps OpenClaw")
        expect(OpenClawPresence.fleetLinkConfigured(fleetMode: "enabled", host: "127.0.0.1"), "an explicit fleet mode keeps OpenClaw")
        expect(!OpenClawPresence.fleetLinkConfigured(fleetMode: "Disabled", host: "10.0.0.5"), "disabled never links")
        for host in ["", "LocalHost", "[::1]", "::1", "0:0:0:0:0:0:0:1", "127.9.9.9"] {
            expect(OpenClawPresence.isLoopbackHost(host), "\(host) is a loopback gateway host")
        }
        for host in ["192.168.1.2", "gateway.local", "::2", "127.0.0", "[::1"] {
            expect(!OpenClawPresence.isLoopbackHost(host), "\(host) is not a loopback gateway host")
        }
        expect(OpenClawPresence.isManagedEnterprise(" Managed_Enterprise ") && !OpenClawPresence.isManagedEnterprise("unmanaged_byod"),
               "managed enterprise leaves the connector as it was")
        let home = "/Users/x"
        expect(OpenClawPresence.configCandidates(configFile: nil, homeDir: nil, home: home) == ["/Users/x/.openclaw/openclaw.json"],
               "the default openclaw.json candidate")
        expect(OpenClawPresence.configCandidates(configFile: "~/custom.json", homeDir: "~/oc", home: home)
               == ["/Users/x/custom.json", "/Users/x/oc/openclaw.json"], "claw.config_file and <home_dir>/openclaw.json")
        expect(OpenClawPresence.configCandidates(configFile: "~/oc/openclaw.json", homeDir: "~/oc", home: home)
               == ["/Users/x/oc/openclaw.json"], "candidates are deduplicated")
        expect(OpenClawPresence.binaryInstalled(path: "/nowhere", home: home, executable: { $0 == "/Users/x/.npm-global/bin/openclaw" }),
               "an npm global install counts")
        expect(OpenClawPresence.binaryInstalled(path: "/opt/x/bin:/nowhere", home: home, executable: { $0 == "/opt/x/bin/openclaw" }),
               "PATH is searched first")
        expect(!OpenClawPresence.binaryInstalled(path: nil, home: home, executable: { _ in false }), "nothing on the machine")
        expect(OpenClawPresence.installed(configFile: nil, homeDir: nil, home: home, path: nil,
                                          present: { $0 == "/Users/x/.openclaw/openclaw.json" }, executable: { _ in false }),
               "an openclaw.json marks OpenClaw as set up")
        expect(!OpenClawPresence.installed(configFile: nil, homeDir: nil, home: home, path: nil,
                                           present: { _ in false }, executable: { _ in false }), "neither config nor binary")
    }

    private static func runtimeOverviewSummaryParsesBoundedOutput() {
        let output = "warning: noise\nDCOVERVIEW:{\"admission_overrides\":\"secrets: HIGH file=block\","
            + "\"storage\":{\"retention\":\"7 days\",\"judge_capture\":\"enabled\",\"local_path\":\"/tmp/x.db\","
            + "\"judge_bodies_path\":\"built-in data directory\"}}\n"
        let parsed = RuntimeOverviewSummary.parse(output)
        expect(parsed?.admissionOverrides == "secrets: HIGH file=block", "the overrides line is the runtime's")
        expect(parsed?.storage?.retention == "7 days" && parsed?.storage?.judgeCapture == "enabled", "storage policy fields are read")
        expect(parsed?.storage?.judgeBodiesPath == "built-in data directory" && parsed?.storageError.isEmpty == true, "paths and the absent error are read")
        expect(RuntimeOverviewSummary.parse("no sentinel") == nil, "no sentinel, no summary")
        let degraded = RuntimeOverviewSummary.parse("DCOVERVIEW:{\"admission_overrides\":\"\",\"storage_error\":\"invalid configuration at $.observability (type)\"}")
        expect(degraded?.storage == nil && degraded?.storageError.hasPrefix("invalid configuration") == true, "a validator error is bounded text")
        expect(RuntimeOverviewSummary.parse("DCOVERVIEW:{\"admission_overrides\":\"a\\nb\"}")?.admissionOverrides == "a b", "line breaks are folded")
    }

    private static func restartIsQueuedOnlyForKeysTheGatewayReadsAtStart() {
        let required = ConfigRestartPolicy.restartRequired([
            "gateway.api_port", "gateway", "gateway.watcher.interval", "gateway.config_reload.mode",
            "gateway.config_reload.debounce_ms", "guardrail.mode", "guardrail.port", "scanners.skill_scanner.policy",
            "fleet.enabled", "fleet", "observability.local.path", "observability.destinations[0].enabled",
        ])
        expect(required == ["gateway.api_port", "gateway", "gateway.config_reload.mode", "guardrail.port", "fleet.enabled", "fleet", "observability.local.path"],
               "only the keys the gateway reads once at start need a restart: \(required)")
        expect(ConfigRestartPolicy.restartRequired(["guardrail.mode", "admission.skill.default"]).isEmpty, "hot-reloaded keys save without a restart")
    }

    private static func anOpenDraftSurvivesADiskGeneration() {
        let original = ["guardrail.mode": "observe", "gateway.api_port": "18970", "llm.model": "a"]
        let edited = ["guardrail.mode": "action", "gateway.api_port": "18971", "llm.model": "a"]
        // Another writer moved gateway.api_port and llm.model on disk.
        let fresh = ["guardrail.mode": "observe", "gateway.api_port": "19000", "llm.model": "b"]
        let rebased = ConfigDraftRebase.rebase(original: original, edited: edited, diskChanged: [], fresh: fresh)
        expect(rebased.edited == ["guardrail.mode": "action", "gateway.api_port": "18971"], "edits still differing from disk are kept; an untouched key is dropped: \(rebased.edited)")
        expect(rebased.diskChanged == ["gateway.api_port"], "only an edited key another writer changed is marked: \(rebased.diskChanged)")
        // The writer later lands the same value the draft holds: no change left.
        let settled = ConfigDraftRebase.rebase(original: fresh, edited: rebased.edited, diskChanged: rebased.diskChanged,
                                               fresh: ["guardrail.mode": "action", "gateway.api_port": "18971", "llm.model": "b"])
        expect(settled.edited.isEmpty && settled.diskChanged.isEmpty, "a draft equal to disk is no draft: \(settled)")
        let saved = ConfigDraftRebase.rebase(original: [:], edited: [:], diskChanged: [], fresh: fresh)
        expect(saved.edited.isEmpty, "a fresh load has no draft")
    }

    private static func invalidConfigIsNamedWithItsLine() {
        let output = """
          Config: /Users/x/.defenseclaw/config.yaml
          ✓ file exists
          ✗ parse error: invalid YAML at line 12, column 3 (mapping values are not allowed here). Fix that line, then check it with 'defenseclaw config validate'
        """
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 1, output: output)
               == "config.yaml line 12 is invalid; run defenseclaw config validate", "the banner names the line")
        // What 1.0.3's `config validate` actually prints for a malformed file.
        let v103 = """
          Config: /Users/x/.defenseclaw/config.yaml
          OK file exists
          X line 4, column 10: invalid YAML (expected ',' or ']', but got ':'). Fix that line in config.yaml, then run 'defenseclaw config validate' again
        """
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 1, output: v103)
               == "config.yaml line 4 is invalid; run defenseclaw config validate", "the 1.0.3 wording is recognised")
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 1,
               output: "  X line 3: guardrail.mode is \"bogus\"; allowed values: observe, action.") == nil,
               "a semantic issue on a file that loads is not a load failure")
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 1, output: "  X line 2: deployment_mode is \"bogus\"; allowed values: managed_enterprise, unmanaged_byod")
               == "config.yaml line 2 is invalid; run defenseclaw config validate", "a deployment_mode the loader refuses is a load failure")
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 0, output: "config is valid") == nil, "a valid file raises nothing")
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 1, output: "✗ guardrail.mode: unknown value") == nil,
               "a semantic issue the file still loads with is not a load failure")
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 2, output: "Usage: defenseclaw config [OPTIONS]") == nil,
               "an older runtime without the command raises nothing")
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 127, output: "defenseclaw binary not found.") == nil, "no CLI, no verdict")
        expect(ConfigValidation.invalidConfigSummary(fileName: "config.yaml", exitCode: 1, output: "parse error: the file is not valid UTF-8 text")
               == "config.yaml is invalid; run defenseclaw config validate", "no line when the runtime names none")
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ label: String) {
        guard condition() else {
            fputs("FAILED: \(label)\n", stderr)
            exit(1)
        }
    }
}
