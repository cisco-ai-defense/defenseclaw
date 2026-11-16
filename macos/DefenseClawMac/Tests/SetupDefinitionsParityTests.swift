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

// Minimal copies of the setup-view data types keep this contract test
// shell-runnable without compiling the SwiftUI application.
struct WizardField: Identifiable {
    enum Kind {
        case text(placeholder: String)
        case secure(placeholder: String)
        case choice(options: [String])
        case bool
        case flagOnly
    }

    let key: String
    let label: String
    let kind: Kind
    var defaultValue: String = ""
    var visibleWhen: (key: String, equals: [String])? = nil
    var visibleWhen2: (key: String, equals: [String])? = nil
    var visibleWhen3: (key: String, equals: [String])? = nil
    var help: String = ""
    var emitsOnlyOnChange: Bool = false
    /// Hidden on runtimes older than this major (runtime 1.0.x additions
    /// a 0.8.x CLI rejects as unknown options). An unknown runtime version
    /// counts as pre-1.0, as SecretStandardInputTransport does.
    var minimumRuntimeMajor: Int? = nil
    /// On pre-1.0 runtimes the field takes this kind (a click `is_flag`
    /// toggle has no --no- form; a choice list is narrower) and default.
    var legacyKind: Kind? = nil
    var legacyDefault: String? = nil
    var id: String { key }
}

struct WizardDefinition: Identifiable {
    let id: String
    let title: String
    let icon: String
    let blurb: String
    let baseArgs: [String]
    var commandField: String? = nil
    var commandMap: [String: String] = [:]
    var appendYes = false
    var appendNonInteractive = false
    var interactiveOnly = false
    var commandBuilder: (([String: String], Bool) -> [[String]])? = nil
    var secretInputField: String? = nil
    var secretEnvironment: (([String: String]) -> [String: String])? = nil
    var validation: (([String: String]) -> String?)? = nil
    var liveDefaults: ((YAMLNode) -> [String: String])? = nil
    let fields: [WizardField]
}

indirect enum YAMLNode {
    case scalar(String)
    case mapping([String: YAMLNode])
    case sequence([YAMLNode])

    subscript(path: String) -> YAMLNode? {
        var node = self
        for key in path.split(separator: ".").map(String.init) {
            guard case .mapping(let values) = node, let next = values[key] else { return nil }
            node = next
        }
        return node
    }

    var string: String? {
        guard case .scalar(let value) = self, !value.isEmpty else { return nil }
        return value
    }

    var int: Int? { string.flatMap(Int.init) }

    var bool: Bool? {
        guard let value = string?.lowercased() else { return nil }
        if ["true", "yes", "on"].contains(value) { return true }
        if ["false", "no", "off"].contains(value) { return false }
        return nil
    }

    var mapping: [String: YAMLNode]? {
        guard case .mapping(let values) = self else { return nil }
        return values
    }
}

extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}

@main
struct SetupDefinitionsParityTests {
    static func main() {
        emitsOnlyCurrentDiscoveryCLIOptions()
        disabledDiscoveryDropsTuningOptions()
        seedsDiscoveryFromTheSelectedConfig()
        validatesDiscoveryCLIRanges()
        observabilityNeverEmitsAnUnsupportedConnectorOption()
        guardrailSetupNeverEmitsTheRetiredVerifyOption()
        includesAmpAcrossSetupSurfaces()
        includesOnlyCanonicalDevinAcrossSetupAndCatalogSurfaces()
        bundledSkillsRemainDiscoveryOnlyAcrossNativeCatalogSurfaces()
        bundledMCPRemainsDiscoveryOnlyAcrossNativeCatalogSurfaces()
        localCatalogCoversActiveConnectorCompatibilityRoots()
        guardrailDefaultsNeverGuessTheWrongConnector()
        llmDefaultsPreserveTheSelectedProvider()
        llmBuilderDropsStaleRegionalOptions()
        customProviderBuilderCoversCurrentCLIOptions()
        customProviderBuilderDropsStaleFamilyOptions()
        customProviderValidationCatchesUnsafeInputs()
        observabilityBuilderCoversPresetSpecificInputs()
        galileoTestEmitsOnlyTimeout()
        skillScannerWizardMatchesRuntime103()
        mcpScannerWizardMatchesRuntime103()
        genericBuilderFollowsTheTUIFormRules()
        legacyRuntimesKeepThe08Contract()
        sandboxMachineCheckPresetsTheInstall()
        splunkHECDefaultsToVerifiedTLS()
        observabilityAddOffersPrivateNetworks()
        secureSetupSecretsUseChildEnvironment()
        webhookBuilderCoversCurrentNotifierOptions()
        webhookValidationRequiresProviderCredentials()
        removedStandaloneSandboxWizardStaysHidden()
        sandboxWizardMatchesTheTUIWizard()
        print("Setup definition parity tests passed")
    }

    private static func acpSetupKeepsEnrollmentScoped() {
        expect(TUIWizards.acpCommands([:], false) == [["acp", "setup", "--client", "zed", "--agent", "kiro", "--profile", "default"]], "ACP defaults to observing")
        let values = ["client": "jetbrains", "agent": "copilot", "profile": "strict", "activate": "yes", "managed": "yes", "runtime-data-dir": "/tmp/fixture", "token-file": "/tmp/fixture/acp/jetbrains-copilot.token"]
        expect(TUIWizards.acpValidation(values) == nil, "managed ACP requires valid paths")
        expect(TUIWizards.acpCommands(values, false)[0].suffix(5) == ["--managed", "--runtime-data-dir", "/tmp/fixture", "--token-file", "/tmp/fixture/acp/jetbrains-copilot.token"], "ACP enrollment uses a file path rather than a secret argv value")
        expect(TUIWizards.acpValidation(["managed": "yes"]) != nil, "missing provisioning paths block enrollment")
        expect(!TUIWizards.acpCommands(["managed": "no", "token-file": "stale"], false)[0].contains("stale"), "unmanaged enrollment drops stale managed fields")
    }

    private static func sandboxSetupMatchesCurrentMacWorkflow() {
        let defaults = TUIWizards.sandboxCommands([:], false)
        // 1.0.x: --install-openshell upgrades an installed OpenShell in place
        // and restarts the gateway, so it is opt-in (the TUI pre-checks it
        // only when doctor reports OpenShell missing).
        expect(defaults == [
            ["sandbox", "setup", "--non-interactive", "--harness", "claudecode", "--harness", "codex", "--no-wrappers", "--skip-images"],
            ["sandbox", "image", "build", "claudecode", "codex"],
            ["sandbox", "doctor"]
        ], "sandbox defaults configure the installed OpenShell, build both images, then verify")
        expect(TUIWizards.sandboxCommands(["install-openshell": "yes"], false)[0].contains("--install-openshell"), "opting in installs or upgrades OpenShell")
        expect(TUIWizards.sandboxCommands(["action": "doctor", "install-openshell": "yes"], false) == [["sandbox", "doctor"]], "doctor never installs or builds even with stale setup choices")
        let optedOut = TUIWizards.sandboxCommands(["install-openshell": "no", "harness-codex": "no", "wrappers": "yes", "build-images": "no"], false)
        expect(optedOut == [["sandbox", "setup", "--non-interactive", "--harness", "claudecode", "--wrappers", "--skip-images"], ["sandbox", "doctor"]], "explicit install and build opt-outs are respected")
        expect(TUIWizards.sandboxCommands(["telemetry-off": "no"], false)[0].contains("--upstream-telemetry"), "upstream telemetry opt-in reaches the runtime")
        let codexOnly = TUIWizards.sandboxCommands(["harness-claudecode": "no"], false)
        expect(codexOnly[1] == ["sandbox", "image", "build", "codex"], "build only selected harnesses")
        expect(!defaults.flatMap { $0 }.contains("--yes") && !defaults.flatMap { $0 }.contains("--restart-gateway"), "installation consent does not force active sandbox restarts or blanket answers")
        let wizard = TUIWizards.all.first { $0.id == "sandbox" }!
        let formDefaults = Dictionary(uniqueKeysWithValues: wizard.fields.map { ($0.key, $0.defaultValue) })
        expect(TUIWizards.sandboxCommands(formDefaults, true) == defaults, "reviewed defaults match actual execution")
        expect(TUIWizards.sandboxValidation(["harness-claudecode": "no", "harness-codex": "no"]) != nil, "empty harness selection is rejected")
        expect(TUIWizards.sandboxValidation(["action": "doctor"]) == nil, "doctor does not require a harness")
    }

    private static func emitsOnlyCurrentDiscoveryCLIOptions() {
        let commands = TUIWizards.aiDiscoveryCommands([
            "enable": "yes",
            "mode": "passive",
            "scan-interval-min": "15",
            "process-interval-s": "30",
            "scan-roots": "~/work,/opt/models",
            "max-files-per-scan": "2500",
            "max-file-bytes": "1048576",
            "include-shell-history": "no",
            "include-package-manifests": "yes",
            "include-env-var-names": "no",
            "include-network-domains": "yes",
            "allow-workspace-signatures": "no",
            "store-raw-local-paths": "yes",
            "restart": "no",
            "scan": "no",
        ], false)
        expect(commands.count == 1, "discovery enable is one CLI command")
        let arguments = commands[0]
        expect(arguments.starts(with: ["agent", "discovery", "enable", "--yes"]), "enable prefix")
        expect(value(after: "--max-files-per-scan", in: arguments) == "2500", "max files option")
        expect(value(after: "--max-file-bytes", in: arguments) == "1048576", "max bytes option")
        expect(arguments.contains("--no-allow-workspace-signatures"), "workspace signature off option")
        expect(arguments.contains("--store-raw-local-paths"), "raw path option")
        expect(!arguments.contains(where: { $0.contains("emit-otel") }), "removed emit-otel option")
        expect(arguments.suffix(2) == ["--no-restart", "--no-scan"], "rollout options")
    }

    private static func disabledDiscoveryDropsTuningOptions() {
        let commands = TUIWizards.aiDiscoveryCommands([
            "enable": "no",
            "restart": "no",
            "mode": "enhanced",
            "max-files-per-scan": "1000",
        ], false)
        expect(
            commands == [["agent", "discovery", "disable", "--yes", "--no-restart"]],
            "disable accepts only its supported rollout option"
        )
    }

    private static func seedsDiscoveryFromTheSelectedConfig() {
        let config: YAMLNode = .mapping([
            "ai_discovery": .mapping([
                "enabled": .scalar("false"),
                "mode": .scalar("passive"),
                "scan_interval_min": .scalar("27"),
                "process_interval_s": .scalar("45"),
                "scan_roots": .sequence([.scalar("~/one"), .scalar("/opt/two")]),
                "max_files_per_scan": .scalar("3333"),
                "max_file_bytes": .scalar("786432"),
                "include_shell_history": .scalar("false"),
                "include_package_manifests": .scalar("true"),
                "include_env_var_names": .scalar("false"),
                "include_network_domains": .scalar("true"),
                "allow_workspace_signatures": .scalar("true"),
                "store_raw_local_paths": .scalar("true"),
            ]),
        ])
        let defaults = TUIWizards.aiDiscoveryLiveDefaults(config)
        expect(defaults["enable"] == "no", "enabled live default")
        expect(defaults["mode"] == "passive", "mode live default")
        expect(defaults["scan-roots"] == "~/one, /opt/two", "scan roots sequence becomes CSV")
        expect(defaults["max-files-per-scan"] == "3333", "max files live default")
        expect(defaults["allow-workspace-signatures"] == "yes", "workspace signature live default")
        expect(defaults["include-shell-history"] == "no", "source toggles live default")
    }

    private static func validatesDiscoveryCLIRanges() {
        let valid = [
            "enable": "yes",
            "scan-interval-min": "1",
            "process-interval-s": "3600",
            "max-files-per-scan": "100000",
            "max-file-bytes": "4096",
        ]
        expect(TUIWizards.aiDiscoveryValidation(valid) == nil, "CLI range boundaries are accepted")
        var invalid = valid
        invalid["max-file-bytes"] = "4095"
        expect(TUIWizards.aiDiscoveryValidation(invalid) != nil, "below-range byte cap is rejected")
        expect(
            TUIWizards.aiDiscoveryValidation(["enable": "no"]) == nil,
            "hidden tuning fields do not block disable"
        )
    }

    private static func observabilityNeverEmitsAnUnsupportedConnectorOption() {
        let commands = TUIWizards.observabilityCommands([
            "action": "add",
            "preset": "otlp",
            "name": "fleet",
            "endpoint": "collector.example:4317",
            "connector": "codex",
        ], false)
        expect(commands.count == 1, "observability add is one command")
        expect(!commands[0].contains("--connector"), "global observability CLI has no connector option")
    }

    /// `setup guardrail`, `setup openclaw` and `setup zeptoclaw` no longer take
    /// --verify / --no-verify (the option did nothing); `defenseclaw doctor` is the check.
    private static func guardrailSetupNeverEmitsTheRetiredVerifyOption() {
        let connector = TUIWizards.all.first { $0.id == "connector" }
        expect(connector?.fields.contains { $0.key == "verify" } == false, "connector wizard has no verify field")
        for name in ["openclaw", "zeptoclaw"] {
            let commands = connector?.commandBuilder?(["action": "setup", "connector": name, "verify": "no"], false) ?? []
            expect(
                commands.count == 1 && !commands[0].contains("--verify") && !commands[0].contains("--no-verify"),
                "\(name) setup emits no verify option"
            )
        }
        let aiDefense = TUIWizards.all.first { $0.id == "ai-defense" }
        let commands = aiDefense?.commandBuilder?(["verify": "no", "skill-scanner": "yes", "restart": "yes"], false) ?? []
        let guardrail = commands.first { $0.contains("guardrail") } ?? []
        expect(!guardrail.isEmpty && !guardrail.contains("--verify") && !guardrail.contains("--no-verify"),
               "AI Defense guardrail setup emits no verify option")
        let scanner = commands.first { $0.contains("skill-scanner") } ?? []
        expect(scanner.contains("--no-verify"), "the skill scanner still takes its own verify option")
    }

    private static func includesAmpAcrossSetupSurfaces() {
        expect(TUIWizards.connectors.contains("amp"), "Amp appears in the native connector picker")
        expect(TUIWizards.hookConnectors.contains("amp"), "Amp is treated as a hook connector")
        let definition = TUIWizards.all.first { $0.id == "connector" }
        let connectorField = definition?.fields.first { $0.key == "connector" }
        guard case .choice(let options) = connectorField?.kind else {
            expect(false, "connector setup field is a choice")
            return
        }
        expect(options.contains("amp"), "Amp appears in connector setup choices")
    }

    private static func includesOnlyCanonicalDevinAcrossSetupAndCatalogSurfaces() {
        expect(TUIWizards.connectors.contains("devin"), "Devin appears in the native connector picker")
        expect(TUIWizards.hookConnectors.contains("devin"), "Devin is treated as a hook connector")

        let testsDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let sourceRoot = testsDirectory.deletingLastPathComponent().appendingPathComponent("DefenseClawMac")
        let scanner = (try? String(
            contentsOf: sourceRoot.appendingPathComponent("DataLayer/SkillScanner.swift"),
            encoding: .utf8
        )) ?? ""
        expect(
            scanner.contains("case \"devin\": return [p(\".config\", \"devin\", \"skills\"), p(\".agents\", \"skills\")]"),
            "native catalog scans Devin user and standardized skills"
        )
        expect(
            scanner.contains("p(\".config\", \"devin\", \"mcp_config.json\")"),
            "native catalog scans canonical Devin MCP config"
        )
        expect(
            scanner.contains("p(\".config\", \"devin\", \"config.json\")"),
            "native catalog retains legacy Devin MCP read compatibility"
        )
    }

    private static func bundledSkillsRemainDiscoveryOnlyAcrossNativeCatalogSurfaces() {
        let testsDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let sourceRoot = testsDirectory.deletingLastPathComponent().appendingPathComponent("DefenseClawMac")
        let scanner = (try? String(
            contentsOf: sourceRoot.appendingPathComponent("DataLayer/SkillScanner.swift"),
            encoding: .utf8
        )) ?? ""
        let catalog = (try? String(
            contentsOf: sourceRoot.appendingPathComponent("DataLayer/CatalogCLI.swift"),
            encoding: .utf8
        )) ?? ""
        let models = (try? String(
            contentsOf: sourceRoot.appendingPathComponent("DataLayer/Models.swift"),
            encoding: .utf8
        )) ?? ""

        expect(scanner.contains("entry == \".system\""),
               "native catalog expands Codex .system containers by child")
        expect(scanner.contains("codexHomePath() + \"/skills\""),
               "native catalog binds bundled provenance to the Codex home")
        expect(scanner.contains("bundled: isBundledCodexSystem"),
               "native fallback keeps arbitrary .system children user-owned")
        expect(models.contains("var bundled: Bool = false"),
               "native skill rows retain bundled provenance")
        expect(catalog.contains("bundled: bool(row[\"bundled\"])"),
               "CLI catalog preserves bundled provenance")
        expect(catalog.contains("if item.bundled"),
               "bundled native rows have a discovery-only action set")
    }

    private static func bundledMCPRemainsDiscoveryOnlyAcrossNativeCatalogSurfaces() {
        let testsDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let sourceRoot = testsDirectory.deletingLastPathComponent().appendingPathComponent("DefenseClawMac")
        let scanner = (try? String(
            contentsOf: sourceRoot.appendingPathComponent("DataLayer/SkillScanner.swift"),
            encoding: .utf8
        )) ?? ""
        let catalog = (try? String(
            contentsOf: sourceRoot.appendingPathComponent("DataLayer/CatalogCLI.swift"),
            encoding: .utf8
        )) ?? ""
        let models = (try? String(
            contentsOf: sourceRoot.appendingPathComponent("DataLayer/Models.swift"),
            encoding: .utf8
        )) ?? ""

        expect(scanner.contains("name == \"openaiDeveloperDocs\""),
               "native fallback recognizes only the exact Codex built-in MCP name")
        expect(scanner.contains("config.count == 1"),
               "modified Codex MCP tables remain scan-eligible")
        expect(scanner.contains("bundled: bundled"),
               "native fallback preserves exact MCP provenance")
        expect(models.contains("var bundled: Bool = false         // vendor-managed; discovery/info only"),
               "native MCP rows retain bundled provenance")
        expect(catalog.contains("bundled: bool(row[\"bundled\"])"),
               "CLI MCP catalog preserves bundled provenance")
        expect(catalog.contains("if item.bundled"),
               "bundled MCP rows have an Info-only action set")
        // The gateway MCP catalog client is gone (7f1ab11a0): the app lists
        // MCP servers through the CLI catalog only (GAP-0121).
    }

    private static func localCatalogCoversActiveConnectorCompatibilityRoots() {
        let testsDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let sourceRoot = testsDirectory.deletingLastPathComponent().appendingPathComponent("DefenseClawMac")
        let scanner = (try? String(
            contentsOf: sourceRoot.appendingPathComponent("DataLayer/SkillScanner.swift"),
            encoding: .utf8
        )) ?? ""

        for expected in [
            "p(\".claude\", \"skills\"), p(\".codex\", \"skills\")",
            "p(\".gemini\", \"config\", \"skills\")",
            "p(\".gemini\", \"antigravity-cli\", \"skills\")",
            "p(\".config\", \"agents\", \"skills\")",
            "p(\".config\", \"amp\", \"skills\")",
        ] {
            expect(scanner.contains(expected), "native skill catalog is missing \(expected)")
        }
        for expected in [
            "p(\".gemini\", \"config\", \"mcp_config.json\")",
            "p(\".config\", \"opencode\", \"config.json\")",
            "p(\".config\", \"opencode\", \"opencode.jsonc\")",
            "p(\".opencode\", \"opencode.jsonc\")",
            "p(\".config\", \"amp\", \"settings.jsonc\")",
            "[[\"amp.mcpServers\"], [\"mcpServers\"]]",
        ] {
            expect(scanner.contains(expected), "native MCP catalog is missing \(expected)")
        }
    }

    private static func guardrailDefaultsNeverGuessTheWrongConnector() {
        let codexConfig: YAMLNode = .mapping([
            "claw": .mapping(["mode": .scalar("codex")]),
            "guardrail": .mapping(["mode": .scalar("action")]),
        ])
        expect(
            TUIWizards.guardrailLiveDefaults(codexConfig)["connector"] == "codex",
            "single-connector config targets its selected connector"
        )

        let multiConfig: YAMLNode = .mapping([
            "claw": .mapping(["mode": .scalar("codex")]),
            "guardrail": .mapping([
                "connector": .scalar("codex"),
                "connectors": .mapping([
                    "codex": .mapping([:]),
                    "cursor": .mapping([:]),
                ]),
            ]),
        ])
        expect(
            TUIWizards.guardrailLiveDefaults(multiConfig)["connector"] == "",
            "multi-connector config leaves the target explicit"
        )
        expect(
            TUIWizards.guardrailValidation(["connector": ""]) != nil,
            "blank multi-connector target requires an operator choice"
        )
        expect(
            TUIWizards.guardrailValidation(["connector": "cursor"]) == nil,
            "explicit guardrail connector is accepted"
        )

        let migratedSingle: YAMLNode = .mapping([
            "guardrail": .mapping([
                "connector": .scalar("claudecode"),
                "connectors": .mapping(["codex": .mapping([:])]),
            ]),
        ])
        expect(
            TUIWizards.guardrailLiveDefaults(migratedSingle)["connector"] == "codex",
            "authoritative connector map outranks a stale legacy connector"
        )
    }

    private static func llmDefaultsPreserveTheSelectedProvider() {
        let config: YAMLNode = .mapping([
            "llm": .mapping([
                "provider": .scalar("openai"),
                "model": .scalar("gpt-4.1"),
                "api_key_env": .scalar("OPENAI_API_KEY"),
                "base_url": .scalar("https://api.openai.example/v1"),
                "timeout": .scalar("45"),
                "max_retries": .scalar("4"),
            ]),
        ])
        let defaults = TUIWizards.llmLiveDefaults(config)
        expect(defaults["provider"] == "openai", "configured LLM provider is preserved")
        expect(defaults["model"] == "gpt-4.1", "configured LLM model is preserved")
        expect(defaults["timeout"] == "45", "configured LLM timeout is preserved")
    }

    private static func llmBuilderDropsStaleRegionalOptions() {
        let commands = TUIWizards.llmCommands([
            "provider": "openai",
            "model": "gpt-4.1",
            "role": "unified",
            "api-key-env": "OPENAI_API_KEY",
            "timeout": "30",
            "max-retries": "2",
            "bedrock-region": "us-east-1",
            "bedrock-auth-mode": "profile",
        ], false)
        expect(commands.count == 1, "LLM setup without a new secret is one command")
        expect(!commands[0].contains("--bedrock-region"), "hidden Bedrock region is not emitted")
        expect(!commands[0].contains("--bedrock-auth-mode"), "hidden Bedrock auth is not emitted")
        expect(TUIWizards.llmValidation([
            "model": "gpt-4.1", "timeout": "30", "max-retries": "2",
        ]) == nil, "valid LLM tuning values pass")
    }

    private static func customProviderBuilderCoversCurrentCLIOptions() {
        let commands = TUIWizards.providerCommands([
            "action": "add",
            "name": "corp-bedrock",
            "domain": "bedrock.corp.example,models.corp.example",
            "env-key": "AWS_BEARER_TOKEN_BEDROCK",
            "profile-id": "corp-profile",
            "allowed-request": "chat,embedding",
            "available-model": "corp-fast,corp-smart",
            "request-path-override": "chat=/invoke/chat",
            "base-provider-type": "bedrock",
            "base-url": "https://bedrock.corp.example",
            "bedrock-region": "us-east-1",
            "bedrock-auth-mode": "profile",
            "bedrock-profile-name": "corp",
            "bedrock-inference-profile": "us.",
            "bedrock-deployment": "fast=model-a,smart=model-b",
            "reload": "no",
        ], false)
        expect(commands.count == 1, "provider add is one command")
        let arguments = commands[0]
        expect(value(after: "--profile-id", in: arguments) == "corp-profile", "profile id option")
        expect(arguments.filter { $0 == "--domain" }.count == 2, "repeatable domains")
        expect(arguments.filter { $0 == "--allowed-request" }.count == 2, "repeatable request types")
        expect(arguments.filter { $0 == "--bedrock-deployment" }.count == 2, "repeatable Bedrock aliases")
        expect(value(after: "--bedrock-profile-name", in: arguments) == "corp", "profile auth option")
        expect(arguments.last == "--no-reload", "reload opt-out is last")
    }

    private static func customProviderBuilderDropsStaleFamilyOptions() {
        let commands = TUIWizards.providerCommands([
            "action": "add",
            "name": "corp-openai",
            "base-provider-type": "openai",
            "base-url": "https://openai.corp.example",
            "bedrock-region": "us-east-1",
            "azure-endpoint": "https://stale.openai.azure.com",
            "reload": "yes",
        ], false)
        let arguments = commands[0]
        expect(!arguments.contains("--bedrock-region"), "stale Bedrock values are dropped")
        expect(!arguments.contains("--azure-endpoint"), "stale Azure values are dropped")
    }

    private static func customProviderValidationCatchesUnsafeInputs() {
        let base = [
            "action": "add",
            "name": "corp",
            "base-url": "https://corp.example",
        ]
        expect(TUIWizards.providerValidation(base) == nil, "minimal provider add is valid")
        expect(TUIWizards.providerValidation(base.merging([
            "allowed-request": "chat,unknown",
        ]) { _, new in new }) != nil, "unknown request type is rejected")
        expect(TUIWizards.providerValidation(base.merging([
            "ca-cert-file": "/tmp/ca.pem",
            "insecure-skip-verify": "yes",
        ]) { _, new in new }) != nil, "conflicting TLS modes are rejected")
        expect(TUIWizards.providerValidation(base.merging([
            "env-key": "NOT-AN-ENV",
        ]) { _, new in new }) != nil, "invalid environment key is rejected")
    }

    private static func observabilityBuilderCoversPresetSpecificInputs() {
        let commands = TUIWizards.observabilityCommands([
            "action": "add",
            "preset": "splunk-hec",
            "name": "hec-main",
            "enabled": "no",
            "host": "splunk.example",
            "port": "8088",
            "index": "defenseclaw",
            "source": "defenseclaw",
            "sourcetype": "_json",
            "verify-tls-hec": "yes",
            "dry-run": "yes",
            "connector": "codex",
        ], false)
        let arguments = commands[0]
        expect(arguments.starts(with: ["setup", "observability", "add", "splunk-hec"]), "observability add prefix")
        expect(value(after: "--host", in: arguments) == "splunk.example", "Splunk host option")
        expect(arguments.contains("--disabled"), "destination enabled state")
        expect(arguments.contains("--verify-tls"), "preset TLS option")
        expect(arguments.contains("--dry-run"), "destination dry-run option")
        expect(!arguments.contains("--connector"), "observability stays global")
        expect(TUIWizards.observabilityValidation([
            "action": "add", "preset": "otlp", "signals-general": "traces", "endpoint": "collector:4317",
        ]) == nil, "valid OTLP destination passes validation")

        let galileo = TUIWizards.observabilityCommands([
            "action": "add",
            "preset": "galileo",
            "signals-galileo": "traces",
            "endpoint": "https://api.galileo.ai/otel/traces",
            "project": "defenseclaw",
            "logstream": "default",
            "enabled": "yes",
        ], false)[0]
        expect(value(after: "--signals", in: galileo) == "traces", "Galileo emits traces only")
    }

    /// `setup galileo test` accepts only --timeout since 0.8.5; the retired
    /// --direct toggle made the wizard's Test action exit 2.
    private static func galileoTestEmitsOnlyTimeout() {
        guard let wizard = TUIWizards.all.first(where: { $0.id == "galileo" }) else {
            fputs("FAILED: galileo wizard missing\n", stderr)
            exit(1)
        }
        expect(!wizard.fields.contains(where: { $0.key == "direct" }), "galileo wizard no longer offers the retired --direct toggle")
        let defaultTest = wizard.commandBuilder?(["action": "test", "timeout": "15"], false).flatMap { $0 } ?? []
        expect(defaultTest == ["setup", "galileo", "test"], "galileo test with the default timeout emits no options")
        let longer = wizard.commandBuilder?(["action": "test", "timeout": "30", "direct": "yes"], false).flatMap { $0 } ?? []
        expect(value(after: "--timeout", in: longer) == "30", "galileo test forwards a custom timeout")
        expect(!longer.contains("--direct"), "a stale direct value never reaches argv")
    }

    /// The form's opening values: static defaults, then the live config
    /// (SetupView.onAppear), the baseline for emit-on-change fields.
    private static func seed(_ wizard: WizardDefinition, _ raw: YAMLNode) -> [String: String] {
        var values: [String: String] = [:]
        for field in wizard.fields { values[field.key] = field.defaultValue }
        for (key, value) in wizard.liveDefaults?(raw) ?? [:] where !value.isEmpty { values[key] = value }
        return values
    }

    private static func argv(_ wizard: WizardDefinition, seeded: [String: String], _ changes: [String: String] = [:]) -> [String] {
        let values = seeded.merging(changes) { $1 }
        return TUIWizards.genericArguments(for: wizard, values: values, seeded: seeded, visibleFields: wizard.fields)
    }

    private static func skillScannerWizardMatchesRuntime103() {
        guard let wizard = TUIWizards.all.first(where: { $0.id == "skill-scanner" }) else {
            expect(false, "skill-scanner wizard exists"); return
        }
        func field(_ key: String) -> WizardField? { wizard.fields.first { $0.key == key } }
        guard case .choice(let policies)? = field("policy")?.kind else { expect(false, "policy is a choice"); return }
        expect(policies == ["strict", "balanced", "permissive", "low-noise", "quiet"], "policy presets match scanner/settings.py POLICY_PRESETS: \(policies)")
        expect(field("policy")?.defaultValue == "quiet", "quiet is the recommended default")
        guard case .choice(let providers)? = field("llm-provider")?.kind else { expect(false, "provider is a choice"); return }
        expect(providers.contains("openai-compatible") && providers.contains("ollama") && providers.contains("vllm") && !providers.contains("custom"),
               "scanner providers are WIZARD_LLM_PROVIDERS + openai-compatible: \(providers)")
        expect(field("fail-on-severity")?.defaultValue == "HIGH" && field("review-queue-min")?.defaultValue == "MEDIUM", "severity gate and review threshold open on the recommended values")
        expect(field("use-osv") != nil && field("llm-base-url") != nil, "OSV checks and the judge base URL are offered")
        for key in ["use-llm", "use-behavioral", "enable-meta", "use-trigger", "use-virustotal", "use-aidefense", "use-osv", "lenient"] {
            guard let toggle = field(key), case .bool = toggle.kind, toggle.emitsOnlyOnChange else {
                expect(false, "\(key) is a configured toggle that can turn the analyzer off"); continue
            }
        }

        // A stock 1.0.3 install (no skill_scanner block): an untouched Run
        // must not move the effective policy from quiet to anything else,
        // and the judge opens on the runtime default (on), so it can be turned off.
        let fresh = seed(wizard, .mapping([:]))
        expect(fresh["use-llm"] == "yes", "the LLM judge opens on SkillScannerConfig.use_llm = true")
        expect(argv(wizard, seeded: fresh, ["use-llm": "no"]).contains("--no-use-llm"), "the judge can be turned off from a fresh install")
        expect(argv(wizard, seeded: fresh) == ["setup", "skill-scanner", "--verify", "--non-interactive"],
               "an untouched form on a fresh install emits no policy or analyzer flags: \(argv(wizard, seeded: fresh))")

        let configured: YAMLNode = .mapping(["scanners": .mapping(["skill_scanner": .mapping([
            "policy": .scalar("custom"),
            "use_llm": .scalar("true"),
            "lenient": .scalar("false"),
            "fail_on_severity": .scalar("medium"),
            "review_queue_min": .scalar("bogus"),
            "llm": .mapping(["provider": .scalar("ollama")]),
            "analyzers": .mapping(["osv": .mapping(["enabled": .scalar("yes")])]),
        ])])])
        let live = wizard.liveDefaults?(configured) ?? [:]
        expect(live["policy"] == "custom", "a custom policy opens as itself so an untouched Run keeps it")
        expect(live["use-llm"] == "yes" && live["lenient"] == "no" && live["use-osv"] == "yes", "toggles open on the configured values: \(live)")
        expect(live["fail-on-severity"] == "MEDIUM" && live["review-queue-min"] == nil, "severities are upper-cased and unknown values ignored")
        expect(live["llm-provider"] == "ollama", "a local judge provider is kept, not reset to anthropic")
        let seeded = seed(wizard, configured)
        let untouched = argv(wizard, seeded: seeded)
        expect(untouched == ["setup", "skill-scanner", "--verify", "--non-interactive"], "untouched: no flag rewrites the configured posture: \(untouched)")
        let changed = argv(wizard, seeded: seeded, ["policy": "strict", "use-llm": "no", "use-osv": "no", "review-queue-min": "LOW", "lenient": "yes"])
        expect(changed.contains("--policy=strict") && changed.contains("--no-use-llm") && changed.contains("--no-use-osv")
               && changed.contains("--review-queue-min=LOW") && changed.contains("--lenient"),
               "changes emit the click flags, including the off switches: \(changed)")
        expect(!changed.contains(where: { $0.hasPrefix("--fail-on-severity") || $0.hasPrefix("--llm-provider") }), "unchanged fields stay silent")
        expect(!wizard.fields.contains(where: { if case .choice(let options) = $0.kind { return options.contains("none") } else { return false } }),
               "the retired policy \"none\" is never offered")
    }

    private static func mcpScannerWizardMatchesRuntime103() {
        guard let wizard = TUIWizards.all.first(where: { $0.id == "mcp-scanner" }) else {
            expect(false, "mcp-scanner wizard exists"); return
        }
        func field(_ key: String) -> WizardField? { wizard.fields.first { $0.key == key } }
        expect(field("analyzers")?.defaultValue == "auto", "analyzers default to auto as MCPScannerConfig does")
        for key in ["llm-base-url", "api-endpoint", "api-key-env", "api-timeout-ms"] {
            expect(field(key) != nil, "\(key) is offered")
        }
        guard case .choice(let providers)? = field("llm-provider")?.kind else { expect(false, "provider is a choice"); return }
        expect(providers == TUIWizards.scannerLLMProviders, "MCP judge providers match the skill scanner's")
        let configured: YAMLNode = .mapping(["scanners": .mapping(["mcp_scanner": .mapping([
            "analyzers": .sequence([.scalar("yara"), .scalar("llm")]),
            "scan_prompts": .scalar("true"),
        ])])])
        let seeded = seed(wizard, configured)
        expect(seeded["analyzers"] == "yara,llm" && seeded["scan-prompts"] == "yes", "opens on the configured analyzers and toggles")
        expect(argv(wizard, seeded: seeded) == ["setup", "mcp-scanner", "--verify", "--non-interactive"], "untouched MCP form emits nothing but verify")
        expect(argv(wizard, seeded: seeded, ["analyzers": ""]).contains("--analyzers=auto"), "clearing the analyzers list means auto (GAP-2572)")
        expect(!argv(wizard, seeded: seed(wizard, .mapping([:])), ["analyzers": " "]).contains(where: { $0.hasPrefix("--analyzers") }), "clearing an auto list sends nothing")
        let changed = argv(wizard, seeded: seeded, ["scan-prompts": "no", "scan-resources": "yes", "api-key-env": "AI_DEFENSE_API_KEY"])
        expect(changed.contains("--no-scan-prompts") && changed.contains("--scan-resources") && changed.contains("--api-key-env=AI_DEFENSE_API_KEY"),
               "MCP toggles turn off and on, text fields emit when set: \(changed)")
    }

    /// A 0.8.x CLI rejects the 1.0.x options and --no- forms as unknown, so
    /// on such a runtime (or an unknown version) the wizards keep the shape
    /// release 1.1.31 shipped.
    private static func legacyRuntimesKeepThe08Contract() {
        expect(TUIWizards.runtimeMajor("1.0.3") == 1 && TUIWizards.runtimeMajor("0.8.10") == 0 && TUIWizards.runtimeMajor(nil) == nil, "runtime major parsing")
        let skill = TUIWizards.all.first { $0.id == "skill-scanner" }!
        for major in [Int?.none, 0] {
            let fields = TUIWizards.fields(of: skill, runtimeMajor: major)
            let keys = fields.map(\.key)
            expect(!keys.contains("fail-on-severity") && !keys.contains("review-queue-min") && !keys.contains("use-osv") && !keys.contains("llm-base-url"),
                   "1.0.x-only fields are hidden on a legacy runtime (\(String(describing: major)))")
            guard case .choice(let policies)? = fields.first(where: { $0.key == "policy" })?.kind,
                  case .choice(let providers)? = fields.first(where: { $0.key == "llm-provider" })?.kind else { expect(false, "legacy choices"); return }
            expect(policies == ["strict", "balanced", "permissive", "none"] && providers == ["anthropic", "openai"], "legacy choice lists: \(policies) \(providers)")
            expect(fields.first { $0.key == "policy" }?.defaultValue == "permissive", "0.8.x SkillScannerConfig.policy default")
            for key in ["use-llm", "use-behavioral", "use-virustotal", "lenient"] {
                guard let toggle = fields.first(where: { $0.key == key }), case .flagOnly = toggle.kind, toggle.defaultValue == "no" else {
                    expect(false, "\(key) is a bare flag on 0.8.x"); continue
                }
            }
            var seeded: [String: String] = [:]
            for field in fields { seeded[field.key] = field.defaultValue }
            let untouched = TUIWizards.genericArguments(for: skill, values: seeded, seeded: seeded, visibleFields: fields)
            expect(untouched == ["setup", "skill-scanner", "--verify", "--non-interactive"], "untouched legacy form: \(untouched)")
            let on = TUIWizards.genericArguments(for: skill, values: seeded.merging(["use-llm": "yes", "policy": "strict"]) { $1 }, seeded: seeded, visibleFields: fields)
            expect(on.contains("--use-llm") && on.contains("--policy=strict") && !on.contains(where: { $0.hasPrefix("--no-") }), "legacy toggles emit bare flags only: \(on)")
        }
        let modern = TUIWizards.fields(of: skill, runtimeMajor: 1)
        expect(modern.count == skill.fields.count && modern.contains { $0.key == "use-osv" }, "1.0.x keeps every field")
        let mcp = TUIWizards.fields(of: TUIWizards.all.first { $0.id == "mcp-scanner" }!, runtimeMajor: 0)
        expect(!mcp.contains { ["llm-base-url", "api-endpoint", "api-key-env", "api-timeout-ms"].contains($0.key) }, "MCP 1.0.x fields hidden on 0.8.x")
        guard let prompts = mcp.first(where: { $0.key == "scan-prompts" }), case .flagOnly = prompts.kind else { expect(false, "scan-prompts legacy flag"); return }
        let observability = TUIWizards.fields(of: TUIWizards.all.first { $0.id == "observability" }!, runtimeMajor: 0)
        expect(!observability.contains { $0.key == "allow-private-networks" }, "--allow-private-networks hidden on 0.8.x")
    }

    private static func sandboxMachineCheckPresetsTheInstall() {
        let missing = TUIWizards.sandboxMachineCheck(from: "diag line\n{\"ok\": false, \"openshell_install\": true, \"openshell_upgrade\": false, \"openshell_install_version\": \"0.9.2\", \"checks\": []}")!
        expect(missing.openshellNeeded && !missing.openshellUpgrade && missing.release == "0.9.2", "a missing OpenShell presets the install: \(missing)")
        let upgrade = TUIWizards.sandboxMachineCheck(from: "{\"ok\": true, \"openshell_install\": false, \"openshell_upgrade\": true}")!
        expect(!upgrade.openshellNeeded && upgrade.openshellUpgrade, "a supported older OpenShell offers the in-place upgrade")
        let older = TUIWizards.sandboxMachineCheck(from: "{\"checks\": [{\"id\": \"openshell-cli\", \"status\": \"fail\"}]}")!
        expect(older.openshellNeeded, "an older doctor: a failed CLI check")
        let fine = TUIWizards.sandboxMachineCheck(from: "{\"checks\": [{\"id\": \"openshell-cli\", \"status\": \"pass\"}]}")!
        expect(!fine.openshellNeeded && !fine.openshellUpgrade, "an older doctor with a passing CLI check")
        expect(TUIWizards.sandboxMachineCheck(from: "no json here") == nil, "no report, no check")
    }

    private static func genericBuilderFollowsTheTUIFormRules() {
        let wizard = WizardDefinition(
            id: "probe", title: "Probe", icon: "", blurb: "", baseArgs: ["setup"],
            commandField: "connector", commandMap: ["claudecode": "claude-code"], appendYes: true,
            fields: [
                WizardField(key: "connector", label: "Connector", kind: .choice(options: ["claudecode"]), defaultValue: "claudecode"),
                WizardField(key: "mode", label: "Mode", kind: .choice(options: ["observe", "action"]), defaultValue: "observe"),
                WizardField(key: "restart", label: "Restart", kind: .bool, defaultValue: "yes"),
                WizardField(key: "force", label: "Force", kind: .flagOnly, defaultValue: "no"),
                WizardField(key: "token", label: "Token", kind: .secure(placeholder: ""), defaultValue: "hunter2"),
                WizardField(key: "quiet", label: "Quiet", kind: .bool, defaultValue: "no", emitsOnlyOnChange: true),
            ]
        )
        var values: [String: String] = [:]
        for field in wizard.fields { values[field.key] = field.defaultValue }
        let args = TUIWizards.genericArguments(for: wizard, values: values, seeded: values, visibleFields: wizard.fields)
        expect(args == ["setup", "claude-code", "--mode=observe", "--restart", "--yes"],
               "command field maps, bools are click-style, bare flags only when on, secrets never, unchanged emit-on-change fields silent: \(args)")
        values["quiet"] = "yes"; values["force"] = "yes"
        let more = TUIWizards.genericArguments(for: wizard, values: values, seeded: [:], visibleFields: wizard.fields)
        expect(more.contains("--quiet") && more.contains("--force") && !more.contains("hunter2"), "a change emits; a missing baseline compares against the default: \(more)")
    }

    private static func observabilityAddOffersPrivateNetworks() {
        guard let wizard = TUIWizards.all.first(where: { $0.id == "observability" }),
              let field = wizard.fields.first(where: { $0.key == "allow-private-networks" }) else {
            expect(false, "Allow private networks field exists"); return
        }
        expect(field.defaultValue == "no", "private networks stay off unless asked (TUI default no)")
        expect(field.visibleWhen2?.equals.contains("splunk-hec") == true, "offered for Splunk HEC like the TUI form")
        let base = ["action": "add", "preset": "splunk-hec", "name": "lab", "host": "localhost"]
        let off = TUIWizards.observabilityCommands(base, false)[0]
        expect(!off.contains("--allow-private-networks"), "unchecked emits nothing: \(off)")
        let on = TUIWizards.observabilityCommands(base.merging(["allow-private-networks": "yes"]) { $1 }, false)[0]
        expect(on.contains("--allow-private-networks") && on.contains("--verify-tls"), "checked emits the bare flag next to the TLS choice: \(on)")
        let otlp = TUIWizards.observabilityCommands(["action": "add", "preset": "otlp", "endpoint": "10.0.0.5:4317", "allow-private-networks": "yes"], false)[0]
        expect(otlp.contains("--allow-private-networks"), "a typed private OTLP endpoint can be allowed too: \(otlp)")
        let galileo = TUIWizards.observabilityCommands(["action": "add", "preset": "galileo", "allow-private-networks": "yes"], false)[0]
        expect(!galileo.contains("--allow-private-networks"), "presets without a typed endpoint never carry a stale value")
    }

    private static func splunkHECDefaultsToVerifiedTLS() {
        guard let wizard = TUIWizards.all.first(where: { $0.id == "observability" }),
              let field = wizard.fields.first(where: { $0.key == "verify-tls-hec" }) else {
            expect(false, "Splunk HEC TLS field exists")
            return
        }
        expect(field.defaultValue == "yes", "Splunk HEC verifies TLS by default")

        let omittedToggle = TUIWizards.observabilityCommands([
            "action": "add",
            "preset": "splunk-hec",
        ], false)[0]
        expect(omittedToggle.contains("--verify-tls"), "omitted HEC TLS setting fails secure")
        expect(!omittedToggle.contains("--no-verify-tls"), "omitted HEC TLS setting never disables verification")

        let explicitOptOut = TUIWizards.observabilityCommands([
            "action": "add",
            "preset": "splunk-hec",
            "host": "splunk.example",
            "verify-tls-hec": "no",
        ], false)[0]
        expect(!explicitOptOut.contains("--no-verify-tls"), "remote HEC cannot disable TLS verification")
        expect(explicitOptOut.contains("--verify-tls"), "remote HEC is forced to verify TLS")
        expect(
            TUIWizards.observabilityValidation([
                "action": "add",
                "preset": "splunk-hec",
                "host": "splunk.example",
                "port": "8088",
                "verify-tls-hec": "no",
            ]) != nil,
            "remote HEC TLS opt-out shows a validation error"
        )

        for host in ["localhost", "collector.localhost", "127.0.0.1", "127.42.7.9", "::1", "[::1]"] {
            let values = [
                "action": "add",
                "preset": "splunk-hec",
                "host": host,
                "port": "8088",
                "verify-tls-hec": "no",
            ]
            expect(TUIWizards.observabilityValidation(values) == nil, "\(host) permits local TLS opt-out")
            expect(
                TUIWizards.observabilityCommands(values, false)[0].contains("--no-verify-tls"),
                "\(host) emits the explicit local TLS opt-out"
            )
        }
    }

    private static func secureSetupSecretsUseChildEnvironment() {
        let cases: [(id: String, field: String, environmentKey: String, values: [String: String])] = [
            ("splunk", "access-token", "SPLUNK_ACCESS_TOKEN", ["mode": "splunk-o11y", "access-token": "private-value"]),
            ("splunk", "hec-token", "DEFENSECLAW_SPLUNK_HEC_TOKEN", ["mode": "splunk-enterprise", "hec-token": "private-value"]),
            ("observability", "token", "DEFENSECLAW_SETUP_OBSERVABILITY_TOKEN", ["action": "add", "preset": "datadog", "token": "private-value"]),
            ("splunk-dashboards", "o11y-api-token", "SFX_AUTH_TOKEN", ["action": "apply", "o11y-api-token": "private-value"]),
        ]

        for item in cases {
            guard let wizard = TUIWizards.all.first(where: { $0.id == item.id }),
                  let field = wizard.fields.first(where: { $0.key == item.field }) else {
                expect(false, "\(item.id) secure field exists")
                continue
            }
            let message = SetupSecretTransportPolicy.validationMessage(
                wizard: wizard,
                values: item.values,
                visibleFields: [field]
            )
            expect(message == nil, "\(item.id) accepts its child-environment secret transport")
            let environment = wizard.secretEnvironment?(item.values) ?? [:]
            expect(environment[item.environmentKey] == "private-value", "\(item.id) exports its documented child environment key")
            let arguments = wizard.commandBuilder?(item.values, false).flatMap { $0 } ?? []
            expect(!arguments.contains("private-value"), "\(item.id) secret never enters argv")

            var withoutSecret = item.values
            withoutSecret[item.field] = ""
            expect(
                SetupSecretTransportPolicy.validationMessage(
                    wizard: wizard,
                    values: withoutSecret,
                    visibleFields: [field]
                ) == nil,
                "\(item.id) preserves non-secret setup operations"
            )
        }
    }

    private static func webhookBuilderCoversCurrentNotifierOptions() {
        let commands = TUIWizards.webhookCommands([
            "action": "add",
            "type": "webex",
            "name": "secops",
            "url": "https://webexapis.com/v1/messages",
            "webex-secret-env": "DEFENSECLAW_WEBEX_TOKEN",
            "room-id": "room-123",
            "enabled": "yes",
            "min-severity": "HIGH",
            "events": "block,scan",
            "timeout-seconds": "12",
            "cooldown-seconds": "0",
            "connector": "codex",
            "dry-run-add": "yes",
        ], false)
        let arguments = commands[0]
        expect(arguments.starts(with: ["setup", "webhook", "add", "webex"]), "webhook add prefix")
        expect(value(after: "--secret-env", in: arguments) == "DEFENSECLAW_WEBEX_TOKEN", "Webex token env")
        expect(value(after: "--room-id", in: arguments) == "room-123", "Webex room")
        expect(value(after: "--timeout-seconds", in: arguments) == "12", "delivery timeout")
        expect(value(after: "--cooldown-seconds", in: arguments) == "0", "disabled dedup cooldown")
        expect(value(after: "--connector", in: arguments) == "codex", "connector-scoped webhook")
        expect(arguments.contains("--dry-run"), "webhook dry run")
    }

    private static func webhookValidationRequiresProviderCredentials() {
        let webex = [
            "action": "add",
            "type": "webex",
            "url": "https://webexapis.com/v1/messages",
            "timeout-seconds": "10",
            "events": "block",
        ]
        expect(TUIWizards.webhookValidation(webex) != nil, "Webex requires token env and room")
        let pagerDuty = [
            "action": "add",
            "type": "pagerduty",
            "url": "https://events.pagerduty.com/v2/enqueue",
            "pagerduty-secret-env": "DEFENSECLAW_PD_ROUTING_KEY",
            "timeout-seconds": "10",
            "events": "block,health",
        ]
        expect(TUIWizards.webhookValidation(pagerDuty) == nil, "valid PagerDuty notifier")
    }

    private static func removedStandaloneSandboxWizardStaysHidden() {
        // `defenseclaw sandbox setup --sandbox-ip/--host-ip/...` was deleted
        // with the legacy standalone OpenShell integration.
        let legacyKeys: Set<String> = ["sandbox-ip", "host-ip", "no-auto-pair", "no-host-networking"]
        expect(
            TUIWizards.all.allSatisfy { wizard in wizard.fields.allSatisfy { !legacyKeys.contains($0.key) } },
            "no setup wizard offers the removed standalone sandbox options"
        )
    }

    private static func sandboxWizardMatchesTheTUIWizard() {
        let wizard = TUIWizards.all.first { $0.id == "sandbox" }
        expect(wizard != nil, "the Sandbox wizard is listed")
        expect(wizard?.fields.contains { $0.key == "install-openshell" } == false,
               "the app never runs the sudo installer (it needs a terminal)")
        expect(wizard?.fields.contains { $0.key == "telemetry-off" && $0.defaultValue == "yes" } == true,
               "the telemetry question: the Homebrew service reads gateway.env")
        expect(wizard?.fields.contains { $0.key.contains("mount") || $0.label.lowercased().contains("mount") } == false,
               "no mounts question: setup runs macOS sandboxes in MicroVMs, which mount no host folders")
        let blurb = wizard?.blurb ?? ""
        for fact in ["MicroVM", "Apple silicon", "compute_driver = \"vm\"", "every run works on a copy",
                     "defenseclaw sandbox pull", "e2fsprogs"] {
            expect(blurb.contains(fact), "the Sandbox wizard's blurb names \(fact)")
        }
        expect(!blurb.contains("cannot run on a Mac"), "the blurb no longer says sandboxes cannot run on a Mac")
        // The same literal the TUI test pins for macOS (test_sandbox_setup_wizard.py).
        let defaults = Dictionary(uniqueKeysWithValues: (wizard?.fields ?? []).map { ($0.key, $0.defaultValue) })
        expect(TUIWizards.sandboxCommands(defaults, false) == [[
            "sandbox", "setup", "--non-interactive", "--harness", "claudecode", "--harness", "codex", "--no-wrappers",
        ]], "defaults match the TUI wizard")
        expect(TUIWizards.sandboxCommands([
            "harness-codex": "no", "mounts": "no", "telemetry-off": "no", "wrappers": "yes", "build-images": "no",
        ], false) == [[
            "sandbox", "setup", "--non-interactive", "--harness", "claudecode", "--upstream-telemetry", "--wrappers",
            "--skip-images",
        ]], "every consent flag, and never --no-mounts")
        expect(TUIWizards.sandboxCommands(["action": "doctor"], false) == [["sandbox", "doctor"]], "doctor action")
        expect(TUIWizards.sandboxValidation(["harness-claudecode": "no", "harness-codex": "no"]) != nil,
               "a harness is required")
        let config: YAMLNode = .mapping(["openshell": .mapping(["harnesses": .sequence([.scalar("codex")])])])
        expect(TUIWizards.sandboxLiveDefaults(config) == ["harness-claudecode": "no", "harness-codex": "yes"],
               "configured harnesses seed the toggles")

        // Every flag the TUI builder can emit is one the app emits too, except
        // the sudo installer and the mounts question the TUI offers only off
        // macOS.
        let testsDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let python = (try? String(
            contentsOf: testsDirectory.appendingPathComponent("../../../cli/defenseclaw/tui/panels/setup.py"),
            encoding: .utf8
        )) ?? ""
        guard let start = python.range(of: "def _build_sandbox_args("),
              let end = python.range(of: "\ndef ", range: start.upperBound..<python.endIndex)
        else {
            expect(false, "the TUI sandbox argv builder was not found in setup.py")
            return
        }
        let body = String(python[start.upperBound..<end.lowerBound])
        let pattern = try! NSRegularExpression(pattern: #""(--[a-z-]+)""#)
        let matches = pattern.matches(in: body, range: NSRange(body.startIndex..., in: body))
        let tuiFlags = Set(matches.compactMap { match in
            Range(match.range(at: 1), in: body).map { String(body[$0]) }
        })
        let swiftFlags: Set<String> = [
            "--non-interactive", "--harness", "--upstream-telemetry", "--wrappers", "--no-wrappers", "--skip-images",
        ]
        expect(tuiFlags == swiftFlags.union(["--install-openshell", "--no-mounts"]),
               "TUI sandbox flags \(tuiFlags.sorted()) differ from the app's")
    }

    private static func value(after flag: String, in arguments: [String]) -> String? {
        guard let index = arguments.firstIndex(of: flag), arguments.indices.contains(index + 1) else {
            return nil
        }
        return arguments[index + 1]
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else {
            FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
            Foundation.exit(1)
        }
    }
}
