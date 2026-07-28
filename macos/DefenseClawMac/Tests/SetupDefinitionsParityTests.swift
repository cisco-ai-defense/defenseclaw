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
        guardrailDefaultsNeverGuessTheWrongConnector()
        llmDefaultsPreserveTheSelectedProvider()
        llmBuilderDropsStaleRegionalOptions()
        customProviderBuilderCoversCurrentCLIOptions()
        customProviderBuilderDropsStaleFamilyOptions()
        customProviderValidationCatchesUnsafeInputs()
        observabilityBuilderCoversPresetSpecificInputs()
        webhookBuilderCoversCurrentNotifierOptions()
        webhookValidationRequiresProviderCredentials()
        print("Setup definition parity tests passed")
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
