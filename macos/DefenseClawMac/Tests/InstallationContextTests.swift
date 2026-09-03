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
struct InstallationContextTests {
    private static let userHome = URL(fileURLWithPath: "/Users/context-test", isDirectory: true)
    private static let currentDirectory = URL(fileURLWithPath: "/work", isDirectory: true)

    static func main() async {
        CLIProcessGroupLauncher.execIfRequested()
        sourcePrecedenceMatchesRuntime()
        managedLayoutAndCapabilitiesAreExact()
        explicitUnreadableAndRelativePathsFailClosed()
        configPathsAndVenvResolveIndependently()
        emptyFlowCollectionsMatchRuntimeGeneratedConfig()
        populatedFlowCollectionsMatchRuntimeGeneratedConfig()
        managedEvidenceMonotonicallyRemovesMutation()
        nestedAuditPathIsReadCorrectly()
        protectedEnvironmentCannotBeOverridden()
        await redactionDefaultProfileMatchesRuntimeSchema()
        await configStoreRebindDropsThePreviousInstallation()
        await lowerLevelMutationGateSurvivesRebind()
        await gatewayPOSTGateFailsBeforeNetwork()
        print("InstallationContextTests passed")
    }

    private static func sourcePrecedenceMatchesRuntime() {
        let envConfig = "/chosen/environment.yaml"
        let appConfig = "/chosen/app.yaml"
        var context = resolve(
            environment: [
                "DEFENSECLAW_CONFIG": envConfig,
                "DEFENSECLAW_HOME": "/chosen/home",
            ],
            appOverride: appConfig,
            texts: [envConfig: unmanagedConfig]
        )
        expect(context.source == .environmentConfig, "DEFENSECLAW_CONFIG wins")
        expect(context.configURL.path == envConfig, "environment config path selected")
        expect(context.homeRoot.path == "/chosen/home", "HOME still supplies the runtime root")

        context = resolve(
            environment: ["DEFENSECLAW_HOME": "/chosen/home"],
            appOverride: appConfig,
            texts: [appConfig: unmanagedConfig]
        )
        expect(context.source == .appOverride, "app override wins over DEFENSECLAW_HOME")

        context = resolve(
            environment: ["DEFENSECLAW_HOME": "/chosen/home"],
            texts: ["/chosen/home/config.yaml": unmanagedConfig]
        )
        expect(context.source == .environmentHome, "DEFENSECLAW_HOME wins without config overrides")

        context = resolve(existing: [InstallationContext.managedLaunchdPlistPath])
        expect(context.source == .managedPackage, "managed package wins over user default")

        context = resolve()
        expect(context.source == .userDefault, "user default is the final fallback")
        expect(context.configURL.path == "/Users/context-test/.defenseclaw/config.yaml", "default config path")
    }

    private static func managedLayoutAndCapabilitiesAreExact() {
        let context = resolve(
            existing: [InstallationContext.managedConfigPath],
            texts: [InstallationContext.managedConfigPath: managedConfig]
        )
        expect(!context.permitsMutation, "managed package is read only")
        expect(context.homeRoot.path == InstallationContext.managedRootPath, "managed home root")
        expect(context.configURL.path == InstallationContext.managedConfigPath, "managed config")
        expect(context.dataDirectory.path == InstallationContext.managedRuntimePath, "managed runtime")
        expect(
            context.gatewayLogURL.path == InstallationContext.managedLogDirectoryPath + "/gateway.log",
            "managed launchd log"
        )
        expect(
            context.venvURL.path == InstallationContext.managedRuntimePath + "/.venv",
            "managed fallback venv stays below runtime, not the admin config root"
        )

        let explicitlySelected = resolve(
            environment: ["DEFENSECLAW_CONFIG": InstallationContext.managedConfigPath],
            existing: [InstallationContext.managedConfigPath],
            texts: [InstallationContext.managedConfigPath: managedConfig]
        )
        expect(
            explicitlySelected.homeRoot.path == InstallationContext.managedRootPath,
            "explicit packaged config still uses the packaged home root"
        )
        expect(
            explicitlySelected.venvURL.path == InstallationContext.managedRuntimePath + "/.venv",
            "explicit packaged config never invents an admin-root venv"
        )
    }

    private static func explicitUnreadableAndRelativePathsFailClosed() {
        var context = resolve(
            environment: ["DEFENSECLAW_CONFIG": "/missing/config.yaml"]
        )
        expect(isInvalid(context), "missing explicit config fails closed")

        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": "relative/config.yaml"]
        )
        expect(isInvalid(context), "relative config override fails closed")

        let unsupportedModePath = "/chosen/unsupported-mode.yaml"
        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": unsupportedModePath],
            texts: [unsupportedModePath: """
            config_version: 8
            deployment_mode: enterprise-ish
            """]
        )
        expect(isInvalid(context), "unsupported config deployment mode fails closed")

        let edgeModePath = "/chosen/edge-mode.yaml"
        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": edgeModePath],
            texts: [edgeModePath: """
            config_version: 8
            deployment_mode: edge
            """]
        )
        expect(!isInvalid(context), "runtime-supported edge alias remains valid")

        let structuredSecurityPath = "/chosen/structured-security.yaml"
        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": structuredSecurityPath],
            texts: [structuredSecurityPath: """
            config_version: 8
            deployment_mode:
              unexpected: managed_enterprise
            data_dir:
              unexpected: /runtime/data
            """]
        )
        expect(isInvalid(context), "non-scalar security and path values fail closed")

        let path = "/chosen/relative-data.yaml"
        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": path],
            texts: [path: """
            config_version: 8
            deployment_mode: unmanaged_byod
            data_dir: relative/data
            observability:
              local:
                path: relative/audit.db
            """]
        )
        expect(isInvalid(context), "relative YAML runtime paths fail closed")
        expect(
            context.dataDirectory.path == "/Users/context-test/.defenseclaw",
            "invalid relative data_dir is never adopted"
        )
    }

    private static func configPathsAndVenvResolveIndependently() {
        let path = "/chosen/config.yaml"
        let context = resolve(
            environment: [
                "DEFENSECLAW_CONFIG": path,
                "DEFENSECLAW_HOME": "/runtime/home",
                "DEFENSECLAW_VENV": "/runtime/python",
            ],
            texts: [path: """
            config_version: 8
            deployment_mode: unmanaged_byod
            data_dir: /runtime/data
            observability:
              local:
                path: /runtime/audit/custom.db
            """]
        )
        expect(context.dataDirectory.path == "/runtime/data", "YAML data_dir wins")
        expect(context.auditDBURL.path == "/runtime/audit/custom.db", "YAML audit path wins")
        expect(context.environmentURL.path == "/runtime/data/.env", "dotenv follows data_dir")
        expect(context.venvURL.path == "/runtime/python", "VENV override wins independently")

        let selectedPackaged = resolve(
            environment: ["DEFENSECLAW_CONFIG": InstallationContext.managedConfigPath],
            texts: [InstallationContext.managedConfigPath: """
            config_version: 8
            deployment_mode: managed_enterprise
            """]
        )
        expect(
            selectedPackaged.dataDirectory.path == InstallationContext.managedRuntimePath,
            "explicit packaged config without data_dir uses the managed runtime"
        )
    }

    private static func emptyFlowCollectionsMatchRuntimeGeneratedConfig() {
        let path = "/chosen/generated-empty-collections.yaml"
        var context = resolve(
            environment: ["DEFENSECLAW_CONFIG": path],
            texts: [path: """
            config_version: 8
            deployment_mode: unmanaged_byod
            observability: { } # no custom destinations
            registries: [ ] # no external registries
            """]
        )
        expect(!isInvalid(context), "runtime-generated empty mappings remain valid")
        expect(
            MiniYAML.parse("observability: {}\n")["observability"]?.mapping?.isEmpty == true,
            "empty flow mapping retains its YAML type"
        )
        expect(
            MiniYAML.parse("registries: []\n")["registries"]?.sequence?.isEmpty == true,
            "empty flow sequence retains its YAML type"
        )

        let quotedPath = "/chosen/quoted-empty-mapping.yaml"
        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": quotedPath],
            texts: [quotedPath: """
            config_version: 8
            deployment_mode: unmanaged_byod
            observability: "{}"
            """]
        )
        expect(isInvalid(context), "quoted braces remain a scalar and fail closed")

        let sequencePath = "/chosen/observability-sequence.yaml"
        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": sequencePath],
            texts: [sequencePath: """
            config_version: 8
            deployment_mode: unmanaged_byod
            observability: []
            """]
        )
        expect(isInvalid(context), "an observability sequence remains invalid")
    }

    private static func populatedFlowCollectionsMatchRuntimeGeneratedConfig() {
        let path = "/chosen/generated-splunk-observability.yaml"
        let generatedConfig = """
        config_version: 8
        deployment_mode: unmanaged_byod
        observability: {destinations: [{enabled: true, endpoint: 'https://127.0.0.1:8088/services/collector/event', kind: splunk-hec, name: 'splunk, local', network_safety: {allow_private_networks: true}, tls: {insecure_skip_verify: true}, token_env: SPLUNK_HEC_TOKEN}]}
        """
        var context = resolve(
            environment: ["DEFENSECLAW_CONFIG": path],
            texts: [path: generatedConfig]
        )
        expect(!isInvalid(context), "runtime-generated Splunk flow mapping remains valid")

        let observability = MiniYAML.parse(generatedConfig)["observability"]?.mapping
        let destination = observability?["destinations"]?.sequence?.first?.mapping
        expect(destination?["kind"]?.string == "splunk-hec", "flow destination kind is parsed")
        expect(destination?["name"]?.string == "splunk, local", "quoted flow scalar preserves commas")
        expect(
            destination?["network_safety"]?.mapping?["allow_private_networks"]?.bool == true,
            "nested flow mapping is parsed"
        )
        expect(
            destination?["tls"]?.mapping?["insecure_skip_verify"]?.bool == true,
            "second nested flow mapping is parsed"
        )

        let stringHeaders = MiniYAML.parse(
            "observability: {headers: {inf: value, nan: value, Infinity: value, 1e2: value}}\n"
        )["observability"]?.mapping?["headers"]?.mapping
        expect(
            stringHeaders?.count == 4,
            "PyYAML string-like numeric header keys remain valid strings"
        )

        let localPath = "/chosen/generated-local-observability.yaml"
        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": localPath],
            texts: [localPath: """
            config_version: 8
            deployment_mode: unmanaged_byod
            observability: {local: {path: /runtime/audit/compact.db}, destinations: []}
            """]
        )
        expect(!isInvalid(context), "populated observability flow mapping remains valid")
        expect(context.auditDBURL.path == "/runtime/audit/compact.db", "flow mapping audit path is read")

        let wrappedPath = "/chosen/generated-wrapped-observability.yaml"
        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": wrappedPath],
            texts: [wrappedPath: """
            config_version: 8
            deployment_mode: unmanaged_byod
            observability: {destinations: [{enabled: true,
                kind: splunk-hec, name: splunk-local,
                network_safety: {allow_private_networks: true}}],
              local: {path: /runtime/audit/wrapped.db}}
            """]
        )
        expect(!isInvalid(context), "wrapped runtime flow mapping remains valid")
        expect(context.auditDBURL.path == "/runtime/audit/wrapped.db", "wrapped flow audit path is read")

        let escapedPath = "/chosen/generated-escaped-observability.yaml"
        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": escapedPath],
            texts: [escapedPath: """
            config_version: 8
            deployment_mode: unmanaged_byod
            observability: {"local":{"path":"/runtime/a\\u0075dit/escaped.db"}}
            """]
        )
        expect(!isInvalid(context), "JSON-compatible flow mapping remains valid")
        expect(context.auditDBURL.path == "/runtime/audit/escaped.db", "flow scalar escapes are decoded")

        let embeddedHashPath = "/chosen/generated-embedded-hash-observability.yaml"
        let embeddedHashConfig = """
        config_version: 8
        deployment_mode: unmanaged_byod
        observability: {label: "a\\t \\\" # b", local: {path: /runtime/audit/hash.db}}
        """
        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": embeddedHashPath],
            texts: [embeddedHashPath: embeddedHashConfig]
        )
        expect(!isInvalid(context), "hash inside an escaped flow scalar is not treated as a comment")
        expect(context.auditDBURL.path == "/runtime/audit/hash.db", "content after escaped quote is retained")
        expect(
            MiniYAML.parse(embeddedHashConfig)["observability"]?.mapping?["label"]?.string == "a\t \" # b",
            "escaped quote and hash decode like the runtime loader"
        )

        let missingSeparatorPath = "/chosen/missing-flow-separator.yaml"
        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": missingSeparatorPath],
            texts: [missingSeparatorPath: """
            config_version: 8
            deployment_mode: unmanaged_byod
            observability: {local: {path:/runtime/wrong.db}}
            """]
        )
        expect(isInvalid(context), "plain flow keys require a YAML value separator")

        let duplicatePath = "/chosen/duplicate-flow-key.yaml"
        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": duplicatePath],
            texts: [duplicatePath: """
            config_version: 8
            deployment_mode: unmanaged_byod
            observability: {local: {path: /runtime/first.db, path: /runtime/second.db}}
            """]
        )
        expect(isInvalid(context), "duplicate flow keys fail closed like the runtime loader")

        for invalidKey in ["true", "123", "2026-08-20", "<<"] {
            let invalidKeyPath = "/chosen/non-string-flow-key-\(invalidKey).yaml"
            context = resolve(
                environment: ["DEFENSECLAW_CONFIG": invalidKeyPath],
                texts: [invalidKeyPath: """
                config_version: 8
                deployment_mode: unmanaged_byod
                observability: {\(invalidKey): ignored, local: {path: /runtime/audit.db}}
                """]
            )
            expect(isInvalid(context), "non-string or merge flow key \(invalidKey) fails closed")
        }

        let quotedMergePath = "/chosen/quoted-merge-flow-key.yaml"
        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": quotedMergePath],
            texts: [quotedMergePath: """
            config_version: 8
            deployment_mode: unmanaged_byod
            observability: {"<<": ignored, local: {path: /runtime/audit.db}}
            """]
        )
        expect(isInvalid(context), "quoted merge keys fail closed like the runtime loader")

        let multilineQuotedPath = "/chosen/multiline-quoted-flow-value.yaml"
        let longLabel = String(repeating: "a", count: 4_100)
        let multilineQuotedConfig = """
        config_version: 8
        deployment_mode: unmanaged_byod
        observability: {label: "\(longLabel)\\
          # retained inside the quoted value", local: {path: /runtime/audit/multiline.db}}
        """
        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": multilineQuotedPath],
            texts: [multilineQuotedPath: multilineQuotedConfig]
        )
        expect(!isInvalid(context), "wrapped quoted flow scalars retain YAML line-continuation semantics")
        expect(
            context.auditDBURL.path == "/runtime/audit/multiline.db",
            "content following a wrapped quoted scalar remains visible"
        )
        expect(
            MiniYAML.parse(multilineQuotedConfig)["observability"]?.mapping?["label"]?.string
                == longLabel + "# retained inside the quoted value",
            "escaped quoted line breaks decode exactly like the runtime loader"
        )

        let oversizedPath = "/chosen/oversized-config.yaml"
        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": oversizedPath],
            texts: [
                oversizedPath: "config_version: 8\n#"
                    + String(repeating: "\u{00E9}", count: 2 * 1024 * 1024 + 1),
            ]
        )
        expect(isInvalid(context), "multibyte configs over the runtime byte limit fail closed")

        let malformedPath = "/chosen/malformed-flow-observability.yaml"
        context = resolve(
            environment: ["DEFENSECLAW_CONFIG": malformedPath],
            texts: [malformedPath: """
            config_version: 8
            deployment_mode: unmanaged_byod
            observability: {destinations: [{name: splunk-local}]
            """]
        )
        expect(isInvalid(context), "truncated flow mapping still fails closed")
    }

    private static func managedEvidenceMonotonicallyRemovesMutation() {
        let appPath = "/chosen/app.yaml"
        var context = resolve(
            appOverride: appPath,
            existing: [InstallationContext.managedLaunchdPlistPath],
            texts: [appPath: unmanagedConfig]
        )
        expect(isInvalid(context), "app override cannot hide a managed package marker")

        context = resolve(
            environment: [
                "DEFENSECLAW_CONFIG": appPath,
                "DEFENSECLAW_DEPLOYMENT_MODE": "unmanaged_byod",
            ],
            existing: [InstallationContext.managedLaunchdPlistPath],
            texts: [appPath: unmanagedConfig]
        )
        expect(isInvalid(context), "pinned unmanaged mode cannot hide managed package evidence")

        let reduced = resolve(texts: [
            "/Users/context-test/.defenseclaw/config.yaml": unmanagedConfig,
        ]).reducingToInvalidReadOnly("runtime reports managed")
        expect(isInvalid(reduced), "runtime health can only reduce capability")
    }

    private static func nestedAuditPathIsReadCorrectly() {
        let path = "/chosen/nested.yaml"
        let context = resolve(
            environment: ["DEFENSECLAW_CONFIG": path],
            texts: [path: """
            config_version: 8
            deployment_mode: unmanaged_byod
            observability:
              local:
                path: /nested/audit.db
            """]
        )
        expect(context.auditDBURL.path == "/nested/audit.db", "MiniYAML nested lookup is used")
    }

    private static func protectedEnvironmentCannotBeOverridden() {
        let context = resolve(texts: [
            "/Users/context-test/.defenseclaw/config.yaml": unmanagedConfig,
        ])
        let environment = CLIRunner.subprocessEnvironment(
            inheriting: [
                "PATH": "/custom/bin",
                "DEFENSECLAW_CONFIG": "/attacker/config.yaml",
                "DEFENSECLAW_HOME": "/attacker/home",
            ],
            home: userHome.path,
            protected: context.protectedSubprocessEnvironment
        )
        expect(environment["DEFENSECLAW_CONFIG"] == context.configURL.path, "config env is pinned")
        expect(environment["DEFENSECLAW_HOME"] == context.homeRoot.path, "home env is pinned")
        expect(environment["PATH"]?.hasPrefix("/custom/bin") == true, "normal PATH inheritance remains")
    }

    private static func redactionDefaultProfileMatchesRuntimeSchema() async {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("defenseclaw-redaction-profile-\(UUID().uuidString)", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            defer { try? FileManager.default.removeItem(at: directory) }

            let configURL = directory.appendingPathComponent("config.yaml", isDirectory: false)
            let context = InstallationContext.resolve(
                environment: ["DEFENSECLAW_CONFIG": configURL.path],
                appConfigOverride: nil,
                userHome: directory
            )
            let store = ConfigStore(context: context)

            try """
            config_version: 8
            deployment_mode: unmanaged_byod
            privacy:
              disable_redaction: true
            """.write(to: configURL, atomically: true, encoding: .utf8)
            var config = await store.reload()
            expect(
                config.redactionDefaultProfile.isEmpty,
                "legacy privacy.disable_redaction no longer defines the v8 redaction profile"
            )

            try """
            config_version: 8
            deployment_mode: unmanaged_byod
            observability:
              defaults:
                redaction_profile: none
            """.write(to: configURL, atomically: true, encoding: .utf8)
            config = await store.reload()
            expect(
                config.redactionDefaultProfile == "none",
                "the permissive none profile remains distinct from an absent profile"
            )

            try """
            config_version: 8
            deployment_mode: unmanaged_byod
            observability:
              defaults:
                redaction_profile: strict
            """.write(to: configURL, atomically: true, encoding: .utf8)
            config = await store.reload()
            expect(config.redactionDefaultProfile == "strict", "v8 redaction profile is loaded")
        } catch {
            fail("redaction profile fixture failed: \(error)")
        }
    }

    private static func lowerLevelMutationGateSurvivesRebind() async {
        let mutable = resolve(texts: [
            "/Users/context-test/.defenseclaw/config.yaml": unmanagedConfig,
        ])
        let managed = resolve(
            existing: [InstallationContext.managedConfigPath],
            texts: [InstallationContext.managedConfigPath: managedConfig]
        )
        let runner = CLIRunner(context: mutable)
        await runner.rebind(to: managed)
        let denied = await runner.run(binary: "/usr/bin/true", arguments: [], mutation: true)
        expect(denied.exitCode == 77, "lower-level runner blocks mutations after context rebind")
        let allowed = await runner.run(binary: "/usr/bin/true", arguments: [], mutation: false)
        expect(allowed.succeeded, "explicit read-only subprocess remains available")
    }

    private static func configStoreRebindDropsThePreviousInstallation() async {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("defenseclaw-context-rebind-\(UUID().uuidString)", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            defer { try? FileManager.default.removeItem(at: directory) }

            let firstData = directory.appendingPathComponent("first-data", isDirectory: true)
            let secondData = directory.appendingPathComponent("second-data", isDirectory: true)
            let firstConfig = directory.appendingPathComponent("first.yaml", isDirectory: false)
            let secondConfig = directory.appendingPathComponent("second.yaml", isDirectory: false)
            try """
            config_version: 8
            deployment_mode: unmanaged_byod
            data_dir: \(firstData.path)
            gateway:
              api_port: 19001
            """.write(to: firstConfig, atomically: true, encoding: .utf8)
            try """
            config_version: 8
            deployment_mode: unmanaged_byod
            data_dir: \(secondData.path)
            gateway:
              api_port: 19002
            """.write(to: secondConfig, atomically: true, encoding: .utf8)

            let firstContext = InstallationContext.resolve(
                environment: ["DEFENSECLAW_CONFIG": firstConfig.path],
                appConfigOverride: nil,
                userHome: directory
            )
            let secondContext = InstallationContext.resolve(
                environment: ["DEFENSECLAW_CONFIG": secondConfig.path],
                appConfigOverride: nil,
                userHome: directory
            )
            let store = ConfigStore(context: firstContext)
            let first = await store.reload()
            expect(first.gatewayPort == 19001, "ConfigStore reads the first context")
            await store.rebind(to: secondContext)
            let second = await store.reload()
            expect(second.gatewayPort == 19002, "ConfigStore reads only the rebound context")
        } catch {
            fail("ConfigStore rebind fixture failed: \(error)")
        }
    }

    private static func gatewayPOSTGateFailsBeforeNetwork() async {
        let managed = resolve(
            existing: [InstallationContext.managedConfigPath],
            texts: [InstallationContext.managedConfigPath: managedConfig]
        )
        let client = GatewayClient()
        await client.update(installationContext: managed)
        do {
            try await client.aiScan()
            fail("managed gateway POST should be refused")
        } catch {
            expect(
                error.localizedDescription.contains("Operation refused by the Mac app"),
                "gateway POST is rejected locally before a network request"
            )
        }
    }

    private static let unmanagedConfig = """
    config_version: 8
    deployment_mode: unmanaged_byod
    """

    private static let managedConfig = """
    config_version: 8
    deployment_mode: managed_enterprise
    data_dir: /opt/cisco/secureclient/defenseclaw/runtime
    observability:
      local:
        path: /opt/cisco/secureclient/defenseclaw/runtime/audit.db
    """

    private static func resolve(
        environment: [String: String] = [:],
        appOverride: String? = nil,
        existing: Set<String> = [],
        texts: [String: String] = [:]
    ) -> InstallationContext {
        InstallationContext.resolve(
            environment: environment,
            appConfigOverride: appOverride,
            userHome: userHome,
            currentDirectory: currentDirectory,
            fileExists: { existing.contains($0) || texts[$0] != nil },
            readText: { texts[$0.path] }
        )
    }

    private static func isInvalid(_ context: InstallationContext) -> Bool {
        if case .invalidReadOnly = context.accessMode { return true }
        return false
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else {
            FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
            Foundation.exit(1)
        }
    }

    private static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
        Foundation.exit(1)
    }
}
