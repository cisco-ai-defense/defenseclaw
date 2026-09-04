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

import Darwin
import Foundation

@main
struct CatalogActionSafetyTests {
    static func main() async {
        CLIProcessGroupLauncher.execIfRequested()
        scanActionsRemainOneClickButAreMutations()
        informationalActionsRemainNonMutating()
        auditCorruptionClassifierIsExact()
        await malformedAuditUsesPrivateReadOnlyCatalog()
        await genericFailuresDoNotUseIsolatedCatalog()
        await binaryOverrideDoesNotCrossCatalogLoad()
        await installationRebindInvalidatesCatalogLoad()
        print("CatalogActionSafetyTests passed")
    }

    private static func scanActionsRemainOneClickButAreMutations() {
        let skill = SkillItem(
            key: "codex/example",
            name: "example",
            version: "1",
            source: "/tmp/example",
            enabled: true,
            connector: "codex"
        )
        let mcp = MCPItem(
            name: "example",
            transport: "stdio",
            endpoint: "example",
            version: "1",
            enabled: true,
            connector: "codex"
        )
        let plugin = PluginItem(
            name: "example",
            version: "1",
            category: "command",
            enabled: true,
            connector: "codex",
            commandID: "example"
        )

        let checks: [(CatalogResourceAction, CatalogInvocation)] = [
            actionAndInvocation(CatalogActions.skills(skill), skill: skill),
            actionAndInvocation(CatalogActions.mcps(mcp), mcp: mcp),
            actionAndInvocation(CatalogActions.plugins(plugin), plugin: plugin),
        ]
        for (action, invocation) in checks {
            expect(action.readOnly, "scan remains a one-click action")
            expect(action.changesState, "scan explicitly changes installation state")
            expect(!invocation.requiresConfirmation, "scan does not gain an unrelated confirmation")
            expect(invocation.changesState, "scan invocation reaches the mutation gate")
        }
    }

    private static func informationalActionsRemainNonMutating() {
        let skill = SkillItem(
            key: "codex/example",
            name: "example",
            version: "1",
            source: "/tmp/example",
            enabled: true,
            connector: "codex"
        )
        guard let info = CatalogActions.skills(skill).first(where: { $0.verb == "info" }) else {
            fail("skill info action is missing")
        }
        let invocation = CatalogActions.invocation(info, skill: skill)
        expect(info.readOnly, "info remains one-click")
        expect(!info.changesState, "info remains non-mutating")
        expect(!invocation.changesState, "info invocation bypasses only the mutation gate")
    }

    private static func auditCorruptionClassifierIsExact() {
        expect(
            CLIRunner.isAuditStoreCorruption(
                "Failed to open audit store: database disk image is malformed\n"
            ),
            "the runtime's exact malformed-audit error enables degraded catalog mode"
        )
        expect(
            !CLIRunner.isAuditStoreCorruption("database disk image is malformed"),
            "an unattributed SQLite error cannot redirect catalog execution"
        )
        expect(
            !CLIRunner.isAuditStoreCorruption(
                "Failed to open audit store: database is locked"
            ),
            "busy and permission failures remain ordinary errors"
        )
        expect(
            !CLIRunner.isAuditStoreCorruption(
                "prefix Failed to open audit store: database disk image is malformed suffix"
            ),
            "the classifier requires a complete diagnostic line"
        )
    }

    private static func malformedAuditUsesPrivateReadOnlyCatalog() async {
        guard let fixture = try? CatalogFixture() else { fail("could not create catalog fixture") }
        defer { fixture.cleanup() }
        setenv("CATALOG_TEST_FAILURE", "corrupt", 1)
        defer { unsetenv("CATALOG_TEST_FAILURE") }

        let before = isolatedCatalogDirectories()
        do {
            let listing = try await CatalogCLI.plugins(using: CLIRunner(context: fixture.context))
            expect(listing.auditHistoryUnavailable, "fallback is labeled as audit-history unavailable")
            expect(listing.items.map(\.name) == ["example"], "fallback catalog JSON is parsed")
        } catch {
            fail("private read-only fallback failed: \(error)")
        }
        expect(
            isolatedCatalogDirectories() == before,
            "the private catalog workspace is removed after the command"
        )
    }

    private static func genericFailuresDoNotUseIsolatedCatalog() async {
        guard let fixture = try? CatalogFixture() else { fail("could not create catalog fixture") }
        defer { fixture.cleanup() }
        setenv("CATALOG_TEST_FAILURE", "generic", 1)
        defer { unsetenv("CATALOG_TEST_FAILURE") }

        let before = isolatedCatalogDirectories()
        do {
            _ = try await CatalogCLI.plugins(using: CLIRunner(context: fixture.context))
            fail("a generic catalog failure must be surfaced")
        } catch {
            expect(
                error.localizedDescription.contains("permission denied"),
                "the original generic failure is preserved"
            )
        }
        expect(
            isolatedCatalogDirectories() == before,
            "generic failures never create an isolated catalog workspace"
        )
    }

    private static func installationRebindInvalidatesCatalogLoad() async {
        guard let first = try? CatalogFixture(), let second = try? CatalogFixture() else {
            fail("could not create rebind fixtures")
        }
        defer {
            first.cleanup()
            second.cleanup()
        }
        setenv("CATALOG_TEST_FAILURE", "rebind", 1)
        defer { unsetenv("CATALOG_TEST_FAILURE") }
        let runner = CLIRunner(context: first.context)

        let load = Task { try await CatalogCLI.plugins(using: runner) }
        try? await Task.sleep(for: .milliseconds(100))
        await runner.rebind(to: second.context)
        do {
            _ = try await load.value
            fail("a catalog load cannot cross installations")
        } catch {
            expect(
                error.localizedDescription.contains("installation changed"),
                "rebind returns a retryable installation-change failure"
            )
        }
    }

    private static func binaryOverrideDoesNotCrossCatalogLoad() async {
        guard let first = try? CatalogFixture(), let second = try? CatalogFixture() else {
            fail("could not create binary override fixtures")
        }
        defer {
            first.cleanup()
            second.cleanup()
        }
        let defaults = UserDefaults.standard
        let previousOverride = defaults.string(forKey: CLIRunner.pathOverrideKey)
        defaults.set(first.binaryURL.path, forKey: CLIRunner.pathOverrideKey)
        defer {
            if let previousOverride {
                defaults.set(previousOverride, forKey: CLIRunner.pathOverrideKey)
            } else {
                defaults.removeObject(forKey: CLIRunner.pathOverrideKey)
            }
        }
        setenv("CATALOG_TEST_FAILURE", "rebind", 1)
        defer { unsetenv("CATALOG_TEST_FAILURE") }

        let load = Task {
            try await CatalogCLI.plugins(using: CLIRunner(context: first.context))
        }
        try? await Task.sleep(for: .milliseconds(100))
        defaults.set(second.binaryURL.path, forKey: CLIRunner.pathOverrideKey)
        do {
            let listing = try await load.value
            expect(listing.auditHistoryUnavailable, "the pinned binary completes degraded loading")
            expect(
                listing.selectedBinaryPath == first.binaryURL.path,
                "catalog loading pins the binary selected before its first await"
            )
        } catch {
            fail("binary override crossed an in-flight catalog load: \(error)")
        }
    }

    private static func isolatedCatalogDirectories() -> Set<String> {
        let prefix = "DefenseClaw-catalog-read-only-"
        let values = (try? FileManager.default.contentsOfDirectory(
            atPath: FileManager.default.temporaryDirectory.path
        )) ?? []
        return Set(values.filter { $0.hasPrefix(prefix) })
    }

    private static func actionAndInvocation(
        _ actions: [CatalogResourceAction],
        skill: SkillItem
    ) -> (CatalogResourceAction, CatalogInvocation) {
        guard let action = actions.first(where: { $0.verb == "scan" }) else {
            fail("skill scan action is missing")
        }
        return (action, CatalogActions.invocation(action, skill: skill))
    }

    private static func actionAndInvocation(
        _ actions: [CatalogResourceAction],
        mcp: MCPItem
    ) -> (CatalogResourceAction, CatalogInvocation) {
        guard let action = actions.first(where: { $0.verb == "scan" }) else {
            fail("MCP scan action is missing")
        }
        return (action, CatalogActions.invocation(action, mcp: mcp))
    }

    private static func actionAndInvocation(
        _ actions: [CatalogResourceAction],
        plugin: PluginItem
    ) -> (CatalogResourceAction, CatalogInvocation) {
        guard let action = actions.first(where: { $0.verb == "scan" }) else {
            fail("plugin scan action is missing")
        }
        return (action, CatalogActions.invocation(action, plugin: plugin))
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else { fail(message) }
    }

    private static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
        Foundation.exit(1)
    }

    private final class CatalogFixture {
        let root: URL
        let context: InstallationContext
        let binaryURL: URL

        init() throws {
            root = FileManager.default.temporaryDirectory.appendingPathComponent(
                "DefenseClaw-catalog-fixture-\(UUID().uuidString)",
                isDirectory: true
            )
            let home = root.appendingPathComponent("home", isDirectory: true)
            let venv = root.appendingPathComponent("venv", isDirectory: true)
            let bin = venv.appendingPathComponent("bin", isDirectory: true)
            try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
            let config = home.appendingPathComponent("config.yaml", isDirectory: false)
            try Data("config_version: 8\n".utf8).write(to: config)

            let executable = bin.appendingPathComponent("defenseclaw", isDirectory: false)
            binaryURL = executable
            let script = """
            #!/bin/sh
            set -eu
            if [ "$*" = "config show --source --format json" ]; then
              printf '%s\\n' '{"config_version":8,"token":"SENTINEL_SECRET","gateway":{"token_env":"OPENCLAW_GATEWAY_TOKEN"}}'
              exit 0
            fi
            if [ "$*" != "plugin list --json" ]; then
              printf '%s\\n' 'unexpected command' >&2
              exit 64
            fi
            if [ "${CATALOG_TEST_FAILURE:-}" = "generic" ]; then
              printf '%s\\n' 'permission denied' >&2
              exit 1
            fi
            if [ "$DEFENSECLAW_HOME" = "\(home.path)" ]; then
              if [ "${CATALOG_TEST_FAILURE:-}" = "rebind" ]; then sleep 1; fi
              printf '%s\\n' 'Failed to open audit store: database disk image is malformed' >&2
              exit 1
            fi
            case "$DEFENSECLAW_CONFIG" in
              "$DEFENSECLAW_HOME"/*) ;;
              *) printf '%s\\n' 'config escaped isolated home' >&2; exit 65 ;;
            esac
            [ "$DEFENSECLAW_VENV" = "\(venv.path)" ]
            [ "$(stat -f '%Lp' "$DEFENSECLAW_HOME")" = "700" ]
            [ "$(stat -f '%Lp' "$DEFENSECLAW_CONFIG")" = "600" ]
            ! grep -q 'SENTINEL_SECRET' "$DEFENSECLAW_CONFIG"
            ! grep -q '"audit_db"' "$DEFENSECLAW_CONFIG"
            printf '%s\\n' '[{"connector":"codex","plugins":[{"id":"example","name":"example","enabled":true}]}]'
            """
            try Data(script.utf8).write(to: executable)
            guard chmod(executable.path, 0o755) == 0 else {
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
            }

            context = InstallationContext(
                source: .userDefault,
                accessMode: .unmanagedMutable,
                homeRoot: home,
                configURL: config,
                dataDirectory: home,
                auditDBURL: home.appendingPathComponent("audit.db"),
                environmentURL: home.appendingPathComponent(".env"),
                gatewayJSONLURL: home.appendingPathComponent("gateway.jsonl"),
                gatewayLogURL: home.appendingPathComponent("gateway.log"),
                gatewayErrorLogURL: nil,
                watchdogLogURL: home.appendingPathComponent("watchdog.log"),
                venvURL: venv
            )
        }

        func cleanup() {
            try? FileManager.default.removeItem(at: root)
        }
    }
}
