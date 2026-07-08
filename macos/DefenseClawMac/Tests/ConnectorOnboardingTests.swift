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
struct ConnectorOnboardingTests {
    static func main() {
        parsesInstalledConnectorsInSupportedOrder()
        usesObserveAllForDetectedConnectors()
        scopesActionToExplicitConnectors()
        fallsBackToLegacySingleConnectorOnlyWhenDiscoveryIsEmpty()
        parsesCommandArguments()
        rejectsMalformedCommandArguments()
        print("ConnectorOnboardingTests and CommandArgumentParser tests passed")
    }

    private static func parsesInstalledConnectorsInSupportedOrder() {
        let output = """
        diagnostic prefix
        {"agents":{
          "cursor":{"installed":true,"name":"cursor"},
          "claude-code":{"installed":true,"name":"claude-code"},
          "codex":{"installed":false,"name":"codex"}
        }}
        """
        let result = ConnectorOnboarding.installedConnectors(
            from: output,
            supportedOrder: ["codex", "claudecode", "cursor"]
        )
        expect(result == ["claudecode", "cursor"], "installed connector parsing")
    }

    private static func usesObserveAllForDetectedConnectors() {
        let arguments = makeArguments(
            detected: ["codex", "claudecode"],
            action: [],
            profile: "observe"
        )
        expect(arguments.contains("--observe-all"), "detected connectors use --observe-all")
        expect(!arguments.contains("--connector"), "observe-all avoids legacy --connector")
        expect(!arguments.contains("--action-connectors"), "observe profile has no action subset")
    }

    private static func scopesActionToExplicitConnectors() {
        let arguments = makeArguments(
            detected: ["codex", "claudecode", "cursor"],
            action: ["codex", "cursor"],
            profile: "action"
        )
        let index = arguments.firstIndex(of: "--action-connectors")
        expect(index != nil, "action profile emits --action-connectors")
        expect(index.map { arguments[$0 + 1] } == "codex,cursor", "action connectors preserve discovery order")
        expect(arguments.contains("--observe-all"), "non-enforcing peers remain observed")
    }

    private static func fallsBackToLegacySingleConnectorOnlyWhenDiscoveryIsEmpty() {
        let arguments = makeArguments(detected: [], action: [], profile: "observe")
        let index = arguments.firstIndex(of: "--connector")
        expect(index != nil, "empty discovery emits explicit fallback connector")
        expect(index.map { arguments[$0 + 1] } == "codex", "fallback connector is preserved")
        expect(!arguments.contains("--observe-all"), "empty discovery does not emit observe-all")
    }

    private static func parsesCommandArguments() {
        expect(
            (try? CommandArgumentParser.parse(#""" ''"#)) == ["", ""],
            "empty quoted command arguments"
        )
        expect(
            (try? CommandArgumentParser.parse(#"hello\ world"#)) == ["hello world"],
            "escaped command whitespace"
        )
        expect(
            (try? CommandArgumentParser.parse(#"pre"mid dle"post tail"#)) == ["premid dlepost", "tail"],
            "quoted and unquoted command token boundaries"
        )
    }

    private static func rejectsMalformedCommandArguments() {
        expectParseFailure(#""unclosed"#, "unclosed command quote")
        expectParseFailure("trailing\\", "trailing command backslash")
    }

    private static func expectParseFailure(_ input: String, _ label: String) {
        do {
            _ = try CommandArgumentParser.parse(input)
            expect(false, label)
        } catch {
            expect(true, label)
        }
    }

    private static func makeArguments(
        detected: [String],
        action: Set<String>,
        profile: String
    ) -> [String] {
        ConnectorOnboarding.initializationArguments(
            detectedConnectors: detected,
            fallbackConnector: "codex",
            actionConnectors: action,
            profile: profile,
            scannerMode: "local",
            llmJudge: false,
            failMode: "open",
            humanApproval: false,
            hiltSeverity: "HIGH",
            startGateway: true,
            verify: true
        )
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ label: String) {
        guard condition() else {
            fputs("FAILED: \(label)\n", stderr)
            exit(1)
        }
    }
}
