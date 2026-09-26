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
        validatesInitializationCompletionBeforeGatewayStart()
        parsesInstalledConnectorsInSupportedOrder()
        excludesProxyConnectorsFromDiscoveryAndInitialization()
        usesObserveAllWhenEverythingIsRegistered()
        scopesActionToExplicitConnectors()
        fallsBackToLegacySingleConnectorOnlyWhenDiscoveryIsEmpty()
        singleRegisteredConnectorUsesLegacyContract()
        subsetRegistrationEmitsInitPlusAdditiveSetup()
        multipleAdditiveSetupsRestartOnlyAfterTheFinalConnector()
        subsetActionLeadsWithAnEnforcedConnector()
        subsetWithoutGatewayStartNeverRestarts()
        emptyRegistrationDefensivelyRegistersEverything()
        proxyConnectorsNeverEnterInitializationPlans()
        setupCommandNameHyphenatesOnlyClaudeCode()
        commandRegistryIncludesAmpSetup()
        commandRegistryIncludesOmniGentSetup()
        commandRegistryIncludesCanonicalDevinSetup()
        parsesCommandArguments()
        rejectsMalformedCommandArguments()
        quotesDisplayedShellArguments()
        print("ConnectorOnboardingTests, CommandArgumentParser, and ShellQuoting tests passed")
    }

    private static func validatesInitializationCompletionBeforeGatewayStart() {
        let ready = #"{"status":"ready","setup":[{"name":"Config","status":"pass"}],"readiness":[{"name":"Audit database","status":"pass"}]}"#
        expect(ConnectorOnboarding.initializationFailure(from: ready) == nil,
               "ready initialization permits the final gateway start")
        expect(ConnectorOnboarding.initializationFailure(from: "WARNING: optional runtime diagnostic\n" + ready + "\n") == nil,
               "ordinary diagnostic prefixes do not hide successful structured output")
        let partial = #"{"status":"partial","setup":[{"name":"Sidecar","status":"skip"}],"readiness":[{"name":"Scanner","status":"warn"}]}"#
        expect(ConnectorOnboarding.initializationFailure(from: partial) == nil,
               "warnings and intentionally deferred gateway startup permit completion")

        for output in [
            #"{"status":"needs_attention","setup":[{"status":"fail"}],"readiness":[]}"#,
            #"{"status":"ready","setup":[{"status":"fail"}],"readiness":[]}"#,
            #"{"status":"partial","setup":[],"readiness":[{"status":"fail"}]}"#,
            #"{"status":"unexpected","setup":[],"readiness":[]}"#,
            #"{"status":"ready","setup":[{"status":"unexpected"}],"readiness":[]}"#,
            #"{"status":"ready","setup":[{}],"readiness":[]}"#,
            #"{"status":"ready","setup":{},"readiness":[]}"#,
            #"{"status":"ready"}"#,
            #"{"status":true,"setup":[],"readiness":[]}"#,
            #"{"status":"ready","setup":[],"readiness":[]"#,
            "unstructured success message",
            ready + "\n" + partial,
            "{invalid diagnostic}\n" + ready,
        ] {
            expect(ConnectorOnboarding.initializationFailure(from: output) != nil,
                   "failed, ambiguous, or malformed reports cannot authorize a gateway start")
        }
    }

    private static func parsesInstalledConnectorsInSupportedOrder() {
        let output = """
        diagnostic prefix
        {"agents":{
          "cursor":{"installed":true,"name":"cursor"},
          "claude-code":{"installed":true,"name":"claude-code"},
          "openclaw":{"installed":true,"name":"openclaw"},
          "zeptoclaw":{"installed":true,"name":"zeptoclaw"},
          "codex":{"installed":false,"name":"codex"}
        }}
        """
        let result = ConnectorOnboarding.installedConnectors(
            from: output,
            supportedOrder: ["openclaw", "zeptoclaw", "codex", "claudecode", "cursor"]
        )
        expect(result == ["claudecode", "cursor"], "discovery excludes proxy connectors")
    }

    private static func excludesProxyConnectorsFromDiscoveryAndInitialization() {
        let output = """
        {"agents":{
          "openclaw":{"installed":true,"name":"openclaw"},
          "zeptoclaw":{"installed":true,"name":"zeptoclaw"},
          "devin":{"installed":true,"name":"devin"}
        }}
        """
        let detected = ConnectorOnboarding.installedConnectors(
            from: output,
            supportedOrder: ["openclaw", "zeptoclaw", "devin"]
        )
        expect(detected == ["devin"], "proxy connectors stay out of hook discovery")

        let plan = makePlan(
            detected: ["openclaw"],
            registered: ["openclaw"],
            action: [],
            profile: "observe"
        )
        expect(plan.count == 1, "proxy-only discovery uses one safe fallback command")
        let index = plan[0].firstIndex(of: "--connector")
        expect(index.map { plan[0][$0 + 1] } == "codex", "proxy fallback maps to a hook connector")
    }

    private static func usesObserveAllWhenEverythingIsRegistered() {
        let plan = makePlan(
            detected: ["codex", "claudecode"],
            registered: ["codex", "claudecode"],
            action: [],
            profile: "observe"
        )
        expect(plan.count == 1, "full registration is a single command")
        expect(plan[0].contains("--observe-all"), "full registration uses --observe-all")
        expect(!plan[0].contains("--connector"), "observe-all avoids legacy --connector")
        expect(!plan[0].contains("--action-connectors"), "observe profile has no action subset")
    }

    private static func scopesActionToExplicitConnectors() {
        let plan = makePlan(
            detected: ["codex", "claudecode", "cursor"],
            registered: ["codex", "claudecode", "cursor"],
            action: ["codex", "cursor"],
            profile: "action"
        )
        expect(plan.count == 1, "full registration is a single command")
        let arguments = plan[0]
        let index = arguments.firstIndex(of: "--action-connectors")
        expect(index != nil, "action profile emits --action-connectors")
        expect(index.map { arguments[$0 + 1] } == "codex,cursor", "action connectors preserve discovery order")
        expect(arguments.contains("--observe-all"), "non-enforcing peers remain observed")
    }

    private static func fallsBackToLegacySingleConnectorOnlyWhenDiscoveryIsEmpty() {
        let plan = makePlan(detected: [], registered: [], action: [], profile: "observe")
        expect(plan.count == 1, "empty discovery is a single command")
        let arguments = plan[0]
        let index = arguments.firstIndex(of: "--connector")
        expect(index != nil, "empty discovery emits explicit fallback connector")
        expect(index.map { arguments[$0 + 1] } == "codex", "fallback connector is preserved")
        expect(!arguments.contains("--observe-all"), "empty discovery does not emit observe-all")
    }

    private static func singleRegisteredConnectorUsesLegacyContract() {
        let plan = makePlan(
            detected: ["codex", "claudecode", "cursor"],
            registered: ["claudecode"],
            action: [],
            profile: "observe"
        )
        expect(plan.count == 1, "single registration is a single command")
        let arguments = plan[0]
        let index = arguments.firstIndex(of: "--connector")
        expect(index.map { arguments[$0 + 1] } == "claudecode", "single registration targets the selected connector")
        expect(!arguments.contains("--observe-all"), "single registration avoids observe-all")
    }

    private static func subsetRegistrationEmitsInitPlusAdditiveSetup() {
        let plan = makePlan(
            detected: ["codex", "claudecode", "cursor"],
            registered: ["codex", "claudecode"],
            action: [],
            profile: "observe"
        )
        expect(plan.count == 2, "subset registration adds one setup follow-up")
        let head = plan[0]
        let headIndex = head.firstIndex(of: "--connector")
        expect(headIndex.map { head[$0 + 1] } == "codex", "init configures the first selected connector")
        expect(!head.contains("--observe-all"), "subset never emits observe-all")
        expect(!head.contains("cursor"), "unregistered connector is absent from init")
        let followUp = plan[1]
        expect(followUp.starts(with: ["setup", "claude-code", "--yes", "--mode", "observe"]),
               "follow-up adds the remaining connector via its setup alias")
        expect(!followUp.contains("--no-restart"), "last follow-up restarts when the gateway should run")
        expect(!plan.contains { $0.contains("cursor") }, "unregistered connector never appears in the plan")
    }

    private static func subsetActionLeadsWithAnEnforcedConnector() {
        let plan = makePlan(
            detected: ["codex", "claudecode", "cursor"],
            registered: ["codex", "cursor"],
            action: ["cursor"],
            profile: "action"
        )
        expect(plan.count == 2, "subset action registration adds one setup follow-up")
        let head = plan[0]
        let headIndex = head.firstIndex(of: "--connector")
        expect(headIndex.map { head[$0 + 1] } == "cursor", "init leads with an enforced connector")
        let profileIndex = head.firstIndex(of: "--profile")
        expect(profileIndex.map { head[$0 + 1] } == "action", "init carries the action profile")
        expect(head.contains("--no-human-approval"), "init carries the global enforcement options")
        let followUp = plan[1]
        expect(followUp.starts(with: ["setup", "codex", "--yes", "--mode", "observe"]),
               "non-enforced peer is added in observe mode")
    }

    private static func multipleAdditiveSetupsRestartOnlyAfterTheFinalConnector() {
        let plan = makePlan(
            detected: ["codex", "claudecode", "cursor", "amp"],
            registered: ["codex", "claudecode", "cursor"],
            action: [],
            profile: "observe"
        )
        expect(plan.count == 3, "three selected connectors produce init plus two follow-ups")
        expect(
            plan[1].starts(with: ["setup", "claude-code", "--yes", "--mode", "observe"]),
            "first additive setup preserves connector order and alias"
        )
        expect(plan[1].contains("--no-restart"), "intermediate additive setup does not restart")
        expect(
            plan[2].starts(with: ["setup", "cursor", "--yes", "--mode", "observe"]),
            "final additive setup preserves connector order"
        )
        expect(!plan[2].contains("--no-restart"), "final additive setup performs the restart")
        expect(!plan.contains { $0.contains("amp") }, "unregistered connector stays absent")
    }

    private static func subsetWithoutGatewayStartNeverRestarts() {
        let plan = makePlan(
            detected: ["codex", "claudecode", "cursor", "devin"],
            registered: ["codex", "claudecode", "cursor"],
            action: [],
            profile: "observe",
            startGateway: false
        )
        expect(plan.count == 3, "subset registration adds both setup follow-ups")
        expect(plan[0].contains("--no-start-gateway"), "init defers gateway startup to the app")
        expect(plan[0].contains("--verify"), "deferred startup preserves configuration readiness checks")
        expect(!plan[0].contains("--start-gateway"), "init cannot bypass administrator-aware lifecycle routing")
        expect(plan.dropFirst().allSatisfy { $0.contains("--no-restart") },
               "all connector setup steps leave gateway lifecycle to the final app action")
    }

    private static func emptyRegistrationDefensivelyRegistersEverything() {
        let plan = makePlan(
            detected: ["codex", "claudecode"],
            registered: [],
            action: [],
            profile: "observe"
        )
        expect(plan.count == 1, "empty registration collapses to one command")
        expect(plan[0].contains("--observe-all"), "empty registration defensively registers everything")
    }

    private static func proxyConnectorsNeverEnterInitializationPlans() {
        let plan = makePlan(
            detected: ["openclaw", "codex", "zeptoclaw"],
            registered: ["openclaw", "codex", "zeptoclaw"],
            action: ["openclaw", "codex", "zeptoclaw"],
            profile: "action"
        )
        expect(!plan.contains { $0.contains("openclaw") }, "OpenClaw is absent from first-run plans")
        expect(!plan.contains { $0.contains("zeptoclaw") }, "ZeptoClaw is absent from first-run plans")

        let fallback = makePlan(
            detected: [],
            registered: [],
            action: [],
            profile: "observe",
            fallbackConnector: "openclaw"
        )
        let connectorIndex = fallback[0].firstIndex(of: "--connector")
        expect(connectorIndex.map { fallback[0][$0 + 1] } == "codex",
               "proxy fallback resolves to a hook connector")
    }

    private static func setupCommandNameHyphenatesOnlyClaudeCode() {
        expect(ConnectorOnboarding.setupCommandName("claudecode") == "claude-code", "claudecode maps to claude-code")
        expect(ConnectorOnboarding.setupCommandName("claude-code") == "claude-code", "claude-code stays hyphenated")
        expect(ConnectorOnboarding.setupCommandName("codex") == "codex", "other connectors map to themselves")
    }

    private static func commandRegistryIncludesAmpSetup() {
        let command = CommandRegistry.all.first { $0.title == "setup amp" }
        expect(command?.arguments == ["setup", "amp", "--yes"], "Amp setup command is available")
        expect(CommandRegistry.all.count == CommandRegistry.sourceCount, "native command count matches source")
    }

    private static func commandRegistryIncludesOmniGentSetup() {
        let command = CommandRegistry.all.first { $0.title == "setup omnigent" }
        expect(
            command?.arguments == ["setup", "omnigent", "--yes"],
            "OmniGent setup command is available"
        )
    }

    private static func commandRegistryIncludesCanonicalDevinSetup() {
        let command = CommandRegistry.all.first { $0.title == "setup devin" }
        expect(command?.arguments == ["setup", "devin", "--yes"], "Devin setup command is available")
        expect(CommandRegistry.all.allSatisfy { !$0.arguments.contains("windsurf") },
               "legacy Windsurf setup is absent from the native command registry")
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

    private static func quotesDisplayedShellArguments() {
        expect(ShellQuoting.quote("defenseclaw") == "defenseclaw", "safe shell token")
        expect(ShellQuoting.quote("") == "''", "empty shell token")
        expect(ShellQuoting.quote("two words") == "'two words'", "shell whitespace")
        expect(ShellQuoting.quote("can't") == "'can'\\''t'", "embedded shell quote")
        expect(ShellQuoting.quote("$(whoami)") == "'$(whoami)'", "shell command substitution")
        expect(ShellQuoting.quote("allow;rm") == "'allow;rm'", "shell command separator")
    }

    private static func expectParseFailure(_ input: String, _ label: String) {
        do {
            _ = try CommandArgumentParser.parse(input)
            expect(false, label)
        } catch {
            expect(true, label)
        }
    }

    private static func makePlan(
        detected: [String],
        registered: Set<String>,
        action: Set<String>,
        profile: String,
        fallbackConnector: String = "codex",
        startGateway: Bool = true
    ) -> [[String]] {
        ConnectorOnboarding.initializationPlan(
            detectedConnectors: detected,
            registeredConnectors: registered,
            fallbackConnector: fallbackConnector,
            actionConnectors: action,
            profile: profile,
            scannerMode: "local",
            llmJudge: false,
            failMode: "open",
            humanApproval: false,
            hiltSeverity: "HIGH",
            startGateway: startGateway,
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
