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

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import Darwin
import Foundation
import Security
import ServiceManagement

struct DoctorCheck {
    enum Result { case pass, warn, fail }
    var name: String
    var result: Result
    var detail: String
}

private actor InvocationProbe {
    var calls: [InstallationContext] = []
    var released = false
    func record(_ context: InstallationContext) { calls.append(context) }
    func release() { released = true }
    func count() -> Int { calls.count }
    func isReleased() -> Bool { released }
    func firstContext() -> InstallationContext? { calls.first }
}

@main
struct GatewayAdministratorTests {
    static func main() async {
        CLIProcessGroupLauncher.execIfRequested()
        testRepairOnlyAction()
        testRootStateMarkers()
        testRepairRoutingDecision()
        testPathPolicy()
        testCodeRequirements()
        testInitialRegistrationPolicy()
        testCancellationState()
        testNativeAuthorizationResults()
        await testRepairBindsInstallationAndStopEndsThere()
        await testStartContinuesAsAccountAfterRepair()
        await testFailedRepairStopsTheCommand()
        await testUnresolvedRepairDoesNotPromptAgain()
        testRetiredPreferenceRemoved()
        testRepairHintQuotesTheHome()
        await testRefusalBeforeAuthorization()
        await testTaskCancellationAfterReservationRefusesDispatch()
        await testRebindCancelsPendingAuthorization()
        await testCancellationAfterDispatchWaitsForResult()
        print("GatewayAdministratorTests passed")
    }

    private static func expect(_ value: Bool, _ message: String) {
        guard value else { fputs("FAIL: \(message)\n", stderr); exit(1) }
    }

    private static func context(_ suffix: String = "") -> InstallationContext {
        InstallationContext.resolve(environment: [:], appConfigOverride: nil,
            userHome: URL(fileURLWithPath: "/Users/admin-test\(suffix)"),
            fileExists: { _ in false }, readText: { _ in nil })
    }

    /// Root-owned state a successful repair clears, and this runner's own
    /// repair memory (never the app's UserDefaults).
    final class RootStateFixture: @unchecked Sendable {
        private let lock = NSLock()
        private var markers = [GatewayRootState.Marker(name: "gateway.pid", identity: "gateway.pid:1"),
                               GatewayRootState.Marker(name: "hook_contract_lock.json", identity: "hook_contract_lock.json:1")]
        private var memory: String?

        var current: [GatewayRootState.Marker] { lock.lock(); defer { lock.unlock() }; return markers }
        var remembered: String? { lock.lock(); defer { lock.unlock() }; return memory }
        func set(_ value: [GatewayRootState.Marker]) { lock.lock(); markers = value; lock.unlock() }
        var repairMemory: GatewayRepairMemory {
            GatewayRepairMemory(load: { [self] in lock.lock(); defer { lock.unlock() }; return memory },
                                save: { [self] value in lock.lock(); memory = value; lock.unlock() })
        }
    }

    private static func makeRunner(
        _ context: InstallationContext, _ state: RootStateFixture, clearOnRepair: Bool = true,
        repair: @escaping @Sendable (InstallationContext, GatewayAdministratorOperation) async -> CLIResult
    ) -> CLIRunner {
        CLIRunner(context: context, rootOwnedState: { _ in state.current }, administratorRepair: { context, operation in
            let result = await repair(context, operation)
            if clearOnRepair, result.succeeded { state.set([]) }
            return result
        }, repairMemory: state.repairMemory)
    }

    private static func testRepairOnlyAction() {
        expect(GatewayAdminAction.allCases == [.repair], "the helper offers only the repair; the app never starts a gateway as root")
        expect(CLIRunner.gatewayLifecycleActions == ["start", "stop", "restart"], "lifecycle commands are the account's")
        for action in ["start", "stop", "restart", "START", ""] {
            expect(GatewayAdminAction(rawValue: action) == nil, "lifecycle verb is not a privileged action: \(action)")
        }
    }

    private static func testRootStateMarkers() {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("defenseclaw-root-state-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        try? Data("{}".utf8).write(to: directory.appendingPathComponent("gateway.pid"))
        expect(GatewayRootState.rootOwnedMarkers(home: directory).isEmpty, "the account's own gateway state is not root state")
        expect(GatewayRootState.rootOwnedMarkers(home: directory, accountUID: 0).isEmpty, "a root app has nothing to repair")
        expect(GatewayRootState.markers.contains("hook_contract_lock.json") && GatewayRootState.markers.contains("gateway.pid"),
               "the markers cover the gateway's root-run footprint")
    }

    private static func testPathPolicy() {
        for path in ["relative", "/Users/me/../other", "/Users/me//a", "/Users/me/./a", "/Users/me/a\n", "/Users/me/a\0", "/Users/me/"] {
            expect(!GatewayAdminPolicy.isCanonicalAbsolutePath(path), "noncanonical path rejected: \(path.debugDescription)")
        }
        expect(GatewayAdminPolicy.isStrictDescendant("/Users/me/My DefenseClaw/config.yaml", of: "/Users/me"), "spaces remain literal")
        expect(!GatewayAdminPolicy.isStrictDescendant("/Users/me2/config.yaml", of: "/Users/me"), "sibling prefix rejected")
        expect(!GatewayAdminPolicy.isStrictDescendant("/Users/me", of: "/Users/me"), "home itself is not an installation child")
        expect(!GatewayAdminPolicy.isStrictDescendant("/etc/config.yaml", of: "/"), "root cannot become authorized installation")
    }

    private static func testCodeRequirements() {
        let team = "ABCDE12345"
        for identifier in [GatewayAdminPolicy.appIdentifier, GatewayAdminPolicy.helperIdentifier] {
            let expression = GatewayAdminPolicy.requirement(identifier: identifier, teamIdentifier: team)
            var requirement: SecRequirement?
            expect(SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess, "signing requirement parses")
            expect(expression.contains("certificate leaf[subject.OU] = \"\(team)\"") && expression.contains("anchor apple generic"),
                   "signing team and Apple anchor required")
            expect(expression.contains("identifier \"\(identifier)\""), "exact code identifier required")
        }
        for team in [nil, "", "9r236bb67s", "ABCDE1234", "ABCDE123456", "ABCDE\"1234"] as [String?] {
            let expression = GatewayAdminPolicy.requirement(identifier: GatewayAdminPolicy.appIdentifier, teamIdentifier: team)
            var requirement: SecRequirement?
            expect(expression == "never" && SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess,
                   "a missing or malformed team never authorizes a peer")
        }
        // Test binaries are ad-hoc signed, like development builds of the app.
        expect(GatewayAdminPolicy.teamIdentifier == nil, "ad-hoc code has no signing team")
        for expression in [GatewayAdminPolicy.appRequirement, GatewayAdminPolicy.helperRequirement] {
            expect(expression == "never", "ad-hoc builds cannot authorize the administrator service")
        }
        expect(GatewayAdminPolicy.serviceName == "com.cisco.defenseclaw.macos.GatewayAdmin"
               && GatewayAdminPolicy.appIdentifier == "com.cisco.defenseclaw.macos",
               "administrator identifiers use the Cisco bundle identifier")
    }

    private static func testInitialRegistrationPolicy() {
        expect(GatewayAdministratorClient.needsRegistration(status: .notFound, bundledServiceAvailable: true), "macOS notFound can enter first-time registration when the helper exists")
        expect(GatewayAdministratorClient.needsRegistration(status: .notRegistered, bundledServiceAvailable: true), "unregistered service is registered")
        expect(!GatewayAdministratorClient.needsRegistration(status: .notFound, bundledServiceAvailable: false), "missing helper cannot be registered")
        expect(!GatewayAdministratorClient.needsRegistration(status: .enabled, bundledServiceAvailable: true), "approved service is not re-registered")
        expect(!GatewayAdministratorClient.needsRegistration(status: .requiresApproval, bundledServiceAvailable: true), "pending approval is not confused with missing registration")
    }

    private static func testCancellationState() {
        let pending = GatewayAdministratorOperation()
        expect(pending.cancel() == .requested, "pending request can cancel")
        expect(pending.cancel() == .alreadyRequested, "repeated cancel retained")
        expect(!pending.beginDispatch(), "cancelled authorization cannot dispatch")
        let active = GatewayAdministratorOperation()
        expect(active.beginDispatch(), "authorized operation can dispatch")
        expect(!active.beginDispatch(), "operation dispatch is single-use")
        expect(active.cancel() == .finishing, "in-flight repair waits for truthful completion")
    }

    private static func testNativeAuthorizationResults() {
        let cancelled = GatewayAdministratorClient.resultForHelperReply(exitCode: 130, output: "Native authorization cancelled")
        expect(cancelled.cancelled && !cancelled.succeeded, "native authorization cancellation is recorded as cancelled")
        expect(cancelled.output == "Native authorization cancelled", "helper cancellation explanation is preserved")
        let denied = GatewayAdministratorClient.resultForHelperReply(exitCode: 77, output: "Authorization denied")
        expect(!denied.cancelled && !denied.succeeded, "authorization denial remains a failure")
        let completed = GatewayAdministratorClient.resultForHelperReply(exitCode: 0, output: "Returned 3 files")
        expect(completed.succeeded && !completed.cancelled, "authorized repair completion remains successful")
    }

    /// Only an exact lifecycle command with root-owned state goes to the
    /// helper; everything else runs as this account without asking.
    private static func testRepairRoutingDecision() {
        let home = URL(fileURLWithPath: "/Users/admin-test/.defenseclaw")
        var asked: [URL] = []
        let state: (URL) -> [GatewayRootState.Marker] = {
            asked.append($0)
            return [GatewayRootState.Marker(name: "gateway.pid", identity: "gateway.pid:1")]
        }
        for action in ["start", "stop", "restart"] {
            expect(CLIRunner.rootStateToRepair(binary: "defenseclaw-gateway", arguments: [action], home: home,
                                               rootOwnedState: state).map(\.name) == ["gateway.pid"], "\(action) repairs root state first")
        }
        expect(asked == [home, home, home], "the selected installation's home is inspected")
        asked = []
        for (binary, arguments) in [("defenseclaw-gateway", ["status"]), ("defenseclaw-gateway", ["start", "--anything"]),
                                    ("defenseclaw-gateway", ["watchdog", "start"]), ("defenseclaw-gateway", [String]()),
                                    ("defenseclaw", ["start"]), ("/tmp/defenseclaw-gateway", ["start"])] {
            expect(CLIRunner.rootStateToRepair(binary: binary, arguments: arguments, home: home, rootOwnedState: state).isEmpty,
                   "no repair for \(binary) \(arguments)")
        }
        expect(asked.isEmpty, "other commands never inspect or repair")
        expect(CLIRunner.rootStateToRepair(binary: "defenseclaw-gateway", arguments: ["start"], home: home,
                                           rootOwnedState: { _ in [] }).isEmpty, "no root state, no administrator request")
    }

    private static func testRepairBindsInstallationAndStopEndsThere() async {
        let probe = InvocationProbe()
        let selected = context()
        let runner = makeRunner(selected, RootStateFixture(), repair: { context, _ in
            await probe.record(context)
            return CLIResult(exitCode: 0, output: "repaired via helper")
        })
        let result = await runner.run(binary: "defenseclaw-gateway", arguments: ["stop"])
        expect(result.succeeded && result.output == "repaired via helper", "Stop is complete once the repair stopped the root gateway")
        let recorded = await probe.firstContext()
        expect(recorded == selected, "selected installation identity reaches the helper")
    }

    /// After the repair, Start runs as this account. A cancellation that
    /// arrives during the repair stops right after it, which shows the
    /// command continues past the repair without running a real gateway here.
    private static func testStartContinuesAsAccountAfterRepair() async {
        let probe = InvocationProbe()
        let runner = makeRunner(context(), RootStateFixture(), repair: { context, _ in
            await probe.record(context)
            while !(await probe.isReleased()) { try? await Task.sleep(for: .milliseconds(10)) }
            return CLIResult(exitCode: 0, output: "repaired\n")
        })
        let task = Task { await runner.run(binary: "defenseclaw-gateway", arguments: ["start"]) }
        await waitForCall(probe)
        task.cancel()
        await probe.release()
        let result = await task.value
        expect(result.cancelled && result.output.contains("repaired") && result.output.contains("cancelled after the repair"),
               "Start continues after a successful repair: \(result.output)")
    }

    private static func testFailedRepairStopsTheCommand() async {
        let runner = makeRunner(context(), RootStateFixture(), repair: { _, _ in
            CLIResult(exitCode: 75, output: "still running as root")
        })
        let result = await runner.run(binary: "defenseclaw-gateway", arguments: ["restart"])
        expect(result.exitCode == 75 && result.output == "still running as root", "a failed repair is the result; nothing runs as root or as the account")
    }

    /// NH-4: when the helper ran and root-owned markers remain (a hard link or
    /// special file it skips, a sudo-run gateway), the user gets the files and
    /// the sudo chown command, and no new prompt until the leftovers change.
    private static func testUnresolvedRepairDoesNotPromptAgain() async {
        let probe = InvocationProbe()
        let state = RootStateFixture()
        let runner = makeRunner(context(), state, clearOnRepair: false, repair: { context, _ in
            await probe.record(context)
            return CLIResult(exitCode: 0, output: "Left 1 root-owned items unchanged\n")
        })
        let first = await runner.run(binary: "defenseclaw-gateway", arguments: ["start"])
        expect(first.exitCode == 1 && first.output.contains("still owned by root: gateway.pid, hook_contract_lock.json")
               && first.output.contains("sudo chown -R"), "the leftovers and the command are shown: \(first.output)")
        expect(state.remembered == GatewayRootState.fingerprint(state.current), "the unresolved leftovers are remembered")
        let second = await runner.run(binary: "defenseclaw-gateway", arguments: ["restart"])
        var calls = await probe.count()
        expect(second.exitCode == 77 && second.output.contains("will not ask") && calls == 1,
               "unchanged leftovers do not bring the administrator prompt back")
        state.set([GatewayRootState.Marker(name: "gateway.pid", identity: "gateway.pid:2")])
        _ = await runner.run(binary: "defenseclaw-gateway", arguments: ["stop"])
        calls = await probe.count()
        expect(calls == 2, "a changed leftover is repaired again")

        let cancelledState = RootStateFixture()
        let cancelled = makeRunner(context(), cancelledState, repair: { _, _ in
            CLIResult(exitCode: 130, output: "cancelled", cancelled: true)
        })
        _ = await cancelled.run(binary: "defenseclaw-gateway", arguments: ["start"])
        expect(cancelledState.remembered == nil, "a cancelled prompt is not remembered; the next start asks again")
        let clearedState = RootStateFixture()
        let cleared = makeRunner(context(), clearedState, repair: { _, _ in CLIResult(exitCode: 0, output: "repaired") })
        _ = await cleared.run(binary: "defenseclaw-gateway", arguments: ["stop"])
        expect(clearedState.remembered == nil, "a home the repair cleared leaves nothing remembered")
    }

    /// REVIEW-2 NH-6: every pasted sudo chown hint quotes the home as one shell word.
    private static func testRepairHintQuotesTheHome() {
        let home = URL(fileURLWithPath: "/Users/admin-test/My Home;touch pwned'x")
        let message = GatewayRootState.unresolvedMessage(
            [GatewayRootState.Marker(name: "gateway.pid", identity: "gateway.pid:1")], home: home)
        expect(message.hasSuffix("sudo chown -R \"$(id -un)\" '/Users/admin-test/My Home;touch pwned'\\''x'\n"),
               "the home path is one single-quoted word: \(message)")
        expect(GatewayRootState.shellQuoted("plain") == "'plain'", "a plain path is single-quoted")
    }

    /// NH-5: the switch of app versions up to 1.0.8 leaves no stale default.
    private static func testRetiredPreferenceRemoved() {
        guard let defaults = UserDefaults(suiteName: "defenseclaw-retired-preference-\(UUID().uuidString)") else {
            expect(false, "test defaults available")
            return
        }
        defaults.set(true, forKey: "gatewayAdministratorMode")
        GatewayAdministratorClient.removeRetiredPreferences(defaults)
        expect(defaults.object(forKey: "gatewayAdministratorMode") == nil, "the retired administrator switch is removed")
    }

    private static func testRefusalBeforeAuthorization() async {
        let probe = InvocationProbe()
        let execute: @Sendable (InstallationContext, GatewayAdministratorOperation) async -> CLIResult = { context, _ in
            await probe.record(context)
            return CLIResult(exitCode: 0, output: "unexpected")
        }
        let readOnly = makeRunner(context().reducingToInvalidReadOnly("managed fixture"), RootStateFixture(), repair: execute)
        let denied = await readOnly.run(binary: "defenseclaw-gateway", arguments: ["restart"], mutation: false)
        expect(denied.exitCode == 77, "read-only policy cannot be bypassed by mutation flag")
        let runner = makeRunner(context(), RootStateFixture(), repair: execute)
        let id = UUID()
        expect(awaitValue(await runner.reserve(runID: id)), "run reserved")
        _ = await runner.cancel(runID: id)
        let cancelled = await runner.run(binary: "defenseclaw-gateway", arguments: ["start"], runID: id)
        expect(cancelled.cancelled, "prelaunch cancellation preserved")
        let count = await probe.count()
        expect(count == 0, "no refused request reaches authorization")
    }

    private static func testTaskCancellationAfterReservationRefusesDispatch() async {
        let probe = InvocationProbe()
        let runner = makeRunner(context(), RootStateFixture(), repair: { context, _ in
            await probe.record(context)
            return CLIResult(exitCode: 0, output: "repaired via helper")
        })
        let id = UUID()
        let task = Task {
            let reserved = await runner.reserve(runID: id)
            expect(reserved, "Activity reservation succeeds before task cancellation")
            // Match cancellation after Activity reserves its row but before
            // the runner enters its dispatch actor; do not use runner.cancel.
            withUnsafeCurrentTask { $0?.cancel() }
            return await runner.run(binary: "defenseclaw-gateway", arguments: ["start"], runID: id)
        }
        let result = await task.value
        expect(result.exitCode == 130 && result.cancelled && !result.succeeded,
               "cancelled caller gets the normal cancellation result before authorization")
        let calls = await probe.count()
        expect(calls == 0, "cancelled caller never invokes the administrator repair")
        let disposition = await runner.cancel(runID: id)
        expect(disposition == .notFound, "cancelled dispatch consumes its reservation without leaving a pending operation")

        let reservedAgain = await runner.reserve(runID: id)
        expect(reservedAgain, "cancelled reservation can be reused by a later independent operation")
        let later = await runner.run(binary: "defenseclaw-gateway", arguments: ["stop"], runID: id)
        let laterCalls = await probe.count()
        expect(later.succeeded && !later.cancelled && laterCalls == 1,
               "fresh uncancelled operation is not blocked or cancelled by stale run state")
    }

    private static func awaitValue(_ value: Bool) -> Bool { value }

    private static func waitForCall(_ probe: InvocationProbe) async {
        for _ in 0..<100 {
            if await probe.count() > 0 { return }
            try? await Task.sleep(for: .milliseconds(10))
        }
        expect(false, "fake authorization started")
    }

    private static func testRebindCancelsPendingAuthorization() async {
        let probe = InvocationProbe()
        let runner = makeRunner(context(), RootStateFixture(), repair: { context, operation in
            await probe.record(context)
            while !(await probe.isReleased()) { try? await Task.sleep(for: .milliseconds(10)) }
            return CLIResult(exitCode: operation.beginDispatch() ? 0 : 130, output: "authorization completed", cancelled: operation.isCancelled)
        })
        let task = Task { await runner.run(binary: "defenseclaw-gateway", arguments: ["start"]) }
        await waitForCall(probe)
        await runner.rebind(to: context("-other"))
        await probe.release()
        let result = await task.value
        expect(result.cancelled && !result.succeeded, "installation switch cancels a pending repair")
    }

    private static func testCancellationAfterDispatchWaitsForResult() async {
        let probe = InvocationProbe()
        let runner = makeRunner(context(), RootStateFixture(), repair: { context, operation in
            expect(operation.beginDispatch(), "dispatch succeeds")
            await probe.record(context)
            while !(await probe.isReleased()) { try? await Task.sleep(for: .milliseconds(10)) }
            return CLIResult(exitCode: 0, output: "gateway stopped")
        })
        let id = UUID()
        let task = Task { await runner.run(binary: "defenseclaw-gateway", arguments: ["stop"], runID: id) }
        await waitForCall(probe)
        let disposition = await runner.cancel(runID: id)
        expect(disposition == .finishing, "cancel cannot imply the root repair was undone")
        await probe.release()
        let result = await task.value
        expect(result.succeeded && !result.cancelled, "actual helper completion reported")
    }
}
