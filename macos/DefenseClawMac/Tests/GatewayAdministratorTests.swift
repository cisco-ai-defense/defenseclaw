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
    var calls: [(GatewayAdminAction, InstallationContext)] = []
    var released = false
    func record(_ action: GatewayAdminAction, _ context: InstallationContext) { calls.append((action, context)) }
    func release() { released = true }
    func count() -> Int { calls.count }
    func isReleased() -> Bool { released }
    func firstContext() -> InstallationContext? { calls.first?.1 }
}

@main
struct GatewayAdministratorTests {
    static func main() async {
        CLIProcessGroupLauncher.execIfRequested()
        testExactActionPolicy()
        testPathPolicy()
        testCodeRequirements()
        testInitialRegistrationPolicy()
        testCancellationState()
        testNativeAuthorizationResults()
        await testRoutingAndInstallationBinding()
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

    private static func testExactActionPolicy() {
        for action in GatewayAdminAction.allCases {
            expect(GatewayAdministratorClient.selectedAction(binary: "defenseclaw-gateway", arguments: [action.rawValue], enabled: true) == action, "exact lifecycle accepted")
        }
        for arguments in [[String](), ["start", "--config", "/tmp/other"], ["START"], ["start; id"], ["status"], ["watchdog", "start"]] {
            expect(GatewayAdministratorClient.selectedAction(binary: "defenseclaw-gateway", arguments: arguments, enabled: true) == nil, "non-lifecycle request rejected")
        }
        expect(GatewayAdministratorClient.selectedAction(binary: "/tmp/defenseclaw-gateway", arguments: ["start"], enabled: true) == nil, "arbitrary executable never elevated")
        expect(GatewayAdministratorClient.selectedAction(binary: "defenseclaw-gateway", arguments: ["start"], enabled: false) == nil, "opt-in respected")
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
        for identifier in [GatewayAdminPolicy.appIdentifier, GatewayAdminPolicy.helperIdentifier, "com.cisco.defenseclaw.gateway"] {
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
        for expression in [GatewayAdminPolicy.appRequirement, GatewayAdminPolicy.helperRequirement, GatewayAdminPolicy.gatewayRequirement] {
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
        expect(active.cancel() == .finishing, "in-flight lifecycle waits for truthful completion")
    }

    private static func testNativeAuthorizationResults() {
        let cancelled = GatewayAdministratorClient.resultForHelperReply(exitCode: 130, output: "Native authorization cancelled")
        expect(cancelled.cancelled && !cancelled.succeeded, "native authorization cancellation is recorded as cancelled")
        expect(cancelled.output == "Native authorization cancelled", "helper cancellation explanation is preserved")
        let denied = GatewayAdministratorClient.resultForHelperReply(exitCode: 77, output: "Authorization denied")
        expect(!denied.cancelled && !denied.succeeded, "authorization denial remains a failure")
        let completed = GatewayAdministratorClient.resultForHelperReply(exitCode: 0, output: "Gateway started")
        expect(completed.succeeded && !completed.cancelled, "authorized gateway completion remains successful")
    }

    private static func testRoutingAndInstallationBinding() async {
        let probe = InvocationProbe()
        let selected = context()
        let runner = CLIRunner(context: selected, administratorEnabled: { true }, administratorExecutor: { action, context, _ in
            await probe.record(action, context)
            return CLIResult(exitCode: 0, output: "started via helper")
        })
        let result = await runner.run(binary: "defenseclaw-gateway", arguments: ["start"])
        expect(result.succeeded && result.output == "started via helper", "helper result preserved")
        let recorded = await probe.firstContext()
        expect(recorded == selected, "selected installation identity reaches the helper")
    }

    private static func testRefusalBeforeAuthorization() async {
        let probe = InvocationProbe()
        let execute: @Sendable (GatewayAdminAction, InstallationContext, GatewayAdministratorOperation) async -> CLIResult = { action, context, _ in
            await probe.record(action, context)
            return CLIResult(exitCode: 0, output: "unexpected")
        }
        let runner = CLIRunner(context: context(), administratorEnabled: { true }, administratorExecutor: execute)
        let extra = await runner.run(binary: "defenseclaw-gateway", arguments: ["start", "--anything"])
        expect(extra.exitCode == 64, "extra arguments rejected without fallback")
        let redirected = await runner.run(binary: "defenseclaw-gateway", arguments: ["start"], environment: ["DEFENSECLAW_HOME": "/tmp/other"])
        expect(redirected.exitCode == 64, "environment overrides rejected")
        let stdin = await runner.run(binary: "defenseclaw-gateway", arguments: ["start"], standardInput: "not a password transport")
        expect(stdin.exitCode == 64, "stdin does not become privileged transport")
        let readOnly = CLIRunner(context: context().reducingToInvalidReadOnly("managed fixture"), administratorEnabled: { true }, administratorExecutor: execute)
        let denied = await readOnly.run(binary: "defenseclaw-gateway", arguments: ["restart"], mutation: false)
        expect(denied.exitCode == 77, "read-only policy cannot be bypassed by mutation flag")
        let id = UUID()
        expect(awaitValue(await runner.reserve(runID: id)), "run reserved")
        _ = await runner.cancel(runID: id)
        let cancelled = await runner.run(binary: "defenseclaw-gateway", arguments: ["start"], runID: id)
        expect(cancelled.cancelled, "prelaunch cancellation preserved")
        let count = await probe.count()
        expect(count == 0, "no rejected request reaches authorization")
    }

    private static func testTaskCancellationAfterReservationRefusesDispatch() async {
        let probe = InvocationProbe()
        let runner = CLIRunner(context: context(), administratorEnabled: { true }, administratorExecutor: { action, context, _ in
            await probe.record(action, context)
            return CLIResult(exitCode: 0, output: "started via helper")
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
        expect(calls == 0, "cancelled caller never invokes the administrator executor")
        let disposition = await runner.cancel(runID: id)
        expect(disposition == .notFound, "cancelled dispatch consumes its reservation without leaving a pending operation")

        let reservedAgain = await runner.reserve(runID: id)
        expect(reservedAgain, "cancelled reservation can be reused by a later independent operation")
        let later = await runner.run(binary: "defenseclaw-gateway", arguments: ["start"], runID: id)
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
        let runner = CLIRunner(context: context(), administratorEnabled: { true }, administratorExecutor: { action, context, operation in
            await probe.record(action, context)
            while !(await probe.isReleased()) { try? await Task.sleep(for: .milliseconds(10)) }
            return CLIResult(exitCode: operation.beginDispatch() ? 0 : 130, output: "authorization completed", cancelled: operation.isCancelled)
        })
        let task = Task { await runner.run(binary: "defenseclaw-gateway", arguments: ["start"]) }
        await waitForCall(probe)
        await runner.rebind(to: context("-other"))
        await probe.release()
        let result = await task.value
        expect(result.cancelled && !result.succeeded, "installation switch cancels a pending root launch")
    }

    private static func testCancellationAfterDispatchWaitsForResult() async {
        let probe = InvocationProbe()
        let runner = CLIRunner(context: context(), administratorEnabled: { true }, administratorExecutor: { action, context, operation in
            expect(operation.beginDispatch(), "dispatch succeeds")
            await probe.record(action, context)
            while !(await probe.isReleased()) { try? await Task.sleep(for: .milliseconds(10)) }
            return CLIResult(exitCode: 0, output: "gateway stopped")
        })
        let id = UUID()
        let task = Task { await runner.run(binary: "defenseclaw-gateway", arguments: ["stop"], runID: id) }
        await waitForCall(probe)
        let disposition = await runner.cancel(runID: id)
        expect(disposition == .finishing, "cancel cannot imply root operation undone")
        await probe.release()
        let result = await task.value
        expect(result.succeeded && !result.cancelled, "actual helper completion reported")
    }
}
