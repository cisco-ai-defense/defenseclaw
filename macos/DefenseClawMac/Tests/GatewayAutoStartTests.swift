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

import Foundation

/// Deterministically suspend a probe or start until its test changes app state.
@MainActor
private final class Gate<Value> {
    private var continuation: CheckedContinuation<Value, Never>?
    private var enteredWaiters: [CheckedContinuation<Void, Never>] = []
    private var entered = false

    func suspend() async -> Value {
        await withCheckedContinuation { continuation in
            self.continuation = continuation
            entered = true
            enteredWaiters.forEach { $0.resume() }
            enteredWaiters.removeAll()
        }
    }

    func waitUntilEntered() async {
        if entered { return }
        await withCheckedContinuation { enteredWaiters.append($0) }
    }

    func resume(returning value: Value) {
        continuation?.resume(returning: value)
        continuation = nil
    }
}

@main
@MainActor
struct GatewayAutoStartTests {
    typealias Coordinator = GatewayAutoStartCoordinator

    static func main() async {
        testPreferences()
        await testReachability()
        await testEligibilityDefersAttempt()
        await testStaleChecksDoNotStart()
        await testConcurrentChecksAreDeduplicated()
        await testConcurrentStartIsDeduplicated()
        await testFailedAndCancelledStartsAreNotRetried()
        await testCancelledCheckIsNotRetried()
        await testLaunchAndInstallationGenerations()
        print("GatewayAutoStartTests passed")
    }

    private static func expect(_ value: Bool, _ message: String) {
        guard value else { fputs("FAIL: \(message)\n", stderr); exit(1) }
    }

    private static func snapshot(_ generation: Int = 1) -> GatewayAutoStartSnapshot {
        GatewayAutoStartSnapshot(generation: generation, commandGeneration: 0,
            enabled: true, permitsMutation: true, configurationReady: true,
            operationInProgress: false)
    }

    private static func testPreferences() {
        let suite = "GatewayAutoStartTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        expect(GatewayAutoStartPreference.isEnabled(in: defaults), "fresh installation enables automatic start")
        expect(defaults.object(forKey: GatewayAutoStartPreference.key) == nil, "reading the default does not write user preferences")
        defaults.set(false, forKey: GatewayAutoStartPreference.key)
        expect(!GatewayAutoStartPreference.isEnabled(in: defaults), "explicit opt out is preserved")
        defaults.set(true, forKey: GatewayAutoStartPreference.key)
        expect(GatewayAutoStartPreference.isEnabled(in: defaults), "explicit opt in is preserved")
        defaults.set("invalid", forKey: GatewayAutoStartPreference.key)
        expect(GatewayAutoStartPreference.isEnabled(in: defaults), "malformed preference uses the installation default")
    }

    private static func testReachability() async {
        for reachability: Coordinator.Reachability in [.running, .offline, .unavailable] {
            let coordinator = Coordinator()
            let state = snapshot()
            var probes = 0
            var starts = 0
            let result = await coordinator.ensureStarted(snapshot: state, currentSnapshot: { state }, probe: {
                probes += 1
                return reachability
            }, start: {
                starts += 1
                return .started
            })
            switch reachability {
            case .running:
                expect(result == .alreadyRunning && starts == 0, "healthy gateway is retained")
            case .offline:
                expect(result == .started && starts == 1, "verified offline gateway is started")
            case .unavailable:
                expect(result == .skipped && starts == 0, "inconclusive probe cannot launch a duplicate gateway")
            }
            let repeated = await coordinator.ensureStarted(snapshot: state, currentSnapshot: { state }, probe: {
                probes += 1
                return .offline
            }, start: {
                starts += 1
                return .started
            })
            expect(repeated == .skipped && probes == 1, "resolved decision is not retried by refresh")
        }
    }

    private static func testEligibilityDefersAttempt() async {
        let mutations: [(inout GatewayAutoStartSnapshot) -> Void] = [
            { $0.enabled = false },
            { $0.permitsMutation = false },
            { $0.configurationReady = false },
            { $0.operationInProgress = true }
        ]
        for mutate in mutations {
            let coordinator = Coordinator()
            var state = snapshot()
            mutate(&state)
            var calls = 0
            let deferred = await coordinator.ensureStarted(snapshot: state, currentSnapshot: { state }, probe: {
                calls += 1
                return .offline
            }, start: {
                calls += 1
                return .started
            })
            expect(deferred == .skipped && calls == 0, "disabled, read-only, unconfigured, or busy installation is not touched")
            state = snapshot()
            let ready = await coordinator.ensureStarted(snapshot: state, currentSnapshot: { state }, probe: { .offline }, start: {
                calls += 1
                return .started
            })
            expect(ready == .started && calls == 1, "setup or operation completion retains an eligible start opportunity")
        }
    }

    private static func testStaleChecksDoNotStart() async {
        let changes: [(inout GatewayAutoStartSnapshot) -> Void] = [
            { $0.generation += 1 },
            { $0.commandGeneration += 1 },
            { $0.enabled = false },
            { $0.permitsMutation = false },
            { $0.configurationReady = false },
            { $0.operationInProgress = true }
        ]
        for change in changes {
            let coordinator = Coordinator()
            let gate = Gate<Coordinator.Reachability>()
            var state = snapshot()
            let initial = state
            var starts = 0
            let pending = Task {
                await coordinator.ensureStarted(snapshot: initial, currentSnapshot: { state }, probe: {
                    await gate.suspend()
                }, start: {
                    starts += 1
                    return .started
                })
            }
            await gate.waitUntilEntered()
            change(&state)
            gate.resume(returning: .offline)
            let result = await pending.value
            expect(result == .skipped && starts == 0, "changed installation, command, preference, or readiness invalidates the probe")
            state = initial
            let ready = await coordinator.ensureStarted(snapshot: state, currentSnapshot: { state }, probe: { .offline }, start: {
                starts += 1
                return .started
            })
            expect(ready == .started && starts == 1, "stale check does not consume a later eligible opportunity")
        }
    }

    private static func testConcurrentChecksAreDeduplicated() async {
        let coordinator = Coordinator()
        let gate = Gate<Coordinator.Reachability>()
        let state = snapshot()
        var probes = 0
        var starts = 0
        let pending = Task {
            await coordinator.ensureStarted(snapshot: state, currentSnapshot: { state }, probe: {
                probes += 1
                return await gate.suspend()
            }, start: {
                starts += 1
                return .started
            })
        }
        await gate.waitUntilEntered()
        let duplicate = await coordinator.ensureStarted(snapshot: state, currentSnapshot: { state }, probe: {
            probes += 1
            return .offline
        }, start: {
            starts += 1
            return .started
        })
        expect(duplicate == .skipped && probes == 1 && starts == 0, "simultaneous trigger cannot create a second pending probe")
        gate.resume(returning: .offline)
        let result = await pending.value
        expect(result == .started && starts == 1, "first trigger starts exactly once")
    }

    private static func testConcurrentStartIsDeduplicated() async {
        let coordinator = Coordinator()
        let gate = Gate<Coordinator.Outcome>()
        let state = snapshot()
        let pending = Task {
            await coordinator.ensureStarted(snapshot: state, currentSnapshot: { state }, probe: { .offline }, start: {
                await gate.suspend()
            })
        }
        await gate.waitUntilEntered()
        var calls = 0
        let duplicate = await coordinator.ensureStarted(snapshot: state, currentSnapshot: { state }, probe: {
            calls += 1
            return .offline
        }, start: {
            calls += 1
            return .started
        })
        expect(duplicate == .skipped && calls == 0, "pending authorization or start cannot be duplicated")
        gate.resume(returning: .started)
        let result = await pending.value
        expect(result == .started, "original command retains its result")
    }

    private static func testFailedAndCancelledStartsAreNotRetried() async {
        for completion: Coordinator.Outcome in [.failed, .cancelled] {
            let coordinator = Coordinator()
            let state = snapshot()
            var starts = 0
            let first = await coordinator.ensureStarted(snapshot: state, currentSnapshot: { state }, probe: { .offline }, start: {
                starts += 1
                return completion
            })
            let repeated = await coordinator.ensureStarted(snapshot: state, currentSnapshot: { state }, probe: { .offline }, start: {
                starts += 1
                return .started
            })
            expect(first == completion && repeated == .skipped && starts == 1, "failure or cancelled authorization never causes an automatic retry loop")
        }
    }

    private static func testCancelledCheckIsNotRetried() async {
        let coordinator = Coordinator()
        let gate = Gate<Coordinator.Reachability>()
        let state = snapshot()
        var starts = 0
        let pending = Task {
            await coordinator.ensureStarted(snapshot: state, currentSnapshot: { state }, probe: {
                await gate.suspend()
            }, start: {
                starts += 1
                return .started
            })
        }
        await gate.waitUntilEntered()
        pending.cancel()
        gate.resume(returning: .offline)
        let result = await pending.value
        let repeated = await coordinator.ensureStarted(snapshot: state, currentSnapshot: { state }, probe: { .offline }, start: {
            starts += 1
            return .started
        })
        expect(result == .cancelled && repeated == .skipped && starts == 0, "cancelled check cannot dispatch or automatically retry")
    }

    private static func testLaunchAndInstallationGenerations() async {
        let coordinator = Coordinator()
        var state = snapshot()
        var starts = 0
        let first = await coordinator.ensureStarted(snapshot: state, currentSnapshot: { state }, probe: { .offline }, start: {
            starts += 1
            return .started
        })
        expect(first == .started, "first launch starts the gateway")
        state.commandGeneration += 1
        let stoppedManually = await coordinator.ensureStarted(snapshot: state, currentSnapshot: { state }, probe: { .offline }, start: {
            starts += 1
            return .started
        })
        expect(stoppedManually == .skipped && starts == 1, "manual stop after startup is respected for the current session")
        state.generation += 1
        let rebound = await coordinator.ensureStarted(snapshot: state, currentSnapshot: { state }, probe: { .offline }, start: {
            starts += 1
            return .started
        })
        expect(rebound == .started && starts == 2, "new installation generation gets its own start check")
        let relaunched = await Coordinator().ensureStarted(snapshot: state, currentSnapshot: { state }, probe: { .offline }, start: {
            starts += 1
            return .started
        })
        expect(relaunched == .started && starts == 3, "fresh app launch or update gets a fresh decision")
    }
}
