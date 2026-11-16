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
import Observation

struct SandboxInspectionRead<Value: Sendable>: Sendable {
    var value: Value?
    var fetchedAt: Date?
    var error = ""
    var note: String {
        if !error.isEmpty { return value == nil ? error : "Stale: \(error)" }
        return fetchedAt.map { "Updated \($0.formatted(date: .omitted, time: .standard))" } ?? "Not loaded"
    }
    mutating func accept(_ result: CLIResult, decode: (String) throws -> Value) {
        guard result.succeeded else {
            if result.cancelled { error = "Read cancelled or timed out. Retry when the service is available." }
            else if result.outputTruncated { error = "Response exceeded the read limit; partial data was not accepted." }
            else if result.exitCode == 127 { error = "Required executable is unavailable." }
            else if result.exitCode == 75 { error = "Runtime upgrade in progress. Refresh after it completes." }
            else { error = "Read unavailable (exit \(result.exitCode)). Check gateway access and installed command support." }
            return
        }
        do { value = try decode(result.output); fetchedAt = Date(); error = "" }
        catch { self.error = error.localizedDescription }
    }
}

extension SandboxInspectionRead where Value == SandboxPolicyDocument {
    var enforcement: String {
        guard let value else { return "OpenShell policy enforcement is unverified." }
        return error.isEmpty ? value.enforcement : "Last observed: " + value.enforcement
    }
}

@MainActor @Observable
final class SandboxInspectionStore {
    typealias Reader = @Sendable (String, [String]) async -> CLIResult
    private(set) var target: SandboxInspectionTarget?
    private var generation = 0
    private(set) var loading = false
    var paused = false
    var defense = SandboxInspectionRead<[SandboxInspectionField]>()
    var effective = SandboxInspectionRead<SandboxPolicyDocument>()
    var base = SandboxInspectionRead<SandboxPolicyDocument>()
    var global = SandboxInspectionRead<SandboxPolicyDocument>()
    var history = SandboxInspectionRead<SandboxPolicyHistory>()
    var revision = SandboxInspectionRead<SandboxPolicyDocument>()
    var destinations = SandboxInspectionRead<[SandboxDestination]>()
    var sandboxLogs = SandboxInspectionRead<[SandboxInspectionEvent]>()
    var gatewayLogs = SandboxInspectionRead<[SandboxInspectionEvent]>()
    private(set) var historyLoading = false
    private(set) var revisionNumber: Int?
    private var revisionRequest = UUID()

    func invalidate() { generation += 1; loading = false; historyLoading = false; revisionRequest = UUID() }

    func reset(to newTarget: SandboxInspectionTarget) {
        invalidate()
        target = newTarget
        defense = .init(); effective = .init(); base = .init(); global = .init()
        history = .init(); revision = .init(); destinations = .init()
        sandboxLogs = .init(); gatewayLogs = .init(); revisionNumber = nil
    }

    /// All queries are argv arrays and use the app's existing runner, including
    /// its upgrade exclusion and process-tree cancellation. No Activity row
    /// stores raw policy/log output from these read-only background queries.
    nonisolated static func reader(cli: CLIRunner, timeout: Duration = .seconds(12)) -> Reader {
        { binary, arguments in
            await withTaskGroup(of: CLIResult.self) { group in
                let id = UUID()
                group.addTask { await cli.run(binary: binary, arguments: arguments, mutation: false, runID: id) }
                group.addTask {
                    do { try await Task.sleep(for: timeout) } catch { return CLIResult(exitCode: 130, output: "", cancelled: true) }
                    _ = await cli.cancel(runID: id)
                    return CLIResult(exitCode: 130, output: "", cancelled: true)
                }
                let result = await group.next() ?? CLIResult(exitCode: 130, output: "", cancelled: true)
                group.cancelAll()
                return result
            }
        }
    }

    func refresh(target request: SandboxInspectionTarget, read: @escaping Reader) async {
        if target != request { reset(to: request) }
        guard !loading else { return }
        guard request.valid else {
            let message = "Explicit sandbox, gateway and workspace names are required. Refresh the sandbox list with a supported runtime."
            defense.error = message; effective.error = message; base.error = message; global.error = message
            history.error = message; destinations.error = message; sandboxLogs.error = message; gatewayLogs.error = message
            return
        }
        loading = true
        let epoch = generation
        defer { if generation == epoch { loading = false } }
        let os = request.openShellArguments
        async let dc = read("defenseclaw", ["sandbox", "policy", "explain", "--sandbox", request.sandbox, "--json"])
        async let ep = read("openshell", os + ["policy", "get", request.sandbox, "--full", "-o", "json"])
        async let bp = read("openshell", os + ["policy", "get", request.sandbox, "--base", "-o", "json"])
        async let gp = read("openshell", os + ["policy", "get", "--global", "-o", "json"])
        async let hp = read("openshell", os + ["policy", "list", request.sandbox, "--page-size", "20", "-o", "json"])
        async let dp = read("defenseclaw", ["sandbox", "destinations", request.sandbox, "--json"])
        let results = await (dc, ep, bp, gp, hp, dp)
        guard generation == epoch, !Task.isCancelled else { return }
        defense.accept(results.0, decode: SandboxInspectionDecoding.defensePolicy)
        effective.accept(results.1) { try SandboxInspectionDecoding.policy($0, sandbox: request.sandbox) }
        base.accept(results.2) { try SandboxInspectionDecoding.policy($0, sandbox: request.sandbox) }
        if effective.error.isEmpty, base.error.isEmpty,
           let effectiveVersion = effective.value?.version, let baseVersion = base.value?.version,
           effectiveVersion != baseVersion {
            effective.error = "Policy changed during the read. Refresh to compare a consistent revision."
            base.error = effective.error
        }
        global.accept(results.3) { try SandboxInspectionDecoding.policy($0, sandbox: request.sandbox, global: true) }
        history.accept(results.4) { try SandboxInspectionDecoding.history($0, sandbox: request.sandbox) }
        destinations.accept(results.5) { try SandboxInspectionDecoding.destinations($0, sandbox: request.sandbox) }
        loading = false
        await refreshLogs(read: read)
    }

    func refreshLogs(read: @escaping Reader) async {
        guard let target, target.valid, !paused else { return }
        let epoch = generation
        let args = target.openShellArguments + ["logs", target.sandbox, "--since", "15m", "-n", "200"]
        async let sandbox = read("openshell", args + ["--source", "sandbox"])
        async let gateway = read("openshell", args + ["--source", "gateway"])
        let results = await (sandbox, gateway)
        guard epoch == generation, !Task.isCancelled, !paused else { return }
        sandboxLogs.accept(results.0) { SandboxInspectionDecoding.logs($0, source: "OpenShell sandbox") }
        gatewayLogs.accept(results.1) { SandboxInspectionDecoding.logs($0, source: "OpenShell gateway") }
    }

    func moreHistory(read: @escaping Reader) async {
        guard !historyLoading, let target, let current = history.value,
              !current.nextPageToken.isEmpty, current.revisions.count < 200 else { return }
        historyLoading = true
        let pageTimestamp = history.fetchedAt
        let epoch = generation
        defer { if generation == epoch { historyLoading = false } }
        let result = await read("openshell", target.openShellArguments + ["policy", "list", target.sandbox,
            "--page-size", "20", "--page-token", current.nextPageToken, "-o", "json"])
        guard epoch == generation, !Task.isCancelled else { return }
        guard history.fetchedAt == pageTimestamp else { historyLoading = false; return }
        var next = SandboxInspectionRead<SandboxPolicyHistory>()
        next.accept(result) { try SandboxInspectionDecoding.history($0, sandbox: target.sandbox) }
        if let page = next.value {
            let known = Set(current.revisions.map(\.version))
            history.value = .init(revisions: Array((current.revisions + page.revisions.filter { !known.contains($0.version) }).prefix(200)),
                                  nextPageToken: page.nextPageToken == current.nextPageToken ? "" : page.nextPageToken)
            history.fetchedAt = next.fetchedAt; history.error = ""
        } else { history.error = next.error }
        historyLoading = false
    }

    func loadRevision(_ number: Int, read: @escaping Reader) async {
        guard let target, target.valid, history.value?.revisions.contains(where: { $0.version == number }) == true else { return }
        let epoch = generation
        let request = UUID(); revisionRequest = request
        revisionNumber = number; revision = .init()
        let result = await read("openshell", target.openShellArguments + ["policy", "get", target.sandbox,
            "--rev", String(number), "--base", "-o", "json"])
        guard epoch == generation, request == revisionRequest, !Task.isCancelled else { return }
        revision.accept(result) {
            let doc = try SandboxInspectionDecoding.policy($0, sandbox: target.sandbox)
            guard doc.version == number else { throw SandboxInspectionError.invalid("A different policy revision was returned. Refresh history.") }
            return doc
        }
    }
}
