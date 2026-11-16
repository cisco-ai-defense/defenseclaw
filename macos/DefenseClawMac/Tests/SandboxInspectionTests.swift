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
struct SandboxInspectionTests {
    static var checks = 0
    static func expect(_ condition: Bool, _ message: String) {
        checks += 1
        if !condition { fatalError(message) }
    }
    static func json(_ value: Any) -> String { String(data: try! JSONSerialization.data(withJSONObject: value), encoding: .utf8)! }
    static func policy(_ version: Int = 2, sandbox: String = "demo", status: String = "effective") -> String {
        json(["sandbox": sandbox, "scope": "sandbox", "policy_source": "sandbox", "status": status,
              "version": version, "active_version": 2, "hash": "fixture digest",
              "policy": ["version": 1, "network_policies": ["github": ["endpoints": [["host": "example.invalid", "port": 443]]]],
                         "filesystem_policy": ["read_only": ["/usr"], "read_write": ["/work"]]]])
    }
    static func failed(_ text: String, _ decode: (String) throws -> Any) -> Bool {
        do { _ = try decode(text); return false } catch { return true }
    }

    @MainActor static func main() async throws {
        CLIProcessGroupLauncher.execIfRequested()
        let target = SandboxInspectionTarget(sandbox: "demo", gateway: "local", workspace: "default")
        expect(target.valid, "valid explicit target")
        for name in ["", "--global", "../wrong", "a\nb", "a b"] {
            expect(!SandboxInspectionTarget.validName(name), "refuse unsafe or absent identity")
        }
        expect(target.openShellArguments == ["--gateway", "local", "--workspace", "default", "--color", "never"], "explicit scope")
        let document = try SandboxInspectionDecoding.policy(policy(), sandbox: "demo")
        expect(document.enforcement == "Applied: revision 2", "matching effective revision")
        expect(try SandboxInspectionDecoding.policy(policy(1), sandbox: "demo").enforcement.contains("active revision 2"), "mismatch not applied")
        expect(try SandboxInspectionDecoding.policy(policy(status: "pending"), sandbox: "demo").enforcement == "Pending", "pending")
        expect(failed(policy(sandbox: "another")) { try SandboxInspectionDecoding.policy($0, sandbox: "demo") }, "mismatched sandbox rejected")
        expect(failed("{}") { try SandboxInspectionDecoding.policy($0, sandbox: "demo") }, "missing policy not empty success")
        expect(failed(policy()) { try SandboxInspectionDecoding.policy($0, sandbox: "demo", global: true) }, "scope mismatch")
        expect(failed(String(repeating: " ", count: 1_048_577)) { try SandboxInspectionDecoding.object($0) }, "bounded input")
        let resolved = try SandboxInspectionDecoding.defensePolicy(json(["pack": "strict", "settings": [["key": "network", "value": "deny", "source": "organization", "origin": "managed"]]]))
        expect(resolved.contains { $0.source == "organization · managed" }, "provenance preserved")
        let sensitive = SandboxInspectionDecoding.fields(["env": ["CUSTOM": "do not expose"], "api_key": "do not expose", "normal": "safe"])
        expect(!sensitive.map(\.value).joined().contains("do not expose"), "recursive structured redaction")
        let booleans = SandboxInspectionDecoding.fields(try SandboxInspectionDecoding.object("{\"enabled\":true,\"count\":1}"))
        expect(booleans.first { $0.key == "enabled" }?.value == "true" && booleans.first { $0.key == "count" }?.value == "1", "booleans distinguish policy switches from numeric limits")
        for line in ["token='do not expose'", "{\"password\":\"do not expose\"}", "https://user:password@example.invalid/path?secret=value", "request_body=do not expose"] {
            let clean = SandboxInspectionDecoding.safe(line)
            expect(!clean.contains("do not expose") && !clean.contains("user:password") && !clean.contains("secret=value"), "log redaction before display")
        }
        let diff = SandboxInspectionDecoding.difference([.init(key: "a", value: "old"), .init(key: "removed", value: "yes")], [.init(key: "a", value: "new"), .init(key: "added", value: "yes")])
        expect(diff.count == 3, "revision add/remove/change")
        let h = json(["revisions": [["sandbox": "demo", "version": 1, "created_at_ms": 1000, "loaded_at_ms": 0, "status": "pending"]], "next_page_token": "next"])
        let history = try SandboxInspectionDecoding.history(h, sandbox: "demo")
        expect(history.revisions.first?.created == Date(timeIntervalSince1970: 1), "millisecond timestamps")
        expect(history.revisions.first?.loaded == nil, "not loaded remains unverified")
        expect(history.nextPageToken == "next", "pagination cursor")
        expect(failed(h) { try SandboxInspectionDecoding.history($0, sandbox: "other") }, "history mismatch")
        expect(try SandboxInspectionDecoding.destinations(json(["name": "demo", "destinations": []]), sandbox: "demo").isEmpty, "verified empty destinations")
        expect(failed("{}") { try SandboxInspectionDecoding.destinations($0, sandbox: "demo") }, "missing destination data is not empty")
        let logs = SandboxInspectionDecoding.logs("[1800000000.5] [sandbox] [OCSF] NET:OPEN DENIED example.invalid\nunknown timestamp", source: "OpenShell sandbox")
        expect(logs.count == 2 && logs[0].decision == "Blocked", "OCSF shorthand decision")
        expect(logs[0].time == Date(timeIntervalSince1970: 1800000000.5), "epoch timestamp")
        expect(!logs[1].matches(query: "", source: "All", severity: "All", decision: "All", since: Date()), "unknown time excluded from time filter")
        expect(logs[0].matches(query: "example", source: "OpenShell sandbox", severity: "Warning", decision: "Blocked", since: nil), "combined filters")
        expect(!logs[0].matches(query: "nomatch", source: "All", severity: "All", decision: "All", since: nil), "empty search result")
        expect(SandboxInspectionDecoding.logs(String(repeating: "line\n", count: 500), source: "test").count == 200, "bounded log buffer")
        var section = SandboxInspectionRead<SandboxPolicyDocument>()
        section.accept(.init(exitCode: 0, output: policy())) { try SandboxInspectionDecoding.policy($0, sandbox: "demo") }
        let date = section.fetchedAt
        section.accept(.init(exitCode: 1, output: "sensitive backend failure")) { try SandboxInspectionDecoding.policy($0, sandbox: "demo") }
        expect(section.value != nil && section.fetchedAt == date && section.note.hasPrefix("Stale:"), "last good snapshot retained")
        expect(section.enforcement.hasPrefix("Last observed:"), "stale policy does not claim current enforcement")
        expect(!section.note.contains("sensitive"), "raw failure output not shown")
        section.accept(.init(exitCode: 0, output: policy(), outputTruncated: true)) { try SandboxInspectionDecoding.policy($0, sandbox: "demo") }
        expect(section.error.contains("limit"), "truncated data rejected")

        let fixture = InspectionFixture()
        let read: SandboxInspectionStore.Reader = { await fixture.read($0, $1) }
        let store = SandboxInspectionStore()
        await store.refresh(target: target, read: read)
        expect(store.effective.value != nil && store.defense.value != nil, "store loads each section")
        expect(store.global.value == nil && !store.global.error.isEmpty, "global failure does not hide per-sandbox policy")
        await store.loadRevision(1, read: read)
        expect(store.revision.value?.version == 1, "historical revision fetch")
        await store.moreHistory(read: read)
        expect(store.history.value?.revisions.count == 2, "history pages merge and deduplicate")
        let count = await fixture.count
        store.paused = true
        await store.refreshLogs(read: read)
        expect(await fixture.count == count, "pause does not query logs")
        store.paused = false
        await fixture.fail()
        await store.refresh(target: target, read: read)
        expect(store.effective.note.hasPrefix("Stale:"), "outage disclosure")
        await fixture.recover()
        await store.refresh(target: target, read: read)
        expect(store.effective.error.isEmpty, "outage recovery")
        await store.refresh(target: target, read: { binary, args in
            if binary == "openshell", args.contains("--base") { return .init(exitCode: 0, output: policy(1)) }
            return await read(binary, args)
        })
        expect(store.effective.error.contains("changed during the read") && store.base.error == store.effective.error, "concurrent policy change is disclosed")
        let task = Task { await store.refresh(target: target, read: { _, _ in
            try? await Task.sleep(for: .milliseconds(70)); return .init(exitCode: 0, output: policy())
        }) }
        try await Task.sleep(for: .milliseconds(10))
        store.reset(to: .init(sandbox: "other", gateway: "local", workspace: "default"))
        await task.value
        expect(store.target?.sandbox == "other" && store.effective.value == nil, "late response cannot cross target selection")
        let invalid = SandboxInspectionTarget(sandbox: "demo", gateway: "", workspace: "")
        let before = await fixture.count
        await store.refresh(target: invalid, read: read)
        expect(await fixture.count == before && !store.effective.error.isEmpty, "no implicit gateway or workspace fallback")
        let allowedHost = SandboxInspectionDecoding.logs("[1800000000] [INFO] NET:OPEN ALLOWED -> blocked.example.invalid:443 [policy:api]", source: "OpenShell sandbox")[0]
        expect(allowedHost.decision == "Allowed" && allowedHost.severity == "Info", "destination text does not change decision or severity")
        expect(allowedHost.host == "blocked.example.invalid" && allowedHost.rule == "api", "log links retain host and policy rule")
        let escaped = #"password="prefix\"do not expose""#
        expect(!SandboxInspectionDecoding.safe(escaped).contains("do not expose"), "escaped quotes cannot leak a credential")
        let structured = SandboxInspectionDecoding.logs(json(["time": 1800000000500.0, "class_name": "Network Activity", "status": "Denied", "severity_id": 4, "request_body": "do not expose", "credentials": "do not expose", "dst_endpoint": ["hostname": "example.invalid"]]), source: "OpenShell sandbox")
        expect(structured.first?.host == "example.invalid" && structured.first?.severity == "Error", "structured event projection")
        expect(structured.first?.message.contains("do not expose") == false, "structured payload omitted")
        let export = try SandboxDiagnosticsExport.data(target: target,
            events: [.init(id: "fixture", source: "OpenShell sandbox", severity: "Info", decision: "Other", message: "token='do not expose'")],
            sandboxLogStatus: "Stale: unavailable", gatewayLogStatus: "Updated", date: Date(timeIntervalSince1970: 0))
        let exportText = String(decoding: export, as: UTF8.self)
        let exportObject = try SandboxInspectionDecoding.object(exportText)
        expect(!exportText.contains("do not expose") && exportText.contains("[redacted]"), "export sanitizes projected events again")
        expect(exportObject["coverage"] != nil && exportObject["sandbox_logs"] as? String == "Stale: unavailable", "export retains coverage and stale source status")
        let runner = CLIRunner()
        let timed = await SandboxInspectionStore.reader(cli: runner, timeout: .milliseconds(100))("/bin/sleep", ["30"])
        expect(timed.cancelled, "bounded CLI timeout cancels process")
        let pending = Task { await SandboxInspectionStore.reader(cli: runner)("/bin/sleep", ["30"]) }
        try await Task.sleep(for: .milliseconds(100))
        pending.cancel()
        expect(await pending.value.cancelled, "parent cancellation reaches process")
        if let name = ProcessInfo.processInfo.environment["DEFENSECLAW_INSPECTION_LIVE_SANDBOX"] {
            let liveCLI = CLIRunner()
            let status = await liveCLI.run(arguments: ["sandbox", "status", "--json"], mutation: false)
            expect(status.succeeded, "live sandbox status")
            let object = try SandboxInspectionDecoding.object(status.output)
            let gateway = object["gateway"] as! [String: Any]
            let liveTarget = SandboxInspectionTarget(sandbox: name, gateway: gateway["name"] as! String, workspace: gateway["workspace"] as! String)
            let liveStore = SandboxInspectionStore()
            let liveRead = SandboxInspectionStore.reader(cli: liveCLI)
            await liveStore.refresh(target: liveTarget, read: liveRead)
            expect(liveStore.defense.value != nil, "live DefenseClaw policy shape")
            expect(liveStore.effective.value != nil && liveStore.base.value != nil, "live OpenShell policy shapes")
            expect(liveStore.history.value != nil && liveStore.destinations.value != nil, "live history and destination shapes")
            expect(liveStore.sandboxLogs.value != nil && liveStore.gatewayLogs.value != nil, "live bounded log reads")
            if let version = liveStore.history.value?.revisions.first?.version {
                await liveStore.loadRevision(version, read: liveRead)
                expect(liveStore.revision.value != nil, "live stored policy revision")
            }
            print("PASS live read-only policy, history, destination and log contracts; global policy: " + (liveStore.global.value == nil ? "unavailable" : "available"))
        }
        print("PASS \(checks) sandbox inspection checks")
    }
}

actor InspectionFixture {
    var count = 0
    var failed = false
    func fail() { failed = true }
    func recover() { failed = false }
    func read(_ binary: String, _ args: [String]) -> CLIResult {
        count += 1
        if failed { return .init(exitCode: 1, output: "backend unavailable") }
        if binary == "defenseclaw" {
            if args.contains("explain") { return .init(exitCode: 0, output: SandboxInspectionTests.json(["pack": "strict", "settings": []])) }
            return .init(exitCode: 0, output: SandboxInspectionTests.json(["name": "demo", "destinations": []]))
        }
        if args.contains("--global") { return .init(exitCode: 1, output: "no readable global policy") }
        if args.contains("list") {
            let n = args.contains("--page-token") ? 2 : 1
            return .init(exitCode: 0, output: SandboxInspectionTests.json(["revisions": [["sandbox": "demo", "version": n, "status": "loaded"]], "next_page_token": n == 1 ? "page 2" : ""]))
        }
        if args.contains("logs") { return .init(exitCode: 0, output: "[1800000000] [sandbox] [WARN] fixture warning") }
        return .init(exitCode: 0, output: SandboxInspectionTests.policy(args.contains("--rev") ? 1 : 2))
    }
}
