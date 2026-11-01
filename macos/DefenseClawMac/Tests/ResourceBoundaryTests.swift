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

private final class StubGatewayURLProtocol: URLProtocol {
    static var body = Data()
    static var headers: [String: String] = [:]
    static var statusCode = 200
    static var lastAuthorization: String?
    static var requests = 0

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lastAuthorization = request.value(forHTTPHeaderField: "Authorization")
        Self.requests += 1
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: Self.statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: Self.headers
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Self.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

@main
struct ResourceBoundaryTests {
    static func main() async throws {
        try registryAcceptsLegitimateIndex()
        try registryRejectsOversizedDeepAndEntryHeavyIndexes()
        try registryEnforcesAggregateMaterializationLimit()
        try await eventReaderRejectsOversizedRecords()
        try await eventReaderEnforcesAggregateRetainedByteLimit()
        try await gatewayProjectsAppliedPolicy()
        try await gatewayAcceptsLegitimateResponse()
        try await gatewayRefusesUntrustedListenerAndProtectsToken()
        gatewayListenerOwnershipRules()
        try await gatewayDecodesOptionalAIDiscoveryMetadata()
        try await gatewayRuntimeCapabilities()
        try await gatewaySandboxCapabilities()
        try await gatewayRejectsDeclaredOversizedResponse()
        try await gatewayStopsUnknownLengthOversizedResponse()
        print("Resource boundary tests passed")
    }

    private static func registryAcceptsLegitimateIndex() throws {
        let document: [String: Any] = [
            "schema_version": 1,
            "publisher": "Example {{publisher}}",
            "verdicts": [[
                "type": "skill",
                "name": "safe-skill",
                "status": "clean",
                "args": ["--safe"],
            ]],
        ]
        let data = try JSONSerialization.data(withJSONObject: document)
        let index = try RegistryStore.decodeIndex(
            data: data,
            sourceID: "trusted",
            limits: testRegistryLimits()
        )
        expect(index.entries.count == 1, "normal registry entry is retained")
        expect(index.publisher == "Example {{publisher}}", "braces inside strings do not count as nesting")
    }

    private static func registryRejectsOversizedDeepAndEntryHeavyIndexes() throws {
        var limits = testRegistryLimits()
        limits.maximumIndexBytes = 64
        expectThrows("oversized registry index") {
            _ = try RegistryStore.decodeIndex(
                data: Data(repeating: 0x20, count: 65),
                sourceID: "oversized",
                limits: limits
            )
        }

        limits = testRegistryLimits()
        limits.maximumJSONNestingDepth = 3
        let deeplyNested = Data(#"{"verdicts":[],"extra":[[[[0]]]]}"#.utf8)
        expectThrows("deep registry JSON") {
            _ = try RegistryStore.decodeIndex(
                data: deeplyNested,
                sourceID: "nested",
                limits: limits
            )
        }

        limits = testRegistryLimits()
        limits.maximumEntriesPerIndex = 2
        let entryHeavy = try JSONSerialization.data(withJSONObject: [
            "verdicts": [
                ["name": "one"],
                ["name": "two"],
                ["name": "three"],
            ],
        ])
        expectThrows("entry-heavy registry index") {
            _ = try RegistryStore.decodeIndex(
                data: entryHeavy,
                sourceID: "entries",
                limits: limits
            )
        }
    }

    private static func registryEnforcesAggregateMaterializationLimit() throws {
        let root = temporaryDirectory("registry")
        defer { try? FileManager.default.removeItem(at: root) }
        var indexSizes: [Int] = []

        for sourceID in ["alpha", "beta"] {
            let directory = root
                .appendingPathComponent("registries", isDirectory: true)
                .appendingPathComponent(sourceID, isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let data = try JSONSerialization.data(withJSONObject: [
                "verdicts": [["type": "skill", "name": sourceID, "status": "clean"]],
            ])
            try data.write(to: directory.appendingPathComponent("index.json"))
            indexSizes.append(data.count)
        }

        var limits = testRegistryLimits()
        limits.maximumAggregateEntries = 1
        let snapshot = RegistryStore.load(
            sources: [registrySource("alpha"), registrySource("beta")],
            dataDirectory: root,
            limits: limits
        )
        expect(snapshot.entries.count == 1, "aggregate entry limit prevents a second source from materializing")
        expect(
            snapshot.sources.first(where: { $0.id == "beta" })?.indexError?.contains("aggregate entries") == true,
            "aggregate rejection is surfaced on the affected source"
        )

        limits = testRegistryLimits()
        limits.maximumAggregateIndexBytes = indexSizes.max()! + 1
        let byteLimited = RegistryStore.load(
            sources: [registrySource("alpha"), registrySource("beta")],
            dataDirectory: root,
            limits: limits
        )
        expect(byteLimited.entries.count == 1, "aggregate index-byte limit prevents a second source from materializing")
        expect(
            byteLimited.sources.first(where: { $0.id == "beta" })?.indexError?.contains("aggregate index bytes") == true,
            "aggregate index-byte rejection is surfaced on the affected source"
        )
    }

    private static func eventReaderRejectsOversizedRecords() async throws {
        let root = temporaryDirectory("event-record")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let jsonl = root.appendingPathComponent("gateway.jsonl")
        let gateway = root.appendingPathComponent("gateway.log")
        let watchdog = root.appendingPathComponent("watchdog.log")
        try Data().write(to: watchdog)
        let oversized = String(repeating: "x", count: 512)
        try Data("\(oversized)\n12:00:00.000 [gateway] allowed-record\n".utf8).write(to: gateway)
        let oversizedEvent: [String: Any] = [
            "event_type": "scan_finding",
            "severity": "HIGH",
            "scan_finding": [
                "scan_id": "oversized",
                "scanner": "test",
                "target": "target",
                "title": "oversized",
                "description": oversized,
            ],
        ]
        let allowedEvent: [String: Any] = [
            "event_type": "scan_finding",
            "severity": "INFO",
            "scan_finding": [
                "scan_id": "allowed",
                "scanner": "test",
                "target": "target",
                "title": "allowed",
                "description": "normal",
            ],
        ]
        let oversizedData = try JSONSerialization.data(withJSONObject: oversizedEvent)
        let allowedData = try JSONSerialization.data(withJSONObject: allowedEvent)
        var jsonlData = Data()
        jsonlData.append(oversizedData)
        jsonlData.append(0x0A)
        jsonlData.append(allowedData)
        jsonlData.append(0x0A)
        try jsonlData.write(to: jsonl)

        let reader = EventStreamReader(
            url: jsonl,
            gatewayLogURL: gateway,
            watchdogLogURL: watchdog,
            maximumRecordBytes: 256,
            maximumRetainedBytes: 1_024
        )
        let delta = await reader.poll()
        let rows = await reader.logBuffers[.gateway] ?? []
        expect(delta.findings.count == 1, "oversized structured record is excluded from the live delta")
        expect(delta.findings[0].title == "allowed", "normal structured record remains visible")
        expect(
            delta.logRows.filter { $0.eventType == "oversized_record" }.count == 2,
            "oversized structured and plain records produce bounded visible notices"
        )
        expect(rows.count == 2, "plain-log buffer retains a notice and the normal record")
        expect(
            rows.contains(where: { $0.eventType == "oversized_record" }),
            "oversized plain log record is replaced by an explicit omission notice"
        )
        expect(
            rows.contains(where: { $0.message.contains("allowed-record") }),
            "normal log record remains visible"
        )
    }

    private static func eventReaderEnforcesAggregateRetainedByteLimit() async throws {
        let root = temporaryDirectory("event-aggregate")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let jsonl = root.appendingPathComponent("gateway.jsonl")
        let gateway = root.appendingPathComponent("gateway.log")
        let watchdog = root.appendingPathComponent("watchdog.log")
        try Data().write(to: jsonl)

        let gatewayLines = (0..<6).map {
            String(format: "12:00:%02d.000 [gateway] gateway-%02d-payload", $0, $0)
        }.joined(separator: "\n") + "\n"
        let watchdogLines = (0..<6).map {
            String(format: "12:01:%02d.000 [watchdog] watchdog-%02d-payload", $0, $0)
        }.joined(separator: "\n") + "\n"
        try Data(gatewayLines.utf8).write(to: gateway)
        try Data(watchdogLines.utf8).write(to: watchdog)

        let reader = EventStreamReader(
            url: jsonl,
            gatewayLogURL: gateway,
            watchdogLogURL: watchdog,
            maximumRecordBytes: 256,
            maximumRetainedBytes: 420
        )
        _ = await reader.poll()
        let retainedBytes = await reader.retainedBufferBytes
        let gatewayRows = await reader.logBuffers[.gateway] ?? []
        let watchdogRows = await reader.logBuffers[.watchdog] ?? []
        expect(retainedBytes <= 420, "aggregate retained bytes stay within the configured budget")
        expect(gatewayRows.count + watchdogRows.count < 12, "oldest records are evicted across stream buffers")
        expect(watchdogRows.last?.message.contains("watchdog-05") == true, "newest normal record remains visible")
    }

    private static func gatewayProjectsAppliedPolicy() async throws {
        StubGatewayURLProtocol.statusCode = 200
        StubGatewayURLProtocol.headers = [:]
        // Both routes deliberately receive the same fixture; only the typed
        // allowlisted projections may leave GatewayClient.
        StubGatewayURLProtocol.body = Data(#"{"policy":{"effective_digest":"digest-v9","generation":9},"profile":"engineers","effective":{"mode":"action","block_at":"HIGH","alert_at":"LOW","rule_pack":"default","secret":"never project"},"token":"never project"}"#.utf8)
        let client = gatewayClient(maximumResponseBytes: 4096)
        let fields = try await client.appliedPolicy(user: "fixture", connector: "codex", resolveProfile: true)
        expect(fields["Policy digest"] == "digest-v9" && fields["Generation"] == "9", "effective policy identity is projected")
        expect(fields["Profile"] == "engineers" && fields["Block at"] == "HIGH", "effective account profile is projected")
        expect(!fields.values.contains("never project"), "non-display response fields never reach the overview")
        StubGatewayURLProtocol.body = Data("{}".utf8)
        do { _ = try await client.appliedPolicy(user: "fixture", connector: "codex", resolveProfile: true); fail("missing profile must not look healthy") }
        catch GatewayError.badResponse { }
    }

    private static func gatewayAcceptsLegitimateResponse() async throws {
        StubGatewayURLProtocol.body = Data(#"{"state":"running","version":"test"}"#.utf8)
        StubGatewayURLProtocol.headers = [
            "Content-Type": "application/json",
            "Content-Length": String(StubGatewayURLProtocol.body.count),
        ]
        let client = gatewayClient(maximumResponseBytes: 256)
        let health = try await client.health()
        expect(health.state == "running", "normal bounded gateway JSON is parsed")
    }

    private static func gatewayRefusesUntrustedListenerAndProtectsToken() async throws {
        var config = DefenseClawConfig()
        let syntheticToken = UUID().uuidString
        config.gatewayToken = syntheticToken
        StubGatewayURLProtocol.statusCode = 200
        StubGatewayURLProtocol.body = Data(#"{"state":"running"}"#.utf8)
        StubGatewayURLProtocol.lastAuthorization = nil
        let trusted = gatewayClient(maximumResponseBytes: 256, config: config)
        _ = try await trusted.health()
        expect(StubGatewayURLProtocol.lastAuthorization == nil, "unauthenticated health never carries the gateway token")

        StubGatewayURLProtocol.body = Data("{}".utf8)
        _ = try await trusted.status()
        expect(StubGatewayURLProtocol.lastAuthorization == "Bearer \(syntheticToken)",
               "authenticated routes still carry the token to a trusted listener")

        let before = StubGatewayURLProtocol.requests
        let untrusted = gatewayClient(maximumResponseBytes: 256, config: config, listenerTrust: { _ in false })
        do {
            _ = try await untrusted.health()
            fail("an untrusted listener was allowed to report healthy")
        } catch GatewayError.badResponse(let reason) {
            expect(reason.contains("untrusted gateway listener"), "untrusted listener has a clear error")
        }
        do {
            _ = try await untrusted.status()
            fail("a token was sent to an untrusted listener")
        } catch GatewayError.badResponse { }
        expect(StubGatewayURLProtocol.requests == before, "untrusted listener received no requests")
    }

    private static func gatewayListenerOwnershipRules() {
        let url = URL(string: "http://127.0.0.1:18970")!
        let own = "p100\nu501\nf8\nn127.0.0.1:18970\n"
        let root = "p101\nu0\nf8\nn127.0.0.1:18970\n"
        let foreign = "p102\nu502\nf8\nn127.0.0.1:18970\n"
        let expectedPath: (pid_t) -> String? = { _ in "/Users/example/.local/bin/defenseclaw-gateway" }
        func trusted(_ listing: String, executablePath: (pid_t) -> String? = expectedPath) -> Bool {
            GatewayListenerTrust.isTrusted(url, listing: listing, accountUID: 501, executablePath: executablePath)
        }
        expect(trusted(own),
               "the selected account may own its gateway listener")
        expect(trusted(root),
               "administrator gateway mode may use a root listener")
        expect(!trusted(foreign),
               "another local account cannot impersonate the gateway")
        expect(!trusted(own + foreign),
               "a mixed-owner listener set is untrusted")
        expect(!trusted(own, executablePath: { _ in "/usr/bin/python3" }),
               "a same-account impostor executable cannot receive a token")
        expect(!trusted("p100\nn127.0.0.1:18970\n"),
               "an unknown listener owner fails closed")
        expect(!trusted("p100\nu501\nn127.0.0.2:18970\n"),
               "a listener on a different loopback address is not trusted")
    }

    private static func gatewayRuntimeCapabilities() async throws {
        StubGatewayURLProtocol.headers = ["Content-Type": "application/json"]
        StubGatewayURLProtocol.statusCode = 404
        StubGatewayURLProtocol.body = Data("{}".utf8)
        let client = gatewayClient(maximumResponseBytes: 4096)
        do {
            _ = try await client.aiRuntime()
            preconditionFailure("missing Runtime route must not produce a clean snapshot")
        } catch GatewayError.degraded(let status, _) {
            expect(status == 404, "missing route is distinguishable from authentication and transport")
        }
        StubGatewayURLProtocol.statusCode = 200
        do {
            _ = try await client.aiRuntime()
            preconditionFailure("malformed Runtime response must not erase coverage")
        } catch GatewayError.badResponse { }
        StubGatewayURLProtocol.body = Data(#"""
        {"enabled":true,"scanned_at":"2026-09-18T12:00:00Z","degraded":true,
         "connections_observed":1,"connections_unattributed":9223372036854775807,
         "planes":[{"plane":"host","available":false,"running":false,"reason":"permission unavailable"}],
         "findings":[{"finding_id":"b","severity":"low","score":10},
                     {"finding_id":"a","severity":"high","score":90}]}
        """#.utf8)
        let snapshot = try await client.aiRuntime()
        expect(snapshot.enabled && snapshot.degraded, "coverage decoded")
        expect(snapshot.planesNotRunning.first?.reason == "permission unavailable", "blind reason preserved")
        expect(snapshot.findings.first?.findingID == "a", "findings sorted by severity")
        expect(snapshot.unattributedShare == 1, "untrusted counters cannot overflow percentage rendering")
        let hostile = AIRuntimeDecoding.snapshot(from: [
            "findings": [
                ["finding_id": "same", "cmdline": #"worker --token "private value""#],
                ["finding_id": "same"],
            ],
            "planes": [["plane": "host"], ["plane": "host"]],
        ])
        expect(hostile.findings.count == 1 && hostile.planes.count == 1, "duplicate identities cannot collide in SwiftUI")
        expect(!hostile.findings[0].cmdline.contains("private value"), "runtime argument secrets are redacted")
        let header = AIRuntimeDecoding.snapshot(from: [
            "findings": [["finding_id": "auth", "cmdline": "Authorization: Bearer header-placeholder"]],
        ])
        expect(!header.findings[0].cmdline.contains("header-placeholder"), "authorization schemes must not hide a remaining credential")
        do {
            try await client.scanAIRuntime()
            preconditionFailure("read-only client must refuse Runtime mutations")
        } catch { }
        StubGatewayURLProtocol.body = Data("{}".utf8)
    }

    private static func gatewaySandboxCapabilities() async throws {
        let client = gatewayClient(maximumResponseBytes: 4096)
        StubGatewayURLProtocol.headers = ["Content-Type": "application/json"]
        StubGatewayURLProtocol.statusCode = 200
        StubGatewayURLProtocol.body = Data(#"{"enabled":false,"available":false}"#.utf8)
        let status = try await client.sandboxStatus()
        expect(!status.enabled && !status.available, "disabled sandbox coverage is explicit")
        StubGatewayURLProtocol.body = Data("{}".utf8)
        do {
            _ = try await client.sandboxStatus()
            preconditionFailure("malformed sandbox status cannot appear disabled")
        } catch GatewayError.badResponse { }
        do {
            _ = try await client.sandboxes()
            preconditionFailure("missing sandbox list cannot appear empty")
        } catch GatewayError.badResponse { }
        StubGatewayURLProtocol.body = Data(#"{"sandboxes":[]}"#.utf8)
        let rows = try await client.sandboxes()
        expect(rows.isEmpty, "valid empty sandbox list remains empty")
        StubGatewayURLProtocol.statusCode = 403
        StubGatewayURLProtocol.body = Data(#"{"error":"policy denies sandbox approval"}"#.utf8)
        do {
            _ = try await client.sandboxApprovals()
            preconditionFailure("sandbox policy refusal must surface")
        } catch GatewayError.degraded(let code, _) {
            expect(code == 403, "sandbox policy refusal is not mislabeled as an expired login")
        }
        StubGatewayURLProtocol.statusCode = 200
        StubGatewayURLProtocol.body = Data("{}".utf8)
    }

    private static func gatewayDecodesOptionalAIDiscoveryMetadata() async throws {
        StubGatewayURLProtocol.body = Data(#"""
        {
            "enabled": true,
            "lookup_model_provenance_online": true,
            "summary": {
                "active_signals": 1,
                "files_scanned": 3,
                "result": "partial",
                "errors": 2,
                "detector_errors": {
                    "ollama": "request timed out",
                    "empty": "",
                    "numeric": 42
                }
            },
            "signals": [{
                "signal_id": "ollama-model",
                "category": "local_model",
                "model": {
                    "id": "llama3:8b",
                    "owner_application": "Ollama",
                    "relevance": "primary",
                    "discovery_confidence": 86,
                    "provenance": {
                        "publisher": "Meta",
                        "country_code": "us",
                        "root_model": "Llama 3",
                        "quantized": true,
                        "quantization": "Q4_K_M"
                    }
                }
            }]
        }
        """#.utf8)
        StubGatewayURLProtocol.headers = [
            "Content-Type": "application/json",
            "Content-Length": String(StubGatewayURLProtocol.body.count),
        ]
        let client = gatewayClient(maximumResponseBytes: 4_096)
        let snapshot = try await client.aiUsage()
        expect(snapshot.lookupModelProvenanceOnline, "online provenance lookup is decoded")
        expect(snapshot.result == "partial", "discovery result is decoded")
        expect(snapshot.errors == 2, "discovery error count is decoded")
        expect(
            snapshot.detectorErrors == ["ollama": "request timed out"],
            "malformed detector errors are discarded"
        )
        expect(snapshot.signals.count == 1, "bounded response retains its signal")
        expect(snapshot.signals[0].model?.ownerApplication == "Ollama", "model owner is decoded")
        expect(snapshot.signals[0].model?.relevance == "primary", "model relevance is decoded")
        expect(snapshot.signals[0].model?.discoveryConfidence == 0.86, "confidence is normalized")
        expect(snapshot.signals[0].model?.provenance?.publisher == "Meta", "provenance is decoded")
        expect(snapshot.signals[0].model?.provenance?.countryCode == "US", "country is normalized")

        StubGatewayURLProtocol.body = Data(#"{"summary":{},"signals":[]}"#.utf8)
        StubGatewayURLProtocol.headers = [
            "Content-Type": "application/json",
            "Content-Length": String(StubGatewayURLProtocol.body.count),
        ]
        let legacySnapshot = try await client.aiUsage()
        expect(!legacySnapshot.lookupModelProvenanceOnline, "missing lookup mode defaults offline")
        expect(legacySnapshot.result.isEmpty, "missing diagnostics remain absent")
        expect(legacySnapshot.errors == 0, "missing diagnostic count defaults safely")
        expect(legacySnapshot.detectorErrors.isEmpty, "missing detector errors default safely")
    }

    private static func gatewayStopsUnknownLengthOversizedResponse() async throws {
        StubGatewayURLProtocol.body = Data(repeating: 0x78, count: 257)
        StubGatewayURLProtocol.headers = ["Content-Type": "application/json"]
        let client = gatewayClient(maximumResponseBytes: 256)
        do {
            _ = try await client.health()
            fail("unknown-length oversized gateway response was accepted")
        } catch GatewayError.badResponse(let detail) {
            expect(detail.contains("256-byte limit"), "oversized gateway response reports its byte limit")
        } catch {
            fail("unexpected oversized gateway response error: \(error)")
        }
    }

    private static func gatewayRejectsDeclaredOversizedResponse() async throws {
        StubGatewayURLProtocol.body = Data(#"{"state":"running"}"#.utf8)
        StubGatewayURLProtocol.headers = [
            "Content-Type": "application/json",
            "Content-Length": "257",
        ]
        let client = gatewayClient(maximumResponseBytes: 256)
        do {
            _ = try await client.health()
            fail("declared oversized gateway response was accepted")
        } catch GatewayError.badResponse(let detail) {
            expect(detail.contains("256-byte limit"), "declared oversized response reports its byte limit")
        } catch {
            fail("unexpected declared-size gateway response error: \(error)")
        }
    }

    private static func gatewayClient(
        maximumResponseBytes: Int,
        config: DefenseClawConfig = DefenseClawConfig(),
        listenerTrust: @escaping @Sendable (URL) -> Bool = { _ in true }
    ) -> GatewayClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubGatewayURLProtocol.self]
        return GatewayClient(
            config: config,
            maximumResponseBytes: maximumResponseBytes,
            session: URLSession(configuration: configuration),
            listenerTrust: listenerTrust
        )
    }

    private static func testRegistryLimits() -> RegistryStore.Limits {
        RegistryStore.Limits(
            maximumIndexBytes: 4_096,
            maximumEntriesPerIndex: 10,
            maximumAggregateIndexBytes: 8_192,
            maximumAggregateEntries: 10,
            maximumJSONNestingDepth: 8
        )
    }

    private static func registrySource(_ id: String) -> DefenseClawConfig.RegistrySourceConfig {
        DefenseClawConfig.RegistrySourceConfig(
            id: id,
            kind: "local",
            content: "skills",
            url: "",
            authEnv: "",
            enabled: true,
            lastSync: "",
            lastStatus: ""
        )
    }

    private static func temporaryDirectory(_ label: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("defenseclaw-\(label)-\(UUID().uuidString)", isDirectory: true)
    }

    private static func expectThrows(_ label: String, _ operation: () throws -> Void) {
        do {
            try operation()
            fail("\(label) was accepted")
        } catch {
            return
        }
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ label: String) {
        guard condition() else { fail(label) }
    }

    private static func fail(_ message: String) -> Never {
        fputs("FAILED: \(message)\n", stderr)
        exit(1)
    }
}
