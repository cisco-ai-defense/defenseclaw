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
struct LocalModelDiscoveryParityTests {
    static func main() {
        decodesLocalModelRuntimeAndEvidenceMetadata()
        decodesProvenanceDiagnosticsAndClassificationMetadata()
        safelyCoercesUntrustedModelMetadata()
        groupsLocalModelsByModelIDAndSearchesModelNames()
        preservesStableCollisionSafeRowIdentity()
        excludesLocalModelsFromTheAgentOverview()
        rendersPresenceSafeHeaderAndAgentOnlyOverviewSummary()
        ordersAndDeduplicatesModelSignalsLikeTheTUI()
        print("Local-model discovery parity tests passed")
    }

    private static func decodesLocalModelRuntimeAndEvidenceMetadata() {
        let mappings = AISignalDecoding.signalMappings(from: [
            ["signal_id": "valid-1"],
            "malformed",
            ["signal_id": "valid-2"],
        ])
        expect(
            mappings.compactMap { $0["signal_id"] as? String } == ["valid-1", "valid-2"],
            "malformed signal rows are skipped individually"
        )

        let signal = AISignalDecoding.decode([
            "state": "seen",
            "product": "Lemonade Server",
            "vendor": "Lemonade",
            "category": "local_model",
            "detector": "model_runtime",
            "evidence_types": ["local_api", "runtime"],
            "model": [
                "id": "Qwen3-0.6B-GGUF",
                "status": "loaded",
                "format": "gguf",
                "provider": "lemonade",
                "recipe": "llamacpp",
                "modality": "text",
                "device": "gpu",
                "size_bytes": 400_000_000,
                "pinned": true,
            ],
            "runtime": [
                "pid": 4_321,
                "ppid": 123,
                "started_at": "2026-07-10T01:02:03Z",
                "uptime_sec": 3_661,
                "user": "operator",
                "comm": "lemonade-server",
            ],
        ])

        expect(signal.model?.id == "Qwen3-0.6B-GGUF", "model id")
        expect(signal.model?.status == "loaded", "model status")
        expect(signal.model?.format == "gguf", "model format")
        expect(signal.model?.provider == "lemonade", "model provider")
        expect(signal.model?.recipe == "llamacpp", "model recipe")
        expect(signal.model?.modality == "text", "model modality")
        expect(signal.model?.device == "gpu", "model device")
        expect(signal.model?.sizeBytes == 400_000_000, "model size")
        expect(signal.model?.pinned == true, "model pinned")
        expect(signal.runtime?.pid == 4_321, "runtime pid")
        expect(signal.runtime?.ppid == 123, "runtime ppid")
        expect(signal.runtime?.startedAt != nil, "runtime started at")
        expect(signal.runtime?.uptimeSeconds == 3_661, "runtime uptime")
        expect(signal.runtime?.user == "operator", "runtime user")
        expect(signal.runtime?.command == "lemonade-server", "runtime command")
        expect(signal.evidenceTypes == ["local_api", "runtime"], "evidence types")
        expect(
            signal.model.map(AIDiscoveryGrouping.modelDetail)?.contains("recipe=llamacpp") == true,
            "model inspector detail"
        )
        expect(
            signal.runtime.map(AIDiscoveryGrouping.runtimeDetail)
                == "runtime: pid=4321 user=operator up=1h1m comm=lemonade-server",
            "runtime inspector detail"
        )
    }

    private static func decodesProvenanceDiagnosticsAndClassificationMetadata() {
        let signal = AISignalDecoding.decode([
            "model": [
                "id": "llama3:8b-q4",
                "owner_application": "Ollama",
                "relevance": "primary",
                "discovery_confidence": 92,
                "provenance": [
                    "publisher": "Meta",
                    "country_code": " us ",
                    "base_models": ["Llama 3", "", 42] as [Any],
                    "quantized": "yes",
                    "quantization": "4-bit",
                    "distilled": false,
                    "source": "catalog",
                    "confidence": "high",
                ] as [String: Any],
            ] as [String: Any],
        ])

        guard let model = signal.model, let provenance = model.provenance else {
            fail("model provenance is decoded")
        }
        expect(model.ownerApplication == "Ollama", "model owner application")
        expect(model.relevance == "primary", "model relevance")
        expect(model.discoveryConfidence == 0.92, "percent model confidence is normalized")
        expect(provenance.publisher == "Meta", "provenance publisher")
        expect(provenance.countryCode == "US", "country code is normalized")
        expect(provenance.countryDisplay == "US 🇺🇸", "country display includes its derived flag")
        expect(provenance.baseModels == ["Llama 3"], "malformed and empty base models are discarded")
        expect(provenance.rootDisplay == "ambiguous (1)", "ambiguous lineage is explicit")
        expect(provenance.quantized == true, "string quantized flag is decoded")
        expect(provenance.distilled == false, "boolean distilled flag is decoded")
        expect(provenance.derivationDisplay == "quantized · 4-bit", "derivation fallback")
        expect(provenance.source == "catalog", "provenance source")
        expect(provenance.confidence == "high", "provenance confidence")
        expect(
            AIDiscoveryGrouping.modelDetail(model)
                == "model: id=llama3:8b-q4 relevance=primary owner=Ollama discovery_confidence=92%",
            "classification metadata appears in bounded inspector detail"
        )

        let diagnostics = AIDiscoveryDiagnostics.fromMapping([
            "result": "partial",
            "errors": NSNumber(value: 2),
            "detector_errors": [
                "ollama": "request timed out",
                "empty": "   ",
                "numeric": 42,
            ] as [String: Any],
        ])
        expect(diagnostics.result == "partial", "diagnostic result")
        expect(diagnostics.errors == 2, "diagnostic error count")
        expect(
            diagnostics.detectorErrors == ["ollama": "request timed out"],
            "only nonempty string detector errors are retained"
        )

        var snapshot = AIUsageSnapshot()
        snapshot.result = diagnostics.result
        snapshot.errors = diagnostics.errors
        snapshot.detectorErrors = diagnostics.detectorErrors
        expect(snapshot.isPartial, "reported diagnostics mark a partial scan")
        expect(snapshot.reportedDiscoveryErrorCount == 2, "reported count wins over detector map size")
        expect(snapshot.discoveryIssueLabel == "2 errors", "diagnostic issue label")
        expect(
            snapshot.partialDiscoveryDescription == "2 errors occurred during discovery.",
            "diagnostic description"
        )

        expect(AIConfidence.optionalNormalized(true) == nil, "boolean confidence is rejected")
        expect(
            AIConfidence.optionalNormalized(NSNumber(value: true)) == nil,
            "bridged boolean confidence is rejected"
        )
        expect(AIConfidence.optionalNormalized(NSNumber(value: 0)) == 0, "numeric zero is preserved")
        expect(AIConfidence.optionalNormalized(NSNumber(value: 1)) == 1, "numeric one is preserved")
        expect(AIConfidence.optionalNormalized(Double.nan) == nil, "non-finite confidence is rejected")
        expect(AIUsageModel.fromMapping([:]) == nil, "empty model mapping remains absent")
    }

    private static func safelyCoercesUntrustedModelMetadata() {
        let invalid = AISignalDecoding.decode([
            "model": ["id": "private", "size_bytes": "not-a-number", "pinned": "false"],
            "runtime": ["pid": "not-a-pid", "uptime_sec": -1],
            "evidence_types": "model_api",
        ])
        expect(invalid.model?.sizeBytes == 0, "invalid size becomes zero")
        expect(invalid.model?.pinned == false, "false string remains false")
        expect(invalid.runtime?.pid == 0, "invalid pid becomes zero")
        expect(invalid.runtime?.uptimeSeconds == 0, "negative uptime becomes zero")
        expect(invalid.evidenceTypes == ["model_api"], "single evidence string")
        expect(invalid.product.isEmpty, "missing product remains empty like the TUI")

        let negative = AISignalDecoding.decode([
            "model": ["id": "other", "size_bytes": -42, "pinned": "true"],
        ])
        expect(negative.model?.sizeBytes == 0, "negative size becomes zero")
        expect(negative.model?.pinned == true, "true string is accepted")

        let boundary = AISignalDecoding.decode([
            "model": [
                "id": "boundary",
                "size_bytes": Double(Int64.max),
                "discovery_confidence": true,
                "provenance": ["country_code": "USA"],
            ] as [String: Any],
        ])
        expect(boundary.model?.sizeBytes == 0, "rounded Int64 boundary cannot trap")
        expect(boundary.model?.discoveryConfidence == nil, "boolean confidence remains absent")
        expect(boundary.model?.provenance?.countryCode.isEmpty == true, "invalid country code is discarded")

        var distant = makeSignal(id: "distant")
        distant.lastSeen = Date(timeIntervalSince1970: 1e22)
        expect(
            AIDiscoveryGrouping.activityDetail(
                distant,
                now: Date(timeIntervalSince1970: 0)
            ).isEmpty,
            "unrepresentable activity age is omitted"
        )
    }

    private static func groupsLocalModelsByModelIDAndSearchesModelNames() {
        let installed = makeSignal(
            id: "installed",
            model: AIUsageModel(
                id: "Qwen3-0.6B-GGUF", status: "installed", format: "gguf",
                provider: "lemonade"
            )
        )
        let loaded = makeSignal(
            id: "loaded",
            detector: "model_runtime",
            model: AIUsageModel(
                id: "Qwen3-0.6B-GGUF", status: "loaded", format: "gguf",
                provider: "lemonade", recipe: "llamacpp", device: "gpu", pinned: true
            ),
            runtime: AIUsageRuntime(pid: 4_321)
        )
        let whisper = makeSignal(
            id: "whisper",
            model: AIUsageModel(id: "Whisper-Tiny", status: "installed", format: "onnx")
        )

        let rows = AIDiscoveryGrouping.rows(from: [whisper, installed, loaded])
        expect(rows.count == 2, "distinct model ids remain separate")
        expect(AIDiscoveryGrouping.hasModels(in: rows), "model columns are enabled")

        guard let qwen = rows.first(where: { $0.model == "Qwen3-0.6B-GGUF" }),
              let whisperRow = rows.first(where: { $0.model == "Whisper-Tiny" }) else {
            fail("grouped model rows")
        }
        expect(qwen.count == 2, "installed and loaded signals group together")
        expect(qwen.modelStatuses == ["installed", "loaded"], "statuses retain first-seen order")
        expect(qwen.modelFormats == ["gguf"], "formats are deduplicated")
        expect(qwen.id != whisperRow.id, "model id participates in stable row identity")
        expect(AIDiscoveryGrouping.matches(qwen, query: "qwen3"), "model id is searchable")
        expect(!AIDiscoveryGrouping.matches(whisperRow, query: "qwen3"), "search excludes other models")
        expect(rows.map(\.model) == ["Qwen3-0.6B-GGUF", "Whisper-Tiny"], "model id breaks sort ties")
        expect(AIDiscoveryGrouping.detailSignalLimit == 50, "inspector detail is bounded")
    }

    private static func preservesStableCollisionSafeRowIdentity() {
        var first = makeSignal(id: "first", product: "a|b")
        first.vendor = "c"
        var second = makeSignal(id: "second", product: "a")
        second.vendor = "b|c"
        let collisionRows = AIDiscoveryGrouping.rows(from: [first, second])
        expect(collisionRows.count == 2, "delimiter-bearing fields remain separate")
        expect(collisionRows[0].id != collisionRows[1].id, "row ids are collision safe")

        var firstTie = makeSignal(id: "tie-1", product: "same")
        firstTie.vendor = "Zulu"
        var secondTie = makeSignal(id: "tie-2", product: "same")
        secondTie.vendor = "Alpha"
        let tiedRows = AIDiscoveryGrouping.rows(from: [firstTie, secondTie])
        expect(tiedRows.map(\.vendor) == ["Zulu", "Alpha"], "group sort ties preserve insertion order")

        firstTie.name = "same-display"
        secondTie.name = "same-display"
        let tiedSignals = AIOverviewGrouping.sortedSignals([firstTie, secondTie])
        expect(tiedSignals.map(\.signalID) == ["tie-1", "tie-2"], "overview sort ties preserve insertion order")
        expect(
            AIOverviewGrouping.rowID(firstTie) != AIOverviewGrouping.rowID(secondTie),
            "overview ids derive from dedup identity rather than display text"
        )
    }

    private static func excludesLocalModelsFromTheAgentOverview() {
        let agents = [
            makeSignal(id: "claude", name: "Claude Code", category: "ai_cli", product: "Claude Code"),
            makeSignal(id: "codex", name: "Codex", category: "ai_cli", product: "Codex"),
        ]
        let models = (0..<12).map { index in
            makeSignal(
                id: "model-\(index)",
                model: AIUsageModel(id: "model-\(index)", status: "installed")
            )
        }

        let filtered = AIOverviewGrouping.agentSignals(from: agents + models)
        expect(filtered.map(\.name) == ["Claude Code", "Codex"], "models do not consume agent rows")
        expect(AIOverviewGrouping.agentSignals(from: models).isEmpty, "model-only snapshot has no agents")
    }

    private static func rendersPresenceSafeHeaderAndAgentOnlyOverviewSummary() {
        var snapshot = AIUsageSnapshot()
        snapshot.totalDetected = 12
        snapshot.activeSignals = 0
        snapshot.filesScanned = 3
        snapshot.newSignals = 1
        snapshot.changedSignals = 2
        snapshot.goneSignals = 4
        expect(
            snapshot.discoveryHeaderParts
                == [
                    "active=0", "new=1", "changed=2", "gone=4", "files=3",
                    "model-lookup=offline",
                ],
            "reported active zero never falls back to total detected"
        )
        snapshot.lookupModelProvenanceOnline = true
        expect(
            snapshot.discoveryHeaderParts.last == "model-lookup=online",
            "online provenance lookup is visible in the discovery header"
        )

        var newAgent = makeSignal(id: "new", name: "New agent", category: "ai_cli", product: "New")
        newAgent.state = " new "
        var changedAgent = makeSignal(
            id: "changed", name: "Changed agent", category: "ai_cli", product: "Changed"
        )
        changedAgent.state = "changed"
        var goneAgent = makeSignal(id: "gone", name: "Gone agent", category: "ai_cli", product: "Gone")
        goneAgent.state = "gone"
        let models = (0..<10).map { index in
            makeSignal(
                id: "summary-model-\(index)",
                model: AIUsageModel(id: "summary-model-\(index)", status: "installed")
            )
        }
        let now = Date(timeIntervalSince1970: 10_000)
        expect(
            AIOverviewGrouping.summaryParts(
                from: [newAgent, changedAgent, goneAgent] + models,
                lastScan: now.addingTimeInterval(-120),
                privacyMode: "enhanced",
                now: now
            ) == ["2 active", "1 new", "1 changed", "1 gone", "scanned 2m ago", "mode enhanced"],
            "overview summary counts agents only"
        )
    }

    private static func ordersAndDeduplicatesModelSignalsLikeTheTUI() {
        let installed = makeSignal(
            id: "installed",
            model: AIUsageModel(
                id: "Qwen3", status: "installed", format: "gguf", provider: "lemonade"
            )
        )
        let loaded = makeSignal(
            id: "loaded",
            model: AIUsageModel(
                id: "Qwen3", status: "loaded", format: "gguf", provider: "lemonade"
            )
        )
        let sorted = AIOverviewGrouping.sortedSignals([installed, loaded])
        expect(sorted.first?.model?.status == "loaded", "loaded models sort before installed models")
        expect(AIOverviewGrouping.uniqueSignals(sorted).count == 1, "provider plus model id deduplicates")
        expect(AIOverviewGrouping.displayName(loaded) == "Qwen3", "model id is the display name")
        expect(
            AIOverviewGrouping.displayVendor(loaded) == "Lemonade (loaded, gguf)",
            "model status and format appear in the vendor label"
        )

        let delimiterA = makeSignal(
            id: "delimiter-a",
            model: AIUsageModel(id: "c", provider: "a:b")
        )
        let delimiterB = makeSignal(
            id: "delimiter-b",
            model: AIUsageModel(id: "b:c", provider: "a")
        )
        expect(
            AIOverviewGrouping.uniqueSignals([delimiterA, delimiterB]).count == 2,
            "provider/model delimiter values cannot collide"
        )
    }

    private static func makeSignal(
        id: String,
        name: String = "",
        category: String = "local_model",
        product: String = "Lemonade Server",
        detector: String = "model_api",
        model: AIUsageModel? = nil,
        runtime: AIUsageRuntime? = nil
    ) -> AISignal {
        AISignal(
            state: "seen",
            product: product,
            vendor: category == "local_model" ? "Lemonade" : "",
            category: category,
            detector: detector,
            version: "",
            ecosystem: "",
            componentName: "",
            source: "test",
            confidence: 0.9,
            identityScore: 0,
            identityBand: "",
            presenceScore: 0,
            presenceBand: "",
            firstSeen: nil,
            lastSeen: Date(timeIntervalSince1970: 100),
            lastActive: nil,
            name: name,
            signalID: id,
            model: model,
            runtime: runtime
        )
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ label: String) {
        guard condition() else { fail(label) }
    }

    private static func fail(_ label: String) -> Never {
        fputs("FAILED: \(label)\n", stderr)
        exit(1)
    }
}
