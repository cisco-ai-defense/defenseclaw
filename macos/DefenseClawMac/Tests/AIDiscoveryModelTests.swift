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
struct AIDiscoveryModelTests {
    private static var failureCount = 0

    static func main() {
        parsesCanonicalModelProvenance()
        preservesUnknownLineageBooleansAndRejectsInvalidCountries()
        decodesDiscoveryDiagnosticsAndModelRelevanceMetadata()
        formatsPartialScanWithoutSyntheticZeroError()
        partitionsModelsFromProductsAndAggregatesSources()
        searchesModelLineageMetadata()
        appliesFocusedAndExplicitModelFilters()
        guard failureCount == 0 else {
            fputs("AI discovery model provenance tests failed: \(failureCount)\n", stderr)
            exit(1)
        }
        print("AI discovery model provenance tests passed")
    }

    private static func parsesCanonicalModelProvenance() {
        let model = AIUsageModel.fromMapping([
            "id": "mlx-community/Llama-3.2-3B-Instruct-4bit",
            "status": "installed",
            "format": "safetensors",
            "provider": "mlx",
            "recipe": "mlx",
            "modality": "text",
            "device": "gpu",
            "size_bytes": 2_147_483_648,
            "pinned": true,
            "provenance": [
                "publisher": "Meta",
                "country_code": "us",
                "root_model": "meta-llama/Llama-3.2-3B-Instruct",
                "base_models": ["meta-llama/Llama-3.2-3B-Instruct"],
                "quantized": true,
                "quantization": "4-bit",
                "distilled": false,
                "derivation": "quantized",
                "source": "catalog_exact",
                "confidence": "high",
            ] as [String: Any],
        ])

        expect(model?.id == "mlx-community/Llama-3.2-3B-Instruct-4bit", "model id parses")
        expect(model?.sizeBytes == 2_147_483_648, "model size parses")
        expect(model?.pinned == true, "model pinned state parses")
        expect(model?.provenance?.publisher == "Meta", "publisher parses")
        expect(model?.provenance?.countryCode == "US", "country code normalizes")
        expect(model?.provenance?.countryDisplay == "US 🇺🇸", "flag derives from country code")
        expect(model?.provenance?.quantized == true, "quantized true parses")
        expect(model?.provenance?.distilled == false, "distilled false remains known false")
        expect(
            model?.provenance?.derivationDisplay == "quantized · 4-bit",
            "derivation and quantization are displayable"
        )
    }

    private static func preservesUnknownLineageBooleansAndRejectsInvalidCountries() {
        let unknown = AIModelProvenance.fromMapping([
            "country_code": "USA",
            "derivation": "distilled+quantized",
        ])
        expect(unknown?.quantized == nil, "absent quantized state remains unknown")
        expect(unknown?.distilled == nil, "absent distilled state remains unknown")
        expect(unknown?.countryCode.isEmpty == true, "invalid country code is rejected")
        expect(unknown?.countryDisplay.isEmpty == true, "invalid country has no flag")
        expect(
            unknown?.derivationDisplay == "distilled+quantized",
            "combined derivation is readable"
        )

        let compatible = AIModelProvenance.fromMapping([
            "base_models": "publisher/base-model",
            "quantized": "yes",
            "quantization": "Q4_K_M",
            "distilled": 0,
        ])
        expect(compatible?.baseModels == ["publisher/base-model"], "single base model is accepted")
        expect(compatible?.rootDisplay == "ambiguous (1)", "base model alone does not invent a root")
        expect(compatible?.quantized == true, "compatible true boolean parses")
        expect(compatible?.distilled == false, "compatible false boolean parses")
        expect(
            compatible?.derivationDisplay == "quantized · Q4_K_M",
            "lineage derives from explicit boolean metadata"
        )

        let merged = AIModelProvenance.fromMapping([
            "base_models": ["publisher/base-a", "publisher/base-b"],
            "source": "huggingface_hub",
            "confidence": "medium",
        ])
        expect(merged?.rootDisplay == "ambiguous (2)", "multi-parent models do not invent a first root")

        let malformed = AIUsageModel.fromMapping([
            "id": "private-model",
            "size_bytes": Double.infinity,
            "pinned": "true",
        ])
        expect(malformed?.sizeBytes == 0, "non-finite size is rejected")
        expect(malformed?.pinned == true, "compatible string boolean parses consistently")

        let invalid = AIUsageModel.fromMapping([
            "id": "invalid-model",
            "size_bytes": 1.5,
            "pinned": "maybe",
        ])
        expect(invalid?.sizeBytes == 0, "fractional size is rejected consistently")
        expect(invalid?.pinned == false, "invalid pinned value is rejected")
    }

    private static func decodesDiscoveryDiagnosticsAndModelRelevanceMetadata() {
        let diagnostics = AIDiscoveryDiagnostics.fromMapping([
            "result": "partial",
            "errors": NSNumber(value: 2),
            "detector_errors": [
                "process": "process enumeration denied",
                "model_files": "Application Support was not readable",
                "empty": "",
                "invalid": 42,
            ] as [String: Any],
        ])
        expect(diagnostics.result == "partial", "summary result parses")
        expect(diagnostics.errors == 2, "summary error count parses")
        expect(
            diagnostics.detectorErrors == [
                "process": "process enumeration denied",
                "model_files": "Application Support was not readable",
            ],
            "detector errors parse independently and discard malformed values"
        )
        var snapshot = AIUsageSnapshot()
        snapshot.result = "ok"
        snapshot.detectorErrors = diagnostics.detectorErrors
        expect(snapshot.isPartial, "detector failures make the snapshot partial even with a stale ok result")

        let model = AIUsageModel.fromMapping([
            "id": "unknown-app/model",
            "owner_application": "Meetily",
            "relevance": "primary",
            "modality": "generative",
            "discovery_confidence": 0.92,
        ])
        expect(model?.ownerApplication == "Meetily", "owner application parses")
        expect(model?.relevance == "primary", "relevance parses")
        expect(model?.modality == "generative", "canonical modality parses")
        expect(model?.discoveryConfidence == 0.92, "discovery confidence parses")

        let legacyPercent = AIUsageModel.fromMapping([
            "id": "compatible",
            "discovery_confidence": 86,
        ])
        expect(legacyPercent?.discoveryConfidence == 0.86, "percentage confidence normalizes")
        let invalid = AIUsageModel.fromMapping([
            "id": "invalid",
            "discovery_confidence": true,
        ])
        expect(invalid?.discoveryConfidence == nil, "boolean confidence is rejected")
        expect(
            AIConfidence.optionalNormalized(NSNumber(value: false)) == nil,
            "NSNumber false is rejected as a boolean confidence"
        )
        expect(
            AIConfidence.optionalNormalized(NSNumber(value: true)) == nil,
            "NSNumber true is rejected as a boolean confidence"
        )
        expect(
            AIConfidence.optionalNormalized(NSNumber(value: 0)) == 0,
            "NSNumber numeric zero remains an explicit confidence"
        )
        expect(
            AIConfidence.optionalNormalized(NSNumber(value: 1)) == 1,
            "NSNumber numeric one remains an explicit confidence"
        )
    }

    private static func formatsPartialScanWithoutSyntheticZeroError() {
        var snapshot = AIUsageSnapshot()
        snapshot.result = "partial"
        expect(snapshot.reportedDiscoveryErrorCount == 0, "partial scan can omit a numeric error count")
        expect(snapshot.discoveryIssueLabel == "Scan did not complete", "partial scan avoids a zero-error label")
        expect(
            snapshot.partialDiscoveryDescription == "The scan did not complete, so results may be incomplete.",
            "partial scan explains incomplete results when no detector error is reported"
        )

        snapshot.detectorErrors = ["model_files": "permission denied"]
        expect(snapshot.discoveryIssueLabel == "1 error", "detector failures produce a compact error count")
        expect(
            snapshot.partialDiscoveryDescription == "1 error occurred during discovery.",
            "detector failures produce a counted banner description"
        )
    }

    private static func partitionsModelsFromProductsAndAggregatesSources() {
        let provenance = AIModelProvenance(
            publisher: "Alibaba Cloud",
            countryCode: "CN",
            rootModel: "Qwen/Qwen3-0.6B",
            baseModels: ["Qwen/Qwen3-0.6B"],
            quantized: true,
            quantization: "Q4_K_M",
            distilled: false,
            derivation: "quantized",
            source: "catalog_exact",
            confidence: "high"
        )
        let partialProvenance = AIModelProvenance(
            publisher: "Unverified mirror", source: "identifier", confidence: "low"
        )
        let signals = [
            makeSignal(
                product: "Ollama",
                vendor: "Ollama",
                category: "local_model",
                detector: "model_api",
                state: "new",
                model: AIUsageModel(
                    id: "  Qwen3-0.6B-GGUF\n", status: "installed", format: "gguf",
                    provider: "ollama", provenance: partialProvenance
                )
            ),
            makeSignal(
                product: "Lemonade Server",
                vendor: "Lemonade",
                category: "local_model",
                detector: "model_runtime",
                model: AIUsageModel(
                    id: "qWEN3-0.6b-gguf", status: "loaded", format: "gguf",
                    provider: "lemonade", provenance: provenance
                )
            ),
            makeSignal(product: "Codex", vendor: "OpenAI", category: "ai_cli", detector: "binary"),
            makeSignal(
                product: "Acme Model Studio", vendor: "Acme",
                category: "desktop_app", detector: "application",
                model: AIUsageModel(
                    id: "acme/embedded-model", status: "available", format: "safetensors"
                )
            ),
            // Preserve malformed/legacy local-model rows rather than dropping
            // them when an older gateway omitted the model block.
            makeSignal(
                product: "Legacy Model Signal", vendor: "Local",
                category: "local_model", detector: "model_file"
            ),
            makeSignal(
                product: "Malformed Model Signal", vendor: "Local",
                category: "local_model", detector: "model_api", model: AIUsageModel()
            ),
        ]

        let modelRows = AIDiscoveryGrouping.modelRows(from: signals)
        expect(modelRows.count == 1, "case variants of one model aggregate")
        guard let row = modelRows.first else { return }
        expect(row.count == 2, "model signal count aggregates")
        expect(row.modelID == "Qwen3-0.6B-GGUF", "model ID is trimmed for grouping and display")
        expect(row.state == "new", "most actionable state wins across model sources")
        expect(Set(row.statuses) == Set(["installed", "loaded"]), "statuses aggregate")
        expect(Set(row.providers) == Set(["ollama", "lemonade"]), "providers aggregate")
        expect(Set(row.products) == Set(["Ollama", "Lemonade Server"]), "products aggregate")
        expect(Set(row.detectors) == Set(["model_api", "model_runtime"]), "detectors aggregate")
        expect(row.provenance == provenance, "stronger provenance wins during aggregation")

        let productRows = AIDiscoveryGrouping.rows(from: signals)
        expect(productRows.count == 4, "only identified local-model signals leave the product table")
        expect(productRows.contains { $0.product == "Codex" }, "ordinary product remains")
        expect(
            productRows.contains { $0.product == "Acme Model Studio" },
            "non-local signals with model metadata remain product signals"
        )
        expect(
            productRows.contains { $0.product == "Legacy Model Signal" },
            "legacy signal without model metadata remains visible"
        )
        expect(
            productRows.contains { $0.product == "Malformed Model Signal" },
            "empty model identifiers remain visible as product signals"
        )
    }

    private static func searchesModelLineageMetadata() {
        let signal = makeSignal(
            product: "Local Model Artifact",
            vendor: "Local",
            category: "local_model",
            detector: "model_file",
            model: AIUsageModel(
                id: "derived-model-q4", status: "installed", format: "gguf", provider: "filesystem",
                provenance: AIModelProvenance(
                    publisher: "Mistral AI", countryCode: "FR",
                    rootModel: "mistralai/Mistral-7B-v0.3",
                    baseModels: ["mistralai/Mistral-7B-v0.3"],
                    quantized: true, quantization: "Q4_K_M", distilled: nil,
                    derivation: "quantized", source: "identifier", confidence: "medium"
                )
            )
        )
        guard let row = AIDiscoveryGrouping.modelRows(from: [signal]).first else {
            expect(false, "model row exists")
            return
        }
        expect(row.matches("FR"), "country code is searchable")
        expect(row.matches("fr"), "country code search is case-insensitive")
        expect(row.matches("Mistral AI"), "publisher is searchable")
        expect(row.matches("mistral ai"), "publisher search is case-insensitive")
        expect(row.matches("Mistral-7B"), "root model is searchable")
        expect(row.matches("Q4_K_M"), "quantization is searchable")
        expect(row.matches("filesystem"), "provider is searchable")
        expect(row.matches("FILESYSTEM"), "provider search is case-insensitive")
        expect(!row.matches("Anthropic"), "unrelated provenance does not match")
    }

    private static func appliesFocusedAndExplicitModelFilters() {
        let primaryGenerative = modelRow(
            id: "primary-generative", modality: "generative", relevance: "primary", confidence: 0.93
        )
        let unknownHighConfidence = modelRow(
            id: "unknown-high", modality: "unknown", relevance: "unknown", confidence: 0.88
        )
        let supporting = modelRow(
            id: "supporting", modality: "generative", relevance: "supporting", confidence: 0.91
        )
        let embedded = modelRow(
            id: "embedded", modality: "generative", relevance: "embedded", confidence: 0.96
        )
        let speech = modelRow(
            id: "speech", modality: "speech", relevance: "primary", confidence: 0.94
        )
        let supportingSpeech = modelRow(
            id: "supporting-speech", modality: "speech", relevance: "supporting", confidence: 0.92
        )
        let ownerlessSupportingSpeech = modelRow(
            id: "ownerless-supporting-speech", modality: "speech", relevance: "supporting",
            confidence: 0.92, ownerApplication: ""
        )
        let supportingAudio = modelRow(
            id: "supporting-audio", modality: "audio", relevance: "supporting", confidence: 0.8
        )
        let supportingVision = modelRow(
            id: "supporting-vision", modality: "vision", relevance: "supporting", confidence: 0.9
        )
        let supportingEmbedding = modelRow(
            id: "supporting-embedding", modality: "embedding", relevance: "supporting", confidence: 0.9
        )
        let lowConfidence = modelRow(
            id: "low", modality: "generative", relevance: "primary", confidence: 0.79
        )
        let confidenceBoundary = modelRow(
            id: "boundary", modality: "generative", relevance: "primary", confidence: 0.8
        )
        let explicitZeroConfidence = modelRow(
            id: "explicit-zero", modality: "generative", relevance: "primary", confidence: 0,
            signalConfidence: 0.2, detector: "model_api"
        )
        let localAPIMissingConfidence = modelRow(
            id: "local-api-missing", modality: "generative", relevance: "primary", confidence: nil,
            signalConfidence: 0.2, detector: "model_api"
        )
        let localAPISupporting = modelRow(
            id: "local-api-supporting", modality: "generative", relevance: "supporting", confidence: nil,
            signalConfidence: 0.2, detector: "model_api"
        )
        let localAPISpeech = modelRow(
            id: "local-api-speech", modality: "speech", relevance: "primary", confidence: nil,
            signalConfidence: 0.2, detector: "model_api"
        )
        let legacy = modelRow(
            id: "legacy", modality: "", relevance: "", confidence: nil, signalConfidence: 0.9
        )
        let legacyModalityOnly = modelRow(
            id: "legacy-modality", modality: "text", relevance: "", confidence: nil,
            signalConfidence: 0.9, ownerApplication: ""
        )
        var mixedAPISignal = makeSignal(
            product: "Meetily", vendor: "Local", category: "local_model", detector: "model_api",
            model: AIUsageModel(id: "mixed-api-low")
        )
        mixedAPISignal.confidence = 0.2
        var mixedFileSignal = makeSignal(
            product: "Meetily", vendor: "Local", category: "local_model", detector: "model_file",
            model: AIUsageModel(
                id: "mixed-api-low", modality: "unknown", ownerApplication: "Chrome",
                relevance: "embedded", discoveryConfidence: 0.79
            )
        )
        mixedFileSignal.confidence = 0.79
        guard let mixedLocalAPIRow = AIDiscoveryGrouping.modelRows(
            from: [mixedAPISignal, mixedFileSignal]
        ).first else {
            fatalError("mixed local API row should exist")
        }

        let focused = AIModelDiscoveryFilter()
        expect(focused.includes(primaryGenerative), "focused filter includes primary generative model")
        expect(!focused.includes(unknownHighConfidence), "focused filter hides unknown-classification artifacts")
        let legacySnapshotFilter = focused.preservingLegacySnapshot([legacy])
        expect(
            legacySnapshotFilter.includes(legacy),
            "an entirely legacy snapshot preserves the historical all-model view"
        )
        let legacyModalitySnapshotFilter = focused.preservingLegacySnapshot([legacyModalityOnly])
        expect(
            legacyModalitySnapshotFilter.includes(legacyModalityOnly),
            "the pre-existing modality field alone preserves legacy snapshot compatibility"
        )
        let classifiedSnapshotFilter = focused.preservingLegacySnapshot([legacy, primaryGenerative])
        expect(
            !classifiedSnapshotFilter.includes(legacy),
            "legacy rows do not weaken a snapshot that contains classification metadata"
        )
        expect(!focused.includes(supporting), "focused filter hides supporting generative artifacts")
        expect(!focused.includes(embedded), "focused filter hides embedded model")
        expect(focused.includes(speech), "focused filter includes a high-confidence primary speech model")
        expect(focused.includes(supportingSpeech), "focused filter includes owner-attributed supporting speech")
        expect(focused.includes(supportingAudio), "focused filter includes owner-attributed supporting audio")
        expect(focused.includes(supportingVision), "focused filter includes owner-attributed supporting vision")
        expect(focused.includes(supportingEmbedding), "focused filter includes owner-attributed supporting embedding")
        expect(
            !focused.includes(ownerlessSupportingSpeech),
            "focused filter hides ownerless supporting artifacts"
        )
        expect(!focused.includes(lowConfidence), "focused filter hides low-confidence model")
        expect(focused.includes(confidenceBoundary), "focused filter includes the 80-percent boundary")
        expect(
            !focused.includes(explicitZeroConfidence),
            "an explicitly reported zero remains below the confidence threshold"
        )
        expect(
            focused.includes(localAPIMissingConfidence),
            "local API models are not hidden when model-specific confidence is absent"
        )
        expect(
            primaryGenerative.confidenceDisplayLabel == "93%",
            "reported discovery confidence has an unqualified percent label"
        )
        expect(
            primaryGenerative.confidenceAccessibilityLabel == "Discovery confidence 93 percent",
            "reported discovery confidence is identified for accessibility"
        )
        expect(
            localAPIMissingConfidence.confidenceDisplayLabel == "API",
            "local API rows without model confidence match the TUI label"
        )
        expect(
            localAPIMissingConfidence.confidenceAccessibilityLabel
                == "Local model API; discovery confidence not reported",
            "local API accessibility text does not imply a model confidence score"
        )
        expect(
            legacy.confidenceDisplayLabel == "90% signal",
            "non-API fallback confidence remains visibly qualified as a signal score"
        )
        expect(
            legacy.confidenceAccessibilityLabel == "Signal confidence 90 percent",
            "non-API fallback confidence identifies the signal source for accessibility"
        )
        expect(
            focused.includes(localAPISupporting),
            "unclassified local API rows remain visible without model-specific confidence"
        )
        expect(
            focused.includes(localAPISpeech),
            "primary local API speech remains visible without model-specific confidence"
        )
        expect(
            mixedLocalAPIRow.reportedDiscoveryConfidence == 0.79,
            "mixed local API row retains the file detector confidence"
        )
        expect(
            mixedLocalAPIRow.hasLocalModelAPISignalWithoutDiscoveryConfidence,
            "mixed local API row detects missing confidence on the API signal"
        )
        expect(
            mixedLocalAPIRow.effectiveRelevance == .embedded,
            "mixed local API row retains the file detector classification"
        )
        expect(
            focused.includes(mixedLocalAPIRow),
            "missing API confidence bypasses grouped low-confidence embedded classification"
        )

        let speechFilter = AIModelDiscoveryFilter(modality: .speech)
        expect(speechFilter.includes(speech), "explicit modality overrides the default modality scope")
        expect(
            speechFilter.includes(supportingSpeech),
            "explicit speech modality does not retain the recommended relevance exclusion"
        )
        expect(
            speechFilter.includes(localAPISpeech),
            "explicit speech includes a local API model without model-specific confidence"
        )
        expect(
            speechFilter.includes(ownerlessSupportingSpeech),
            "explicit speech can reveal an ownerless supporting artifact"
        )
        expect(!speechFilter.includes(primaryGenerative), "explicit modality excludes other modalities")
        expect(
            !speechFilter.includes(mixedLocalAPIRow),
            "explicit modality still filters an unqualified mixed local API row"
        )

        let supportingFilter = AIModelDiscoveryFilter(relevance: .supporting)
        expect(supportingFilter.includes(supporting), "explicit relevance overrides default relevance scope")
        expect(
            supportingFilter.includes(supportingSpeech),
            "explicit supporting relevance does not retain the recommended modality exclusion"
        )
        let embeddedFilter = AIModelDiscoveryFilter(relevance: .embedded)
        expect(
            embeddedFilter.includes(mixedLocalAPIRow),
            "explicit relevance can select an unqualified mixed local API row"
        )

        let allModels = AIModelDiscoveryFilter(showAllModels: true)
        expect(allModels.includes(lowConfidence), "show all includes low-confidence models")
        expect(allModels.includes(embedded), "show all includes embedded models")
        expect(allModels.includes(unknownHighConfidence), "show all includes unknown models")
        expect(allModels.includes(legacy), "show all includes legacy unclassified models")

        let allSpeech = AIModelDiscoveryFilter(showAllModels: true, modality: .speech)
        expect(allSpeech.includes(speech), "show all can still be narrowed by modality")
        expect(!allSpeech.includes(embedded), "show all modality filter remains effective")
        expect(primaryGenerative.matches("Meetily"), "owner application participates in search")
        expect(primaryGenerative.matches("generative"), "modality participates in search")
        expect(primaryGenerative.matches("primary"), "relevance participates in search")
    }

    private static func modelRow(
        id: String,
        modality: String,
        relevance: String,
        confidence: Double?,
        signalConfidence: Double = 0.9,
        detector: String = "model_file",
        ownerApplication: String? = nil
    ) -> AIModelDiscoveryRow {
        let resolvedOwner = ownerApplication
            ?? (modality.isEmpty && relevance.isEmpty && confidence == nil ? "" : "Meetily")
        var signal = makeSignal(
            product: "Meetily",
            vendor: "Local",
            category: "local_model",
            detector: detector,
            model: AIUsageModel(
                id: id,
                modality: modality,
                ownerApplication: resolvedOwner,
                relevance: relevance,
                discoveryConfidence: confidence
            )
        )
        signal.confidence = signalConfidence
        guard let row = AIDiscoveryGrouping.modelRows(from: [signal]).first else {
            fatalError("test model row should exist")
        }
        return row
    }

    private static func makeSignal(
        product: String,
        vendor: String,
        category: String,
        detector: String,
        state: String = "seen",
        model: AIUsageModel? = nil
    ) -> AISignal {
        AISignal(
            state: state,
            product: product,
            vendor: vendor,
            category: category,
            detector: detector,
            version: "",
            ecosystem: "",
            componentName: "",
            source: "test",
            confidence: 0.9,
            identityScore: 0.9,
            identityBand: "high",
            presenceScore: 0.9,
            presenceBand: "high",
            presenceAxisReported: true,
            firstSeen: nil,
            lastSeen: nil,
            lastActive: nil,
            name: "",
            supportedConnector: "",
            signalID: "",
            signatureID: "",
            model: model
        )
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ label: String) {
        guard condition() else {
            failureCount += 1
            fputs("FAILED: \(label)\n", stderr)
            return
        }
    }
}
