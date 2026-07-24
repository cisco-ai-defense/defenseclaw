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
        partitionsModelsFromProductsAndAggregatesSources()
        searchesModelLineageMetadata()
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
