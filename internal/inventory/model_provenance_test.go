// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestModelProvenanceCatalogLoads(t *testing.T) {
	catalog, err := loadModelProvenanceCatalog()
	if err != nil {
		t.Fatalf("loadModelProvenanceCatalog: %v", err)
	}
	if len(catalog.Publishers) < 10 || len(catalog.Lineages) != 19 {
		t.Fatalf("catalog unexpectedly small: publishers=%d lineages=%d", len(catalog.Publishers), len(catalog.Lineages))
	}
	byID := make(map[string]modelPublisherRule)
	for _, rule := range catalog.Publishers {
		byID[rule.ID] = rule
	}
	if got := byID["deepseek"].Publisher; got != "DeepSeek" {
		t.Fatalf("DeepSeek publisher = %q", got)
	}
}

func TestResolveLocalModelProvenanceFamiliesAndDerivatives(t *testing.T) {
	tests := []struct {
		name       string
		model      LocalModelInfo
		hints      modelProvenanceHints
		publisher  string
		country    string
		root       string
		quant      string
		derivation string
		quantized  *bool
		distilled  *bool
		confidence string
	}{
		{
			name:      "official qwen cache identity",
			model:     LocalModelInfo{ID: "Qwen/Qwen3-0.6B", Provider: "huggingface"},
			hints:     modelProvenanceHints{References: []string{"Qwen/Qwen3-0.6B"}, Source: "hf_cache"},
			publisher: "Alibaba Cloud", country: "CN", root: "Qwen/Qwen3-0.6B", confidence: "high",
		},
		{
			name:      "community llama quantization",
			model:     LocalModelInfo{ID: "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF:Q4_K_M.gguf"},
			publisher: "Meta", country: "US", root: "meta-llama/Meta-Llama-3.1-8B-Instruct",
			quant: "Q4_K_M", derivation: "quantized", quantized: modelBool(true), confidence: "medium",
		},
		{
			name:      "community llama filename quantization",
			model:     LocalModelInfo{ID: "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF-Q4_K_M.gguf"},
			publisher: "Meta", country: "US", root: "meta-llama/Meta-Llama-3.1-8B-Instruct",
			quant: "Q4_K_M", derivation: "quantized", quantized: modelBool(true), confidence: "medium",
		},
		{
			name:      "cross-family distilled llama",
			model:     LocalModelInfo{ID: "deepseek-ai/DeepSeek-R1-Distill-Llama-8B-Q4_K_M"},
			publisher: "Meta", country: "US", root: "meta-llama/Llama-3.1-8B",
			quant: "Q4_K_M", derivation: "distilled+quantized", quantized: modelBool(true), distilled: modelBool(true), confidence: "high",
		},
		{
			name:      "renamed model with explicit base",
			model:     LocalModelInfo{ID: "mystery-renamed", Format: "gguf"},
			hints:     modelProvenanceHints{BaseModels: []string{"meta-llama/Llama-3.2-3B-Instruct"}, Quantization: "Q5_K_M", Quantized: modelBool(true), Source: "gguf_metadata"},
			publisher: "Meta", country: "US", root: "meta-llama/Llama-3.2-3B-Instruct",
			quant: "Q5_K_M", derivation: "quantized", quantized: modelBool(true), confidence: "medium",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveLocalModelProvenance(tc.model, tc.hints)
			if got == nil {
				t.Fatal("resolver returned nil")
			}
			if got.Publisher != tc.publisher || got.CountryCode != tc.country || got.RootModel != tc.root ||
				got.Quantization != tc.quant || got.Derivation != tc.derivation || got.Confidence != tc.confidence {
				t.Fatalf("provenance = %+v", got)
			}
			assertOptionalBool(t, "quantized", got.Quantized, tc.quantized)
			assertOptionalBool(t, "distilled", got.Distilled, tc.distilled)
		})
	}
}

func TestResolveLocalModelProvenanceReservesCatalogExactForReviewedLineages(t *testing.T) {
	got := resolveLocalModelProvenance(
		LocalModelInfo{ID: "meta-llama/customer-secret-llama"},
		modelProvenanceHints{},
	)
	if got == nil {
		t.Fatal("resolver returned nil")
	}
	if got.Publisher != "Meta" || got.CountryCode != "US" ||
		got.RootModel != "meta-llama/customer-secret-llama" || got.Source != "catalog_family" {
		t.Fatalf("namespace-derived provenance = %+v", got)
	}
}

func TestResolveLocalModelProvenancePublisherNamespaceDerivatives(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		publisher  string
		country    string
		root       string
		quant      string
		confidence string
	}{
		{
			name:       "publisher namespace hosting qwen quantization",
			id:         "nvidia/Qwen3.6-35B-A3B-NVFP4",
			publisher:  "Alibaba Cloud",
			country:    "CN",
			root:       "Qwen/Qwen3.6-35B-A3B",
			quant:      "NVFP4",
			confidence: "medium",
		},
		{
			name:       "publisher namespace hosting gemma quantization",
			id:         "nvidia/Gemma-4-31B-NVFP4",
			publisher:  "Google",
			country:    "US",
			root:       "google/Gemma-4-31B",
			quant:      "NVFP4",
			confidence: "medium",
		},
		{
			name:       "publisher namespace with own family",
			id:         "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-FP8",
			publisher:  "NVIDIA",
			country:    "US",
			root:       "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B",
			quant:      "FP8",
			confidence: "medium",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveLocalModelProvenance(LocalModelInfo{ID: tc.id}, modelProvenanceHints{})
			if got == nil {
				t.Fatal("resolver returned nil")
			}
			if got.Publisher != tc.publisher || got.CountryCode != tc.country || got.RootModel != tc.root ||
				got.Quantization != tc.quant || got.Confidence != tc.confidence {
				t.Fatalf("provenance = %+v", got)
			}
			assertOptionalBool(t, "quantized", got.Quantized, modelBool(true))
		})
	}

	ambiguous := resolveLocalModelProvenance(
		LocalModelInfo{ID: "nvidia/Qwen3-Gemma3-12B-FP8"}, modelProvenanceHints{},
	)
	if ambiguous == nil {
		t.Fatal("quantization-only provenance was discarded")
	}
	if ambiguous.Publisher != "" || ambiguous.CountryCode != "" || ambiguous.RootModel != "" {
		t.Fatalf("ambiguous mixed-family model received identity provenance: %+v", ambiguous)
	}
	if ambiguous.Quantization != "FP8" || ambiguous.Quantized == nil || !*ambiguous.Quantized {
		t.Fatalf("ambiguous model lost independent quantization evidence: %+v", ambiguous)
	}
}

func TestModernQuantizationMarkers(t *testing.T) {
	tests := []struct {
		name  string
		value string
		quant string
		root  string
	}{
		{name: "FP8", value: "Qwen3-32B-fp8", quant: "FP8", root: "Qwen3-32B"},
		{name: "NVFP4", value: "Qwen3-32B-NVFP4", quant: "NVFP4", root: "Qwen3-32B"},
		{name: "MXFP4", value: "Qwen3-32B-MXFP4", quant: "MXFP4", root: "Qwen3-32B"},
		{name: "MXFP8", value: "Qwen3-32B-MXFP8", quant: "MXFP8", root: "Qwen3-32B"},
		{name: "W4A16", value: "Qwen3-32B-w4a16", quant: "W4A16", root: "Qwen3-32B"},
		{name: "W8A8", value: "Qwen3-32B-W8A8-GGUF.gguf", quant: "W8A8", root: "Qwen3-32B"},
		{name: "integer 7BPW", value: "Qwen3-32B-7bpw", quant: "7BPW", root: "Qwen3-32B"},
		{name: "decimal 7BPW", value: "Qwen3-32B-7.0bpw", quant: "7.0BPW", root: "Qwen3-32B"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := quantizationFromReferences([]string{tc.value}); got != tc.quant {
				t.Fatalf("quantizationFromReferences(%q) = %q, want %q", tc.value, got, tc.quant)
			}
			if got := cleanDerivedModelName(tc.value); got != tc.root {
				t.Fatalf("cleanDerivedModelName(%q) = %q, want %q", tc.value, got, tc.root)
			}
		})
	}

	for _, value := range []string{"Qwen3-32B-FP16", "Qwen3-32B-BF16"} {
		if got := quantizationFromReferences([]string{value}); got != "" {
			t.Errorf("full-precision encoding %q was classified as quantization %q", value, got)
		}
		if got := cleanDerivedModelName(value); got != value {
			t.Errorf("full-precision encoding %q was stripped to %q", value, got)
		}
	}
}

func TestResolveLocalModelProvenanceUnknownAndTokenBoundaries(t *testing.T) {
	for _, id := range []string{"tokenizer", "deeprank", "intelliph_v3", "llamazing", "qwench"} {
		if got := resolveLocalModelProvenance(LocalModelInfo{ID: id}, modelProvenanceHints{}); got != nil {
			t.Errorf("ambiguous model %q received provenance: %+v", id, got)
		}
	}
	for _, id := range []string{"Qwen3-0.6B", "Llama3.1-8B", "Gemma2-9B"} {
		got := resolveLocalModelProvenance(LocalModelInfo{ID: id}, modelProvenanceHints{})
		if got == nil || got.CountryCode == "" {
			t.Errorf("version-attached family %q did not resolve: %+v", id, got)
		}
	}
	plainGGUF := resolveLocalModelProvenance(LocalModelInfo{ID: "private-model", Format: "gguf"}, modelProvenanceHints{})
	if plainGGUF != nil {
		t.Fatalf("GGUF container alone was treated as quantization/provenance: %+v", plainGGUF)
	}
}

func TestLineageMatchesRequiresTokenBoundaries(t *testing.T) {
	match := "deepseek-r1-distill-qwen-7b"
	for _, reference := range []string{
		"deepseek-ai/DeepSeek-R1-Distill-Qwen-7B",
		"community/DeepSeek-R1-Distill-Qwen-7B-Q4_K_M.gguf",
	} {
		if !lineageMatches(match, []string{reference}) {
			t.Errorf("lineageMatches rejected valid derivative %q", reference)
		}
	}
	for _, reference := range []string{
		"community/MyDeepSeek-R1-Distill-Qwen-7B",
		"deepseek-ai/DeepSeek-R1-Distill-Qwen-7Billion",
		"deepseek-ai/DeepSeek-R1-Distill-Qwen-17B",
	} {
		if lineageMatches(match, []string{reference}) {
			t.Errorf("lineageMatches accepted token lookalike %q", reference)
		}
	}
}

func TestReviewedCommonLineagesRejectAttachedTokenLookalikes(t *testing.T) {
	tests := []struct {
		match     string
		valid     string
		lookalike string
	}{
		{match: "distilbert-base-uncased", valid: "community/distilbert-base-uncased-GGUF", lookalike: "community/distilbert-base-uncasedness"},
		{match: "distilgpt2", valid: "community/distilgpt2-GGUF", lookalike: "community/distilgpt20"},
		{match: "distilroberta-base", valid: "community/distilroberta-base-GGUF", lookalike: "community/distilroberta-baseline"},
		{match: "distil-large-v3", valid: "community/distil-large-v3-GGUF", lookalike: "community/distil-large-v30"},
		{match: "nemotron-3-embed-1b", valid: "community/Nemotron-3-Embed-1B-NVFP4", lookalike: "community/Nemotron-3-Embed-1Billion"},
		{match: "bge-m3", valid: "community/bge-m3-GGUF", lookalike: "community/bge-m30"},
		{match: "all-minilm-l6-v2", valid: "community/all-MiniLM-L6-v2-ONNX", lookalike: "community/all-MiniLM-L6-v20"},
		{match: "multilingual-e5-large", valid: "community/multilingual-e5-large-ONNX", lookalike: "community/multilingual-e5-larger"},
		{match: "all-mpnet-base-v2", valid: "community/all-mpnet-base-v2-ONNX", lookalike: "community/all-mpnet-base-v20"},
	}

	for _, tc := range tests {
		t.Run(tc.match, func(t *testing.T) {
			if !lineageMatches(tc.match, []string{tc.valid}) {
				t.Errorf("lineageMatches rejected valid derivative %q", tc.valid)
			}
			if lineageMatches(tc.match, []string{tc.lookalike}) {
				t.Errorf("lineageMatches accepted attached-token lookalike %q", tc.lookalike)
			}
		})
	}
}

func TestReferencesContainMergeMarkerUsesTokenBoundaries(t *testing.T) {
	for _, reference := range []string{
		"community/Qwen-Llama-Merge",
		"community/Qwen-Llama-Merged-GGUF",
		"mergekit-community/Qwen-Llama",
		"community/Qwen-Llama-FrankenMerge-v2",
	} {
		if !referencesContainMergeMarker([]string{reference}) {
			t.Errorf("merge marker was not detected in %q", reference)
		}
	}
	for _, reference := range []string{
		"community/emergency-model",
		"community/submerged-model",
		"community/merger-model",
		"community/frankenmerger-model",
		"community/mergekitten-model",
	} {
		if referencesContainMergeMarker([]string{reference}) {
			t.Errorf("attached-token lookalike was treated as a merge: %q", reference)
		}
	}
}

func TestResolveLocalModelProvenanceSuppressesSingularIdentityForMerges(t *testing.T) {
	assertNoSingularIdentity := func(t *testing.T, got *LocalModelProvenance) {
		t.Helper()
		if got == nil {
			t.Fatal("resolver returned nil")
		}
		if got.Publisher != "" || got.CountryCode != "" || got.RootModel != "" {
			t.Fatalf("ambiguous merge received singular identity: %+v", got)
		}
	}
	assertBaseModels := func(t *testing.T, got *LocalModelProvenance, want ...string) {
		t.Helper()
		if len(got.BaseModels) != len(want) {
			t.Fatalf("base_models = %v, want %v", got.BaseModels, want)
		}
		for _, baseModel := range want {
			found := false
			for _, gotBaseModel := range got.BaseModels {
				if strings.EqualFold(gotBaseModel, baseModel) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("base_models is missing %q: %v", baseModel, got.BaseModels)
			}
		}
	}

	t.Run("exact lineage with two explicit parents", func(t *testing.T) {
		got := resolveLocalModelProvenance(
			LocalModelInfo{ID: "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B"},
			modelProvenanceHints{
				BaseModels: []string{"Qwen/Qwen2.5-Math-7B", "meta-llama/Llama-3.1-8B"},
				Source:     "gguf_metadata",
			},
		)
		assertNoSingularIdentity(t, got)
		assertBaseModels(t, got, "Qwen/Qwen2.5-Math-7B", "meta-llama/Llama-3.1-8B")
		if got.Source != "gguf_metadata" || got.Confidence != "medium" {
			t.Fatalf("explicit merge evidence source/confidence = %q/%q", got.Source, got.Confidence)
		}
	})

	t.Run("merge-marked multi-family name without parents", func(t *testing.T) {
		got := resolveLocalModelProvenance(
			LocalModelInfo{ID: "community/Qwen3-Llama3-FrankenMerge"}, modelProvenanceHints{},
		)
		if got != nil {
			t.Fatalf("identity-free merge marker produced provenance: %+v", got)
		}
	})

	t.Run("merge-marked exact lineage without parents", func(t *testing.T) {
		got := resolveLocalModelProvenance(
			LocalModelInfo{ID: "community/DeepSeek-R1-Distill-Qwen-7B-MergeKit"}, modelProvenanceHints{},
		)
		assertNoSingularIdentity(t, got)
		assertBaseModels(t, got)
		if got.Source != "model_id" || got.Confidence != "low" || got.Distilled == nil || !*got.Distilled {
			t.Fatalf("merge-marked exact lineage retained curated claims: %+v", got)
		}
	})

	t.Run("merge-marked exact lineage with one parent", func(t *testing.T) {
		got := resolveLocalModelProvenance(
			LocalModelInfo{ID: "community/DeepSeek-R1-Distill-Qwen-7B-Merged"},
			modelProvenanceHints{
				BaseModels: []string{"meta-llama/Llama-3.1-8B"},
				Source:     "gguf_metadata",
			},
		)
		assertNoSingularIdentity(t, got)
		assertBaseModels(t, got, "meta-llama/Llama-3.1-8B")
		if got.Source != "gguf_metadata" || got.Confidence != "medium" {
			t.Fatalf("single-parent merge evidence source/confidence = %q/%q", got.Source, got.Confidence)
		}
	})

	t.Run("ordinary quantized exact lineage remains exact", func(t *testing.T) {
		got := resolveLocalModelProvenance(
			LocalModelInfo{ID: "community/DeepSeek-R1-Distill-Qwen-7B-GGUF-Q4_K_M.gguf"},
			modelProvenanceHints{},
		)
		if got == nil || got.Publisher != "Alibaba Cloud" || got.CountryCode != "CN" ||
			got.RootModel != "Qwen/Qwen2.5-Math-7B" || got.Source != "catalog_exact" ||
			got.Confidence != "high" || got.Derivation != "distilled+quantized" ||
			got.Quantization != "Q4_K_M" {
			t.Fatalf("ordinary quantized derivative lost exact lineage: %+v", got)
		}
	})
}

func TestResolveLocalModelProvenanceKeepsCuratedLineageParents(t *testing.T) {
	got := resolveLocalModelProvenance(
		LocalModelInfo{ID: "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B"},
		modelProvenanceHints{
			BaseModels: []string{"meta-llama/Llama-3.1-8B"},
			Source:     "gguf_metadata",
		},
	)
	if got == nil {
		t.Fatal("resolver returned nil")
	}
	if got.RootModel != "Qwen/Qwen2.5-Math-7B" || got.Publisher != "Alibaba Cloud" ||
		len(got.BaseModels) != 1 || got.BaseModels[0] != "Qwen/Qwen2.5-Math-7B" {
		t.Fatalf("local hints replaced curated lineage: %+v", got)
	}
}

func TestSplitModelReferenceHandlesOnlyUnambiguousRepositories(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		owner     string
		model     string
	}{
		{name: "repo id", reference: "Qwen/Qwen3-4B", owner: "Qwen", model: "Qwen3-4B"},
		{name: "Hub URL", reference: "https://huggingface.co/meta-llama/Llama-3.1-8B/tree/main", owner: "meta-llama", model: "Llama-3.1-8B"},
		{name: "Hub cache", reference: "/cache/hub/models--Qwen--Qwen3-4B/snapshots/deadbeef/model.safetensors", owner: "Qwen", model: "Qwen3-4B"},
		{name: "arbitrary path", reference: "/private/owner/repository/model.gguf", model: "model.gguf"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			owner, model := splitModelReference(tc.reference)
			if owner != tc.owner || model != tc.model {
				t.Fatalf("splitModelReference(%q) = %q/%q, want %q/%q", tc.reference, owner, model, tc.owner, tc.model)
			}
		})
	}
}

func TestResolveLocalModelProvenanceDoesNotInventRootForMerge(t *testing.T) {
	got := resolveLocalModelProvenance(LocalModelInfo{ID: "local-merge"}, modelProvenanceHints{
		BaseModels: []string{"Qwen/Qwen3-4B", "meta-llama/Llama-3.2-3B"},
		Source:     "gguf_metadata",
	})
	if got == nil || len(got.BaseModels) != 2 {
		t.Fatalf("merge parents were not preserved: %+v", got)
	}
	if got.RootModel != "" || got.Publisher != "" || got.CountryCode != "" {
		t.Fatalf("multi-root merge received an invented single origin: %+v", got)
	}
}

func TestReadGGUFProvenanceHintsRecoversRenamedModel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "renamed.gguf")
	writeTestGGUF(t, path, map[string]any{
		"tokenizer.chat_template":           strings.Repeat("x", maxGGUFMetadataStringBytes+1),
		"general.name":                      "unhelpful-local-name",
		"general.organization":              "Community Quantizer",
		"general.quantized_by":              "someone",
		"general.quantization_version":      uint32(2),
		"general.file_type":                 uint32(15),
		"general.base_model.count":          uint32(1),
		"general.base_model.0.name":         "Llama-3.2-3B-Instruct",
		"general.base_model.0.organization": "Meta",
		"general.base_model.0.repo_url":     "https://huggingface.co/meta-llama/Llama-3.2-3B-Instruct",
	})
	hints, err := readGGUFProvenanceHints(path)
	if err != nil {
		t.Fatalf("readGGUFProvenanceHints: %v", err)
	}
	if hints.Source != "gguf_metadata" || hints.Quantization != "Q4_K_M" || hints.Quantized == nil || !*hints.Quantized {
		t.Fatalf("GGUF hints = %+v", hints)
	}
	if len(hints.HuggingFaceRepoIDs) != 1 || hints.HuggingFaceRepoIDs[0] != "meta-llama/Llama-3.2-3B-Instruct" {
		t.Fatalf("GGUF trusted Hub IDs = %v", hints.HuggingFaceRepoIDs)
	}
	got := resolveLocalModelProvenance(LocalModelInfo{ID: "renamed", Format: "gguf"}, hints)
	if got == nil || got.Publisher != "Meta" || got.CountryCode != "US" || got.RootModel != "meta-llama/Llama-3.2-3B-Instruct" {
		t.Fatalf("renamed GGUF provenance = %+v", got)
	}
}

func TestReadGGUFProvenanceHintsRejectsPathologicalHeader(t *testing.T) {
	var raw bytes.Buffer
	raw.WriteString("GGUF")
	_ = binary.Write(&raw, binary.LittleEndian, uint32(3))
	_ = binary.Write(&raw, binary.LittleEndian, uint64(0))
	_ = binary.Write(&raw, binary.LittleEndian, uint64(maxGGUFMetadataPairs+1))
	path := filepath.Join(t.TempDir(), "bad.gguf")
	if err := os.WriteFile(path, raw.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readGGUFProvenanceHints(path); err == nil {
		t.Fatal("pathological GGUF metadata count was accepted")
	}
}

func TestModelConfigProvenanceHintsRecoversRenamedSafetensors(t *testing.T) {
	dir := t.TempDir()
	config := `{"_name_or_path":"private/local-copy","base_model_name_or_path":"Qwen/Qwen3-4B","quantization_config":{"quant_method":"awq","bits":4}}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	hints, ok := readModelConfigProvenanceHints(dir)
	if !ok {
		t.Fatal("config hints not detected")
	}
	if len(hints.HuggingFaceRepoIDs) != 0 {
		t.Fatalf("relative config paths became outbound Hub IDs: %v", hints.HuggingFaceRepoIDs)
	}
	got := resolveLocalModelProvenance(LocalModelInfo{ID: "renamed", Format: "safetensors"}, hints)
	if got == nil || got.Publisher != "Alibaba Cloud" || got.CountryCode != "CN" || got.RootModel != "Qwen/Qwen3-4B" ||
		got.Quantized == nil || !*got.Quantized || got.Quantization != "AWQ-4BIT" {
		t.Fatalf("config provenance = %+v", got)
	}
}

func TestModelConfigProvenanceAllowsOnlyExplicitHubURLOnline(t *testing.T) {
	dir := t.TempDir()
	config := `{"base_model_name_or_path":"https://huggingface.co/Qwen/Qwen3-4B"}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	hints, ok := readModelConfigProvenanceHints(dir)
	if !ok || len(hints.HuggingFaceRepoIDs) != 1 || hints.HuggingFaceRepoIDs[0] != "Qwen/Qwen3-4B" {
		t.Fatalf("explicit Hub URL IDs = %v, detected=%v", hints.HuggingFaceRepoIDs, ok)
	}
}

func writeTestGGUF(t *testing.T, path string, metadata map[string]any) {
	t.Helper()
	var raw bytes.Buffer
	raw.WriteString("GGUF")
	_ = binary.Write(&raw, binary.LittleEndian, uint32(3))
	_ = binary.Write(&raw, binary.LittleEndian, uint64(0))
	_ = binary.Write(&raw, binary.LittleEndian, uint64(len(metadata)))
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		writeTestGGUFString(&raw, key)
		switch value := metadata[key].(type) {
		case string:
			_ = binary.Write(&raw, binary.LittleEndian, uint32(ggufTypeString))
			writeTestGGUFString(&raw, value)
		case uint32:
			_ = binary.Write(&raw, binary.LittleEndian, uint32(ggufTypeUint32))
			_ = binary.Write(&raw, binary.LittleEndian, value)
		default:
			t.Fatalf("unsupported test GGUF value %T", value)
		}
	}
	// A real model is much larger than the metadata budget. Padding proves the
	// prefix reader does not reject a valid large artifact based on total size.
	raw.Write(bytes.Repeat([]byte{0}, int(maxGGUFMetadataPrefixBytes)))
	if err := os.WriteFile(path, raw.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTestGGUFString(raw *bytes.Buffer, value string) {
	_ = binary.Write(raw, binary.LittleEndian, uint64(len(value)))
	raw.WriteString(value)
}

func assertOptionalBool(t *testing.T, label string, got, want *bool) {
	t.Helper()
	if (got == nil) != (want == nil) || (got != nil && *got != *want) {
		t.Fatalf("%s = %v, want %v", label, optionalBoolString(got), optionalBoolString(want))
	}
}

func optionalBoolString(value *bool) string {
	if value == nil {
		return "unknown"
	}
	return strings.ToLower(strconv.FormatBool(*value))
}
