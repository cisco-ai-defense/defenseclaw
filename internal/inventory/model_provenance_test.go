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
	if len(catalog.Publishers) < 10 || len(catalog.Lineages) < 6 {
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
