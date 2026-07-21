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

package inventory

import (
	"strings"
	"testing"
)

func TestModelProvenanceCatalogHasReviewedPublisherCoverage(t *testing.T) {
	catalog, err := loadModelProvenanceCatalog()
	if err != nil {
		t.Fatalf("loadModelProvenanceCatalog: %v", err)
	}
	byID := make(map[string]modelPublisherRule, len(catalog.Publishers))
	for _, rule := range catalog.Publishers {
		byID[rule.ID] = rule
	}

	tests := []struct {
		id                 string
		publisher          string
		country            string
		canonicalNamespace string
		namespaces         []string
		familyTokens       []string
	}{
		{id: "alibaba-nlp", publisher: "Alibaba Cloud", country: "CN", canonicalNamespace: "Alibaba-NLP", namespaces: []string{"Alibaba-NLP"}, familyTokens: []string{"gte"}},
		{id: "alibaba-wan", publisher: "Alibaba Cloud", country: "CN", canonicalNamespace: "Wan-AI", namespaces: []string{"Wan-AI"}, familyTokens: []string{"wan2"}},
		{id: "alibaba-tongyi-mai", publisher: "Alibaba Cloud", country: "CN", canonicalNamespace: "Tongyi-MAI", namespaces: []string{"Tongyi-MAI"}, familyTokens: []string{"z-image"}},
		{id: "openai", publisher: "OpenAI", country: "US", canonicalNamespace: "openai", familyTokens: []string{"gpt-oss", "gpt2", "whisper", "clip-vit"}},
		{id: "baai", publisher: "Beijing Academy of Artificial Intelligence", country: "CN", canonicalNamespace: "BAAI", familyTokens: []string{"bge"}},
		{id: "amazon", publisher: "Amazon", country: "US", canonicalNamespace: "amazon", familyTokens: []string{"chronos"}},
		{id: "nomic-ai", publisher: "Nomic AI", country: "US", canonicalNamespace: "nomic-ai", familyTokens: []string{"nomic-embed", "nomic-bert"}},
		{id: "jina-ai", publisher: "Jina AI", country: "DE", canonicalNamespace: "jinaai", familyTokens: []string{"jina-embeddings", "jina-reranker"}},
		{id: "mixedbread-ai", publisher: "Mixedbread AI", country: "DE", canonicalNamespace: "mixedbread-ai", familyTokens: []string{"mxbai"}},
		{id: "snowflake", publisher: "Snowflake", country: "US", canonicalNamespace: "Snowflake", familyTokens: []string{"snowflake-arctic", "arctic-embed"}},
		{id: "zai", publisher: "Z.ai", country: "CN", canonicalNamespace: "zai-org", familyTokens: []string{"glm-", "glm-ocr", "chatglm"}},
		{id: "01-ai", publisher: "01.AI", country: "CN", canonicalNamespace: "01-ai", familyTokens: []string{"yi-"}},
		{id: "xiaomi-mimo", publisher: "Xiaomi", country: "CN", canonicalNamespace: "XiaomiMiMo", familyTokens: []string{"mimo"}},
		{id: "minimax", publisher: "MiniMax", country: "CN", canonicalNamespace: "MiniMaxAI", familyTokens: []string{"minimax"}},
		{id: "stepfun", publisher: "StepFun", country: "CN", canonicalNamespace: "stepfun-ai", familyTokens: []string{"step-3", "step3", "step-audio"}},
		{id: "poolside", publisher: "Poolside", country: "US", canonicalNamespace: "poolside", familyTokens: []string{"laguna"}},
		{id: "moonshot-ai", publisher: "Moonshot AI", country: "CN", canonicalNamespace: "moonshotai", familyTokens: []string{"kimi"}},
		{id: "inclusion-ai", publisher: "InclusionAI", country: "CN", canonicalNamespace: "inclusionAI", familyTokens: []string{"ling-lite", "ring-2", "ming-omni"}},
		{id: "tencent", publisher: "Tencent", country: "CN", canonicalNamespace: "tencent", familyTokens: []string{"hunyuan", "hunyuanvideo"}},
		{id: "baidu", publisher: "Baidu", country: "CN", canonicalNamespace: "baidu", familyTokens: []string{"ernie", "paddleocr"}},
		{id: "pyannote", publisher: "pyannoteAI", country: "FR", canonicalNamespace: "pyannote", familyTokens: []string{"speaker-diarization"}},
		{id: "kyutai", publisher: "Kyutai", country: "FR", canonicalNamespace: "kyutai", familyTokens: []string{"moshi"}},
		{id: "resemble-ai", publisher: "Resemble AI", country: "CA", canonicalNamespace: "ResembleAI", familyTokens: []string{"chatterbox"}},
		{id: "huggingface-smol", publisher: "Hugging Face", country: "US", canonicalNamespace: "HuggingFaceTB", familyTokens: []string{"smollm", "smolvlm"}},
		{id: "huggingface-distil", publisher: "Hugging Face", country: "US", canonicalNamespace: "distilbert", familyTokens: []string{"distilbert", "distilgpt2", "distilroberta"}},
		{id: "eleutherai", publisher: "EleutherAI", country: "US", canonicalNamespace: "EleutherAI", familyTokens: []string{"pythia", "gpt-neox", "gpt-neo", "gpt-j"}},
		{id: "allenai", publisher: "Allen Institute for AI", country: "US", canonicalNamespace: "allenai", familyTokens: []string{"olmo", "tulu", "molmo"}},
		{id: "openbmb", publisher: "OpenBMB", country: "CN", canonicalNamespace: "openbmb", familyTokens: []string{"minicpm", "voxcpm"}},
		{id: "meta-llama", publisher: "Meta", country: "US", canonicalNamespace: "meta-llama", namespaces: []string{"FacebookAI"}, familyTokens: []string{"opt", "roberta", "xlm-roberta", "wav2vec", "hubert", "encodec", "contriever", "seamless-m4t"}},
		{id: "google", publisher: "Google", country: "US", canonicalNamespace: "google", namespaces: []string{"google-bert", "google-t5"}, familyTokens: []string{"bert", "electra", "t5", "flan-t5", "vit", "siglip", "paligemma", "embeddinggemma"}},
		{id: "microsoft", publisher: "Microsoft", country: "US", canonicalNamespace: "microsoft", familyTokens: []string{"mpnet", "e5", "deberta", "wavlm", "speecht5", "florence", "layoutlm", "bitnet"}},
		{id: "cohere", publisher: "Cohere", country: "CA", canonicalNamespace: "CohereForAI", namespaces: []string{"CohereLabs"}, familyTokens: []string{"north-mini"}},
		{id: "nvidia", publisher: "NVIDIA", country: "US", canonicalNamespace: "nvidia", familyTokens: []string{"parakeet", "canary", "cosmos"}},
	}

	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			rule, ok := byID[tc.id]
			if !ok {
				t.Fatalf("reviewed publisher rule %q is missing", tc.id)
			}
			if rule.Publisher != tc.publisher || rule.CountryCode != tc.country || rule.CanonicalNamespace != tc.canonicalNamespace {
				t.Fatalf("publisher rule %q = %+v", tc.id, rule)
			}
			for _, namespace := range tc.namespaces {
				if !catalogCoverageContainsFold(rule.Namespaces, namespace) {
					t.Errorf("publisher rule %q is missing namespace %q: %v", tc.id, namespace, rule.Namespaces)
				}
			}
			for _, token := range tc.familyTokens {
				if !catalogCoverageContainsFold(rule.FamilyTokens, token) {
					t.Errorf("publisher rule %q is missing family token %q: %v", tc.id, token, rule.FamilyTokens)
				}
			}
		})
	}
}

func TestModelProvenanceCatalogResolvesPopularOfficialModels(t *testing.T) {
	tests := []struct {
		id        string
		publisher string
		country   string
		root      string
	}{
		{id: "openai/gpt-oss-20b", publisher: "OpenAI", country: "US", root: "openai/gpt-oss-20b"},
		{id: "BAAI/bge-m3", publisher: "Beijing Academy of Artificial Intelligence", country: "CN", root: "BAAI/bge-m3"},
		{id: "amazon/chronos-2", publisher: "Amazon", country: "US", root: "amazon/chronos-2"},
		{id: "nomic-ai/nomic-embed-text-v1.5", publisher: "Nomic AI", country: "US", root: "nomic-ai/nomic-embed-text-v1.5"},
		{id: "jinaai/jina-embeddings-v3", publisher: "Jina AI", country: "DE", root: "jinaai/jina-embeddings-v3"},
		{id: "mixedbread-ai/mxbai-embed-large-v1", publisher: "Mixedbread AI", country: "DE", root: "mixedbread-ai/mxbai-embed-large-v1"},
		{id: "Snowflake/snowflake-arctic-embed-m-v1.5", publisher: "Snowflake", country: "US", root: "Snowflake/snowflake-arctic-embed-m-v1.5"},
		{id: "zai-org/GLM-5.2", publisher: "Z.ai", country: "CN", root: "zai-org/GLM-5.2"},
		{id: "01-ai/Yi-1.5-34B", publisher: "01.AI", country: "CN", root: "01-ai/Yi-1.5-34B"},
		{id: "dphn/dolphin-2.9.1-yi-1.5-34b", publisher: "01.AI", country: "CN", root: "01-ai/Yi-1.5-34B"},
		{id: "XiaomiMiMo/MiMo-V2.5", publisher: "Xiaomi", country: "CN", root: "XiaomiMiMo/MiMo-V2.5"},
		{id: "MiniMaxAI/MiniMax-M2.7", publisher: "MiniMax", country: "CN", root: "MiniMaxAI/MiniMax-M2.7"},
		{id: "stepfun-ai/Step-3.7-Flash", publisher: "StepFun", country: "CN", root: "stepfun-ai/Step-3.7-Flash"},
		{id: "poolside/Laguna-XS.2", publisher: "Poolside", country: "US", root: "poolside/Laguna-XS.2"},
		{id: "moonshotai/Kimi-K2.6", publisher: "Moonshot AI", country: "CN", root: "moonshotai/Kimi-K2.6"},
		{id: "inclusionAI/Ring-2.5-1T", publisher: "InclusionAI", country: "CN", root: "inclusionAI/Ring-2.5-1T"},
		{id: "tencent/HunyuanOCR", publisher: "Tencent", country: "CN", root: "tencent/HunyuanOCR"},
		{id: "baidu/Unlimited-OCR", publisher: "Baidu", country: "CN", root: "baidu/Unlimited-OCR"},
		{id: "pyannote/speaker-diarization-community-1", publisher: "pyannoteAI", country: "FR", root: "pyannote/speaker-diarization-community-1"},
		{id: "kyutai/moshi", publisher: "Kyutai", country: "FR", root: "kyutai/moshi"},
		{id: "ResembleAI/chatterbox", publisher: "Resemble AI", country: "CA", root: "ResembleAI/chatterbox"},
		{id: "Alibaba-NLP/gte-multilingual-base", publisher: "Alibaba Cloud", country: "CN", root: "Alibaba-NLP/gte-multilingual-base"},
		{id: "Wan-AI/Wan2.2-T2V-A14B", publisher: "Alibaba Cloud", country: "CN", root: "Wan-AI/Wan2.2-T2V-A14B"},
		{id: "Tongyi-MAI/Z-Image-Turbo", publisher: "Alibaba Cloud", country: "CN", root: "Tongyi-MAI/Z-Image-Turbo"},
		{id: "HuggingFaceTB/SmolLM3-3B", publisher: "Hugging Face", country: "US", root: "HuggingFaceTB/SmolLM3-3B"},
		{id: "distilbert/distilbert-base-uncased", publisher: "Hugging Face", country: "US", root: "distilbert/distilbert-base-uncased"},
		{id: "EleutherAI/pythia-160m", publisher: "EleutherAI", country: "US", root: "EleutherAI/pythia-160m"},
		{id: "allenai/OLMo-2-0425-1B", publisher: "Allen Institute for AI", country: "US", root: "allenai/OLMo-2-0425-1B"},
		{id: "openbmb/MiniCPM-V-4.6", publisher: "OpenBMB", country: "CN", root: "openbmb/MiniCPM-V-4.6"},
		{id: "FacebookAI/roberta-base", publisher: "Meta", country: "US", root: "FacebookAI/roberta-base"},
		{id: "google-bert/bert-base-uncased", publisher: "Google", country: "US", root: "google-bert/bert-base-uncased"},
		{id: "google-t5/t5-small", publisher: "Google", country: "US", root: "google-t5/t5-small"},
		{id: "microsoft/deberta-v3-base", publisher: "Microsoft", country: "US", root: "microsoft/deberta-v3-base"},
		{id: "CohereLabs/North-Mini-Code-1.0", publisher: "Cohere", country: "CA", root: "CohereLabs/North-Mini-Code-1.0"},
		{id: "nvidia/parakeet-tdt-0.6b-v3", publisher: "NVIDIA", country: "US", root: "nvidia/parakeet-tdt-0.6b-v3"},
	}

	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			got := resolveLocalModelProvenance(
				LocalModelInfo{ID: tc.id, Provider: "huggingface"},
				modelProvenanceHints{},
			)
			if got == nil {
				t.Fatal("resolver returned nil")
			}
			if got.Publisher != tc.publisher || got.CountryCode != tc.country || got.RootModel != tc.root {
				t.Fatalf("provenance = %+v", got)
			}
			if got.Confidence != "high" {
				t.Fatalf("official Hub model confidence = %q, want high", got.Confidence)
			}
		})
	}
}

func TestModelProvenanceCatalogResolvesPopularFamilyConversions(t *testing.T) {
	tests := []struct {
		id        string
		publisher string
		country   string
		root      string
	}{
		{id: "nvidia/MiniMax-M2.5-NVFP4", publisher: "MiniMax", country: "CN", root: "MiniMaxAI/MiniMax-M2.5"},
		{id: "community/Yi-1.5-9B-Chat-GGUF", publisher: "01.AI", country: "CN", root: "01-ai/Yi-1.5-9B-Chat"},
		{id: "community/mxbai-embed-large-v1-GGUF", publisher: "Mixedbread AI", country: "DE", root: "mixedbread-ai/mxbai-embed-large-v1"},
		{id: "z-ai/glm-5.2", publisher: "Z.ai", country: "CN", root: "zai-org/glm-5.2"},
		{id: "minimax/minimax-m2.7", publisher: "MiniMax", country: "CN", root: "MiniMaxAI/minimax-m2.7"},
		{id: "openrouter/Step-3.5-Flash", publisher: "StepFun", country: "CN", root: "stepfun-ai/Step-3.5-Flash"},
		{id: "community/MiMo-V2-Flash-GGUF", publisher: "Xiaomi", country: "CN", root: "XiaomiMiMo/MiMo-V2-Flash"},
		{id: "community/Ring-2.5-1T-GGUF", publisher: "InclusionAI", country: "CN", root: "inclusionAI/Ring-2.5-1T"},
		{id: "community/SmolLM2-1.7B-GGUF", publisher: "Hugging Face", country: "US", root: "HuggingFaceTB/SmolLM2-1.7B"},
		{id: "community/distilgpt2-GGUF", publisher: "Hugging Face", country: "US", root: "distilbert/distilgpt2"},
		{id: "community/OLMo-2-7B-GGUF", publisher: "Allen Institute for AI", country: "US", root: "allenai/OLMo-2-7B"},
		{id: "community/Wan2.2-T2V-A14B-GGUF", publisher: "Alibaba Cloud", country: "CN", root: "Wan-AI/Wan2.2-T2V-A14B"},
	}

	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			got := resolveLocalModelProvenance(LocalModelInfo{ID: tc.id}, modelProvenanceHints{})
			if got == nil {
				t.Fatal("resolver returned nil")
			}
			if got.Publisher != tc.publisher || got.CountryCode != tc.country || got.RootModel != tc.root {
				t.Fatalf("provenance = %+v", got)
			}
			if got.Confidence != "medium" {
				t.Fatalf("family conversion confidence = %q, want medium", got.Confidence)
			}
		})
	}
}

func TestModelProvenanceCatalogRejectsLookalikesAndFamilyCollisions(t *testing.T) {
	for _, id := range []string{
		"community/nomic-bert-gpt2-merge",
		"community/mxbai-bert-merge",
		"community/dolphin-yi-1.5-qwen-merge",
		"community/qwen-bert-merge",
		"community/opt-t5-merge",
		"mimosa-7b",
		"minimaximum-7b",
		"stepping-stone",
		"spring-lite",
		"bertology",
		"whispering-model",
		"north-minimum",
		"mxbait-model",
		"yippee-model",
		"TinyLlama/TinyLlama-1.1B-Chat-v1.0",
	} {
		if got := resolveLocalModelProvenance(LocalModelInfo{ID: id}, modelProvenanceHints{}); got != nil {
			t.Errorf("ambiguous/lookalike model %q received provenance: %+v", id, got)
		}
	}

	got := resolveLocalModelProvenance(
		LocalModelInfo{ID: "nomic-ai/nomic-bert-2048", Provider: "huggingface"},
		modelProvenanceHints{},
	)
	if got == nil || got.Publisher != "Nomic AI" || got.CountryCode != "US" || got.RootModel != "nomic-ai/nomic-bert-2048" {
		t.Fatalf("exact publisher namespace did not resolve its overlapping family: %+v", got)
	}
}

func TestModelProvenanceCatalogDeepSeek0528QwenLineage(t *testing.T) {
	catalog, err := loadModelProvenanceCatalog()
	if err != nil {
		t.Fatalf("loadModelProvenanceCatalog: %v", err)
	}
	found := false
	for _, lineage := range catalog.Lineages {
		if lineage.ID != "deepseek-r1-0528-qwen3-8b" {
			continue
		}
		found = true
		if lineage.RootModel != "Qwen/Qwen3-8B" || len(lineage.BaseModels) != 1 ||
			lineage.BaseModels[0] != "Qwen/Qwen3-8B" || !lineage.Distilled {
			t.Fatalf("lineage = %+v", lineage)
		}
	}
	if !found {
		t.Fatal("reviewed DeepSeek-R1-0528-Qwen3-8B lineage is missing")
	}

	got := resolveLocalModelProvenance(
		LocalModelInfo{ID: "deepseek-ai/DeepSeek-R1-0528-Qwen3-8B"},
		modelProvenanceHints{},
	)
	if got == nil {
		t.Fatal("resolver returned nil")
	}
	if got.Publisher != "Alibaba Cloud" || got.CountryCode != "CN" || got.RootModel != "Qwen/Qwen3-8B" ||
		len(got.BaseModels) != 1 || got.BaseModels[0] != "Qwen/Qwen3-8B" || got.Distilled == nil || !*got.Distilled ||
		got.Confidence != "high" || got.Source != "catalog_exact" {
		t.Fatalf("provenance = %+v", got)
	}
}

func TestModelProvenanceCatalogDolphinYiLineage(t *testing.T) {
	catalog, err := loadModelProvenanceCatalog()
	if err != nil {
		t.Fatalf("loadModelProvenanceCatalog: %v", err)
	}
	found := false
	for _, lineage := range catalog.Lineages {
		if lineage.ID != "dolphin-2.9.1-yi-1.5-34b" {
			continue
		}
		found = true
		if lineage.RootModel != "01-ai/Yi-1.5-34B" || len(lineage.BaseModels) != 1 ||
			lineage.BaseModels[0] != "01-ai/Yi-1.5-34B" || lineage.Distilled {
			t.Fatalf("lineage = %+v", lineage)
		}
	}
	if !found {
		t.Fatal("reviewed Dolphin Yi lineage is missing")
	}

	got := resolveLocalModelProvenance(
		LocalModelInfo{ID: "dphn/dolphin-2.9.1-yi-1.5-34b", Provider: "huggingface"},
		modelProvenanceHints{},
	)
	if got == nil {
		t.Fatal("resolver returned nil")
	}
	if got.Publisher != "01.AI" || got.CountryCode != "CN" || got.RootModel != "01-ai/Yi-1.5-34B" ||
		len(got.BaseModels) != 1 || got.BaseModels[0] != "01-ai/Yi-1.5-34B" || got.Distilled != nil ||
		got.Confidence != "high" || got.Source != "catalog_exact" {
		t.Fatalf("provenance = %+v", got)
	}
}

func catalogCoverageContainsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}
