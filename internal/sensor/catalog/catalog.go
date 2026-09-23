// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

// Package catalog classifies an egress peer into an AI provider and a risk
// category, and prices that category.
//
// # One catalog, not two
//
// The domain data comes from the shared signature catalog in
// internal/inventory -- the same ai_signatures.json the continuous scanner and
// the Python CLI both read, byte-identical in both trees. Adding a provider
// there makes it visible to inventory and to the runtime planes at once, which
// is the point of absorbing the two products.
//
// What this package adds on top is the risk classification, which is genuinely
// runtime-only: inventory records that a provider is configured, and does not
// need to price reaching it.
package catalog

import (
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// Category is the provider risk class an egress peer falls into.
type Category string

const (
	// CategoryFrontier is a first-party frontier model API.
	CategoryFrontier Category = "frontier"
	// CategoryAggregator is a multi-provider router. Reaching one is
	// equivalent to reaching whatever it fronts, so it is priced the same.
	CategoryAggregator Category = "aggregator"
	// CategoryCloudAI is a hyperscaler's managed model service.
	CategoryCloudAI Category = "cloud_ai"
	// CategoryConsumerChat is an end-user chat product rather than an API.
	CategoryConsumerChat Category = "consumer_chat"
	// CategoryCodingAssistant is an IDE-attached assistant backend.
	CategoryCodingAssistant Category = "coding_assistant"
	// CategoryAgentOps is agent tracing, evaluation, and orchestration.
	CategoryAgentOps Category = "agent_ops"
	// CategoryModelHub is a weights distribution host.
	CategoryModelHub Category = "model_hub"
	// CategoryUnknownProvider is an inference-shaped hostname the catalog does
	// not know.
	CategoryUnknownProvider Category = "unknown_ai_provider"
)

// categoryWeights prices each category.
//
// Frontier and aggregator are equal on purpose: reaching a router is reaching
// whatever it fronts, and pricing the router lower would make it the cheap way
// around the control.
var categoryWeights = map[Category]int{
	CategoryFrontier:        50,
	CategoryAggregator:      50,
	CategoryCloudAI:         35,
	CategoryConsumerChat:    30,
	CategoryCodingAssistant: 25,
	CategoryAgentOps:        25,
	// Pulling open weights onto a corporate endpoint is itself the setup for
	// local shadow inference, so it clears the default reporting threshold on
	// its own rather than needing corroboration.
	CategoryModelHub:        30,
	CategoryUnknownProvider: 30,
}

// Weight prices a category. An unrecognised category is priced as an unknown
// provider rather than as zero: a category this build does not know is not
// evidence that reaching it is safe.
func (c Category) Weight() int {
	if weight, ok := categoryWeights[c]; ok {
		return weight
	}
	return categoryWeights[CategoryUnknownProvider]
}

// vendorCategories classifies the vendors that appear in the shared signature
// catalog. Keyed by lower-cased vendor so a new signature for an existing
// vendor is priced without a change here.
var vendorCategories = map[string]Category{
	"anthropic":       CategoryFrontier,
	"openai":          CategoryFrontier,
	"google":          CategoryFrontier,
	"google deepmind": CategoryFrontier,
	"meta":            CategoryFrontier,
	"mistral ai":      CategoryFrontier,
	"mistral":         CategoryFrontier,
	"xai":             CategoryFrontier,
	"deepseek":        CategoryFrontier,
	"cohere":          CategoryFrontier,
	"alibaba cloud":   CategoryFrontier,

	"openrouter": CategoryAggregator,
	"litellm":    CategoryAggregator,
	"together":   CategoryAggregator,
	"fireworks":  CategoryAggregator,
	"groq":       CategoryAggregator,
	"replicate":  CategoryAggregator,
	"perplexity": CategoryAggregator,

	"amazon":              CategoryCloudAI,
	"amazon web services": CategoryCloudAI,
	"microsoft":           CategoryCloudAI,
	"azure":               CategoryCloudAI,
	"ibm":                 CategoryCloudAI,
	"nvidia":              CategoryCloudAI,

	"cursor":      CategoryCodingAssistant,
	"github":      CategoryCodingAssistant,
	"sourcegraph": CategoryCodingAssistant,
	"tabnine":     CategoryCodingAssistant,
	"codeium":     CategoryCodingAssistant,
	"windsurf":    CategoryCodingAssistant,
	"cognition":   CategoryCodingAssistant,

	"langchain":        CategoryAgentOps,
	"langsmith":        CategoryAgentOps,
	"weights & biases": CategoryAgentOps,
	"galileo":          CategoryAgentOps,
	"braintrust":       CategoryAgentOps,
	"helicone":         CategoryAgentOps,

	"hugging face": CategoryModelHub,
	"huggingface":  CategoryModelHub,
	"ollama":       CategoryModelHub,
	"lm studio":    CategoryModelHub,
	"modelscope":   CategoryModelHub,
}

// domainCategories classifies a handful of hosts whose vendor field in the
// shared catalog does not settle the category -- a consumer chat front end and
// its API sit under one vendor but are not the same risk.
var domainCategories = map[string]Category{
	"chatgpt.com":            CategoryConsumerChat,
	"chat.openai.com":        CategoryConsumerChat,
	"claude.ai":              CategoryConsumerChat,
	"gemini.google.com":      CategoryConsumerChat,
	"copilot.microsoft.com":  CategoryConsumerChat,
	"poe.com":                CategoryConsumerChat,
	"perplexity.ai":          CategoryConsumerChat,
	"huggingface.co":         CategoryModelHub,
	"cdn-lfs.huggingface.co": CategoryModelHub,
}

// Provider is a resolved egress peer.
type Provider struct {
	// ID is the signature id the domain came from, or "" for an unknown
	// inference-shaped host.
	ID string
	// DisplayName is what an operator reads.
	DisplayName string
	Vendor      string
	Category    Category
	// MatchedDomain is the catalog domain that matched, which is what makes
	// the classification auditable.
	MatchedDomain string
}

// Weight prices reaching this provider.
func (p Provider) Weight() int { return p.Category.Weight() }

// Catalog resolves hostnames to providers.
type Catalog struct {
	// exact maps a full domain to its provider.
	exact map[string]Provider
	// suffixes are the same entries, matched as ".example.com".
	suffixes []suffixEntry
}

type suffixEntry struct {
	suffix   string
	provider Provider
}

var (
	sharedOnce    sync.Once
	sharedCatalog *Catalog
	sharedErr     error
)

// Shared returns the process-wide catalog built from the embedded signature
// set. It is built once: the signature catalog is embedded and immutable for
// the life of the process.
func Shared() (*Catalog, error) {
	sharedOnce.Do(func() {
		signatures, err := inventory.LoadAISignatures()
		if err != nil {
			sharedErr = err
			return
		}
		sharedCatalog = FromSignatures(signatures)
	})
	return sharedCatalog, sharedErr
}

// FromSignatures builds a catalog from an explicit signature set, which is how
// an operator's custom pack reaches the runtime planes and how tests supply a
// fixture.
func FromSignatures(signatures []inventory.AISignature) *Catalog {
	catalog := &Catalog{exact: make(map[string]Provider, 128)}
	for _, signature := range signatures {
		for _, pattern := range signature.DomainPatterns {
			domain := normalizeDomain(pattern)
			if domain == "" {
				continue
			}
			provider := Provider{
				ID:            signature.ID,
				DisplayName:   signature.Name,
				Vendor:        signature.Vendor,
				Category:      classify(signature.Vendor, domain),
				MatchedDomain: domain,
			}
			// First writer wins so a later signature cannot silently reclassify
			// a domain an earlier one already owns.
			if _, exists := catalog.exact[domain]; !exists {
				catalog.exact[domain] = provider
				catalog.suffixes = append(catalog.suffixes, suffixEntry{suffix: "." + domain, provider: provider})
			}
		}
	}
	return catalog
}

func classify(vendor, domain string) Category {
	if category, ok := domainCategories[domain]; ok {
		return category
	}
	if category, ok := vendorCategories[strings.ToLower(strings.TrimSpace(vendor))]; ok {
		return category
	}
	return CategoryUnknownProvider
}

// Lookup resolves a hostname. The longest matching suffix wins, so
// api.anthropic.com resolves through anthropic.com rather than through a
// shorter unrelated entry.
func (c *Catalog) Lookup(hostname string) (Provider, bool) {
	domain := normalizeDomain(hostname)
	if domain == "" {
		return Provider{}, false
	}
	if provider, ok := c.exact[domain]; ok {
		return provider, true
	}
	best := Provider{}
	bestLen := 0
	for _, entry := range c.suffixes {
		if strings.HasSuffix(domain, entry.suffix) && len(entry.suffix) > bestLen {
			best, bestLen = entry.provider, len(entry.suffix)
		}
	}
	if bestLen == 0 {
		return Provider{}, false
	}
	return best, true
}

// inferenceShaped recognises a hostname that looks like an inference endpoint
// without being in the catalog. This is the unknown_provider_egress signal:
// evidence that something is talking to an AI API the catalog has never seen,
// which is more interesting than a known provider, not less.
var inferenceShapedPrefixes = []string{
	"api.", "inference.", "llm.", "ai.", "chat.", "models.", "model.",
	"completions.", "embeddings.", "generativelanguage.",
}

var inferenceShapedFragments = []string{
	"inference", "-llm", "llm-", ".llm.", "openai", "anthropic", "genai",
	"generativeai", "bedrock", "vertexai", "aiplatform",
}

// InferenceShaped reports whether a hostname looks like an AI endpoint the
// catalog does not know.
func InferenceShaped(hostname string) bool {
	domain := normalizeDomain(hostname)
	if domain == "" {
		return false
	}
	for _, fragment := range inferenceShapedFragments {
		if strings.Contains(domain, fragment) {
			return true
		}
	}
	for _, prefix := range inferenceShapedPrefixes {
		if strings.HasPrefix(domain, prefix) {
			// A bare "api." prefix is weak on its own; require the label to
			// also suggest a model service rather than any REST API.
			if strings.Contains(domain, "ai") || strings.Contains(domain, "model") ||
				strings.Contains(domain, "chat") || strings.Contains(domain, "llm") {
				return true
			}
		}
	}
	return false
}

// Unknown builds a provider for an inference-shaped host the catalog does not
// know. It is deliberately priced the same as a consumer chat service: an
// unrecognised AI endpoint is not evidence of safety.
func Unknown(hostname string) Provider {
	domain := normalizeDomain(hostname)
	return Provider{
		DisplayName:   domain,
		Category:      CategoryUnknownProvider,
		MatchedDomain: domain,
	}
}

func normalizeDomain(value string) string {
	domain := strings.ToLower(strings.TrimSpace(value))
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.TrimPrefix(domain, "*.")
	// A catalog entry may be written as a URL; keep only the host.
	if index := strings.Index(domain, "://"); index >= 0 {
		domain = domain[index+3:]
	}
	if index := strings.IndexAny(domain, "/:"); index >= 0 {
		domain = domain[:index]
	}
	return domain
}
