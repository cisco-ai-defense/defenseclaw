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

package catalog

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/inventory"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestSharedCatalogIsBuiltFromTheOneSignatureSet is the "one catalog, not two"
// contract: adding a provider to ai_signatures.json must make it visible to the
// runtime planes without a second edit here.
func TestSharedCatalogIsBuiltFromTheOneSignatureSet(t *testing.T) {
	t.Parallel()
	shared, err := Shared()
	if err != nil {
		t.Fatalf("Shared(): %v", err)
	}
	for _, hostname := range []string{"api.openai.com", "api.anthropic.com"} {
		provider, ok := shared.Lookup(hostname)
		if !ok {
			t.Fatalf("Lookup(%q) missed; the shared signature catalog declares it", hostname)
		}
		if provider.ID == "" || provider.Category == "" {
			t.Fatalf("Lookup(%q) = %+v, want an id and a category", hostname, provider)
		}
	}
}

func TestLongestSuffixWins(t *testing.T) {
	t.Parallel()
	catalog := FromSignatures([]inventory.AISignature{
		{ID: "broad", Name: "Broad", Vendor: "Example", DomainPatterns: []string{"example.com"}},
		{ID: "narrow", Name: "Narrow", Vendor: "OpenAI", DomainPatterns: []string{"ai.example.com"}},
	})
	provider, ok := catalog.Lookup("api.ai.example.com")
	if !ok {
		t.Fatal("Lookup missed a suffix match")
	}
	if provider.ID != "narrow" {
		t.Fatalf("Lookup matched %q, want the longer suffix %q", provider.ID, "narrow")
	}
}

// TestAggregatorIsPricedLikeFrontier pins that a router is not the cheap way
// around the control.
func TestAggregatorIsPricedLikeFrontier(t *testing.T) {
	t.Parallel()
	if CategoryAggregator.Weight() != CategoryFrontier.Weight() {
		t.Fatalf("aggregator %d != frontier %d; reaching a router is reaching whatever it fronts",
			CategoryAggregator.Weight(), CategoryFrontier.Weight())
	}
}

// TestUnknownCategoryIsNotPricedAsSafe pins that a category this build does
// not recognise is not evidence that reaching it is fine.
func TestUnknownCategoryIsNotPricedAsSafe(t *testing.T) {
	t.Parallel()
	if got := Category("invented-later").Weight(); got != CategoryUnknownProvider.Weight() {
		t.Fatalf("unrecognised category priced at %d, want the unknown-provider weight %d",
			got, CategoryUnknownProvider.Weight())
	}
	if CategoryUnknownProvider.Weight() == 0 {
		t.Fatal("an unknown provider is priced at zero")
	}
}

func TestModelHubClearsTheReportingFloorAlone(t *testing.T) {
	t.Parallel()
	// Pulling open weights onto a corporate endpoint is the setup for local
	// shadow inference, so it must not need corroboration to surface.
	// Bound to the real default rather than a restated 30: if the floor
	// moves, this must follow it, not keep asserting a number that no longer
	// governs anything.
	if CategoryModelHub.Weight() < config.DefaultRuntimeMinRiskToReport {
		t.Fatalf("model hub priced at %d, below the %d reporting floor",
			CategoryModelHub.Weight(), config.DefaultRuntimeMinRiskToReport)
	}
}

func TestConsumerChatIsSeparatedFromItsVendorAPI(t *testing.T) {
	t.Parallel()
	catalog := FromSignatures([]inventory.AISignature{{
		ID: "codex", Name: "Codex", Vendor: "OpenAI",
		DomainPatterns: []string{"api.openai.com", "chatgpt.com"},
	}})
	api, _ := catalog.Lookup("api.openai.com")
	chat, _ := catalog.Lookup("chatgpt.com")
	if api.Category != CategoryFrontier {
		t.Errorf("api.openai.com = %s, want %s", api.Category, CategoryFrontier)
	}
	if chat.Category != CategoryConsumerChat {
		t.Errorf("chatgpt.com = %s, want %s", chat.Category, CategoryConsumerChat)
	}
}

func TestInferenceShapedRecognisesUncatalogedEndpoints(t *testing.T) {
	t.Parallel()
	for _, hostname := range []string{
		"llm-gateway.internal.corp",
		"api.someai.example",
		"inference.acme.test",
		"my-openai-proxy.example.net",
		"models.chat.example",
	} {
		if !InferenceShaped(hostname) {
			t.Errorf("InferenceShaped(%q) = false, want true", hostname)
		}
	}
	for _, hostname := range []string{
		"api.github.com", "www.example.com", "cdn.jsdelivr.net", "", "   ",
	} {
		if InferenceShaped(hostname) {
			t.Errorf("InferenceShaped(%q) = true, want false", hostname)
		}
	}
}

func TestNormalizeDomainHandlesCatalogWriteStyles(t *testing.T) {
	t.Parallel()
	catalog := FromSignatures([]inventory.AISignature{{
		ID: "x", Name: "X", Vendor: "Anthropic",
		DomainPatterns: []string{"*.anthropic.com", "https://api.example.com/v1", "TRAILING.dot.com."},
	}})
	for _, hostname := range []string{"anthropic.com", "api.example.com", "trailing.dot.com"} {
		if _, ok := catalog.Lookup(hostname); !ok {
			t.Errorf("Lookup(%q) missed after normalization", hostname)
		}
	}
}

// TestFirstWriterWinsForADomain pins that a later signature cannot silently
// reclassify a domain an earlier one owns, which is what keeps an operator's
// custom pack from downgrading a bundled provider.
func TestFirstWriterWinsForADomain(t *testing.T) {
	t.Parallel()
	catalog := FromSignatures([]inventory.AISignature{
		{ID: "first", Name: "First", Vendor: "Anthropic", DomainPatterns: []string{"shared.example"}},
		{ID: "second", Name: "Second", Vendor: "Cursor", DomainPatterns: []string{"shared.example"}},
	})
	provider, _ := catalog.Lookup("shared.example")
	if provider.ID != "first" || provider.Category != CategoryFrontier {
		t.Fatalf("Lookup = %+v, want the first writer's frontier classification", provider)
	}
}
