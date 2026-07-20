// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type huggingFaceRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn huggingFaceRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestCredibleHuggingFaceRepoIDRejectsAnonymousOrPathLikeValues(t *testing.T) {
	t.Parallel()
	valid := []string{
		"meta-llama/Llama-3.1-8B",
		"https://huggingface.co/Qwen/Qwen3-0.6B",
	}
	for _, value := range valid {
		if _, ok := credibleHuggingFaceRepoID(value); !ok {
			t.Errorf("credibleHuggingFaceRepoID(%q) rejected a repository id", value)
		}
	}
	invalid := []string{
		"renamed-model.gguf", "/private/model", "../secret/model", "owner/repo/file",
		"owner//repo", "owner/repo?revision=main", "owner/.hidden",
	}
	for _, value := range invalid {
		if got, ok := credibleHuggingFaceRepoID(value); ok {
			t.Errorf("credibleHuggingFaceRepoID(%q) = %q, want rejected", value, got)
		}
	}
}

func TestHuggingFaceRepoIDForModelUsesOnlyTrustedLocalIdentifiers(t *testing.T) {
	t.Parallel()
	privateFamilyGuess := LocalModelInfo{
		ID: "customer-secret-llama.gguf",
		Provenance: &LocalModelProvenance{
			Publisher: "Meta", CountryCode: "US",
			RootModel: "meta-llama/customer-secret-llama", Source: "catalog_family", Confidence: "medium",
		},
	}
	if got, ok := huggingFaceRepoIDForModel(privateFamilyGuess); ok {
		t.Fatalf("family-derived private filename became outbound repo %q", got)
	}
	localConfigPath := LocalModelInfo{
		ID: "renamed", Provenance: &LocalModelProvenance{
			RootModel: "checkpoints/customer-secret", BaseModels: []string{"checkpoints/customer-secret"},
			Source: "model_config", Confidence: "medium",
		},
	}
	if got, ok := huggingFaceRepoIDForModel(localConfigPath); ok {
		t.Fatalf("relative config path became outbound repo %q", got)
	}
	localMixed := localConfigPath
	localMixed.Provenance = &LocalModelProvenance{
		RootModel: "checkpoints/customer-secret", BaseModels: []string{"checkpoints/customer-secret"},
		Source: "mixed", Confidence: "medium",
	}
	if got, ok := huggingFaceRepoIDForModel(localMixed); ok {
		t.Fatalf("offline-only mixed provenance became outbound repo %q", got)
	}
	offlineSignal := []AISignal{{Model: &localMixed}}
	refreshHuggingFaceProvenanceHashes(offlineSignal)
	if offlineSignal[0].ModelProvenanceHubHash != "" {
		t.Fatalf("offline-only mixed provenance received Hub hash %q", offlineSignal[0].ModelProvenanceHubHash)
	}
	trusted := LocalModelInfo{ID: "renamed", huggingFaceRepoIDs: []string{"Qwen/Qwen3-0.6B"}}
	if got, ok := huggingFaceRepoIDForModel(trusted); !ok || got != "Qwen/Qwen3-0.6B" {
		t.Fatalf("trusted embedded repo = %q/%v", got, ok)
	}
}

func TestHuggingFaceResolverFollowsDeclaredBaseModelAndCaches(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if got := r.URL.Query()["expand[]"]; len(got) != 2 {
			t.Errorf("expand query = %v, want author + baseModels", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/models/TheBloke/Llama-2-7B-Chat-GGUF":
			fmt.Fprint(w, `{"id":"TheBloke/Llama-2-7B-Chat-GGUF","author":"TheBloke","baseModels":{"relation":"quantized","models":[{"id":"meta-llama/Llama-2-7b-chat-hf"}]}}`)
		case "/api/models/meta-llama/Llama-2-7b-chat-hf":
			fmt.Fprint(w, `{"id":"meta-llama/Llama-2-7b-chat-hf","author":"meta-llama"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	resolver, err := newHuggingFaceProvenanceResolverForTest(server.URL, server.Client())
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	model := LocalModelInfo{ID: "TheBloke/Llama-2-7B-Chat-GGUF", Provider: "huggingface"}
	for i := 0; i < 2; i++ {
		got := resolver.resolve(context.Background(), model)
		if got == nil {
			t.Fatal("resolver returned nil provenance")
		}
		if got.RootModel != "meta-llama/Llama-2-7b-chat-hf" || got.Publisher != "Meta" || got.CountryCode != "US" {
			t.Fatalf("resolved provenance = %+v", got)
		}
		if got.Quantized == nil || !*got.Quantized || got.Derivation != "quantized" {
			t.Fatalf("quantized relation was not retained: %+v", got)
		}
		if got.Source != "huggingface_hub" || got.Confidence != "high" {
			t.Fatalf("source/confidence = %q/%q", got.Source, got.Confidence)
		}
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("Hub requests = %d, want one current + one root lookup cached", got)
	}
}

func TestHuggingFaceResolverCanStartFromRenamedGGUFEmbeddedRoot(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/models/Qwen/Qwen3-0.6B" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"id":"Qwen/Qwen3-0.6B","author":"Qwen"}`)
	}))
	defer server.Close()
	resolver, err := newHuggingFaceProvenanceResolverForTest(server.URL, server.Client())
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	model := LocalModelInfo{
		ID:                 "fully-renamed.gguf",
		huggingFaceRepoIDs: []string{"Qwen/Qwen3-0.6B"},
		Provenance: &LocalModelProvenance{
			RootModel: "Qwen/Qwen3-0.6B", Source: "gguf_metadata", Confidence: "medium",
		},
	}
	got := resolver.resolve(context.Background(), model)
	if got == nil || got.RootModel != "Qwen/Qwen3-0.6B" || got.CountryCode != "CN" {
		t.Fatalf("renamed GGUF provenance = %+v", got)
	}
}

func TestHuggingFaceResolverKeepsDeclaredBaseWhenParentCardIsUnavailable(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/models/community/derived-GGUF":
			fmt.Fprint(w, `{"id":"community/derived-GGUF","author":"community","baseModels":{"relation":"quantized","models":[{"id":"meta-llama/Llama-3.1-8B"}]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	resolver, err := newHuggingFaceProvenanceResolverForTest(server.URL, server.Client())
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	got := resolver.resolve(context.Background(), LocalModelInfo{ID: "community/derived-GGUF", Provider: "huggingface"})
	if got == nil || got.RootModel != "meta-llama/Llama-3.1-8B" || got.CountryCode != "US" {
		t.Fatalf("declared unavailable parent was lost: %+v", got)
	}
	if got.Confidence != "medium" {
		t.Fatalf("unverified declared parent confidence = %q, want medium", got.Confidence)
	}
}

func TestHuggingFaceResolverTreatsParentServerFailureAsTransient(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/models/community/derived-GGUF":
			fmt.Fprint(w, `{"id":"community/derived-GGUF","baseModels":{"relation":"quantized","models":[{"id":"meta-llama/Llama-3.1-8B"}]}}`)
		default:
			http.Error(w, "temporary", http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	resolver, err := newHuggingFaceProvenanceResolverForTest(server.URL, server.Client())
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	got, outcome := resolver.resolveWithOutcome(
		context.Background(), LocalModelInfo{ID: "community/derived-GGUF", Provider: "huggingface"},
	)
	if got == nil || outcome != huggingFaceLookupTransientFailure {
		t.Fatalf("parent server failure provenance=%+v outcome=%v", got, outcome)
	}
}

func TestHuggingFaceResolverDoesNotInventSingleRootForMerge(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"id":"community/merged","author":"community","baseModels":{"relation":"merge","models":[{"id":"Qwen/Qwen3-4B"},{"id":"meta-llama/Llama-3.2-3B"}]}}`)
	}))
	defer server.Close()
	resolver, err := newHuggingFaceProvenanceResolverForTest(server.URL, server.Client())
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	got := resolver.resolve(context.Background(), LocalModelInfo{ID: "community/merged", Provider: "huggingface"})
	if got == nil || len(got.BaseModels) != 2 {
		t.Fatalf("merge parents were not retained: %+v", got)
	}
	if got.RootModel != "" || got.Publisher != "" || got.CountryCode != "" {
		t.Fatalf("merge received an invented single origin: %+v", got)
	}
}

func TestHuggingFaceResolverKeepsMergeAmbiguousWithOneUsableParent(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"id":"community/merged","author":"community","baseModels":{"relation":"merge","models":[{"id":"Qwen/Qwen3-4B"},{"id":"not-a-repo"}]}}`)
	}))
	defer server.Close()
	resolver, err := newHuggingFaceProvenanceResolverForTest(server.URL, server.Client())
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	got := resolver.resolve(context.Background(), LocalModelInfo{ID: "community/merged", Provider: "huggingface"})
	if got == nil || len(got.BaseModels) != 1 || got.BaseModels[0] != "Qwen/Qwen3-4B" {
		t.Fatalf("merge parent was not retained: %+v", got)
	}
	if got.RootModel != "" || got.Publisher != "" || got.CountryCode != "" {
		t.Fatalf("single surviving merge parent became an invented root: %+v", got)
	}
}

func TestHuggingFaceResolverKeepsFamilyOnlyCountryAtMediumConfidence(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"id":"community/Llama3-finetune","author":"community"}`)
	}))
	defer server.Close()
	resolver, err := newHuggingFaceProvenanceResolverForTest(server.URL, server.Client())
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	got := resolver.resolve(context.Background(), LocalModelInfo{ID: "community/Llama3-finetune", Provider: "huggingface"})
	if got == nil || got.CountryCode != "US" || got.Confidence != "medium" {
		t.Fatalf("family-only match confidence = %+v", got)
	}
}

func TestHuggingFaceResolverDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()

	resolver := newHuggingFaceProvenanceResolver()
	endpoint, err := url.Parse(source.URL)
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	resolver.endpoint = endpoint
	if got := resolver.resolve(context.Background(), LocalModelInfo{ID: "owner/model", Provider: "huggingface"}); got != nil {
		t.Fatalf("redirecting lookup returned provenance: %+v", got)
	}
	if redirected.Load() != 0 {
		t.Fatal("provenance client followed a redirect")
	}
}

func TestHuggingFaceResolverBoundsResponse(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", int(huggingFaceHubResponseBytes)+1))
	}))
	defer server.Close()
	resolver, err := newHuggingFaceProvenanceResolverForTest(server.URL, server.Client())
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	if got := resolver.resolve(context.Background(), LocalModelInfo{ID: "owner/model", Provider: "huggingface"}); got != nil {
		t.Fatalf("oversized response returned provenance: %+v", got)
	}
}

func TestHuggingFaceResolverRejectsSuccessfulErrorEnvelopes(t *testing.T) {
	t.Parallel()
	for _, body := range []string{`{}`, `{"error":"model unavailable"}`} {
		body := body
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			resolver, err := newHuggingFaceProvenanceResolverForTest(server.URL, server.Client())
			if err != nil {
				t.Fatalf("new resolver: %v", err)
			}
			got, outcome := resolver.resolveWithOutcome(
				context.Background(), LocalModelInfo{ID: "owner/model", Provider: "huggingface"},
			)
			if got != nil || outcome != huggingFaceLookupTransientFailure {
				t.Fatalf("error envelope resolved as provenance=%+v outcome=%v", got, outcome)
			}
		})
	}
}

func TestMergeHuggingFaceProvenancePreservesLocalOnConflict(t *testing.T) {
	t.Parallel()
	local := &LocalModelProvenance{
		Publisher: "Meta", CountryCode: "US", RootModel: "meta-llama/Llama-3.1-8B",
		Source: "gguf_metadata", Confidence: "high",
	}
	hub := &LocalModelProvenance{
		Publisher: "Qwen", CountryCode: "CN", RootModel: "Qwen/Qwen3-8B",
		Source: "huggingface_hub", Confidence: "high",
	}
	got := mergeHuggingFaceProvenance(local, hub)
	if got.RootModel != local.RootModel || got.CountryCode != "US" {
		t.Fatalf("conflicting Hub data replaced local evidence: %+v", got)
	}
	if got.Confidence != "low" || got.Source != "mixed" {
		t.Fatalf("conflict was not surfaced: %+v", got)
	}
}

func TestMergeHuggingFaceProvenanceReplacesCacheFilenameHeuristic(t *testing.T) {
	t.Parallel()
	local := &LocalModelProvenance{
		Publisher: "Meta", CountryCode: "US",
		RootModel: "meta-llama/Llama-2-7B-Chat-GGUF", Source: "hf_cache", Confidence: "high",
	}
	hub := &LocalModelProvenance{
		Publisher: "Meta", CountryCode: "US", RootModel: "meta-llama/Llama-2-7b-chat-hf",
		BaseModels: []string{"meta-llama/Llama-2-7b-chat-hf"},
		Source:     "huggingface_hub", Confidence: "high",
	}
	got := mergeHuggingFaceProvenance(local, hub)
	if got.RootModel != hub.RootModel || got.CountryCode != "US" || got.Confidence != "high" {
		t.Fatalf("Hub-declared root lost to cache filename heuristic: %+v", got)
	}
}

func TestMergeHuggingFaceProvenanceDoesNotUpgradeUnverifiedHubRoot(t *testing.T) {
	t.Parallel()
	local := &LocalModelProvenance{
		Publisher: "Meta", CountryCode: "US",
		RootModel: "meta-llama/Llama-2-7B-Chat-GGUF", Source: "hf_cache", Confidence: "high",
	}
	hub := &LocalModelProvenance{
		Publisher: "Meta", CountryCode: "US", RootModel: "meta-llama/Llama-2-7b-chat-hf",
		BaseModels: []string{"meta-llama/Llama-2-7b-chat-hf"},
		Source:     "huggingface_hub", Confidence: "medium",
	}
	got := mergeHuggingFaceProvenance(local, hub)
	if got.RootModel != hub.RootModel || got.Confidence != "medium" {
		t.Fatalf("local filename heuristic upgraded unverified Hub root: %+v", got)
	}
}

func TestEnrichModelSignalsFromHuggingFaceMergesLocalEvidence(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/models/Qwen/Qwen3-0.6B-GGUF":
			fmt.Fprint(w, `{"id":"Qwen/Qwen3-0.6B-GGUF","author":"Qwen","baseModels":{"relation":"quantized","models":[{"id":"Qwen/Qwen3-0.6B"}]}}`)
		case "/api/models/Qwen/Qwen3-0.6B":
			fmt.Fprint(w, `{"id":"Qwen/Qwen3-0.6B","author":"Qwen"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	resolver, err := newHuggingFaceProvenanceResolverForTest(server.URL, server.Client())
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	signals := []AISignal{{
		Fingerprint: "model-1", EvidenceHash: "unchanged",
		Model: &LocalModelInfo{
			ID: "Qwen/Qwen3-0.6B-GGUF", Status: "installed", Provider: "huggingface",
			Provenance: &LocalModelProvenance{
				Publisher: "Alibaba Cloud", CountryCode: "CN",
				Source: "hf_cache", Confidence: "high",
			},
		},
	}}
	enrichModelSignalsFromHuggingFace(context.Background(), resolver, signals, 0)
	got := signals[0].Model.Provenance
	if got == nil || got.RootModel != "Qwen/Qwen3-0.6B" || got.Source != "mixed" {
		t.Fatalf("enriched model = %+v", got)
	}
	if signals[0].EvidenceHash != "unchanged" {
		t.Fatal("online enrichment changed detector lifecycle evidence")
	}
}

func TestHuggingFacePageCursorAdvancesByActualAttempts(t *testing.T) {
	t.Parallel()
	var cancel context.CancelFunc
	var paths []string
	requestsThisScan := 0
	client := &http.Client{Transport: huggingFaceRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		requestsThisScan++
		modelID := strings.TrimPrefix(req.URL.Path, "/api/models/")
		response := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"id":%q}`, modelID))),
			Request:    req,
		}
		if requestsThisScan == 2 {
			cancel()
		}
		return response, nil
	})}
	resolver, err := newHuggingFaceProvenanceResolverForTest("https://hub.example", client)
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	signals := make([]AISignal, 5)
	for index := range signals {
		signals[index] = AISignal{
			Fingerprint: fmt.Sprintf("model-%d", index),
			Model: &LocalModelInfo{
				ID: fmt.Sprintf("owner/model-%d", index), Provider: "huggingface", Status: "installed",
			},
		}
	}
	ctx, cancelFirst := context.WithCancel(context.Background())
	cancel = cancelFirst
	outcomes, attempted := enrichModelSignalsFromHuggingFace(ctx, resolver, signals, 0)
	if attempted != 2 || outcomes[0] != huggingFaceLookupFound || outcomes[2] != huggingFaceLookupUnattempted {
		t.Fatalf("first page attempted=%d outcomes=%v", attempted, outcomes)
	}
	requestsThisScan = 0
	paths = nil
	ctx, cancelSecond := context.WithCancel(context.Background())
	cancel = cancelSecond
	_, secondAttempted := enrichModelSignalsFromHuggingFace(ctx, resolver, signals, uint64(attempted))
	if secondAttempted != 2 || len(paths) == 0 || paths[0] != "/api/models/owner/model-2" {
		t.Fatalf("second page attempted=%d paths=%v", secondAttempted, paths)
	}
}

func TestEnrichModelSignalsClearsHeuristicOriginForHubMerge(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"id":"community/Qwen-Llama-merge","author":"community","baseModels":{"relation":"merge","models":[{"id":"Qwen/Qwen3-4B"},{"id":"meta-llama/Llama-3.2-3B"}]}}`)
	}))
	defer server.Close()
	resolver, err := newHuggingFaceProvenanceResolverForTest(server.URL, server.Client())
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	signals := []AISignal{{
		Fingerprint: "merge", EvidenceHash: "local",
		Model: &LocalModelInfo{
			ID: "community/Qwen-Llama-merge", Provider: "huggingface", Status: "installed",
			Provenance: &LocalModelProvenance{
				Publisher: "Alibaba Cloud", CountryCode: "CN",
				RootModel: "Qwen/Qwen-Llama-merge", Source: "catalog_family", Confidence: "medium",
			},
		},
	}}
	enrichModelSignalsFromHuggingFace(context.Background(), resolver, signals, 0)
	got := signals[0].Model.Provenance
	if got == nil || len(got.BaseModels) != 2 || got.RootModel != "" || got.Publisher != "" || got.CountryCode != "" {
		t.Fatalf("Hub merge retained invented heuristic origin: %+v", got)
	}
}

func TestMergeHuggingFaceProvenanceMarksExplicitRootConflictWithMerge(t *testing.T) {
	t.Parallel()
	local := &LocalModelProvenance{
		Publisher: "Meta", CountryCode: "US", RootModel: "meta-llama/Local-Declared-Root",
		BaseModels: []string{"meta-llama/Local-Declared-Root"},
		Source:     "gguf_metadata", Confidence: "high",
	}
	hub := &LocalModelProvenance{
		BaseModels: []string{"Qwen/Qwen3-4B", "meta-llama/Llama-3.2-3B"},
		Source:     "huggingface_hub", Confidence: "medium",
	}
	got := mergeHuggingFaceProvenance(local, hub)
	if got.RootModel != "" || got.Publisher != "" || got.CountryCode != "" {
		t.Fatalf("explicit single root remained visible for Hub merge: %+v", got)
	}
	if got.Confidence != "low" || len(got.BaseModels) != 3 {
		t.Fatalf("explicit/Hub merge conflict was not retained: %+v", got)
	}
}

func TestDefinitiveHubMissDoesNotRestorePreviousProvenance(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer server.Close()
	resolver, err := newHuggingFaceProvenanceResolverForTest(server.URL, server.Client())
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	previous := map[string]aiStoredSignal{"model": {AISignal: AISignal{
		Fingerprint: "model", EvidenceHash: "same", ModelProvenanceHubResolvedAt: now.Add(-time.Hour),
		Model: &LocalModelInfo{ID: "owner/model", Provider: "huggingface", Provenance: &LocalModelProvenance{
			RootModel: "owner/model", Source: "huggingface_hub", Confidence: "medium",
		}},
	}}}
	signals := []AISignal{{
		Fingerprint: "model", EvidenceHash: "same",
		Model: &LocalModelInfo{ID: "owner/model", Provider: "huggingface"},
	}}
	outcomes, _ := enrichModelSignalsFromHuggingFace(context.Background(), resolver, signals, 0)
	preserveHuggingFaceProvenance(signals, previous, outcomes, now)
	if signals[0].Model.Provenance != nil || outcomes[0] != huggingFaceLookupNotFound {
		t.Fatalf("definitive miss retained stale provenance: model=%+v outcome=%v", signals[0].Model, outcomes[0])
	}
}

func TestHubProvenanceGraceIsBounded(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	previous := map[string]aiStoredSignal{"model": {AISignal: AISignal{
		Fingerprint: "model", EvidenceHash: "same",
		ModelProvenanceHubResolvedAt: now.Add(-huggingFaceHubStaleGrace - time.Second),
		Model: &LocalModelInfo{ID: "owner/model", Provenance: &LocalModelProvenance{
			RootModel: "owner/model", Source: "huggingface_hub", Confidence: "medium",
		}},
	}}}
	signals := []AISignal{{Fingerprint: "model", EvidenceHash: "same", Model: &LocalModelInfo{ID: "owner/model"}}}
	preserveHuggingFaceProvenance(
		signals, previous, []huggingFaceLookupOutcome{huggingFaceLookupUnattempted}, now,
	)
	if signals[0].Model.Provenance != nil {
		t.Fatalf("expired Hub provenance was preserved: %+v", signals[0].Model.Provenance)
	}
}

func TestHubProvenanceRevisionTriggersChangedLifecycle(t *testing.T) {
	t.Parallel()
	service := &ContinuousDiscoveryService{
		opts:  AIDiscoveryOptions{Mode: "balanced", MaxFilesPerScan: 1},
		store: NewAIStateStore(""),
	}
	previous := aiStateFile{Signals: map[string]aiStoredSignal{"model": {AISignal: AISignal{
		Fingerprint: "model", EvidenceHash: "same-local-evidence", ModelProvenanceHubHash: "old-hub",
		FirstSeen: time.Now().Add(-time.Hour), Model: &LocalModelInfo{ID: "owner/model", Status: "installed"},
	}}}}
	signal := AISignal{
		Fingerprint: "model", EvidenceHash: "same-local-evidence", ModelProvenanceHubHash: "new-hub",
		Detector: "model_file", Model: &LocalModelInfo{ID: "owner/model", Status: "installed"},
	}
	report := service.classifyAndPersist(
		"scan", "sidecar", time.Now(), []AISignal{signal}, scanStats{}, previous, true,
	)
	if len(report.Signals) != 1 || report.Signals[0].State != AIStateChanged || report.Summary.ChangedSignals != 1 {
		t.Fatalf("Hub metadata revision was not classified changed: %+v", report)
	}
}

func TestAIStateStorePersistsHubFreshnessMetadata(t *testing.T) {
	t.Parallel()
	resolvedAt := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	store := NewAIStateStore(t.TempDir() + "/state.json")
	want := AISignal{
		Fingerprint: "model", EvidenceHash: "evidence", ModelProvenanceHubHash: "hub-hash",
		ModelProvenanceHubResolvedAt: resolvedAt,
		Model:                        &LocalModelInfo{ID: "owner/model", Status: "installed"},
	}
	if err := store.Save(aiStateFile{Signals: map[string]aiStoredSignal{"model": {AISignal: want}}}); err != nil {
		t.Fatalf("save state: %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	stored := got.Signals["model"].AISignal
	if stored.ModelProvenanceHubHash != want.ModelProvenanceHubHash ||
		!stored.ModelProvenanceHubResolvedAt.Equal(resolvedAt) {
		t.Fatalf("Hub freshness round trip = hash %q resolved %v", stored.ModelProvenanceHubHash, stored.ModelProvenanceHubResolvedAt)
	}
}

func TestPreserveHuggingFaceProvenanceOnlyForUnchangedEvidence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	previousProvenance := &LocalModelProvenance{
		RootModel: "meta-llama/Llama-3.1-8B", BaseModels: []string{"meta-llama/Llama-3.1-8B"},
		Source: "huggingface_hub", Confidence: "high",
	}
	previous := map[string]aiStoredSignal{
		"same": {
			AISignal: AISignal{
				Fingerprint: "same", EvidenceHash: "evidence-a",
				ModelProvenanceHubResolvedAt: now.Add(-time.Hour),
				Model:                        &LocalModelInfo{ID: "owner/model", Status: "installed", Provenance: previousProvenance},
			},
		},
		"changed": {
			AISignal: AISignal{
				Fingerprint: "changed", EvidenceHash: "evidence-old",
				ModelProvenanceHubResolvedAt: now.Add(-time.Hour),
				Model:                        &LocalModelInfo{ID: "owner/model", Status: "installed", Provenance: previousProvenance},
			},
		},
	}
	signals := []AISignal{
		{Fingerprint: "same", EvidenceHash: "evidence-a", Model: &LocalModelInfo{ID: "owner/model", Status: "installed"}},
		{Fingerprint: "changed", EvidenceHash: "evidence-new", Model: &LocalModelInfo{ID: "owner/model", Status: "installed"}},
	}
	preserveHuggingFaceProvenance(signals, previous, []huggingFaceLookupOutcome{
		huggingFaceLookupUnattempted, huggingFaceLookupTransientFailure,
	}, now)
	if signals[0].Model.Provenance == nil || signals[0].Model.Provenance.RootModel == "" {
		t.Fatal("unchanged model did not retain last-known Hub provenance")
	}
	if signals[1].Model.Provenance != nil {
		t.Fatal("changed model retained stale Hub provenance")
	}
	signals[0].Model.Provenance.BaseModels[0] = "mutated"
	if previousProvenance.BaseModels[0] == "mutated" {
		t.Fatal("preserved provenance base_models was not deep-copied")
	}
}
