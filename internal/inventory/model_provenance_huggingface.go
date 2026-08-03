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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	huggingFaceHubBaseURL           = "https://huggingface.co"
	huggingFaceHubResponseBytes     = int64(256 << 10)
	huggingFaceHubRequestTimeout    = 2 * time.Second
	huggingFaceHubCacheTTL          = 24 * time.Hour
	huggingFaceHubNegativeCacheTTL  = time.Hour
	huggingFaceHubTransientCacheTTL = 5 * time.Minute
	huggingFaceHubMaxCacheEntries   = 512
	huggingFaceHubMaxLineageDepth   = 4
	huggingFaceHubModelsPerScan     = 8
	huggingFaceHubScanTimeout       = 4 * time.Second
	huggingFaceHubStaleGrace        = 7 * 24 * time.Hour
)

var huggingFaceRepoSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,94}[A-Za-z0-9])?$`)

type huggingFaceModelInfo struct {
	ID         string
	Author     string
	Relation   string
	BaseModels []string
}

type huggingFaceModelInfoEnvelope struct {
	ID         string          `json:"id"`
	Author     string          `json:"author"`
	BaseModels json.RawMessage `json:"baseModels"`
}

type huggingFaceCacheEntry struct {
	info      huggingFaceModelInfo
	found     bool
	err       error
	expiresAt time.Time
}

type huggingFaceLookupOutcome uint8

const (
	huggingFaceLookupNotEligible huggingFaceLookupOutcome = iota
	huggingFaceLookupUnattempted
	huggingFaceLookupFound
	huggingFaceLookupNotFound
	huggingFaceLookupTransientFailure
)

// huggingFaceProvenanceResolver is deliberately fixed to the public Hub in
// production. It never performs fuzzy search: callers must already possess a
// syntactically credible owner/repository identifier from local metadata.
// This keeps opt-in enrichment deterministic and prevents arbitrary paths or
// private filenames from becoming outbound search queries.
type huggingFaceProvenanceResolver struct {
	client   *http.Client
	endpoint *url.URL
	now      func() time.Time

	mu    sync.Mutex
	cache map[string]huggingFaceCacheEntry
}

func newHuggingFaceProvenanceResolver() *huggingFaceProvenanceResolver {
	endpoint, _ := url.Parse(huggingFaceHubBaseURL)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 2
	client := &http.Client{
		Transport: transport,
		Timeout:   huggingFaceHubRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("Hugging Face provenance redirects are disabled")
		},
	}
	return &huggingFaceProvenanceResolver{
		client: client, endpoint: endpoint, now: time.Now,
		cache: make(map[string]huggingFaceCacheEntry),
	}
}

// newHuggingFaceProvenanceResolverForTest is the only endpoint override. The
// runtime config intentionally has no Hub URL field, so an untrusted config
// cannot redirect requests to an internal service.
func newHuggingFaceProvenanceResolverForTest(endpoint string, client *http.Client) (*huggingFaceProvenanceResolver, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("invalid test Hugging Face endpoint")
	}
	if client == nil {
		return nil, errors.New("test Hugging Face client is required")
	}
	return &huggingFaceProvenanceResolver{
		client: client, endpoint: parsed, now: time.Now,
		cache: make(map[string]huggingFaceCacheEntry),
	}, nil
}

func credibleHuggingFaceRepoID(value string) (string, bool) {
	value = modelReferenceFromURL(strings.TrimSpace(value))
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return "", false
	}
	for _, part := range parts {
		if !huggingFaceRepoSegmentPattern.MatchString(part) || strings.Contains(part, "..") {
			return "", false
		}
	}
	return parts[0] + "/" + parts[1], true
}

func explicitHuggingFaceRepoID(value string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") ||
		(!strings.EqualFold(parsed.Hostname(), "huggingface.co") &&
			!strings.EqualFold(parsed.Hostname(), "www.huggingface.co")) {
		return "", false
	}
	return credibleHuggingFaceRepoID(value)
}

func uniqueCredibleHuggingFaceRepoIDs(values []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, min(len(values), maxModelBaseModels))
	for _, value := range values {
		repoID, ok := credibleHuggingFaceRepoID(value)
		key := strings.ToLower(repoID)
		if !ok || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, repoID)
		if len(out) >= maxModelBaseModels {
			break
		}
	}
	return out
}

func huggingFaceRepoIDForModel(model LocalModelInfo) (string, bool) {
	// Only exact IDs copied from trusted local metadata are eligible. Offline
	// family guesses deliberately remain local so a private filename cannot be
	// transformed into an outbound repository request.
	candidates := append([]string(nil), model.huggingFaceRepoIDs...)
	if strings.EqualFold(model.Provider, "huggingface") {
		candidates = append(candidates, model.ID)
	} else if _, ok := explicitHuggingFaceRepoID(model.ID); ok {
		candidates = append(candidates, model.ID)
	}
	if model.Provenance != nil {
		switch model.Provenance.Source {
		case "catalog_exact", "hf_cache", "huggingface_hub":
			candidates = append(candidates, model.Provenance.RootModel)
			candidates = append(candidates, model.Provenance.BaseModels...)
		}
	}
	for _, candidate := range candidates {
		if repoID, ok := credibleHuggingFaceRepoID(candidate); ok {
			return repoID, true
		}
	}
	return "", false
}

func (r *huggingFaceProvenanceResolver) resolve(ctx context.Context, model LocalModelInfo) *LocalModelProvenance {
	provenance, _ := r.resolveWithOutcome(ctx, model)
	return provenance
}

func (r *huggingFaceProvenanceResolver) resolveWithOutcome(
	ctx context.Context,
	model LocalModelInfo,
) (*LocalModelProvenance, huggingFaceLookupOutcome) {
	if r == nil || r.client == nil || r.endpoint == nil {
		return nil, huggingFaceLookupTransientFailure
	}
	repoID, ok := huggingFaceRepoIDForModel(model)
	if !ok {
		return nil, huggingFaceLookupNotEligible
	}

	current := repoID
	root := repoID
	ancestry := make([]string, 0, huggingFaceHubMaxLineageDepth)
	visited := make(map[string]bool)
	var rootAuthor string
	var quantized, distilled *bool
	resolvedAny := false
	ambiguousRoots := false
	rootVerified := false
	transientLineageFailure := false

	for depth := 0; depth < huggingFaceHubMaxLineageDepth; depth++ {
		key := strings.ToLower(current)
		if visited[key] {
			break
		}
		visited[key] = true

		info, found, err := r.modelInfo(ctx, current)
		if err != nil {
			if !resolvedAny {
				return nil, huggingFaceLookupTransientFailure
			}
			transientLineageFailure = true
			break
		}
		if !found {
			if !resolvedAny {
				return nil, huggingFaceLookupNotFound
			}
			break
		}
		resolvedAny = true
		if info.ID != "" {
			current = info.ID
		}
		root = current
		rootAuthor = info.Author
		rootVerified = true
		relation := strings.ToLower(strings.TrimSpace(info.Relation))
		switch relation {
		case "quantized", "quantization":
			quantized = modelBool(true)
		case "distilled", "distillation":
			distilled = modelBool(true)
		}
		for _, base := range info.BaseModels {
			if _, seen := visited[strings.ToLower(base)]; !seen {
				ancestry = append(ancestry, base)
			}
		}
		if relation == "merge" || len(info.BaseModels) > 1 {
			// A merge has multiple immediate roots. Preserve all parents but
			// never turn the first array element into an invented single origin.
			ambiguousRoots = true
			root = ""
			rootAuthor = ""
			rootVerified = true
			break
		}
		if len(info.BaseModels) == 0 {
			break
		}
		current = info.BaseModels[0]
		// The declared parent remains the best-known root even if its own Hub
		// card is gated, missing, times out, or hits the recursion bound.
		root = current
		rootAuthor = ""
		rootVerified = false
	}
	if !resolvedAny {
		return nil, huggingFaceLookupTransientFailure
	}

	ancestry = uniqueBoundedModelReferences(ancestry, maxModelBaseModels)
	if ambiguousRoots {
		if len(ancestry) == 0 {
			// The card definitively declared a merge but supplied no usable
			// parents. Treat the lookup as completed while leaving provenance
			// unknown; callers will clear any stale single-root Hub claim.
			return nil, huggingFaceLookupFound
		}
		provenance := &LocalModelProvenance{
			BaseModels: ancestry, Quantized: quantized, Distilled: distilled,
			Source: "huggingface_hub", Confidence: "medium",
		}
		normalizeLocalModelProvenance(provenance)
		if transientLineageFailure {
			return provenance, huggingFaceLookupTransientFailure
		}
		return provenance, huggingFaceLookupFound
	}
	hints := modelProvenanceHints{
		References: []string{root, repoID},
		BaseModels: []string{root},
		Quantized:  quantized,
		Distilled:  distilled,
		Source:     "huggingface_hub",
	}
	if rootAuthor != "" {
		hints.Organizations = []string{rootAuthor}
	}
	provenance := resolveLocalModelProvenance(model, hints)
	if provenance == nil {
		provenance = &LocalModelProvenance{
			RootModel: root, Source: "huggingface_hub", Confidence: "medium",
			Quantized: quantized, Distilled: distilled,
		}
	}
	provenance.RootModel = boundedProvenanceField(root, maxModelRootBytes)
	provenance.BaseModels = ancestry
	provenance.Source = "huggingface_hub"
	if rootVerified && provenance.Publisher != "" && provenance.CountryCode != "" &&
		huggingFaceRootPublisherIsExact(root, rootAuthor) {
		provenance.Confidence = "high"
	} else if !rootVerified {
		provenance.Confidence = "medium"
	} else if provenance.Confidence == "" || provenance.Confidence == "low" {
		provenance.Confidence = "medium"
	}
	normalizeLocalModelProvenance(provenance)
	if transientLineageFailure {
		return provenance, huggingFaceLookupTransientFailure
	}
	return provenance, huggingFaceLookupFound
}

func huggingFaceRootPublisherIsExact(root, author string) bool {
	catalog, err := loadModelProvenanceCatalog()
	if err != nil {
		return false
	}
	baseOrganizations := []string(nil)
	if author != "" {
		baseOrganizations = []string{author}
	}
	_, score := bestPublisherRule(
		catalog.Publishers, nil, nil, baseOrganizations, []string{root},
	)
	return score >= 600
}

func (r *huggingFaceProvenanceResolver) modelInfo(ctx context.Context, repoID string) (huggingFaceModelInfo, bool, error) {
	repoID, ok := credibleHuggingFaceRepoID(repoID)
	if !ok {
		return huggingFaceModelInfo{}, false, errors.New("invalid Hugging Face repository id")
	}
	now := r.now().UTC()
	cacheKey := strings.ToLower(repoID)
	r.mu.Lock()
	if cached, exists := r.cache[cacheKey]; exists && now.Before(cached.expiresAt) {
		r.mu.Unlock()
		return cached.info, cached.found, cached.err
	}
	r.mu.Unlock()

	requestURL := *r.endpoint
	requestURL.Path = strings.TrimRight(requestURL.Path, "/") + "/api/models/" +
		url.PathEscape(strings.Split(repoID, "/")[0]) + "/" +
		url.PathEscape(strings.Split(repoID, "/")[1])
	query := requestURL.Query()
	query.Add("expand[]", "author")
	query.Add("expand[]", "baseModels")
	requestURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return huggingFaceModelInfo{}, false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "DefenseClaw-AI-Discovery/1")
	resp, err := r.client.Do(req)
	if err != nil {
		return huggingFaceModelInfo{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		r.storeCache(cacheKey, huggingFaceCacheEntry{found: false, expiresAt: now.Add(huggingFaceHubNegativeCacheTTL)})
		return huggingFaceModelInfo{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		statusErr := fmt.Errorf("Hugging Face model API returned HTTP %d", resp.StatusCode)
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
			// Authentication/gating and rate-limit responses are not proof that a
			// repository does not exist. Cache the error briefly to avoid hammering
			// the Hub, while returning an error so callers preserve prior lineage.
			r.storeCache(cacheKey, huggingFaceCacheEntry{
				err: statusErr, expiresAt: now.Add(huggingFaceHubTransientCacheTTL),
			})
		}
		return huggingFaceModelInfo{}, false, statusErr
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, huggingFaceHubResponseBytes+1))
	if err != nil {
		return huggingFaceModelInfo{}, false, err
	}
	if int64(len(raw)) > huggingFaceHubResponseBytes {
		return huggingFaceModelInfo{}, false, errors.New("Hugging Face model API response exceeds limit")
	}
	var envelope huggingFaceModelInfoEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return huggingFaceModelInfo{}, false, err
	}
	validated, valid := credibleHuggingFaceRepoID(envelope.ID)
	if !valid || !strings.EqualFold(validated, repoID) {
		return huggingFaceModelInfo{}, false, errors.New("Hugging Face model API returned a missing or mismatched id")
	}
	relation, bases := parseHuggingFaceBaseModels(envelope.BaseModels)
	info := huggingFaceModelInfo{
		ID:         validated,
		Author:     boundedProvenanceField(envelope.Author, maxModelPublisherBytes),
		Relation:   boundedProvenanceField(relation, maxModelDerivationBytes),
		BaseModels: bases,
	}
	r.storeCache(cacheKey, huggingFaceCacheEntry{
		info: info, found: true, expiresAt: now.Add(huggingFaceHubCacheTTL),
	})
	return info, true, nil
}

func parseHuggingFaceBaseModels(raw json.RawMessage) (string, []string) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var object struct {
		Relation string `json:"relation"`
		Models   []struct {
			ID string `json:"id"`
		} `json:"models"`
	}
	if err := json.Unmarshal(raw, &object); err == nil {
		bases := make([]string, 0, len(object.Models))
		for _, item := range object.Models {
			if id, ok := credibleHuggingFaceRepoID(item.ID); ok {
				bases = append(bases, id)
			}
		}
		return object.Relation, uniqueBoundedModelReferences(bases, maxModelBaseModels)
	}
	var stringsOnly []string
	if err := json.Unmarshal(raw, &stringsOnly); err != nil {
		return "", nil
	}
	bases := make([]string, 0, len(stringsOnly))
	for _, item := range stringsOnly {
		if id, ok := credibleHuggingFaceRepoID(item); ok {
			bases = append(bases, id)
		}
	}
	return "", uniqueBoundedModelReferences(bases, maxModelBaseModels)
}

func (r *huggingFaceProvenanceResolver) storeCache(key string, entry huggingFaceCacheEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) >= huggingFaceHubMaxCacheEntries {
		now := r.now().UTC()
		for existingKey, existing := range r.cache {
			if !now.Before(existing.expiresAt) {
				delete(r.cache, existingKey)
			}
		}
		if len(r.cache) >= huggingFaceHubMaxCacheEntries {
			for existingKey := range r.cache {
				delete(r.cache, existingKey)
				break
			}
		}
	}
	r.cache[key] = entry
}

func mergeHuggingFaceProvenance(existing, hub *LocalModelProvenance) *LocalModelProvenance {
	if hub == nil {
		return existing
	}
	if existing == nil {
		copyHub := *hub
		copyHub.BaseModels = append([]string(nil), hub.BaseModels...)
		return &copyHub
	}
	merged := *existing
	merged.BaseModels = append([]string(nil), existing.BaseModels...)
	conflict := false
	discardedLocalIdentity := false
	// A local cache/runtime name can identify a family without identifying the
	// root weights. When the Hub card declares a root and local metadata supplied
	// no explicit parent list, prefer that declared ancestry over the synthetic
	// root built from the derivative filename. Explicit local base metadata and
	// reviewed exact lineage rules still take the conflict-preserving path.
	discardableSyntheticRoot := existing.Source == "hf_cache" || existing.Source == "catalog_family" ||
		existing.Source == "ollama_metadata" || existing.Source == "checkpoint" || existing.Source == "model_id"
	if hub.RootModel != "" && len(existing.BaseModels) == 0 && discardableSyntheticRoot {
		merged.Publisher = ""
		merged.CountryCode = ""
		merged.RootModel = ""
		discardedLocalIdentity = true
	}
	// Multiple declared parents are an explicit ambiguity, not permission to
	// display any single root. Preserve an explicit local root as another parent
	// candidate, then clear the singular origin. If local metadata had asserted
	// an origin, the combined result is an explicit low-confidence conflict.
	ambiguousHubRoot := hub.RootModel == "" && len(hub.BaseModels) > 0
	if ambiguousHubRoot {
		localRootIsHeuristic := existing.Source == "catalog_family" || existing.Source == "ollama_metadata" ||
			existing.Source == "model_id" || existing.Source == "hf_cache" || existing.Source == "checkpoint"
		if merged.RootModel != "" && !localRootIsHeuristic {
			merged.BaseModels = append(merged.BaseModels, merged.RootModel)
		}
		if merged.RootModel != "" || merged.Publisher != "" || merged.CountryCode != "" {
			conflict = true
		}
		merged.Publisher = ""
		merged.CountryCode = ""
		merged.RootModel = ""
	}
	mergeString := func(target *string, incoming string) {
		if incoming == "" {
			return
		}
		if *target == "" {
			*target = incoming
			return
		}
		if !strings.EqualFold(*target, incoming) {
			conflict = true
		}
	}
	mergeString(&merged.Publisher, hub.Publisher)
	mergeString(&merged.CountryCode, hub.CountryCode)
	mergeString(&merged.RootModel, hub.RootModel)
	mergeString(&merged.Quantization, hub.Quantization)
	merged.BaseModels = uniqueBoundedModelReferences(
		append(merged.BaseModels, hub.BaseModels...), maxModelBaseModels,
	)
	mergeBool := func(target **bool, incoming *bool) {
		if incoming == nil {
			return
		}
		if *target == nil {
			*target = modelBool(*incoming)
			return
		}
		if **target != *incoming {
			conflict = true
		}
	}
	mergeBool(&merged.Quantized, hub.Quantized)
	mergeBool(&merged.Distilled, hub.Distilled)
	if existing.Source == "" {
		merged.Source = "huggingface_hub"
	} else if existing.Source != "huggingface_hub" {
		merged.Source = "mixed"
	}
	if conflict {
		merged.Confidence = "low"
	} else if discardedLocalIdentity {
		merged.Confidence = hub.Confidence
	} else if ambiguousHubRoot {
		merged.Confidence = hub.Confidence
	} else if hub.Confidence == "high" || existing.Confidence == "high" {
		merged.Confidence = "high"
	} else {
		merged.Confidence = "medium"
	}
	normalizeLocalModelProvenance(&merged)
	return &merged
}

// enrichModelSignalsFromHuggingFace resolves at most a small, rotating page
// of unique repository IDs. The resolver cache makes already-seen pages cheap;
// the total deadline prevents optional enrichment from stretching a discovery
// scan indefinitely when the public service is slow or unavailable.
func enrichModelSignalsFromHuggingFace(
	ctx context.Context,
	resolver *huggingFaceProvenanceResolver,
	signals []AISignal,
	pageStart uint64,
) ([]huggingFaceLookupOutcome, int) {
	outcomes := make([]huggingFaceLookupOutcome, len(signals))
	if resolver == nil || len(signals) == 0 {
		return outcomes, 0
	}
	indicesByRepo := make(map[string][]int)
	for index := range signals {
		if signals[index].Model == nil {
			continue
		}
		repoID, ok := huggingFaceRepoIDForModel(*signals[index].Model)
		if !ok {
			continue
		}
		key := strings.ToLower(repoID)
		indicesByRepo[key] = append(indicesByRepo[key], index)
		outcomes[index] = huggingFaceLookupUnattempted
	}
	keys := make([]string, 0, len(indicesByRepo))
	for key := range indicesByRepo {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return outcomes, 0
	}
	start := int(pageStart % uint64(len(keys)))
	lookupCtx, cancel := context.WithTimeout(ctx, huggingFaceHubScanTimeout)
	defer cancel()
	attempted := 0
	for offset := 0; offset < len(keys) && offset < huggingFaceHubModelsPerScan; offset++ {
		if lookupCtx.Err() != nil {
			break
		}
		key := keys[(start+offset)%len(keys)]
		indices := indicesByRepo[key]
		if len(indices) == 0 {
			continue
		}
		attempted++
		seed := *signals[indices[0]].Model
		hub, outcome := resolver.resolveWithOutcome(lookupCtx, seed)
		for _, index := range indices {
			outcomes[index] = outcome
		}
		if outcome != huggingFaceLookupFound || hub == nil {
			continue
		}
		resolvedAt := resolver.now().UTC()
		for _, index := range indices {
			model := signals[index].Model
			model.Provenance = mergeHuggingFaceProvenance(model.Provenance, hub)
			signals[index].ModelProvenanceHubResolvedAt = resolvedAt
		}
	}
	return outcomes, attempted
}

// preserveHuggingFaceProvenance carries a last-known Hub result through a
// transient offline scan only when the underlying detector evidence is
// unchanged. If the artifact/API evidence changed, stale lineage is dropped
// and must be resolved again.
func preserveHuggingFaceProvenance(
	signals []AISignal,
	previous map[string]aiStoredSignal,
	outcomes []huggingFaceLookupOutcome,
	now time.Time,
) {
	for index := range signals {
		current := &signals[index]
		if current.Model == nil {
			continue
		}
		outcome := huggingFaceLookupNotEligible
		if index < len(outcomes) {
			outcome = outcomes[index]
		}
		if outcome != huggingFaceLookupUnattempted && outcome != huggingFaceLookupTransientFailure {
			continue
		}
		old, ok := previous[current.Fingerprint]
		resolvedAt := old.ModelProvenanceHubResolvedAt
		if resolvedAt.IsZero() && old.StoredModelProvenanceHubResolvedAt != nil {
			resolvedAt = *old.StoredModelProvenanceHubResolvedAt
		}
		if !ok || old.Model == nil || old.Model.Provenance == nil ||
			current.EvidenceHash != old.EvidenceHash ||
			!signalHasHuggingFaceProvenance(old.AISignal) ||
			signalHasHuggingFaceProvenance(*current) || resolvedAt.IsZero() ||
			now.Before(resolvedAt) || now.Sub(resolvedAt) > huggingFaceHubStaleGrace {
			continue
		}
		copyProvenance := *old.Model.Provenance
		copyProvenance.BaseModels = append([]string(nil), old.Model.Provenance.BaseModels...)
		current.Model.Provenance = &copyProvenance
		current.ModelProvenanceHubResolvedAt = resolvedAt
	}
}

func refreshHuggingFaceProvenanceHashes(signals []AISignal) {
	for index := range signals {
		signals[index].ModelProvenanceHubHash = ""
		if !signalHasHuggingFaceProvenance(signals[index]) {
			continue
		}
		raw, err := json.Marshal(signals[index].Model.Provenance)
		if err == nil {
			signals[index].ModelProvenanceHubHash = hashValue(string(raw))
		}
	}
}

// preserveHuggingFaceComparisonHashes carries the last authoritative Hub hash
// through scans that did not obtain an authoritative Hub result. This includes
// offline and non-full scans (no outcomes), page-deferred or otherwise
// unattempted lookups, transient failures, and models that were not eligible
// for an outbound lookup. A found result -- including an explicit merge with
// no singular root -- and a definitive not-found result are authoritative, so
// their freshly computed (or intentionally empty) hash must win.
//
// Only the internal comparison hash is carried. The prior Hub-derived model
// payload and freshness timestamp are deliberately not restored here, and a
// local evidence change always invalidates the old comparison baseline.
func preserveHuggingFaceComparisonHashes(
	signals []AISignal,
	previous map[string]aiStoredSignal,
	outcomes []huggingFaceLookupOutcome,
) {
	for index := range signals {
		current := &signals[index]
		if current.Model == nil {
			continue
		}
		if index < len(outcomes) {
			switch outcomes[index] {
			case huggingFaceLookupFound, huggingFaceLookupNotFound:
				continue
			}
		}
		old, ok := previous[current.Fingerprint]
		if !ok {
			continue
		}
		storedEvidenceHash := old.EvidenceHash
		if storedEvidenceHash == "" {
			storedEvidenceHash = old.StoredEvidenceHash
		}
		if storedEvidenceHash == "" || storedEvidenceHash != current.EvidenceHash {
			continue
		}
		storedHubHash := old.ModelProvenanceHubHash
		if storedHubHash == "" {
			storedHubHash = old.StoredModelProvenanceHubHash
		}
		if storedHubHash != "" {
			current.ModelProvenanceHubHash = storedHubHash
		}
	}
}

func signalHasHuggingFaceProvenance(signal AISignal) bool {
	if signal.Model == nil || signal.Model.Provenance == nil || signal.ModelProvenanceHubResolvedAt.IsZero() {
		return false
	}
	return signal.Model.Provenance.Source == "huggingface_hub" || signal.Model.Provenance.Source == "mixed"
}
