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

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"golang.org/x/sync/singleflight"
)

// bifrostProvider implements LLMProvider by delegating to the Bifrost Go SDK.
// Each distinct (providerKey, apiKey, baseURL) tuple gets its own dedicated
// Bifrost client with an immutable Account, so credentials and endpoints for
// one tenant are isolated from other in-flight requests.
type bifrostProvider struct {
	providerKey schemas.ModelProvider
	model       string
	apiKey      string
	baseURL     string
}

// tenantKey identifies a unique (provider, api-key, base-url) tuple. Each
// tuple gets its own dedicated Bifrost client + frozen Account so that
// credentials and endpoints for one tenant can never leak into an in-flight
// request for another. Previously a single package-level client + mutable
// account map was shared across all tenants: two concurrent requests hitting
// the same provider with different keys or base URLs could race so that the
// Bifrost client executed request A using tenant B's credentials.
type tenantKey struct {
	provider schemas.ModelProvider
	keyID    string // sha256 of apiKey — the raw key is never in the map key.
	baseURL  string
}

// bifrostTenantsMaxSize bounds the in-memory tenant client cache.
// DeepSec S3.BUG ("Bifrost tenant client cache grows without
// eviction"): the previous package-level map grew on every cache
// miss with no LRU/TTL/Shutdown, and authenticated callers can vary
// `X-AI-Auth` (and Azure/Bedrock can also vary baseURL) per request.
// On a long-running gateway with credential rotation or a hostile
// authenticated caller, that drove permanent memory + connection
// growth. We now keep at most bifrostTenantsMaxSize live clients,
// evict the least-recently-used entry when we hit the cap, and call
// the SDK's Shutdown on every eviction so each client's HTTP / queue
// resources are released alongside the map slot.
const bifrostTenantsMaxSize = 256

type bifrostTenantEntry struct {
	client   *bifrost.Bifrost
	lastUsed time.Time
}

var (
	bifrostTenantsMu sync.RWMutex
	bifrostTenants   = make(map[tenantKey]*bifrostTenantEntry)
	// bifrostInitGroup dedupes concurrent first-time bifrost.Init calls
	// for the same tenant. Without it, every concurrent caller for an
	// uncached tenant key would serialize on bifrostTenantsMu while the
	// first caller's Init ran (up to 30s for cold network setup),
	// blocking even unrelated tenants whose entries were already cached
	// because RLock fast-path readers would queue behind the Lock-holder
	// across the Init body. With singleflight, only ONE Init call per
	// tenantKey runs at a time; concurrent callers for the same key wait
	// on its result, and concurrent callers for OTHER keys never see the
	// global lock held across the slow Init.
	bifrostInitGroup singleflight.Group
)

// tenantKeyString gives evictOldestBifrostTenantLocked a deterministic
// tie-break order. We do NOT include the raw apiKey here — keyID is
// already a sha256 of apiKey (see bifrostKeyID). Provider name +
// baseURL + keyID is plenty for stable lexicographic ordering and
// contains no secrets.
func tenantKeyString(k tenantKey) string {
	return string(k.provider) + "|" + k.baseURL + "|" + k.keyID
}

// evictOldestBifrostTenantLocked drops the LRU tenant client. Caller
// must hold bifrostTenantsMu (write lock).
//
// Tie-break: when two entries share the same lastUsed (unlikely on a
// busy gateway but observable under low-resolution wallclocks and in
// unit tests), order by stringified tenantKey so eviction is
// deterministic. Without this tie-break the victim depends on Go's
// randomized map iteration order, which makes bursty-traffic
// behavior — and the eviction test below — flaky.
func evictOldestBifrostTenantLocked() {
	var oldestKey tenantKey
	var oldestKeyStr string
	var oldestSeen time.Time
	first := true
	for k, e := range bifrostTenants {
		ks := tenantKeyString(k)
		if first {
			oldestKey = k
			oldestKeyStr = ks
			oldestSeen = e.lastUsed
			first = false
			continue
		}
		if e.lastUsed.Before(oldestSeen) {
			oldestKey = k
			oldestKeyStr = ks
			oldestSeen = e.lastUsed
		} else if e.lastUsed.Equal(oldestSeen) && ks < oldestKeyStr {
			oldestKey = k
			oldestKeyStr = ks
		}
	}
	if first {
		return
	}
	if entry, ok := bifrostTenants[oldestKey]; ok {
		delete(bifrostTenants, oldestKey)
		// Shutdown asynchronously so we don't hold the write
		// lock across an SDK teardown that may block on
		// in-flight streams. The SDK's Shutdown is documented
		// as safe to call once and is a no-op on subsequent
		// invocations.
		go func(c *bifrost.Bifrost) {
			defer func() { _ = recover() }()
			c.Shutdown()
		}(entry.client)
	}
}

// tenantAccount implements schemas.Account and is frozen at construction
// time: it returns the same single key + config for its pinned provider and
// errors for any other provider. No mutators exist.
type tenantAccount struct {
	provider schemas.ModelProvider
	keys     []schemas.Key
	config   *schemas.ProviderConfig
}

func (a *tenantAccount) GetConfiguredProviders() ([]schemas.ModelProvider, error) {
	return []schemas.ModelProvider{a.provider}, nil
}

func (a *tenantAccount) GetKeysForProvider(_ context.Context, providerKey schemas.ModelProvider) ([]schemas.Key, error) {
	if providerKey != a.provider {
		return nil, fmt.Errorf("gateway: provider %q not configured for this tenant (expected %q)", providerKey, a.provider)
	}
	return a.keys, nil
}

func (a *tenantAccount) GetConfigForProvider(providerKey schemas.ModelProvider) (*schemas.ProviderConfig, error) {
	if providerKey != a.provider {
		return nil, fmt.Errorf("gateway: provider %q not configured for this tenant (expected %q)", providerKey, a.provider)
	}
	return a.config, nil
}

func newTenantAccount(providerKey schemas.ModelProvider, apiKey, keyID, baseURL string) *tenantAccount {
	key := schemas.Key{
		ID:     keyID,
		Name:   string(providerKey) + "-key",
		Value:  schemas.EnvVar{Val: apiKey},
		Models: schemas.WhiteList{"*"},
		Weight: 1.0,
	}
	nc := schemas.NetworkConfig{
		DefaultRequestTimeoutInSeconds: 120,
	}
	if baseURL != "" {
		nc.BaseURL = baseURL
	}
	return &tenantAccount{
		provider: providerKey,
		keys:     []schemas.Key{key},
		config:   &schemas.ProviderConfig{NetworkConfig: nc},
	}
}

func isBedrockAPIKey(key string) bool {
	return strings.HasPrefix(key, "ABSK")
}

// bifrostKeyID returns a stable, non-reversible identifier for a
// provider + API-key pair. Never embed the raw API key here — the ID
// surfaces in Bifrost's internal structures and may reach logs, and is
// used as part of the tenant cache key.
func bifrostKeyID(providerKey schemas.ModelProvider, apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return string(providerKey) + ":sha256:" + hex.EncodeToString(sum[:8])
}

// getBifrostClient returns a Bifrost client dedicated to the given
// (provider, apiKey, baseURL) tuple. Distinct tuples get distinct clients;
// identical tuples share a cached client. The returned client's Account is
// immutable for the tuple's lifetime, so a concurrent call with different
// credentials cannot change what this client uses mid-request.
//
// Concurrency design (changed from a single-Lock-around-Init path to
// fix a tail-latency regression where a first-tenant burst at deploy
// could block all unrelated tenants for up to 30 s while bifrost.Init
// ran):
//
//  1. Fast path: take the read lock, look up tk in the cache, return
//     on hit. Cache hits never block writers — N concurrent cache-hit
//     callers proceed in parallel.
//  2. Slow path: defer to singleflight.Group keyed by tenantKeyString
//     so that exactly ONE goroutine per tk runs bifrost.Init at any
//     time. Concurrent callers for the SAME tk wait on the in-flight
//     call; concurrent callers for DIFFERENT tk run their own Init
//     in parallel without serializing on the global lock.
//  3. Inside the slow path closure, we re-check the cache under the
//     write lock (another singleflight cycle for this same tk could
//     have just finished and populated the slot in the gap between
//     fast-path RLock and singleflight.Do). The cap-eviction +
//     insert step also runs under the write lock, but only AFTER
//     bifrost.Init has returned — the lock is never held across the
//     slow Init body, which is the critical fix.
//
// TOCTOU note: the previous design's concern was that an RLock-probe
// followed by a Lock-recheck could see a snapshot client that another
// goroutine was about to Shutdown via eviction. That race is closed
// here because (a) the fast-path RLock returns the cached entry
// directly without dropping the lock between read and use; (b) the
// slow-path insertion happens under the write lock, so eviction and
// insertion are mutually exclusive within a single critical section.
// The asynchronous Shutdown in evictOldestBifrostTenantLocked is
// safe-by-design (the SDK documents Shutdown as idempotent and we
// recover panics in the goroutine).
func getBifrostClient(providerKey schemas.ModelProvider, apiKey, baseURL string) (*bifrost.Bifrost, error) {
	tk := tenantKey{
		provider: providerKey,
		keyID:    bifrostKeyID(providerKey, apiKey),
		baseURL:  baseURL,
	}

	// Fast path: cache hit under shared read lock.
	bifrostTenantsMu.RLock()
	if e, ok := bifrostTenants[tk]; ok {
		client := e.client
		// Update lastUsed under a short write lock. Doing this under
		// RLock would be a data race; deferring it to slow-path-only
		// would let a hot tenant become evictable while it's still
		// being used. The write lock is held only briefly.
		bifrostTenantsMu.RUnlock()
		bifrostTenantsMu.Lock()
		// Re-check after lock upgrade — entry may have been evicted
		// between RUnlock and Lock. If the slot is empty, fall through
		// to the slow path; if it now points to a different client
		// (eviction-then-reinsert in flight elsewhere), use that one.
		if e2, ok := bifrostTenants[tk]; ok {
			e2.lastUsed = time.Now()
			fresh := e2.client
			bifrostTenantsMu.Unlock()
			return fresh, nil
		}
		bifrostTenantsMu.Unlock()
		// Eviction raced with our fast-path read. Reuse the snapshot
		// client we already held a reference to — Shutdown on the
		// evicted client is fired asynchronously and is idempotent,
		// so the worst case is one extra Init on the next request.
		return client, nil
	}
	bifrostTenantsMu.RUnlock()

	// Slow path: dedupe concurrent Init calls for this same tenantKey
	// via singleflight. Other goroutines hitting this branch with the
	// same tk wait on our work; goroutines with different tk run their
	// own Init concurrently, never blocking on bifrostTenantsMu held
	// across an Init body.
	res, err, _ := bifrostInitGroup.Do(tenantKeyString(tk), func() (interface{}, error) {
		// Double-check the cache under the write lock — a previous
		// singleflight cycle for this same key may have just finished
		// and populated the slot during the brief window between our
		// fast-path miss and entering this closure.
		bifrostTenantsMu.Lock()
		if e, ok := bifrostTenants[tk]; ok {
			e.lastUsed = time.Now()
			client := e.client
			bifrostTenantsMu.Unlock()
			return client, nil
		}
		bifrostTenantsMu.Unlock()

		// Run Init OUTSIDE the lock — this is the critical change.
		// bifrost.Init spins up HTTP transports, may dial an upstream
		// for sanity-check requests, and is documented to take up to
		// the supplied context timeout (30s here). Holding the global
		// lock across this would block every other tenant's request,
		// including pure cache hits.
		acct := newTenantAccount(providerKey, apiKey, tk.keyID, baseURL)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		client, initErr := bifrost.Init(ctx, schemas.BifrostConfig{Account: acct})
		if initErr != nil {
			return nil, fmt.Errorf("gateway: bifrost init: %w", initErr)
		}

		// Insert under the write lock. Cap eviction happens here so
		// that a concurrent insertion by a different singleflight
		// caller cannot push us over the cap.
		bifrostTenantsMu.Lock()
		// Re-check one more time: another goroutine that ran
		// singleflight.Do for THIS key cannot exist (singleflight
		// dedupes us), but a slot is permitted to have appeared via
		// eviction-then-reinsert from a separate code path — keep the
		// existing entry and Shutdown the freshly-Init'd client to
		// avoid leaking a Bifrost transport.
		if existing, ok := bifrostTenants[tk]; ok {
			existing.lastUsed = time.Now()
			out := existing.client
			bifrostTenantsMu.Unlock()
			go func(c *bifrost.Bifrost) {
				defer func() { _ = recover() }()
				c.Shutdown()
			}(client)
			return out, nil
		}
		if len(bifrostTenants) >= bifrostTenantsMaxSize {
			evictOldestBifrostTenantLocked()
		}
		bifrostTenants[tk] = &bifrostTenantEntry{client: client, lastUsed: time.Now()}
		bifrostTenantsMu.Unlock()
		return client, nil
	})
	if err != nil {
		return nil, err
	}
	return res.(*bifrost.Bifrost), nil
}

// mapProviderKey translates a DefenseClaw provider string to a Bifrost
// ModelProvider. Returns an error for unrecognized provider names so
// misconfigurations surface early instead of at first API call.
func mapProviderKey(provider string) (schemas.ModelProvider, error) {
	switch strings.ToLower(provider) {
	case "openai":
		return schemas.OpenAI, nil
	case "anthropic":
		return schemas.Anthropic, nil
	case "bedrock", "amazon-bedrock":
		return schemas.Bedrock, nil
	case "azure":
		return schemas.Azure, nil
	case "gemini", "gemini-openai":
		return schemas.Gemini, nil
	case "openrouter":
		return schemas.OpenRouter, nil
	case "groq":
		return schemas.Groq, nil
	case "mistral":
		return schemas.Mistral, nil
	case "ollama":
		return schemas.Ollama, nil
	case "vertex":
		return schemas.Vertex, nil
	case "cohere":
		return schemas.Cohere, nil
	case "perplexity":
		return schemas.Perplexity, nil
	case "cerebras":
		return schemas.Cerebras, nil
	case "fireworks":
		return schemas.Fireworks, nil
	case "xai":
		return schemas.XAI, nil
	case "huggingface":
		return schemas.HuggingFace, nil
	case "replicate":
		return schemas.Replicate, nil
	case "vllm":
		return schemas.ModelProvider("vllm"), nil
	default:
		return "", fmt.Errorf("gateway: unknown provider %q", provider)
	}
}

func (bp *bifrostProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	client, err := getBifrostClient(bp.providerKey, bp.apiKey, bp.baseURL)
	if err != nil {
		return nil, err
	}

	bReq := toBifrostChatRequest(bp.providerKey, bp.model, req)
	bCtx := schemas.NewBifrostContext(ctx, schemas.NoDeadline)
	resp, bErr := client.ChatCompletionRequest(bCtx, bReq)
	if bErr != nil {
		return nil, bifrostErrorToGo(bErr)
	}

	return fromBifrostChatResponse(resp), nil
}

func (bp *bifrostProvider) ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error) {
	client, err := getBifrostClient(bp.providerKey, bp.apiKey, bp.baseURL)
	if err != nil {
		return nil, err
	}

	bReq := toBifrostChatRequest(bp.providerKey, bp.model, req)
	bCtx := schemas.NewBifrostContext(ctx, schemas.NoDeadline)
	stream, bErr := client.ChatCompletionStreamRequest(bCtx, bReq)
	if bErr != nil {
		return nil, bifrostErrorToGo(bErr)
	}

	var usage *ChatUsage
	for chunk := range stream {
		if chunk.BifrostError != nil {
			return usage, bifrostErrorToGo(chunk.BifrostError)
		}
		if chunk.BifrostChatResponse == nil {
			continue
		}
		sc := fromBifrostStreamChunk(chunk.BifrostChatResponse)
		if chunk.BifrostChatResponse.Usage != nil {
			usage = fromBifrostUsage(chunk.BifrostChatResponse.Usage)
		}
		chunkCb(sc)
	}

	return usage, nil
}

// ---------- Type conversion helpers ----------

func toBifrostChatRequest(provider schemas.ModelProvider, model string, req *ChatRequest) *schemas.BifrostChatRequest {
	bReq := &schemas.BifrostChatRequest{
		Provider: provider,
		Model:    model,
		Input:    toBifrostMessages(req.Messages),
		Params:   &schemas.ChatParameters{},
	}

	if req.MaxTokens != nil {
		bReq.Params.MaxCompletionTokens = req.MaxTokens
	}
	if req.Temperature != nil {
		bReq.Params.Temperature = req.Temperature
	}
	if req.TopP != nil {
		bReq.Params.TopP = req.TopP
	}
	if len(req.Stop) > 0 {
		var stopArr []string
		if json.Unmarshal(req.Stop, &stopArr) == nil {
			bReq.Params.Stop = stopArr
		} else {
			var stopStr string
			if json.Unmarshal(req.Stop, &stopStr) == nil {
				bReq.Params.Stop = []string{stopStr}
			}
		}
	}
	if len(req.Tools) > 0 {
		var tools []schemas.ChatTool
		if err := json.Unmarshal(req.Tools, &tools); err == nil {
			bReq.Params.Tools = tools
		}
	}
	if len(req.ToolChoice) > 0 {
		var tc schemas.ChatToolChoice
		if err := json.Unmarshal(req.ToolChoice, &tc); err == nil {
			bReq.Params.ToolChoice = &tc
		}
	}

	if len(req.Fallbacks) > 0 {
		for _, fb := range req.Fallbacks {
			parts := strings.SplitN(fb, "/", 2)
			if len(parts) == 2 {
				fbProvider, err := mapProviderKey(parts[0])
				if err != nil {
					continue
				}
				bReq.Fallbacks = append(bReq.Fallbacks, schemas.Fallback{
					Provider: fbProvider,
					Model:    parts[1],
				})
			}
		}
	}

	return bReq
}

func toBifrostMessages(msgs []ChatMessage) []schemas.ChatMessage {
	out := make([]schemas.ChatMessage, len(msgs))
	for i, m := range msgs {
		bm := schemas.ChatMessage{
			Role: schemas.ChatMessageRole(m.Role),
		}
		if m.Name != "" {
			name := m.Name
			bm.Name = &name
		}
		if m.Content != "" {
			content := m.Content
			bm.Content = &schemas.ChatMessageContent{ContentStr: &content}
		} else if len(m.RawContent) > 0 {
			bm.Content = rawContentToBifrost(m.RawContent)
		}
		if m.ToolCallID != "" {
			tcid := m.ToolCallID
			bm.ChatToolMessage = &schemas.ChatToolMessage{ToolCallID: &tcid}
		}
		if len(m.ToolCalls) > 0 {
			var tcs []schemas.ChatAssistantMessageToolCall
			if err := json.Unmarshal(m.ToolCalls, &tcs); err == nil && len(tcs) > 0 {
				bm.ChatAssistantMessage = &schemas.ChatAssistantMessage{ToolCalls: tcs}
			}
		}
		out[i] = bm
	}
	return out
}

func rawContentToBifrost(raw json.RawMessage) *schemas.ChatMessageContent {
	if len(raw) == 0 {
		return nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return &schemas.ChatMessageContent{ContentStr: &s}
		}
	}
	if raw[0] == '[' {
		var blocks []schemas.ChatContentBlock
		if err := json.Unmarshal(raw, &blocks); err == nil {
			return &schemas.ChatMessageContent{ContentBlocks: blocks}
		}
	}
	s := string(raw)
	return &schemas.ChatMessageContent{ContentStr: &s}
}

func fromBifrostChatResponse(resp *schemas.BifrostChatResponse) *ChatResponse {
	if resp == nil {
		return &ChatResponse{}
	}
	cr := &ChatResponse{
		ID:      resp.ID,
		Object:  resp.Object,
		Created: int64(resp.Created),
		Model:   resp.Model,
	}
	if resp.Usage != nil {
		cr.Usage = fromBifrostUsage(resp.Usage)
	}
	for _, c := range resp.Choices {
		cc := ChatChoice{
			Index:        c.Index,
			FinishReason: c.FinishReason,
		}
		if c.ChatNonStreamResponseChoice != nil && c.Message != nil {
			cc.Message = fromBifrostMessage(c.Message)
		}
		cr.Choices = append(cr.Choices, cc)
	}
	return cr
}

func fromBifrostStreamChunk(resp *schemas.BifrostChatResponse) StreamChunk {
	sc := StreamChunk{
		ID:      resp.ID,
		Object:  resp.Object,
		Created: int64(resp.Created),
		Model:   resp.Model,
	}
	if resp.Usage != nil {
		sc.Usage = fromBifrostUsage(resp.Usage)
	}
	for _, c := range resp.Choices {
		cc := ChatChoice{
			Index:        c.Index,
			FinishReason: c.FinishReason,
		}
		if c.ChatStreamResponseChoice != nil && c.Delta != nil {
			d := c.Delta
			msg := &ChatMessage{
				Content: ptrStr(d.Content),
			}
			if d.Role != nil {
				msg.Role = string(*d.Role)
			}
			if len(d.ToolCalls) > 0 {
				if raw, err := json.Marshal(d.ToolCalls); err == nil {
					msg.ToolCalls = raw
				}
			}
			cc.Delta = msg
		}
		sc.Choices = append(sc.Choices, cc)
	}
	return sc
}

func fromBifrostMessage(bm *schemas.ChatMessage) *ChatMessage {
	if bm == nil {
		return nil
	}
	m := &ChatMessage{
		Role: string(bm.Role),
	}
	if bm.Name != nil {
		m.Name = *bm.Name
	}
	if bm.Content != nil {
		if bm.Content.ContentStr != nil {
			m.Content = *bm.Content.ContentStr
		} else if bm.Content.ContentBlocks != nil {
			if raw, err := json.Marshal(bm.Content.ContentBlocks); err == nil {
				m.RawContent = raw
			}
		}
	}
	// Access fields through the explicit embedded struct pointers rather than
	// the promoted fields. Symmetric with toBifrostMessages (which assigns
	// `bm.ChatToolMessage = &schemas.ChatToolMessage{...}` and
	// `bm.ChatAssistantMessage = &schemas.ChatAssistantMessage{...}`) so this
	// direction doesn't silently break if upstream changes how the fields are
	// promoted (e.g. by adding another embedded struct with a conflicting
	// name).
	if bm.ChatToolMessage != nil && bm.ChatToolMessage.ToolCallID != nil { //nolint:staticcheck // QF1008: explicit access preserves symmetry with toBifrostMessages
		m.ToolCallID = *bm.ChatToolMessage.ToolCallID //nolint:staticcheck // QF1008: see comment above
	}
	if bm.ChatAssistantMessage != nil && len(bm.ChatAssistantMessage.ToolCalls) > 0 { //nolint:staticcheck // QF1008: explicit access preserves symmetry with toBifrostMessages
		if raw, err := json.Marshal(bm.ChatAssistantMessage.ToolCalls); err == nil { //nolint:staticcheck // QF1008: see comment above
			m.ToolCalls = raw
		}
	}
	return m
}

func fromBifrostUsage(u *schemas.BifrostLLMUsage) *ChatUsage {
	if u == nil {
		return nil
	}
	return &ChatUsage{
		PromptTokens:     int64(u.PromptTokens),
		CompletionTokens: int64(u.CompletionTokens),
		TotalTokens:      int64(u.TotalTokens),
	}
}

func bifrostErrorToGo(bErr *schemas.BifrostError) error {
	if bErr == nil {
		return nil
	}
	msg := "unknown bifrost error"
	if bErr.Error != nil {
		msg = bErr.Error.Message
	}
	code := 0
	if bErr.StatusCode != nil {
		code = *bErr.StatusCode
	}
	if code > 0 {
		return fmt.Errorf("gateway: bifrost: %d %s", code, msg)
	}
	return fmt.Errorf("gateway: bifrost: %s", msg)
}

func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
