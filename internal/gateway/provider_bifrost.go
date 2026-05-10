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
	"os"
	"strings"
	"sync"
	"time"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// bifrostProvider implements LLMProvider by delegating to the Bifrost Go SDK.
// Each distinct (providerKey, apiKey, baseURL, tls, sub-block) tuple gets its
// own dedicated Bifrost client with an immutable Account, so credentials,
// endpoints, regional posture, and TLS posture for one tenant are isolated
// from other in-flight requests.
type bifrostProvider struct {
	providerKey schemas.ModelProvider
	model       string
	apiKey      string
	baseURL     string
	tls         tlsOverrides
	// Effective per-provider sub-blocks (role wins, overlay fills
	// blanks; see NewProviderForLLMConfig). Pointer-typed so an
	// absent block contributes nothing to the Bifrost Key.
	bedrock *config.BedrockKeyConfig
	vertex  *config.VertexKeyConfig
	azure   *config.AzureKeyConfig
}

// tenantKey identifies a unique (provider, api-key, base-url, tls, sub-block)
// tuple. Each tuple gets its own dedicated Bifrost client + frozen Account so
// that credentials and endpoints for one tenant can never leak into an
// in-flight request for another. Previously a single package-level client +
// mutable account map was shared across all tenants: two concurrent requests
// hitting the same provider with different keys or base URLs could race so
// that the Bifrost client executed request A using tenant B's credentials.
//
// “tlsID“ is a sha256 of the TLS posture (insecure_skip_verify || ca_cert_pem)
// so two custom-provider instances with the same base URL but different TLS
// trust stores get distinct clients and cannot share connections.
//
// “subID“ is a sha256 of the per-provider sub-block (Bedrock region,
// Vertex project, Azure endpoint, deployment aliases, ...) so two
// instances differing only in region or auth mode never share a
// Bifrost client and never confuse their dispatch routing.
type tenantKey struct {
	provider schemas.ModelProvider
	keyID    string // sha256 of apiKey — the raw key is never in the map key.
	baseURL  string
	tlsID    string // sha256 of tls posture; empty when no per-instance TLS overrides.
	subID    string // sha256 of per-provider sub-block; empty when none set.
}

// tlsOverrides bundles the per-instance TLS knobs from a custom-providers
// overlay. Both fields are forwarded to the Bifrost “NetworkConfig“ which
// already supports custom CA bundles and TLS-skip; this type just keeps the
// API on our side cohesive.
type tlsOverrides struct {
	CACertPEM          string
	InsecureSkipVerify bool
}

func (t tlsOverrides) isZero() bool {
	return !t.InsecureSkipVerify && t.CACertPEM == ""
}

func (t tlsOverrides) id() string {
	if t.isZero() {
		return ""
	}
	h := sha256.New()
	if t.InsecureSkipVerify {
		_, _ = h.Write([]byte("insecure;"))
	}
	_, _ = h.Write([]byte("ca="))
	_, _ = h.Write([]byte(t.CACertPEM))
	sum := h.Sum(nil)
	return "tls:sha256:" + hex.EncodeToString(sum[:8])
}

// bifrostTenantsMaxSize bounds the in-memory tenant client cache.
// ("Bifrost tenant client cache grows without
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

// envOr resolves an env-var name to its current value (trimmed); empty
// env-var name returns the empty string. Centralised so the dispatcher
// can lift per-instance secrets from the env without sprinkling Getenv
// calls through provider-specific branches.
func envOr(name string) string {
	if name == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(name))
}

// awsProfileOnce serializes process-wide AWS_PROFILE writes so two
// concurrent dispatches for different Bedrock instances cannot race on
// the env var. Bifrost has no per-key profile-name field, so the only
// reliable handoff to the AWS default credential chain is the env var
// itself. The first profile to win is logged; any conflicting second
// caller is dropped with a warning (operators must reach for
// iam_credentials or instance_role to mix profiles in one process).
var (
	awsProfileMu      sync.Mutex
	awsProfileApplied string
)

func applyAWSProfile(profile string) {
	if profile == "" {
		return
	}
	awsProfileMu.Lock()
	defer awsProfileMu.Unlock()
	if awsProfileApplied == profile {
		return
	}
	if awsProfileApplied != "" && awsProfileApplied != profile {
		fmt.Fprintf(os.Stderr,
			"[gateway] AWS_PROFILE already pinned to %q; refusing to switch to %q. "+
				"Use iam_credentials or instance_role to mix Bedrock profiles in one process.\n",
			awsProfileApplied, profile)
		return
	}
	_ = os.Setenv("AWS_PROFILE", profile)
	awsProfileApplied = profile
	fmt.Fprintf(os.Stderr,
		"[gateway] AWS_PROFILE set to %q for the lifetime of this process (Bedrock dispatch).\n",
		profile)
}

func newTenantAccount(
	providerKey schemas.ModelProvider,
	apiKey, keyID, baseURL string,
	tls tlsOverrides,
	bedrock *config.BedrockKeyConfig,
	vertex *config.VertexKeyConfig,
	azure *config.AzureKeyConfig,
) *tenantAccount {
	key := schemas.Key{
		ID:     keyID,
		Name:   string(providerKey) + "-key",
		Value:  schemas.EnvVar{Val: apiKey},
		Models: schemas.WhiteList{"*"},
		Weight: 1.0,
	}

	// Bedrock posture → Bifrost BedrockKeyConfig. Auth modes:
	//   - "api_key":         key.Value carries the API key (already set).
	//   - "iam_credentials": access-key + secret-key env vars supply the creds.
	//   - "profile":         AWS_PROFILE applied process-wide before init.
	//   - "instance_role":   leave AccessKey/SecretKey empty so Bifrost
	//                        falls through to the default credential chain.
	if providerKey == schemas.Bedrock && bedrock != nil {
		bcfg := &schemas.BedrockKeyConfig{}
		mode := strings.ToLower(strings.TrimSpace(bedrock.AuthMode))
		switch mode {
		case "iam_credentials":
			bcfg.AccessKey = schemas.EnvVar{Val: envOr(bedrock.AccessKeyEnv), EnvVar: bedrock.AccessKeyEnv, FromEnv: bedrock.AccessKeyEnv != ""}
			bcfg.SecretKey = schemas.EnvVar{Val: envOr(bedrock.SecretKeyEnv), EnvVar: bedrock.SecretKeyEnv, FromEnv: bedrock.SecretKeyEnv != ""}
			if bedrock.SessionTokenEnv != "" {
				bcfg.SessionToken = &schemas.EnvVar{Val: envOr(bedrock.SessionTokenEnv), EnvVar: bedrock.SessionTokenEnv, FromEnv: true}
			}
		case "profile":
			applyAWSProfile(bedrock.ProfileName)
			// Bifrost reads default cred chain when AccessKey/SecretKey are empty.
		case "instance_role":
			// Leave AccessKey/SecretKey empty for IMDS / IRSA / ECS task creds.
		default:
			// "api_key" or unspecified — key.Value already carries the bearer token.
		}
		if bedrock.Region != "" {
			bcfg.Region = &schemas.EnvVar{Val: bedrock.Region}
		}
		key.BedrockKeyConfig = bcfg
		if len(bedrock.DeploymentAliases) > 0 {
			key.Aliases = schemas.KeyAliases(bedrock.DeploymentAliases)
		}
	}

	// Vertex posture → Bifrost VertexKeyConfig. Auth modes:
	//   - "service_account":   env var holds the JSON; AuthCredentials populated.
	//   - "adc" / "workload_identity": leave AuthCredentials empty so
	//     Bifrost falls through to the default credential chain.
	if providerKey == schemas.Vertex && vertex != nil {
		vcfg := &schemas.VertexKeyConfig{
			ProjectID: schemas.EnvVar{Val: vertex.ProjectID},
			Region:    schemas.EnvVar{Val: vertex.Region},
		}
		mode := strings.ToLower(strings.TrimSpace(vertex.AuthMode))
		if mode == "service_account" && vertex.ServiceAccountJSONEnv != "" {
			vcfg.AuthCredentials = schemas.EnvVar{
				Val:     envOr(vertex.ServiceAccountJSONEnv),
				EnvVar:  vertex.ServiceAccountJSONEnv,
				FromEnv: true,
			}
		}
		key.VertexKeyConfig = vcfg
	}

	// Azure posture → Bifrost AzureKeyConfig. Auth modes:
	//   - "api_key":          key.Value carries the API key (already set).
	//   - "managed_identity": Bifrost defers to AAD; leave Client*/Tenant*
	//                         nil so the default-credential chain runs.
	if providerKey == schemas.Azure && azure != nil {
		acfg := &schemas.AzureKeyConfig{
			Endpoint: schemas.EnvVar{Val: azure.Endpoint},
		}
		if azure.APIVersion != "" {
			acfg.APIVersion = &schemas.EnvVar{Val: azure.APIVersion}
		}
		key.AzureKeyConfig = acfg
		if len(azure.DeploymentAliases) > 0 {
			key.Aliases = schemas.KeyAliases(azure.DeploymentAliases)
		}
	}

	nc := schemas.NetworkConfig{
		DefaultRequestTimeoutInSeconds: 120,
	}
	if baseURL != "" {
		nc.BaseURL = baseURL
	}
	if tls.InsecureSkipVerify {
		nc.InsecureSkipVerify = true
	}
	if tls.CACertPEM != "" {
		nc.CACertPEM = tls.CACertPEM
	}
	return &tenantAccount{
		provider: providerKey,
		keys:     []schemas.Key{key},
		config:   &schemas.ProviderConfig{NetworkConfig: nc},
	}
}

// subBlockID returns a stable hash of the per-provider sub-block so two
// instances with the same API key + base URL but different regions or
// deployment aliases get distinct Bifrost clients. Pointer-nil + empty
// fields collapse to "" so a role with no sub-blocks behaves
// identically to before this change.
func subBlockID(bedrock *config.BedrockKeyConfig, vertex *config.VertexKeyConfig, azure *config.AzureKeyConfig) string {
	if bedrock == nil && vertex == nil && azure == nil {
		return ""
	}
	h := sha256.New()
	enc := json.NewEncoder(h)
	// json.Marshal would allocate a buffer per call; reusing the same
	// stream encoder keeps the hash cost in the noise even for
	// hot-path dispatches.
	if bedrock != nil {
		_, _ = h.Write([]byte("b:"))
		_ = enc.Encode(bedrock)
	}
	if vertex != nil {
		_, _ = h.Write([]byte("v:"))
		_ = enc.Encode(vertex)
	}
	if azure != nil {
		_, _ = h.Write([]byte("a:"))
		_ = enc.Encode(azure)
	}
	sum := h.Sum(nil)
	return "sub:sha256:" + hex.EncodeToString(sum[:8])
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
// (provider, apiKey, baseURL, tls, sub-block) tuple. Distinct tuples get
// distinct clients; identical tuples share a cached client. The
// returned client's Account is immutable for the tuple's lifetime, so a
// concurrent call with different credentials cannot change what this
// client uses mid-request.
func getBifrostClient(
	providerKey schemas.ModelProvider,
	apiKey, baseURL string,
	tls tlsOverrides,
	bedrock *config.BedrockKeyConfig,
	vertex *config.VertexKeyConfig,
	azure *config.AzureKeyConfig,
) (*bifrost.Bifrost, error) {
	tk := tenantKey{
		provider: providerKey,
		keyID:    bifrostKeyID(providerKey, apiKey),
		baseURL:  baseURL,
		tlsID:    tls.id(),
		subID:    subBlockID(bedrock, vertex, azure),
	}

	now := time.Now()
	// Single Lock path. The previous double-checked-locking variant
	// had an RLock-probe + Lock-recheck, which sounded like a fast
	// path but was actually a TOCTOU footgun: between dropping RLock
	// and acquiring Lock, a concurrent eviction could call
	// client.Shutdown() on the snapshot client we were about to
	// return. With the cache capped at bifrostTenantsMaxSize entries
	// and lookups being a single map read, the lock contention from a
	// pure write-lock path is negligible compared to the work we're
	// otherwise doing (Bifrost's per-request payload assembly and
	// upstream HTTP). The simpler model also lets us hold the lock
	// across the cap-eviction and slow-path re-init below without any
	// further race.
	bifrostTenantsMu.Lock()
	defer bifrostTenantsMu.Unlock()
	if e, ok := bifrostTenants[tk]; ok {
		e.lastUsed = now
		return e.client, nil
	}
	if len(bifrostTenants) >= bifrostTenantsMaxSize {
		evictOldestBifrostTenantLocked()
	}

	acct := newTenantAccount(providerKey, apiKey, tk.keyID, baseURL, tls, bedrock, vertex, azure)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := bifrost.Init(ctx, schemas.BifrostConfig{Account: acct})
	if err != nil {
		return nil, fmt.Errorf("gateway: bifrost init: %w", err)
	}
	bifrostTenants[tk] = &bifrostTenantEntry{client: client, lastUsed: now}
	return client, nil
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
	client, err := getBifrostClient(bp.providerKey, bp.apiKey, bp.baseURL, bp.tls, bp.bedrock, bp.vertex, bp.azure)
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
	client, err := getBifrostClient(bp.providerKey, bp.apiKey, bp.baseURL, bp.tls, bp.bedrock, bp.vertex, bp.azure)
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
