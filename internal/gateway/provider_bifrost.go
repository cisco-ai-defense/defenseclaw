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
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
)

// bifrostProvider implements LLMProvider by delegating to the Bifrost Go SDK.
// A single Bifrost client instance is shared across all requests via a
// package-level singleton, initialized lazily on first use.
type bifrostProvider struct {
	providerKey schemas.ModelProvider
	model       string
	apiKey      string
	baseURL     string
}

var (
	bifrostMu       sync.Mutex
	bifrostClient   *bifrost.Bifrost
	bifrostAccMu    sync.Mutex
	bifrostAccounts = make(map[schemas.ModelProvider]*providerAccount)
	bifrostUpdated  = make(map[schemas.ModelProvider]bool)
)

// providerAccount holds per-provider key and config data for the Bifrost
// Account interface.
type providerAccount struct {
	keys   []schemas.Key
	config *schemas.ProviderConfig
}

// globalBifrostAccount implements schemas.Account, returning keys and configs
// that have been registered by bifrostProvider instances.
type globalBifrostAccount struct{}

func (a *globalBifrostAccount) GetConfiguredProviders() ([]schemas.ModelProvider, error) {
	bifrostAccMu.Lock()
	defer bifrostAccMu.Unlock()
	providers := make([]schemas.ModelProvider, 0, len(bifrostAccounts))
	for k := range bifrostAccounts {
		providers = append(providers, k)
	}
	return providers, nil
}

func (a *globalBifrostAccount) GetKeysForProvider(_ context.Context, providerKey schemas.ModelProvider) ([]schemas.Key, error) {
	bifrostAccMu.Lock()
	defer bifrostAccMu.Unlock()
	acc, ok := bifrostAccounts[providerKey]
	if !ok {
		return nil, fmt.Errorf("gateway: no keys configured for provider %q", providerKey)
	}
	return acc.keys, nil
}

func (a *globalBifrostAccount) GetConfigForProvider(providerKey schemas.ModelProvider) (*schemas.ProviderConfig, error) {
	bifrostAccMu.Lock()
	defer bifrostAccMu.Unlock()
	acc, ok := bifrostAccounts[providerKey]
	if !ok {
		return nil, fmt.Errorf("gateway: no config for provider %q", providerKey)
	}
	return acc.config, nil
}

// registerProvider ensures the given provider/key/baseURL combo is registered
// with the global account so that the Bifrost client can route to it.
// If the provider already exists but the key or baseURL changed, the
// registration is updated and the provider is marked for re-sync.
func registerProvider(providerKey schemas.ModelProvider, apiKey, baseURL string) (changed bool) {
	bifrostAccMu.Lock()
	defer bifrostAccMu.Unlock()

	keyID := string(providerKey) + ":" + apiKey

	if existing, ok := bifrostAccounts[providerKey]; ok {
		same := len(existing.keys) == 1 &&
			existing.keys[0].ID == keyID &&
			existing.config.NetworkConfig.BaseURL == baseURL
		if same {
			return false
		}
		delete(bifrostUpdated, providerKey)
	}

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

	bifrostAccounts[providerKey] = &providerAccount{
		keys: []schemas.Key{key},
		config: &schemas.ProviderConfig{
			NetworkConfig: nc,
		},
	}
	return true
}

func isBedrockAPIKey(key string) bool {
	return strings.HasPrefix(key, "ABSK")
}

// getBifrostClient returns a lazily-initialized, shared Bifrost client.
// If the initial Init call fails, subsequent calls retry instead of
// permanently returning the cached error.
func getBifrostClient(providerKey schemas.ModelProvider, apiKey, baseURL string) (*bifrost.Bifrost, error) {
	regChanged := registerProvider(providerKey, apiKey, baseURL)

	bifrostMu.Lock()
	defer bifrostMu.Unlock()

	if bifrostClient == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		client, err := bifrost.Init(ctx, schemas.BifrostConfig{
			Account: &globalBifrostAccount{},
		})
		if err != nil {
			return nil, fmt.Errorf("gateway: bifrost init: %w", err)
		}
		bifrostClient = client
	}

	bifrostAccMu.Lock()
	alreadyUpdated := bifrostUpdated[providerKey]
	bifrostAccMu.Unlock()

	if !alreadyUpdated || regChanged {
		if err := bifrostClient.UpdateProvider(providerKey); err != nil {
			return nil, fmt.Errorf("gateway: bifrost update provider %s: %w", providerKey, err)
		}
		bifrostAccMu.Lock()
		bifrostUpdated[providerKey] = true
		bifrostAccMu.Unlock()
	}

	return bifrostClient, nil
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
	case "bedrock":
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
	if bm.ChatToolMessage != nil && bm.ToolCallID != nil {
		m.ToolCallID = *bm.ToolCallID
	}
	if bm.ChatAssistantMessage != nil && len(bm.ToolCalls) > 0 {
		if raw, err := json.Marshal(bm.ToolCalls); err == nil {
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
