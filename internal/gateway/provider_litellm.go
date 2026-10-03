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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// contextKeyExtraHeaders is a context key for forwarding inbound HTTP headers
// to the upstream provider. Replaces the former Bifrost context key.
type extraHeadersKeyType struct{}

var contextKeyExtraHeaders = extraHeadersKeyType{}

// litellmProvider implements LLMProvider by forwarding requests to a local
// LiteLLM sidecar over HTTP. The sidecar handles all provider-specific
// API differences (auth, request format, streaming) so this provider is
// a thin OpenAI-compatible HTTP client.
type litellmProvider struct {
	// model is the "provider/model-name" string forwarded to LiteLLM.
	model string
	// apiKey is forwarded as the Authorization bearer token.
	apiKey string
	// baseURL is the LiteLLM sidecar endpoint (e.g. "http://127.0.0.1:4001").
	baseURL string
	// extraHeaders are forwarded verbatim to the upstream.
	extraHeaders map[string]string
}

func (lp *litellmProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	body, err := lp.buildRequestBody(req, false)
	if err != nil {
		return nil, fmt.Errorf("litellm: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		lp.baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("litellm: create request: %w", err)
	}
	lp.setHeaders(httpReq)

	resp, err := providerHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("litellm: do request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("litellm: read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("litellm: upstream error %d: %s", resp.StatusCode, truncateErrBody(string(respBody), 500))
	}

	var chatResp ChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("litellm: unmarshal response: %w", err)
	}
	chatResp.RawResponse = respBody
	return &chatResp, nil
}

func (lp *litellmProvider) ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error) {
	body, err := lp.buildRequestBody(req, true)
	if err != nil {
		return nil, fmt.Errorf("litellm: marshal stream request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		lp.baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("litellm: create stream request: %w", err)
	}
	lp.setHeaders(httpReq)

	resp, err := providerHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("litellm: do stream request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("litellm: upstream stream error %d: %s", resp.StatusCode, truncateErrBody(string(errBody), 500))
	}

	var usage *ChatUsage
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}
		var chunk StreamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		if chunk.Usage != nil {
			usage = chunk.Usage
		}
		chunkCb(chunk)
	}

	return usage, scanner.Err()
}

func (lp *litellmProvider) buildRequestBody(req *ChatRequest, stream bool) ([]byte, error) {
	if req.RawBody != nil {
		var raw map[string]interface{}
		if err := json.Unmarshal(req.RawBody, &raw); err == nil {
			raw["model"] = lp.model
			raw["stream"] = stream
			return json.Marshal(raw)
		}
	}

	payload := map[string]interface{}{
		"model":    lp.model,
		"messages": req.Messages,
		"stream":   stream,
	}
	if req.MaxTokens != nil {
		payload["max_tokens"] = *req.MaxTokens
	}
	if req.Temperature != nil {
		payload["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		payload["top_p"] = *req.TopP
	}
	if req.FrequencyPenalty != nil {
		payload["frequency_penalty"] = *req.FrequencyPenalty
	}
	if req.PresencePenalty != nil {
		payload["presence_penalty"] = *req.PresencePenalty
	}
	if len(req.Stop) > 0 {
		payload["stop"] = json.RawMessage(req.Stop)
	}
	if len(req.Tools) > 0 {
		payload["tools"] = json.RawMessage(req.Tools)
	}
	if len(req.ToolChoice) > 0 {
		payload["tool_choice"] = json.RawMessage(req.ToolChoice)
	}
	if len(req.ResponseFormat) > 0 {
		payload["response_format"] = json.RawMessage(req.ResponseFormat)
	}
	return json.Marshal(payload)
}

func (lp *litellmProvider) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	if lp.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+lp.apiKey)
	}
	for k, v := range lp.extraHeaders {
		req.Header.Set(k, v)
	}
}

func truncateErrBody(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
