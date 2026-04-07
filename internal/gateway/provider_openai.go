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

// ---------------------------------------------------------------------------
// OpenAI provider — pass-through
// ---------------------------------------------------------------------------

type openaiProvider struct {
	model   string
	apiKey  string
	baseURL string
}

// patchRawBody takes raw JSON bytes and overrides the "model" and "stream"
// fields, preserving every other field the client sent (response_format,
// seed, frequency_penalty, parallel_tool_calls, logit_bias, etc.).
// It also caps max_tokens to the model's limit to avoid 400 errors when
// the upstream client was configured for a different model family.
func patchRawBody(raw json.RawMessage, model string, stream bool) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("provider: patch raw body: %w", err)
	}
	modelBytes, _ := json.Marshal(model)
	m["model"] = modelBytes
	streamBytes, _ := json.Marshal(stream)
	m["stream"] = streamBytes

	limit := modelMaxTokens(model)
	for _, tokKey := range []string{"max_tokens", "max_completion_tokens"} {
		if maxTokRaw, ok := m[tokKey]; ok {
			var maxTok int
			if json.Unmarshal(maxTokRaw, &maxTok) == nil && limit > 0 && maxTok > limit {
				capBytes, _ := json.Marshal(limit)
				m[tokKey] = capBytes
			}
		}
	}

	return json.Marshal(m)
}

// modelMaxTokens returns the max completion tokens for known models.
// Returns 0 for unknown models (no capping applied).
func modelMaxTokens(model string) int {
	switch {
	case strings.HasPrefix(model, "gpt-4o-mini"):
		return 16384
	case strings.HasPrefix(model, "gpt-4o"):
		return 16384
	case strings.HasPrefix(model, "gpt-4-turbo"):
		return 4096
	case strings.HasPrefix(model, "gpt-4"):
		return 8192
	case strings.HasPrefix(model, "o3-mini"):
		return 100000
	case strings.HasPrefix(model, "o3"):
		return 100000
	case strings.HasPrefix(model, "o4-mini"):
		return 100000
	default:
		return 0
	}
}

func (p *openaiProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	var body []byte
	var err error

	if len(req.RawBody) > 0 {
		body, err = patchRawBody(req.RawBody, p.model, false)
	} else {
		req.Model = p.model
		req.Stream = false
		body, err = json.Marshal(req)
	}
	if err != nil {
		return nil, fmt.Errorf("provider: marshal request: %w", err)
	}

	url := p.baseURL + "/v1/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := providerHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("provider: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("provider: upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	rawResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("provider: read response: %w", err)
	}

	var chatResp ChatResponse
	if err := json.Unmarshal(rawResp, &chatResp); err != nil {
		return nil, fmt.Errorf("provider: decode response: %w", err)
	}
	chatResp.RawResponse = rawResp
	return &chatResp, nil
}

func (p *openaiProvider) ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error) {
	var body []byte
	var err error

	if len(req.RawBody) > 0 {
		body, err = patchRawBody(req.RawBody, p.model, true)
	} else {
		req.Model = p.model
		req.Stream = true
		body, err = json.Marshal(req)
	}
	if err != nil {
		return nil, fmt.Errorf("provider: marshal request: %w", err)
	}

	url := p.baseURL + "/v1/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := providerHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("provider: stream request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("provider: upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	return readOpenAISSE(resp.Body, chunkCb)
}

func readOpenAISSE(r io.Reader, cb func(StreamChunk)) (*ChatUsage, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 256*1024)
	var usage *ChatUsage

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
		cb(chunk)
	}
	return usage, scanner.Err()
}
