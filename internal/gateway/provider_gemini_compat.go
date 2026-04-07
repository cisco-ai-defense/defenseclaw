package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// geminiCompatDefaultBase is now DefaultGeminiCompatBaseURL in constants.go

type geminiCompatProvider struct {
	model   string
	apiKey  string
	baseURL string
}

func (p *geminiCompatProvider) effectiveBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return DefaultGeminiCompatBaseURL
}

func (p *geminiCompatProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
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

	url := p.effectiveBase() + "/chat/completions"
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
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorResponseSize))
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

func (p *geminiCompatProvider) ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error) {
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

	url := p.effectiveBase() + "/chat/completions"
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
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorResponseSize))
		return nil, fmt.Errorf("provider: upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	return readOpenAISSE(resp.Body, chunkCb)
}
