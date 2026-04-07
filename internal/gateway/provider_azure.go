package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// azureAPIVersion is now AzureAPIVersion in constants.go

type azureOpenAIProvider struct {
	model   string
	apiKey  string
	baseURL string
}

func (p *azureOpenAIProvider) chatURL() string {
	base := strings.TrimRight(p.baseURL, "/")
	// Normalize Foundry-style base URLs (ending in /openai/v1 or /openai/v1/)
	// to the classic deployments path format that Azure expects.
	// openai/v1 → openai/deployments/{deployment}/chat/completions
	for _, suffix := range []string{"/openai/v1", "/v1"} {
		if strings.HasSuffix(base, suffix) {
			base = strings.TrimSuffix(base, suffix)
			break
		}
	}
	base = strings.TrimRight(base, "/")
	return fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
		base, p.model, AzureAPIVersion)
}

func (p *azureOpenAIProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
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

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.chatURL(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(HeaderAzureAPIKey, p.apiKey)

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

func (p *azureOpenAIProvider) ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error) {
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

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.chatURL(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(HeaderAzureAPIKey, p.apiKey)

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
