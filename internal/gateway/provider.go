package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

// ChatMessage is the OpenAI-compatible message format used as the canonical
// representation throughout the proxy. Content can be a plain string or an
// array of content blocks ([{"type":"text","text":"..."}]).
type ChatMessage struct {
	Role       string          `json:"role"`
	Content    string          `json:"-"`
	RawContent json.RawMessage `json:"content,omitempty"`
	ToolCalls  json.RawMessage `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
	Name       string          `json:"name,omitempty"`
}

func (m *ChatMessage) UnmarshalJSON(data []byte) error {
	type plain struct {
		Role       string          `json:"role"`
		Content    json.RawMessage `json:"content,omitempty"`
		ToolCalls  json.RawMessage `json:"tool_calls,omitempty"`
		ToolCallID string          `json:"tool_call_id,omitempty"`
		Name       string          `json:"name,omitempty"`
	}
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	m.Role = p.Role
	m.RawContent = p.Content
	m.ToolCalls = p.ToolCalls
	m.ToolCallID = p.ToolCallID
	m.Name = p.Name

	if len(p.Content) == 0 {
		return nil
	}

	// String content: "hello"
	if p.Content[0] == '"' {
		return json.Unmarshal(p.Content, &m.Content)
	}

	// Array content: [{"type":"text","text":"..."},...]
	if p.Content[0] == '[' {
		var blocks []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(p.Content, &blocks); err != nil {
			m.Content = string(p.Content)
			return nil
		}
		var sb strings.Builder
		for i, b := range blocks {
			if b.Type == "text" || b.Type == "" {
				if i > 0 && sb.Len() > 0 {
					sb.WriteString("\n")
				}
				sb.WriteString(b.Text)
			}
		}
		m.Content = sb.String()
		return nil
	}

	m.Content = string(p.Content)
	return nil
}

func (m ChatMessage) MarshalJSON() ([]byte, error) {
	type alias struct {
		Role       string          `json:"role"`
		Content    json.RawMessage `json:"content,omitempty"`
		ToolCalls  json.RawMessage `json:"tool_calls,omitempty"`
		ToolCallID string          `json:"tool_call_id,omitempty"`
		Name       string          `json:"name,omitempty"`
	}
	a := alias{
		Role:       m.Role,
		ToolCalls:  m.ToolCalls,
		ToolCallID: m.ToolCallID,
		Name:       m.Name,
	}
	if m.RawContent != nil {
		a.Content = m.RawContent
	} else if m.Content != "" || m.Role != "" {
		c, _ := json.Marshal(m.Content)
		a.Content = c
	}
	return json.Marshal(a)
}

// ChatRequest is the OpenAI-compatible chat completion request body.
// Fields used by the proxy for inspection: Model, Messages, Stream.
// Everything else is pass-through. RawBody carries the original JSON so
// the OpenAI provider can forward unknown fields verbatim.
type ChatRequest struct {
	Model       string          `json:"model"`
	Messages    []ChatMessage   `json:"messages"`
	MaxTokens   *int            `json:"max_tokens,omitempty"`
	Temperature *float64        `json:"temperature,omitempty"`
	TopP        *float64        `json:"top_p,omitempty"`
	Stream      bool            `json:"stream,omitempty"`
	Stop        json.RawMessage `json:"stop,omitempty"`
	Tools       json.RawMessage `json:"tools,omitempty"`
	ToolChoice  json.RawMessage `json:"tool_choice,omitempty"`
	RawBody     json.RawMessage `json:"-"`
	APIKey      string          `json:"-"` // pass-through from incoming Authorization header
}

// ChatChoice is a single choice in an OpenAI chat completion response.
type ChatChoice struct {
	Index        int             `json:"index"`
	Message      *ChatMessage    `json:"message,omitempty"`
	Delta        *ChatMessage    `json:"delta,omitempty"`
	FinishReason *string         `json:"finish_reason"`
}

// ChatUsage tracks token counts.
type ChatUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// ChatResponse is the OpenAI-compatible chat completion response.
// RawResponse carries the original upstream bytes so the proxy can
// forward unknown fields (system_fingerprint, service_tier, etc.) verbatim.
type ChatResponse struct {
	ID          string          `json:"id"`
	Object      string          `json:"object"`
	Created     int64           `json:"created"`
	Model       string          `json:"model"`
	Choices     []ChatChoice    `json:"choices"`
	Usage       *ChatUsage      `json:"usage,omitempty"`
	RawResponse json.RawMessage `json:"-"`
}

// StreamChunk is one SSE chunk in OpenAI format.
type StreamChunk struct {
	ID      string       `json:"id"`
	Object  string       `json:"object"`
	Created int64        `json:"created"`
	Model   string       `json:"model"`
	Choices []ChatChoice `json:"choices"`
	Usage   *ChatUsage   `json:"usage,omitempty"`
}

// LLMProvider abstracts the upstream LLM API.
type LLMProvider interface {
	ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error)
	ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error)
}

// NewProvider creates an LLM provider adapter based on the model string.
// The model format is "provider/model-name" (e.g. "anthropic/claude-opus-4-5").
func NewProvider(model string, apiKey string) (LLMProvider, error) {
	provider, modelID := splitModel(model)
	if provider == "" {
		provider = inferProvider(modelID, apiKey)
	}
	switch provider {
	case "anthropic":
		return &anthropicProvider{model: modelID, apiKey: apiKey}, nil
	case "openrouter":
		return &openaiProvider{model: modelID, apiKey: apiKey, baseURL: "https://openrouter.ai/api"}, nil
	case "ollama":
		return &openaiProvider{model: modelID, apiKey: apiKey, baseURL: "http://localhost:11434"}, nil
	case "openai":
		return &openaiProvider{model: modelID, apiKey: apiKey, baseURL: "https://api.openai.com"}, nil
	case "azure":
		return &azureProvider{
			deployment: modelID,
			apiKey:     apiKey,
			baseURL:    "https://api.openai.azure.com",
			apiVersion: "2024-02-01",
		}, nil
	case "google", "gemini":
		// Google AI Studio OpenAI-compatible endpoint.
		return &openaiProvider{
			model:   modelID,
			apiKey:  apiKey,
			baseURL: "https://generativelanguage.googleapis.com/v1beta/openai",
		}, nil
	case "bedrock":
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = os.Getenv("AWS_DEFAULT_REGION")
		}
		if region == "" {
			region = "us-east-1"
		}
		return &bedrockProvider{modelID: modelID, region: region}, nil
	default:
		return &openaiProvider{model: modelID, apiKey: apiKey, baseURL: "https://api.openai.com"}, nil
	}
}

// inferProvider detects the provider from the model name or API key format
// when no explicit "provider/" prefix is given.
func inferProvider(model string, apiKey string) string {
	if strings.HasPrefix(model, "claude") {
		return "anthropic"
	}
	if strings.HasPrefix(apiKey, "sk-ant-") {
		return "anthropic"
	}
	if strings.HasPrefix(apiKey, "sk-or-") {
		return "openrouter"
	}
	if strings.HasPrefix(model, "gemini") {
		return "google"
	}
	return "openai"
}

// inferAPIKeyEnv returns the conventional environment variable name for the
// provider prefix in a "provider/model" model string. Used as a fallback when
// guardrail.api_key_env is not explicitly configured.
func inferAPIKeyEnv(model string) string {
	provider, _ := splitModel(model)
	switch provider {
	case "anthropic":
		return "ANTHROPIC_API_KEY"
	case "openai":
		return "OPENAI_API_KEY"
	case "openrouter":
		return "OPENROUTER_API_KEY"
	case "ollama":
		return "" // no key needed
	default:
		return "OPENAI_API_KEY"
	}
}

// NewProviderWithBase creates a provider that sends requests to a custom base URL
// using OpenAI-compatible format. Used for the LLM judge to support arbitrary endpoints.
func NewProviderWithBase(model string, apiKey string, baseURL string) LLMProvider {
	_, modelID := splitModel(model)
	if baseURL == "" {
		p, _ := NewProvider(model, apiKey)
		return p
	}
	return &openaiProvider{model: modelID, apiKey: apiKey, baseURL: strings.TrimRight(baseURL, "/")}
}

func splitModel(model string) (provider, modelID string) {
	if i := strings.IndexByte(model, '/'); i >= 0 {
		return model[:i], model[i+1:]
	}
	return "", model
}

// resolvePassThroughKey returns the API key to use for a request: if the
// request carries a pass-through key (extracted from the incoming Authorization
// header by the proxy), that takes priority; otherwise the provider's
// configured key is used.
func resolvePassThroughKey(passThrough, configured string) string {
	if passThrough != "" {
		return passThrough
	}
	return configured
}

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
func patchRawBody(raw json.RawMessage, model string, stream bool) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("provider: patch raw body: %w", err)
	}
	modelBytes, _ := json.Marshal(model)
	m["model"] = modelBytes
	streamBytes, _ := json.Marshal(stream)
	m["stream"] = streamBytes
	return json.Marshal(m)
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
	httpReq.Header.Set("Authorization", "Bearer "+resolvePassThroughKey(req.APIKey, p.apiKey))

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
	httpReq.Header.Set("Authorization", "Bearer "+resolvePassThroughKey(req.APIKey, p.apiKey))

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

// ---------------------------------------------------------------------------
// Azure OpenAI provider — api-key header, api-version query param
// ---------------------------------------------------------------------------

type azureProvider struct {
	deployment string // Azure deployment name (the model name part after "azure/")
	apiKey     string
	baseURL    string // e.g. https://<resource>.openai.azure.com
	apiVersion string // e.g. "2024-02-01"
}

func (p *azureProvider) endpoint() string {
	return fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
		strings.TrimRight(p.baseURL, "/"), p.deployment, p.apiVersion)
}

func (p *azureProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	var body []byte
	var err error
	if len(req.RawBody) > 0 {
		body, err = patchRawBody(req.RawBody, p.deployment, false)
	} else {
		req.Model = p.deployment
		req.Stream = false
		body, err = json.Marshal(req)
	}
	if err != nil {
		return nil, fmt.Errorf("provider: azure marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: azure create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("api-key", resolvePassThroughKey(req.APIKey, p.apiKey))

	resp, err := providerHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("provider: azure request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("provider: azure upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	rawResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("provider: azure read response: %w", err)
	}
	var chatResp ChatResponse
	if err := json.Unmarshal(rawResp, &chatResp); err != nil {
		return nil, fmt.Errorf("provider: azure decode response: %w", err)
	}
	chatResp.RawResponse = rawResp
	return &chatResp, nil
}

func (p *azureProvider) ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error) {
	var body []byte
	var err error
	if len(req.RawBody) > 0 {
		body, err = patchRawBody(req.RawBody, p.deployment, true)
	} else {
		req.Model = p.deployment
		req.Stream = true
		body, err = json.Marshal(req)
	}
	if err != nil {
		return nil, fmt.Errorf("provider: azure marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: azure create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("api-key", resolvePassThroughKey(req.APIKey, p.apiKey))

	resp, err := providerHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("provider: azure stream request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("provider: azure upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	return readOpenAISSE(resp.Body, chunkCb)
}

// ---------------------------------------------------------------------------
// Amazon Bedrock provider — AWS Signature V4, Anthropic format translation
// ---------------------------------------------------------------------------

type bedrockProvider struct {
	modelID string
	region  string
}

func (p *bedrockProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(p.region))
	if err != nil {
		return nil, fmt.Errorf("provider: bedrock load config: %w", err)
	}
	client := bedrockruntime.NewFromConfig(cfg)

	// Translate OpenAI format to Anthropic Messages API format
	ap := &anthropicProvider{model: p.modelID}
	aReq := ap.translateRequest(req)
	aReq.Stream = false

	body, err := json.Marshal(aReq)
	if err != nil {
		return nil, fmt.Errorf("provider: bedrock marshal: %w", err)
	}

	contentType := "application/json"
	out, err := client.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     &p.modelID,
		Body:        body,
		ContentType: &contentType,
	})
	if err != nil {
		return nil, fmt.Errorf("provider: bedrock invoke: %w", err)
	}

	var aResp anthropicResponse
	if err := json.Unmarshal(out.Body, &aResp); err != nil {
		return nil, fmt.Errorf("provider: bedrock decode response: %w", err)
	}

	return ap.translateResponse(&aResp, req.Model), nil
}

func (p *bedrockProvider) ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error) {
	// Fall back to non-streaming for Bedrock — collect the full response then emit as a single chunk
	resp, err := p.ChatCompletion(ctx, req)
	if err != nil {
		return nil, err
	}

	if len(resp.Choices) > 0 && resp.Choices[0].Message != nil {
		content := resp.Choices[0].Message.Content
		finishReason := "stop"
		if resp.Choices[0].FinishReason != nil {
			finishReason = *resp.Choices[0].FinishReason
		}

		// Emit role chunk
		chunkCb(StreamChunk{
			ID:      resp.ID,
			Object:  "chat.completion.chunk",
			Created: resp.Created,
			Model:   resp.Model,
			Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Role: "assistant"}}},
		})

		// Emit content chunk
		chunkCb(StreamChunk{
			ID:      resp.ID,
			Object:  "chat.completion.chunk",
			Created: resp.Created,
			Model:   resp.Model,
			Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: content}}},
		})

		// Emit finish chunk
		chunkCb(StreamChunk{
			ID:      resp.ID,
			Object:  "chat.completion.chunk",
			Created: resp.Created,
			Model:   resp.Model,
			Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &finishReason}},
		})
	}

	return resp.Usage, nil
}

// ---------------------------------------------------------------------------
// Anthropic provider — translates between OpenAI format and Anthropic Messages API
// ---------------------------------------------------------------------------

type anthropicProvider struct {
	model   string
	apiKey  string
	baseURL string // optional override for tests; defaults to https://api.anthropic.com
}

func (p *anthropicProvider) endpoint() string {
	if p.baseURL != "" {
		return strings.TrimRight(p.baseURL, "/") + "/v1/messages"
	}
	return "https://api.anthropic.com/v1/messages"
}

type anthropicRequest struct {
	Model       string              `json:"model"`
	Messages    []anthropicMessage  `json:"messages"`
	System      string              `json:"system,omitempty"`
	MaxTokens   int                 `json:"max_tokens"`
	Temperature *float64            `json:"temperature,omitempty"`
	TopP        *float64            `json:"top_p,omitempty"`
	Stream      bool                `json:"stream,omitempty"`
	Stop        json.RawMessage     `json:"stop_sequences,omitempty"`
	Tools       json.RawMessage     `json:"tools,omitempty"`
	ToolChoice  json.RawMessage     `json:"tool_choice,omitempty"`
}

type anthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type anthropicResponse struct {
	ID         string             `json:"id"`
	Type       string             `json:"type"`
	Role       string             `json:"role"`
	Content    []anthropicContent `json:"content"`
	Model      string             `json:"model"`
	StopReason string             `json:"stop_reason"`
	Usage      *anthropicUsage    `json:"usage"`
}

type anthropicContent struct {
	Type  string          `json:"type"`
	Text  string          `json:"text,omitempty"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

type anthropicUsage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

func (p *anthropicProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	aReq := p.translateRequest(req)
	aReq.Stream = false

	body, err := json.Marshal(aReq)
	if err != nil {
		return nil, fmt.Errorf("provider: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.endpoint(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", resolvePassThroughKey(req.APIKey, p.apiKey))
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := providerHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("provider: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("provider: upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	var aResp anthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&aResp); err != nil {
		return nil, fmt.Errorf("provider: decode response: %w", err)
	}

	return p.translateResponse(&aResp, req.Model), nil
}

func (p *anthropicProvider) ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error) {
	aReq := p.translateRequest(req)
	aReq.Stream = true

	body, err := json.Marshal(aReq)
	if err != nil {
		return nil, fmt.Errorf("provider: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.endpoint(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", resolvePassThroughKey(req.APIKey, p.apiKey))
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := providerHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("provider: stream request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("provider: upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	return p.readAnthropicSSE(resp.Body, req.Model, chunkCb)
}

func (p *anthropicProvider) translateRequest(req *ChatRequest) *anthropicRequest {
	var system string
	var msgs []anthropicMessage

	for _, m := range req.Messages {
		if m.Role == "system" {
			if system != "" {
				system += "\n"
			}
			system += m.Content
			continue
		}

		// Tool-result messages map to Anthropic's user role with tool_result content blocks.
		if m.Role == "tool" && m.ToolCallID != "" {
			block := map[string]interface{}{
				"type":        "tool_result",
				"tool_use_id": m.ToolCallID,
				"content":     m.Content,
			}
			contentJSON, _ := json.Marshal([]interface{}{block})
			msgs = append(msgs, anthropicMessage{Role: "user", Content: contentJSON})
			continue
		}

		// Assistant messages with tool_calls: build content blocks with text + tool_use.
		if m.Role == "assistant" && len(m.ToolCalls) > 0 {
			var blocks []interface{}
			if m.Content != "" {
				blocks = append(blocks, map[string]string{"type": "text", "text": m.Content})
			}
			var toolCalls []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			}
			if err := json.Unmarshal(m.ToolCalls, &toolCalls); err == nil {
				for _, tc := range toolCalls {
					var args json.RawMessage
					if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err != nil {
						args = json.RawMessage(tc.Function.Arguments)
					}
					blocks = append(blocks, map[string]interface{}{
						"type":  "tool_use",
						"id":    tc.ID,
						"name":  tc.Function.Name,
						"input": args,
					})
				}
			}
			contentJSON, _ := json.Marshal(blocks)
			msgs = append(msgs, anthropicMessage{Role: "assistant", Content: contentJSON})
			continue
		}

		// Regular text message.
		contentJSON, _ := json.Marshal(m.Content)
		msgs = append(msgs, anthropicMessage{Role: m.Role, Content: contentJSON})
	}

	maxTokens := 4096
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		maxTokens = *req.MaxTokens
	}

	aReq := &anthropicRequest{
		Model:       p.model,
		Messages:    msgs,
		System:      system,
		MaxTokens:   maxTokens,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Stop:        req.Stop,
	}

	// Pass through tools if present (Anthropic uses the same format for tools definitions).
	if len(req.Tools) > 0 {
		// OpenAI wraps each tool as {"type":"function","function":{...}}.
		// Anthropic expects {"name":...,"description":...,"input_schema":{...}}.
		var oaiTools []struct {
			Type     string `json:"type"`
			Function struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				Parameters  json.RawMessage `json:"parameters"`
			} `json:"function"`
		}
		if err := json.Unmarshal(req.Tools, &oaiTools); err == nil {
			var aTools []map[string]interface{}
			for _, t := range oaiTools {
				aTools = append(aTools, map[string]interface{}{
					"name":         t.Function.Name,
					"description":  t.Function.Description,
					"input_schema": t.Function.Parameters,
				})
			}
			aReq.Tools, _ = json.Marshal(aTools)
		}
	}

	return aReq
}

func (p *anthropicProvider) translateResponse(aResp *anthropicResponse, modelAlias string) *ChatResponse {
	var textParts []string
	var toolCalls []map[string]interface{}

	for _, c := range aResp.Content {
		switch c.Type {
		case "text":
			textParts = append(textParts, c.Text)
		case "tool_use":
			argsJSON := string(c.Input)
			if argsJSON == "" {
				argsJSON = "{}"
			}
			toolCalls = append(toolCalls, map[string]interface{}{
				"id":   c.ID,
				"type": "function",
				"function": map[string]interface{}{
					"name":      c.Name,
					"arguments": argsJSON,
				},
			})
		}
	}

	content := strings.Join(textParts, "")
	finishReason := mapAnthropicStopReason(aResp.StopReason)

	msg := &ChatMessage{Role: "assistant", Content: content}
	if len(toolCalls) > 0 {
		msg.ToolCalls, _ = json.Marshal(toolCalls)
		if finishReason == "stop" {
			finishReason = "tool_calls"
		}
	}

	resp := &ChatResponse{
		ID:      "chatcmpl-" + strings.TrimPrefix(aResp.ID, "msg_"),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   modelAlias,
		Choices: []ChatChoice{{
			Index:        0,
			Message:      msg,
			FinishReason: &finishReason,
		}},
	}
	if aResp.Usage != nil {
		resp.Usage = &ChatUsage{
			PromptTokens:     aResp.Usage.InputTokens,
			CompletionTokens: aResp.Usage.OutputTokens,
			TotalTokens:      aResp.Usage.InputTokens + aResp.Usage.OutputTokens,
		}
	}
	return resp
}

func (p *anthropicProvider) readAnthropicSSE(r io.Reader, modelAlias string, cb func(StreamChunk)) (*ChatUsage, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 256*1024)
	var msgID, model string
	var usage *ChatUsage
	created := time.Now().Unix()

	// Track current tool_use block for streaming tool call assembly.
	type pendingToolCall struct {
		Index int
		ID    string
		Name  string
		Args  strings.Builder
	}
	var toolCallIndex int
	var currentTool *pendingToolCall

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")

		var evt struct {
			Type         string          `json:"type"`
			Index        int             `json:"index"`
			Message      json.RawMessage `json:"message,omitempty"`
			Delta        json.RawMessage `json:"delta,omitempty"`
			ContentBlock json.RawMessage `json:"content_block,omitempty"`
			Usage        *anthropicUsage `json:"usage,omitempty"`
		}
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			continue
		}

		switch evt.Type {
		case "message_start":
			var msgStart struct {
				ID    string `json:"id"`
				Model string `json:"model"`
			}
			if json.Unmarshal(evt.Message, &msgStart) == nil {
				msgID = "chatcmpl-" + strings.TrimPrefix(msgStart.ID, "msg_")
				model = modelAlias
			}
			role := "assistant"
			cb(StreamChunk{
				ID: msgID, Object: "chat.completion.chunk", Created: created, Model: model,
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Role: role}}},
			})

		case "content_block_start":
			var block struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if json.Unmarshal(evt.ContentBlock, &block) == nil && block.Type == "tool_use" {
				currentTool = &pendingToolCall{
					Index: toolCallIndex,
					ID:    block.ID,
					Name:  block.Name,
				}
				toolCallIndex++
				// Emit the initial tool_call chunk with function name.
				tcJSON, _ := json.Marshal([]map[string]interface{}{{
					"index": currentTool.Index,
					"id":    currentTool.ID,
					"type":  "function",
					"function": map[string]interface{}{
						"name":      currentTool.Name,
						"arguments": "",
					},
				}})
				cb(StreamChunk{
					ID: msgID, Object: "chat.completion.chunk", Created: created, Model: model,
					Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{ToolCalls: tcJSON}}},
				})
			}

		case "content_block_delta":
			var delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
			}
			if json.Unmarshal(evt.Delta, &delta) == nil {
				if delta.Type == "text_delta" {
					cb(StreamChunk{
						ID: msgID, Object: "chat.completion.chunk", Created: created, Model: model,
						Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: delta.Text}}},
					})
				} else if delta.Type == "input_json_delta" && currentTool != nil {
					currentTool.Args.WriteString(delta.PartialJSON)
					// Stream the argument fragment as a tool_call delta.
					tcJSON, _ := json.Marshal([]map[string]interface{}{{
						"index": currentTool.Index,
						"function": map[string]interface{}{
							"arguments": delta.PartialJSON,
						},
					}})
					cb(StreamChunk{
						ID: msgID, Object: "chat.completion.chunk", Created: created, Model: model,
						Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{ToolCalls: tcJSON}}},
					})
				}
			}

		case "content_block_stop":
			currentTool = nil

		case "message_delta":
			var delta struct {
				StopReason string `json:"stop_reason"`
			}
			_ = json.Unmarshal(evt.Delta, &delta)
			fr := mapAnthropicStopReason(delta.StopReason)
			chunk := StreamChunk{
				ID: msgID, Object: "chat.completion.chunk", Created: created, Model: model,
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &fr}},
			}
			if evt.Usage != nil {
				chunk.Usage = &ChatUsage{
					PromptTokens:     evt.Usage.InputTokens,
					CompletionTokens: evt.Usage.OutputTokens,
					TotalTokens:      evt.Usage.InputTokens + evt.Usage.OutputTokens,
				}
				usage = chunk.Usage
			}
			cb(chunk)

		case "message_stop":
			// handled by the caller after we return
		}
	}
	return usage, scanner.Err()
}

func mapAnthropicStopReason(reason string) string {
	switch reason {
	case "end_turn":
		return "stop"
	case "max_tokens":
		return "length"
	case "stop_sequence":
		return "stop"
	case "tool_use":
		return "tool_calls"
	default:
		if reason == "" {
			return "stop"
		}
		return reason
	}
}

var providerHTTPClient = &http.Client{
	Timeout: 5 * time.Minute,
	Transport: &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

// ResolveAPIKey reads the API key from the named environment variable,
// optionally loading a .env file first (for daemon contexts where the
// user's shell env is not inherited).
func ResolveAPIKey(envVar string, dotenvPath string) string {
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	if dotenvPath != "" {
		if dotenv, err := loadDotEnv(dotenvPath); err == nil {
			if v, ok := dotenv[envVar]; ok && v != "" {
				return v
			}
		}
	}
	return ""
}
