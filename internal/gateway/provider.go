package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"
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
			// "text" — Chat Completions / Anthropic
			// "input_text" / "output_text" — OpenAI Responses API
			if b.Type == "text" || b.Type == "input_text" || b.Type == "output_text" || b.Type == "" {
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
		Role       string          `json:"role,omitempty"`
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
	} else if m.Content != "" {
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
	Model        string          `json:"model"`
	Messages     []ChatMessage   `json:"messages"`
	MaxTokens    *int            `json:"max_tokens,omitempty"`
	Temperature  *float64        `json:"temperature,omitempty"`
	TopP         *float64        `json:"top_p,omitempty"`
	Stream       bool            `json:"stream,omitempty"`
	Stop         json.RawMessage `json:"stop,omitempty"`
	Tools        json.RawMessage `json:"tools,omitempty"`
	ToolChoice   json.RawMessage `json:"tool_choice,omitempty"`
	Fallbacks    []string        `json:"fallbacks,omitempty"` // gateway failover models (e.g. Bifrost)
	RawBody      json.RawMessage `json:"-"`
	TargetURL    string          `json:"-"` // from X-DC-Target-URL header, set by fetch interceptor
	TargetAPIKey string          `json:"-"` // from Authorization header, forwarded to upstream
}

// ChatChoice is a single choice in an OpenAI chat completion response.
type ChatChoice struct {
	Index        int          `json:"index"`
	Message      *ChatMessage `json:"message,omitempty"`
	Delta        *ChatMessage `json:"delta,omitempty"`
	FinishReason *string      `json:"finish_reason"`
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
	ID                 string          `json:"id"`
	Object             string          `json:"object"`
	Created            int64           `json:"created"`
	Model              string          `json:"model"`
	Choices            []ChatChoice    `json:"choices"`
	Usage              *ChatUsage      `json:"usage,omitempty"`
	DefenseClawBlocked *bool           `json:"defenseclaw_blocked,omitempty"`
	DefenseClawReason  string          `json:"defenseclaw_reason,omitempty"`
	RawResponse        json.RawMessage `json:"-"`
}

// StreamChunk is one SSE chunk in OpenAI format.
type StreamChunk struct {
	ID                 string       `json:"id"`
	Object             string       `json:"object"`
	Created            int64        `json:"created"`
	Model              string       `json:"model"`
	Choices            []ChatChoice `json:"choices"`
	Usage              *ChatUsage   `json:"usage,omitempty"`
	DefenseClawBlocked *bool        `json:"defenseclaw_blocked,omitempty"`
	DefenseClawReason  string       `json:"defenseclaw_reason,omitempty"`
}

// LLMProvider abstracts the upstream LLM API.
type LLMProvider interface {
	ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error)
	ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error)
}

// NewProvider creates an LLM provider adapter based on the model string.
// The model format is "provider/model-name" (e.g. "anthropic/claude-opus-4-5").
// All provider routing and API translation is handled by the Bifrost Go SDK.
func NewProvider(model string, apiKey string) (LLMProvider, error) {
	provider, modelID := splitModel(model)
	if provider == "" {
		provider = inferProvider(modelID, apiKey)
	}

	providerKey, err := mapProviderKey(provider)
	if err != nil {
		return nil, err
	}
	return &bifrostProvider{
		providerKey: providerKey,
		model:       modelID,
		apiKey:      apiKey,
	}, nil
}

// inferProvider detects the provider from the model name or API key format
// when no explicit "provider/" prefix is given.
func inferProvider(model string, apiKey string) string {
	if strings.HasPrefix(apiKey, "ABSK") {
		return "bedrock"
	}
	if strings.HasPrefix(model, "claude") {
		return "anthropic"
	}
	if strings.HasPrefix(apiKey, "sk-ant-") {
		return "anthropic"
	}
	if strings.HasPrefix(model, "gemini") {
		return "gemini"
	}
	if strings.HasPrefix(apiKey, "AIza") {
		return "gemini"
	}
	return "openai"
}

// NewProviderWithBase creates a provider that sends requests to a custom base URL.
// The Bifrost SDK handles all provider-specific API differences (auth headers,
// request format translation, streaming) internally.
func NewProviderWithBase(model string, apiKey string, baseURL string) (LLMProvider, error) {
	if baseURL == "" {
		return NewProvider(model, apiKey)
	}

	baseURL = strings.TrimRight(baseURL, "/")

	provider, modelID := splitModel(model)
	if provider == "" {
		provider = inferProvider(modelID, apiKey)
	}

	providerKey, err := mapProviderKey(provider)
	if err != nil {
		return nil, err
	}
	return &bifrostProvider{
		providerKey: providerKey,
		model:       modelID,
		apiKey:      apiKey,
		baseURL:     baseURL,
	}, nil
}

// knownProviders lists provider prefixes recognized in "provider/model" strings.
var knownProviders = map[string]bool{
	"openai":        true,
	"anthropic":     true,
	"openrouter":    true,
	"azure":         true,
	"gemini":        true,
	"gemini-openai": true,
	"bedrock":       true,
	// amazon-bedrock is OpenClaw's stock provider name for AWS Bedrock; see
	// https://docs.openclaw.ai/providers/bedrock. Both prefixes are accepted
	// and routed to the same Bifrost Bedrock backend via mapProviderKey.
	"amazon-bedrock": true,
	"groq":           true,
	"mistral":        true,
	"ollama":         true,
	"vertex":         true,
	"cohere":         true,
	"perplexity":     true,
	"cerebras":       true,
	"fireworks":      true,
	"xai":            true,
	"huggingface":    true,
	"replicate":      true,
	"vllm":           true,
}

func splitModel(model string) (provider, modelID string) {
	i := strings.IndexByte(model, '/')
	if i < 0 {
		return "", model
	}
	prefix := model[:i]
	if knownProviders[prefix] {
		return prefix, model[i+1:]
	}
	return "", model
}

// providerHTTPClient is used for passthrough upstream requests in the proxy.
// No client-level Timeout is set because each call site passes a
// context.WithTimeout — a client-level timeout would race with that.
var providerHTTPClient = &http.Client{
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
