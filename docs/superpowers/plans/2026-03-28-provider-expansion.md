# Provider Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add OpenRouter, Azure OpenAI, and Google Gemini (native + compat) providers to the guardrail proxy, with multi-provider openclaw.json patching.

**Architecture:** Separate Go provider structs per backend, all implementing `LLMProvider`. OpenAI-compatible variants reuse `patchRawBody`/`readOpenAISSE`. Gemini native gets full translation. Python CLI updated for new providers + multi-provider config patching. Proxy routes by provider prefix with blocked-provider fallback.

**Tech Stack:** Go 1.25, Python 3.12 (Click CLI), httptest for Go tests, pytest for Python tests.

---

## File Map

### Go files (new)
- `internal/gateway/provider_openai.go` — extracted `openaiProvider` struct + methods
- `internal/gateway/provider_anthropic.go` — extracted `anthropicProvider` struct + types + methods
- `internal/gateway/provider_openrouter.go` — `openrouterProvider`
- `internal/gateway/provider_azure.go` — `azureOpenAIProvider`
- `internal/gateway/provider_gemini_compat.go` — `geminiCompatProvider`
- `internal/gateway/provider_gemini.go` — `geminiNativeProvider` + Gemini types + translation
- `internal/gateway/provider_openrouter_test.go` — tests
- `internal/gateway/provider_azure_test.go` — tests
- `internal/gateway/provider_gemini_compat_test.go` — tests
- `internal/gateway/provider_gemini_test.go` — tests

### Go files (modified)
- `internal/gateway/provider.go` — keep types/interface/routing/helpers, remove provider impls
- `internal/gateway/proxy.go:48-119` — multi-provider map, `blockedProviders`, updated constructor + routing
- `internal/config/config.go:254-265` — add `APIBase` field to `GuardrailConfig`

### Python files (modified)
- `cli/defenseclaw/config.py:428-438` — add `api_base` field to `GuardrailConfig` dataclass
- `cli/defenseclaw/config.py:713-727` — read `api_base` in `_merge_guardrail()`
- `cli/defenseclaw/guardrail.py:33-101` — multi-provider patching in `patch_openclaw_config()`
- `cli/defenseclaw/guardrail.py:103-132` — multi-provider restore in `restore_openclaw_config()`
- `cli/defenseclaw/guardrail.py:258-313` — updated `detect_current_model()` + new `detect_provider_configs()`
- `cli/defenseclaw/guardrail.py:276-313` — updated `detect_api_key_env()`, `model_to_proxy_name()`, `KNOWN_PROVIDERS`, `guess_provider()`
- `cli/defenseclaw/commands/cmd_setup.py:895-1050` — multi-provider interactive wizard

---

## Task 1: Split provider.go — Extract openaiProvider

**Files:**
- Modify: `internal/gateway/provider.go` (remove openaiProvider impl, keep types/interface/helpers)
- Create: `internal/gateway/provider_openai.go`

- [ ] **Step 1: Run existing tests to establish baseline**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./internal/gateway/ -run TestProxy -count=1 -v 2>&1 | tail -20`
Expected: All existing tests PASS.

- [ ] **Step 2: Create `provider_openai.go` with extracted openaiProvider**

```go
// internal/gateway/provider_openai.go
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type openaiProvider struct {
	model   string
	apiKey  string
	baseURL string
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
```

- [ ] **Step 3: Remove openaiProvider from `provider.go`**

Remove lines 217–346 from `provider.go` (the `openaiProvider` struct, `ChatCompletion`, `ChatCompletionStream`, and `readOpenAISSE` stays since it's shared). Specifically remove:
- `type openaiProvider struct` and its two methods
- Keep: `patchRawBody`, `readOpenAISSE`, `providerHTTPClient`, all types, interface, `NewProvider`, etc.

- [ ] **Step 4: Run tests to verify extraction didn't break anything**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./internal/gateway/ -count=1 -v 2>&1 | tail -20`
Expected: All tests PASS — identical behavior.

- [ ] **Step 5: Commit**

```bash
git add internal/gateway/provider_openai.go internal/gateway/provider.go
git commit -m "refactor: extract openaiProvider to provider_openai.go"
```

---

## Task 2: Split provider.go — Extract anthropicProvider

**Files:**
- Modify: `internal/gateway/provider.go` (remove anthropicProvider impl)
- Create: `internal/gateway/provider_anthropic.go`

- [ ] **Step 1: Create `provider_anthropic.go` with extracted anthropicProvider**

Move from `provider.go` lines 348–784:
- `type anthropicProvider struct`
- All Anthropic types: `anthropicRequest`, `anthropicMessage`, `anthropicResponse`, `anthropicContent`, `anthropicUsage`
- `ChatCompletion`, `ChatCompletionStream`, `translateRequest`, `translateResponse`, `readAnthropicSSE`, `mapAnthropicStopReason`

The file needs these imports:
```go
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
	"time"
)
```

- [ ] **Step 2: Remove anthropicProvider code from `provider.go`**

Remove lines 348–784. After this, `provider.go` should contain only:
- `ChatMessage`, `ChatRequest`, `ChatChoice`, `ChatUsage`, `ChatResponse`, `StreamChunk` types
- `LLMProvider` interface
- `NewProvider`, `NewProviderWithBase`, `inferProvider`, `splitModel`
- `patchRawBody`, `readOpenAISSE`
- `providerHTTPClient`
- `ResolveAPIKey`, `loadDotEnv` reference

- [ ] **Step 3: Run tests**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./internal/gateway/ -count=1 -v 2>&1 | tail -20`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/gateway/provider_anthropic.go internal/gateway/provider.go
git commit -m "refactor: extract anthropicProvider to provider_anthropic.go"
```

---

## Task 3: Update routing — splitModel, inferProvider, NewProviderWithBase

**Files:**
- Modify: `internal/gateway/provider.go`
- Modify: `internal/config/config.go:254-265`

- [ ] **Step 1: Write tests for updated routing**

Add to `internal/gateway/gateway_test.go`:

```go
func TestSplitModelKnownPrefixes(t *testing.T) {
	tests := []struct {
		input      string
		wantProv   string
		wantModel  string
	}{
		{"openai/gpt-4o", "openai", "gpt-4o"},
		{"anthropic/claude-opus-4-5", "anthropic", "claude-opus-4-5"},
		{"openrouter/anthropic/claude-opus-4-5", "openrouter", "anthropic/claude-opus-4-5"},
		{"azure/gpt-4o", "azure", "gpt-4o"},
		{"gemini/gemini-2.0-flash", "gemini", "gemini-2.0-flash"},
		{"gemini-openai/gemini-2.0-flash", "gemini-openai", "gemini-2.0-flash"},
		{"unknown/foo", "", "unknown/foo"},
		{"gpt-4o", "", "gpt-4o"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			prov, model := splitModel(tt.input)
			if prov != tt.wantProv || model != tt.wantModel {
				t.Errorf("splitModel(%q) = (%q, %q), want (%q, %q)",
					tt.input, prov, model, tt.wantProv, tt.wantModel)
			}
		})
	}
}

func TestInferProviderNew(t *testing.T) {
	tests := []struct {
		model  string
		apiKey string
		want   string
	}{
		{"claude-opus-4-5", "", "anthropic"},
		{"gpt-4o", "", "openai"},
		{"gemini-2.0-flash", "", "gemini"},
		{"anything", "AIzaSyExample", "gemini"},
		{"anything", "sk-ant-api123", "anthropic"},
		{"anything", "sk-proj-abc", "openai"},
	}
	for _, tt := range tests {
		t.Run(tt.model+"_"+tt.apiKey, func(t *testing.T) {
			got := inferProvider(tt.model, tt.apiKey)
			if got != tt.want {
				t.Errorf("inferProvider(%q, %q) = %q, want %q", tt.model, tt.apiKey, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./internal/gateway/ -run "TestSplitModelKnown|TestInferProviderNew" -count=1 -v 2>&1 | tail -30`
Expected: FAIL — `splitModel("openrouter/anthropic/claude-opus-4-5")` returns `("openrouter", "anthropic/claude-opus-4-5")` incorrectly with current first-slash split; `inferProvider("gemini-2.0-flash", "")` returns `"openai"`.

- [ ] **Step 3: Update `splitModel` in `provider.go`**

Replace the existing `splitModel` function:

```go
// knownProviders is the set of provider prefixes recognized by the proxy.
// splitModel uses this to avoid mis-splitting model names that contain
// slashes (e.g. openrouter/anthropic/claude-opus-4-5).
var knownProviders = map[string]bool{
	"openai":       true,
	"anthropic":    true,
	"openrouter":   true,
	"azure":        true,
	"gemini":       true,
	"gemini-openai": true,
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
```

- [ ] **Step 4: Update `inferProvider` in `provider.go`**

Replace the existing function:

```go
func inferProvider(model string, apiKey string) string {
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
```

- [ ] **Step 5: Add `APIBase` to Go `GuardrailConfig`**

In `internal/config/config.go`, add after the `BlockMessage` field (line 263):

```go
	APIBase       string      `mapstructure:"api_base"        yaml:"api_base"`
```

- [ ] **Step 6: Run tests**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./internal/gateway/ -run "TestSplitModelKnown|TestInferProviderNew" -count=1 -v`
Expected: All PASS.

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./internal/... -count=1 2>&1 | tail -10`
Expected: All PASS (no regressions).

- [ ] **Step 7: Commit**

```bash
git add internal/gateway/provider.go internal/gateway/gateway_test.go internal/config/config.go
git commit -m "feat: update routing for new providers — splitModel, inferProvider, APIBase config"
```

---

## Task 4: OpenRouter provider

**Files:**
- Create: `internal/gateway/provider_openrouter.go`
- Create: `internal/gateway/provider_openrouter_test.go`

- [ ] **Step 1: Write failing test**

```go
// internal/gateway/provider_openrouter_test.go
package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenRouterProvider_Headers(t *testing.T) {
	var gotHeaders http.Header
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header
		gotBody, _ = io.ReadAll(r.Body)
		resp := ChatResponse{
			ID: "chatcmpl-test", Object: "chat.completion", Model: "anthropic/claude-opus-4-5",
			Choices: []ChatChoice{{Index: 0, Message: &ChatMessage{Role: "assistant", Content: "hi"}, FinishReason: strPtr("stop")}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &openrouterProvider{model: "anthropic/claude-opus-4-5", apiKey: "sk-or-test", baseURL: srv.URL}
	_, err := p.ChatCompletion(context.Background(), &ChatRequest{
		Model: "anthropic/claude-opus-4-5", Messages: []ChatMessage{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := gotHeaders.Get("Authorization"); got != "Bearer sk-or-test" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer sk-or-test")
	}
	if got := gotHeaders.Get("HTTP-Referer"); got != "https://github.com/defenseclaw/defenseclaw" {
		t.Errorf("HTTP-Referer = %q, want defenseclaw URL", got)
	}
	if got := gotHeaders.Get("X-Title"); got != "defenseclaw" {
		t.Errorf("X-Title = %q, want %q", got, "defenseclaw")
	}

	var body map[string]interface{}
	json.Unmarshal(gotBody, &body)
	if body["model"] != "anthropic/claude-opus-4-5" {
		t.Errorf("body model = %v, want anthropic/claude-opus-4-5", body["model"])
	}
}

func TestOpenRouterProvider_DefaultBaseURL(t *testing.T) {
	p := &openrouterProvider{model: "test", apiKey: "key"}
	got := p.effectiveBase()
	if got != "https://openrouter.ai/api" {
		t.Errorf("effectiveBase() = %q, want %q", got, "https://openrouter.ai/api")
	}
}

func TestOpenRouterProvider_CustomBaseURL(t *testing.T) {
	p := &openrouterProvider{model: "test", apiKey: "key", baseURL: "https://custom.example.com"}
	got := p.effectiveBase()
	if got != "https://custom.example.com" {
		t.Errorf("effectiveBase() = %q, want %q", got, "https://custom.example.com")
	}
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./internal/gateway/ -run TestOpenRouter -count=1 -v 2>&1 | tail -10`
Expected: FAIL — `openrouterProvider` not defined.

- [ ] **Step 3: Implement `provider_openrouter.go`**

```go
// internal/gateway/provider_openrouter.go
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	openrouterDefaultBase = "https://openrouter.ai/api"
	openrouterReferer     = "https://github.com/defenseclaw/defenseclaw"
	openrouterTitle       = "defenseclaw"
)

type openrouterProvider struct {
	model   string
	apiKey  string
	baseURL string
}

func (p *openrouterProvider) effectiveBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return openrouterDefaultBase
}

func (p *openrouterProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
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

	url := p.effectiveBase() + "/v1/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	httpReq.Header.Set("HTTP-Referer", openrouterReferer)
	httpReq.Header.Set("X-Title", openrouterTitle)

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

func (p *openrouterProvider) ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error) {
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

	url := p.effectiveBase() + "/v1/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	httpReq.Header.Set("HTTP-Referer", openrouterReferer)
	httpReq.Header.Set("X-Title", openrouterTitle)

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
```

- [ ] **Step 4: Add `openrouter` case to `NewProviderWithBase` in `provider.go`**

In the `switch provider` block of `NewProviderWithBase`, add:
```go
	case "openrouter":
		return &openrouterProvider{model: modelID, apiKey: apiKey, baseURL: baseURL}
```

Also update `NewProvider` switch:
```go
	case "openrouter":
		return &openrouterProvider{model: modelID, apiKey: apiKey}, nil
```

- [ ] **Step 5: Run tests**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./internal/gateway/ -run TestOpenRouter -count=1 -v`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/gateway/provider_openrouter.go internal/gateway/provider_openrouter_test.go internal/gateway/provider.go
git commit -m "feat: add OpenRouter provider with attribution headers"
```

---

## Task 5: Azure OpenAI provider

**Files:**
- Create: `internal/gateway/provider_azure.go`
- Create: `internal/gateway/provider_azure_test.go`

- [ ] **Step 1: Write failing test**

```go
// internal/gateway/provider_azure_test.go
package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAzureProvider_AuthAndURL(t *testing.T) {
	var gotPath string
	var gotQuery string
	var gotAuthHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAuthHeader = r.Header.Get("api-key")
		resp := ChatResponse{
			ID: "chatcmpl-test", Object: "chat.completion", Model: "gpt-4o",
			Choices: []ChatChoice{{Index: 0, Message: &ChatMessage{Role: "assistant", Content: "hi"}, FinishReason: strPtr("stop")}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &azureOpenAIProvider{model: "gpt-4o", apiKey: "azure-key-123", baseURL: srv.URL + "/openai/deployments/gpt4o"}
	_, err := p.ChatCompletion(context.Background(), &ChatRequest{
		Model: "gpt-4o", Messages: []ChatMessage{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotAuthHeader != "azure-key-123" {
		t.Errorf("api-key header = %q, want %q", gotAuthHeader, "azure-key-123")
	}
	if !strings.HasSuffix(gotPath, "/chat/completions") {
		t.Errorf("path = %q, want suffix /chat/completions", gotPath)
	}
	if !strings.Contains(gotQuery, "api-version=") {
		t.Errorf("query = %q, want api-version param", gotQuery)
	}

	// Verify no Bearer token
	if auth := gotAuthHeader; strings.HasPrefix(auth, "Bearer ") {
		t.Errorf("should use api-key header, not Bearer token")
	}
}

func TestAzureProvider_NoBearer(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		resp := ChatResponse{
			ID: "chatcmpl-test", Object: "chat.completion", Model: "gpt-4o",
			Choices: []ChatChoice{{Index: 0, Message: &ChatMessage{Role: "assistant", Content: "hi"}, FinishReason: strPtr("stop")}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &azureOpenAIProvider{model: "gpt-4o", apiKey: "azure-key", baseURL: srv.URL}
	p.ChatCompletion(context.Background(), &ChatRequest{
		Model: "gpt-4o", Messages: []ChatMessage{{Role: "user", Content: "test"}},
	})

	if gotAuth != "" {
		t.Errorf("Authorization header should be empty for Azure, got %q", gotAuth)
	}
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./internal/gateway/ -run TestAzureProvider -count=1 -v 2>&1 | tail -10`
Expected: FAIL — `azureOpenAIProvider` not defined.

- [ ] **Step 3: Implement `provider_azure.go`**

```go
// internal/gateway/provider_azure.go
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

const azureAPIVersion = "2024-12-01-preview"

type azureOpenAIProvider struct {
	model   string
	apiKey  string
	baseURL string // e.g. https://myresource.openai.azure.com/openai/deployments/gpt4o
}

func (p *azureOpenAIProvider) chatURL() string {
	base := strings.TrimRight(p.baseURL, "/")
	return base + "/chat/completions?api-version=" + azureAPIVersion
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
	httpReq.Header.Set("api-key", p.apiKey)

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
	httpReq.Header.Set("api-key", p.apiKey)

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
```

- [ ] **Step 4: Add `azure` case to `NewProvider` and `NewProviderWithBase`**

In `NewProvider`:
```go
	case "azure":
		return nil, fmt.Errorf("provider: azure requires api_base; use NewProviderWithBase")
```

In `NewProviderWithBase`:
```go
	case "azure":
		return &azureOpenAIProvider{model: modelID, apiKey: apiKey, baseURL: strings.TrimRight(baseURL, "/")}
```

- [ ] **Step 5: Run tests**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./internal/gateway/ -run TestAzureProvider -count=1 -v`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/gateway/provider_azure.go internal/gateway/provider_azure_test.go internal/gateway/provider.go
git commit -m "feat: add Azure OpenAI provider with api-key auth"
```

---

## Task 6: Gemini OpenAI-compatible provider

**Files:**
- Create: `internal/gateway/provider_gemini_compat.go`
- Create: `internal/gateway/provider_gemini_compat_test.go`

- [ ] **Step 1: Write failing test**

```go
// internal/gateway/provider_gemini_compat_test.go
package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGeminiCompatProvider_DefaultBase(t *testing.T) {
	p := &geminiCompatProvider{model: "gemini-2.0-flash", apiKey: "key"}
	got := p.effectiveBase()
	if got != "https://generativelanguage.googleapis.com/v1beta/openai" {
		t.Errorf("effectiveBase() = %q, want Google compat URL", got)
	}
}

func TestGeminiCompatProvider_BearerAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		resp := ChatResponse{
			ID: "chatcmpl-test", Object: "chat.completion", Model: "gemini-2.0-flash",
			Choices: []ChatChoice{{Index: 0, Message: &ChatMessage{Role: "assistant", Content: "hi"}, FinishReason: strPtr("stop")}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &geminiCompatProvider{model: "gemini-2.0-flash", apiKey: "AIzaTest123", baseURL: srv.URL}
	_, err := p.ChatCompletion(context.Background(), &ChatRequest{
		Model: "gemini-2.0-flash", Messages: []ChatMessage{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotAuth != "Bearer AIzaTest123" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer AIzaTest123")
	}
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./internal/gateway/ -run TestGeminiCompat -count=1 -v 2>&1 | tail -10`
Expected: FAIL — `geminiCompatProvider` not defined.

- [ ] **Step 3: Implement `provider_gemini_compat.go`**

```go
// internal/gateway/provider_gemini_compat.go
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const geminiCompatDefaultBase = "https://generativelanguage.googleapis.com/v1beta/openai"

type geminiCompatProvider struct {
	model   string
	apiKey  string
	baseURL string
}

func (p *geminiCompatProvider) effectiveBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return geminiCompatDefaultBase
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
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("provider: upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	return readOpenAISSE(resp.Body, chunkCb)
}
```

- [ ] **Step 4: Add cases to `NewProvider` and `NewProviderWithBase`**

In `NewProvider`:
```go
	case "gemini-openai":
		return &geminiCompatProvider{model: modelID, apiKey: apiKey}, nil
```

In `NewProviderWithBase`:
```go
	case "gemini-openai":
		return &geminiCompatProvider{model: modelID, apiKey: apiKey, baseURL: baseURL}
```

- [ ] **Step 5: Run tests**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./internal/gateway/ -run TestGeminiCompat -count=1 -v`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/gateway/provider_gemini_compat.go internal/gateway/provider_gemini_compat_test.go internal/gateway/provider.go
git commit -m "feat: add Gemini OpenAI-compatible provider"
```

---

## Task 7: Gemini native provider

**Files:**
- Create: `internal/gateway/provider_gemini.go`
- Create: `internal/gateway/provider_gemini_test.go`

- [ ] **Step 1: Write failing tests**

```go
// internal/gateway/provider_gemini_test.go
package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGeminiNative_TranslateRequest(t *testing.T) {
	p := &geminiNativeProvider{model: "gemini-2.0-flash", apiKey: "AIzaTest"}
	req := &ChatRequest{
		Model: "gemini-2.0-flash",
		Messages: []ChatMessage{
			{Role: "system", Content: "You are helpful."},
			{Role: "user", Content: "Hello"},
			{Role: "assistant", Content: "Hi there"},
			{Role: "user", Content: "How are you?"},
		},
		MaxTokens: intPtr(1024),
	}
	gReq := p.translateRequest(req)

	if gReq.SystemInstruction == nil || len(gReq.SystemInstruction.Parts) == 0 {
		t.Fatal("systemInstruction should contain the system message")
	}
	if gReq.SystemInstruction.Parts[0].Text != "You are helpful." {
		t.Errorf("system text = %q, want %q", gReq.SystemInstruction.Parts[0].Text, "You are helpful.")
	}
	if len(gReq.Contents) != 3 {
		t.Fatalf("contents length = %d, want 3 (user, model, user)", len(gReq.Contents))
	}
	if gReq.Contents[0].Role != "user" {
		t.Errorf("contents[0].role = %q, want 'user'", gReq.Contents[0].Role)
	}
	if gReq.Contents[1].Role != "model" {
		t.Errorf("contents[1].role = %q, want 'model'", gReq.Contents[1].Role)
	}
	if gReq.GenerationConfig.MaxOutputTokens != 1024 {
		t.Errorf("maxOutputTokens = %d, want 1024", gReq.GenerationConfig.MaxOutputTokens)
	}
}

func TestGeminiNative_TranslateResponse(t *testing.T) {
	p := &geminiNativeProvider{model: "gemini-2.0-flash", apiKey: "key"}
	gResp := &geminiResponse{
		Candidates: []geminiCandidate{{
			Content: geminiContent{
				Role:  "model",
				Parts: []geminiPart{{Text: "Hello world"}},
			},
			FinishReason: "STOP",
		}},
		UsageMetadata: &geminiUsage{
			PromptTokenCount:     10,
			CandidatesTokenCount: 5,
			TotalTokenCount:      15,
		},
	}
	resp := p.translateResponse(gResp, "gemini-2.0-flash")

	if len(resp.Choices) != 1 {
		t.Fatalf("choices = %d, want 1", len(resp.Choices))
	}
	if resp.Choices[0].Message.Content != "Hello world" {
		t.Errorf("content = %q, want %q", resp.Choices[0].Message.Content, "Hello world")
	}
	if *resp.Choices[0].FinishReason != "stop" {
		t.Errorf("finish_reason = %q, want 'stop'", *resp.Choices[0].FinishReason)
	}
	if resp.Usage.TotalTokens != 15 {
		t.Errorf("total_tokens = %d, want 15", resp.Usage.TotalTokens)
	}
}

func TestGeminiNative_FinishReasonMapping(t *testing.T) {
	tests := []struct{ gemini, openai string }{
		{"STOP", "stop"},
		{"MAX_TOKENS", "length"},
		{"SAFETY", "content_filter"},
		{"", "stop"},
	}
	for _, tt := range tests {
		got := mapGeminiFinishReason(tt.gemini)
		if got != tt.openai {
			t.Errorf("mapGeminiFinishReason(%q) = %q, want %q", tt.gemini, got, tt.openai)
		}
	}
}

func TestGeminiNative_URLConstruction(t *testing.T) {
	p := &geminiNativeProvider{model: "gemini-2.0-flash", apiKey: "AIzaTest"}

	nonStream := p.generateURL(false)
	if !strings.Contains(nonStream, "/models/gemini-2.0-flash:generateContent") {
		t.Errorf("non-streaming URL = %q, want :generateContent", nonStream)
	}
	if !strings.Contains(nonStream, "key=AIzaTest") {
		t.Errorf("non-streaming URL should contain API key, got %q", nonStream)
	}

	stream := p.generateURL(true)
	if !strings.Contains(stream, "/models/gemini-2.0-flash:streamGenerateContent") {
		t.Errorf("streaming URL = %q, want :streamGenerateContent", stream)
	}
	if !strings.Contains(stream, "alt=sse") {
		t.Errorf("streaming URL should contain alt=sse, got %q", stream)
	}
}

func TestGeminiNative_EndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var gReq geminiRequest
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &gReq)

		resp := geminiResponse{
			Candidates: []geminiCandidate{{
				Content: geminiContent{
					Role:  "model",
					Parts: []geminiPart{{Text: "I am Gemini"}},
				},
				FinishReason: "STOP",
			}},
			UsageMetadata: &geminiUsage{
				PromptTokenCount:     5,
				CandidatesTokenCount: 3,
				TotalTokenCount:      8,
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &geminiNativeProvider{model: "gemini-2.0-flash", apiKey: "AIzaTest", baseURL: srv.URL}
	resp, err := p.ChatCompletion(context.Background(), &ChatRequest{
		Model: "gemini-2.0-flash",
		Messages: []ChatMessage{
			{Role: "user", Content: "Who are you?"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Choices[0].Message.Content != "I am Gemini" {
		t.Errorf("content = %q, want %q", resp.Choices[0].Message.Content, "I am Gemini")
	}
}

func TestGeminiNative_StreamEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		chunks := []geminiResponse{
			{Candidates: []geminiCandidate{{Content: geminiContent{Role: "model", Parts: []geminiPart{{Text: "Hello "}}}}}},
			{Candidates: []geminiCandidate{{Content: geminiContent{Role: "model", Parts: []geminiPart{{Text: "world"}}}, FinishReason: "STOP"}},
				UsageMetadata: &geminiUsage{PromptTokenCount: 5, CandidatesTokenCount: 2, TotalTokenCount: 7}},
		}
		for _, c := range chunks {
			data, _ := json.Marshal(c)
			fmt.Fprintf(w, "data: %s\n\n", data)
		}
	}))
	defer srv.Close()

	p := &geminiNativeProvider{model: "gemini-2.0-flash", apiKey: "AIzaTest", baseURL: srv.URL}
	var collected []string
	usage, err := p.ChatCompletionStream(context.Background(), &ChatRequest{
		Model: "gemini-2.0-flash", Stream: true,
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
	}, func(chunk StreamChunk) {
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta != nil {
			collected = append(collected, chunk.Choices[0].Delta.Content)
		}
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	full := strings.Join(collected, "")
	if full != "Hello world" {
		t.Errorf("streamed content = %q, want %q", full, "Hello world")
	}
	if usage == nil || usage.TotalTokens != 7 {
		t.Errorf("usage = %v, want TotalTokens=7", usage)
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./internal/gateway/ -run TestGeminiNative -count=1 -v 2>&1 | tail -10`
Expected: FAIL — `geminiNativeProvider` not defined.

- [ ] **Step 3: Implement `provider_gemini.go`**

```go
// internal/gateway/provider_gemini.go
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
	"time"
)

const geminiDefaultBase = "https://generativelanguage.googleapis.com/v1beta"

// ---------------------------------------------------------------------------
// Gemini API types
// ---------------------------------------------------------------------------

type geminiRequest struct {
	Contents         []geminiContent    `json:"contents"`
	SystemInstruction *geminiContent    `json:"systemInstruction,omitempty"`
	GenerationConfig geminiGenConfig    `json:"generationConfig,omitempty"`
	Tools            []geminiTool       `json:"tools,omitempty"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text             string                 `json:"text,omitempty"`
	FunctionCall     *geminiFunctionCall    `json:"functionCall,omitempty"`
	FunctionResponse *geminiFunctionResp    `json:"functionResponse,omitempty"`
}

type geminiFunctionCall struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

type geminiFunctionResp struct {
	Name     string          `json:"name"`
	Response json.RawMessage `json:"response"`
}

type geminiGenConfig struct {
	MaxOutputTokens int      `json:"maxOutputTokens,omitempty"`
	Temperature     *float64 `json:"temperature,omitempty"`
	TopP            *float64 `json:"topP,omitempty"`
	StopSequences   []string `json:"stopSequences,omitempty"`
}

type geminiTool struct {
	FunctionDeclarations []geminiFuncDecl `json:"functionDeclarations,omitempty"`
}

type geminiFuncDecl struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

type geminiResponse struct {
	Candidates    []geminiCandidate `json:"candidates"`
	UsageMetadata *geminiUsage      `json:"usageMetadata,omitempty"`
}

type geminiCandidate struct {
	Content      geminiContent `json:"content"`
	FinishReason string        `json:"finishReason,omitempty"`
}

type geminiUsage struct {
	PromptTokenCount     int64 `json:"promptTokenCount"`
	CandidatesTokenCount int64 `json:"candidatesTokenCount"`
	TotalTokenCount      int64 `json:"totalTokenCount"`
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

type geminiNativeProvider struct {
	model   string
	apiKey  string
	baseURL string
}

func (p *geminiNativeProvider) effectiveBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return geminiDefaultBase
}

func (p *geminiNativeProvider) generateURL(stream bool) string {
	base := strings.TrimRight(p.effectiveBase(), "/")
	if stream {
		return fmt.Sprintf("%s/models/%s:streamGenerateContent?alt=sse&key=%s", base, p.model, p.apiKey)
	}
	return fmt.Sprintf("%s/models/%s:generateContent?key=%s", base, p.model, p.apiKey)
}

func (p *geminiNativeProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	gReq := p.translateRequest(req)

	body, err := json.Marshal(gReq)
	if err != nil {
		return nil, fmt.Errorf("provider: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.generateURL(false), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := providerHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("provider: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("provider: upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	var gResp geminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&gResp); err != nil {
		return nil, fmt.Errorf("provider: decode response: %w", err)
	}

	return p.translateResponse(&gResp, req.Model), nil
}

func (p *geminiNativeProvider) ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error) {
	gReq := p.translateRequest(req)

	body, err := json.Marshal(gReq)
	if err != nil {
		return nil, fmt.Errorf("provider: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.generateURL(true), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := providerHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("provider: stream request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("provider: upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	return p.readGeminiSSE(resp.Body, req.Model, chunkCb)
}

// ---------------------------------------------------------------------------
// Translation
// ---------------------------------------------------------------------------

func (p *geminiNativeProvider) translateRequest(req *ChatRequest) *geminiRequest {
	var system *geminiContent
	var contents []geminiContent

	for _, m := range req.Messages {
		switch m.Role {
		case "system":
			if system == nil {
				system = &geminiContent{Parts: []geminiPart{{Text: m.Content}}}
			} else {
				system.Parts = append(system.Parts, geminiPart{Text: m.Content})
			}

		case "assistant":
			content := geminiContent{Role: "model"}
			if m.Content != "" {
				content.Parts = append(content.Parts, geminiPart{Text: m.Content})
			}
			if len(m.ToolCalls) > 0 {
				var toolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				}
				if json.Unmarshal(m.ToolCalls, &toolCalls) == nil {
					for _, tc := range toolCalls {
						var args json.RawMessage
						if json.Unmarshal([]byte(tc.Function.Arguments), &args) != nil {
							args = json.RawMessage(tc.Function.Arguments)
						}
						content.Parts = append(content.Parts, geminiPart{
							FunctionCall: &geminiFunctionCall{Name: tc.Function.Name, Args: args},
						})
					}
				}
			}
			contents = append(contents, content)

		case "tool":
			respJSON, _ := json.Marshal(map[string]string{"result": m.Content})
			contents = append(contents, geminiContent{
				Role: "function",
				Parts: []geminiPart{{
					FunctionResponse: &geminiFunctionResp{
						Name:     m.Name,
						Response: respJSON,
					},
				}},
			})

		default: // "user"
			contents = append(contents, geminiContent{
				Role:  "user",
				Parts: []geminiPart{{Text: m.Content}},
			})
		}
	}

	gReq := &geminiRequest{
		Contents:          contents,
		SystemInstruction: system,
	}

	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		gReq.GenerationConfig.MaxOutputTokens = *req.MaxTokens
	}
	gReq.GenerationConfig.Temperature = req.Temperature
	gReq.GenerationConfig.TopP = req.TopP

	if len(req.Stop) > 0 {
		var stops []string
		if json.Unmarshal(req.Stop, &stops) != nil {
			var single string
			if json.Unmarshal(req.Stop, &single) == nil {
				stops = []string{single}
			}
		}
		gReq.GenerationConfig.StopSequences = stops
	}

	if len(req.Tools) > 0 {
		var oaiTools []struct {
			Function struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				Parameters  json.RawMessage `json:"parameters"`
			} `json:"function"`
		}
		if json.Unmarshal(req.Tools, &oaiTools) == nil {
			var decls []geminiFuncDecl
			for _, t := range oaiTools {
				decls = append(decls, geminiFuncDecl{
					Name:        t.Function.Name,
					Description: t.Function.Description,
					Parameters:  t.Function.Parameters,
				})
			}
			gReq.Tools = []geminiTool{{FunctionDeclarations: decls}}
		}
	}

	return gReq
}

func (p *geminiNativeProvider) translateResponse(gResp *geminiResponse, modelAlias string) *ChatResponse {
	resp := &ChatResponse{
		ID:      "chatcmpl-gemini-" + fmt.Sprintf("%d", time.Now().UnixNano()),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   modelAlias,
	}

	if len(gResp.Candidates) > 0 {
		cand := gResp.Candidates[0]
		var textParts []string
		var toolCalls []map[string]interface{}

		for _, part := range cand.Content.Parts {
			if part.Text != "" {
				textParts = append(textParts, part.Text)
			}
			if part.FunctionCall != nil {
				argsJSON := string(part.FunctionCall.Args)
				if argsJSON == "" {
					argsJSON = "{}"
				}
				toolCalls = append(toolCalls, map[string]interface{}{
					"id":   fmt.Sprintf("call_%d", len(toolCalls)),
					"type": "function",
					"function": map[string]interface{}{
						"name":      part.FunctionCall.Name,
						"arguments": argsJSON,
					},
				})
			}
		}

		finishReason := mapGeminiFinishReason(cand.FinishReason)
		msg := &ChatMessage{Role: "assistant", Content: strings.Join(textParts, "")}
		if len(toolCalls) > 0 {
			msg.ToolCalls, _ = json.Marshal(toolCalls)
			if finishReason == "stop" {
				finishReason = "tool_calls"
			}
		}

		resp.Choices = []ChatChoice{{
			Index:        0,
			Message:      msg,
			FinishReason: &finishReason,
		}}
	}

	if gResp.UsageMetadata != nil {
		resp.Usage = &ChatUsage{
			PromptTokens:     gResp.UsageMetadata.PromptTokenCount,
			CompletionTokens: gResp.UsageMetadata.CandidatesTokenCount,
			TotalTokens:      gResp.UsageMetadata.TotalTokenCount,
		}
	}

	return resp
}

func (p *geminiNativeProvider) readGeminiSSE(r io.Reader, modelAlias string, cb func(StreamChunk)) (*ChatUsage, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 256*1024)
	var usage *ChatUsage
	created := time.Now().Unix()
	chunkID := fmt.Sprintf("chatcmpl-gemini-%d", time.Now().UnixNano())

	firstChunk := true

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		var gResp geminiResponse
		if err := json.Unmarshal([]byte(data), &gResp); err != nil {
			continue
		}

		if firstChunk {
			cb(StreamChunk{
				ID: chunkID, Object: "chat.completion.chunk", Created: created, Model: modelAlias,
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Role: "assistant"}}},
			})
			firstChunk = false
		}

		if len(gResp.Candidates) > 0 {
			cand := gResp.Candidates[0]
			for _, part := range cand.Content.Parts {
				if part.Text != "" {
					cb(StreamChunk{
						ID: chunkID, Object: "chat.completion.chunk", Created: created, Model: modelAlias,
						Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: part.Text}}},
					})
				}
			}
			if cand.FinishReason != "" {
				fr := mapGeminiFinishReason(cand.FinishReason)
				chunk := StreamChunk{
					ID: chunkID, Object: "chat.completion.chunk", Created: created, Model: modelAlias,
					Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &fr}},
				}
				if gResp.UsageMetadata != nil {
					chunk.Usage = &ChatUsage{
						PromptTokens:     gResp.UsageMetadata.PromptTokenCount,
						CompletionTokens: gResp.UsageMetadata.CandidatesTokenCount,
						TotalTokens:      gResp.UsageMetadata.TotalTokenCount,
					}
					usage = chunk.Usage
				}
				cb(chunk)
			}
		}

		if gResp.UsageMetadata != nil && usage == nil {
			usage = &ChatUsage{
				PromptTokens:     gResp.UsageMetadata.PromptTokenCount,
				CompletionTokens: gResp.UsageMetadata.CandidatesTokenCount,
				TotalTokens:      gResp.UsageMetadata.TotalTokenCount,
			}
		}
	}
	return usage, scanner.Err()
}

func mapGeminiFinishReason(reason string) string {
	switch reason {
	case "STOP":
		return "stop"
	case "MAX_TOKENS":
		return "length"
	case "SAFETY":
		return "content_filter"
	case "RECITATION":
		return "content_filter"
	default:
		if reason == "" {
			return "stop"
		}
		return reason
	}
}
```

- [ ] **Step 4: Add cases to `NewProvider` and `NewProviderWithBase`**

In `NewProvider`:
```go
	case "gemini":
		return &geminiNativeProvider{model: modelID, apiKey: apiKey}, nil
```

In `NewProviderWithBase`:
```go
	case "gemini":
		return &geminiNativeProvider{model: modelID, apiKey: apiKey, baseURL: baseURL}
```

- [ ] **Step 5: Run tests**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./internal/gateway/ -run TestGeminiNative -count=1 -v`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/gateway/provider_gemini.go internal/gateway/provider_gemini_test.go internal/gateway/provider.go
git commit -m "feat: add Gemini native provider with full translation"
```

---

## Task 8: Multi-provider proxy routing

**Files:**
- Modify: `internal/gateway/proxy.go:48-119, 238-310, 311-340, 370-420`

- [ ] **Step 1: Update `GuardrailProxy` struct**

Replace the `provider LLMProvider` field with multi-provider support:

```go
type GuardrailProxy struct {
	cfg       *config.GuardrailConfig
	logger    *audit.Logger
	health    *SidecarHealth
	otel      *telemetry.Provider
	store     *audit.Store
	dataDir   string

	providers        map[string]LLMProvider
	blockedProviders map[string]bool
	primary          LLMProvider
	inspector        ContentInspector
	masterKey        string

	rtMu         sync.RWMutex
	mode         string
	blockMessage string
}
```

- [ ] **Step 2: Update `NewGuardrailProxy` constructor**

Replace the single-provider construction (lines 82-93) with:

```go
	dotenvPath := filepath.Join(dataDir, ".env")

	if cfg.Model == "" {
		return nil, fmt.Errorf("proxy: guardrail.model is required")
	}

	apiKey := ResolveAPIKey(cfg.APIKeyEnv, dotenvPath)
	if apiKey == "" {
		return nil, fmt.Errorf("proxy: no API key available (set guardrail.api_key_env and provide the key in ~/.defenseclaw/.env or environment)")
	}

	primary := NewProviderWithBase(cfg.Model, apiKey, cfg.APIBase)

	providers := map[string]LLMProvider{}
	blockedProviders := map[string]bool{}

	// Load multi-provider config if available
	provCfgPath := filepath.Join(dataDir, "guardrail_providers.json")
	if data, err := os.ReadFile(provCfgPath); err == nil {
		var provEntries map[string]struct {
			BaseURL   string `json:"base_url"`
			APIKeyEnv string `json:"api_key_env"`
			Supported bool   `json:"supported"`
		}
		if json.Unmarshal(data, &provEntries) == nil {
			for name, entry := range provEntries {
				if !entry.Supported {
					blockedProviders[name] = true
					continue
				}
				key := ResolveAPIKey(entry.APIKeyEnv, dotenvPath)
				if key == "" {
					continue
				}
				modelPrefix := name + "/placeholder"
				providers[name] = NewProviderWithBase(modelPrefix, key, entry.BaseURL)
			}
		}
	}

	// Ensure primary provider prefix is in the map
	primaryPrefix, _ := splitModel(cfg.Model)
	if primaryPrefix != "" {
		providers[primaryPrefix] = primary
	}
```

Update the struct literal to use the new fields:

```go
	return &GuardrailProxy{
		cfg:              cfg,
		logger:           logger,
		health:           health,
		otel:             otel,
		store:            store,
		dataDir:          dataDir,
		providers:        providers,
		blockedProviders: blockedProviders,
		primary:          primary,
		inspector:        inspector,
		masterKey:        masterKey,
		mode:             cfg.Mode,
		blockMessage:     cfg.BlockMessage,
	}, nil
```

- [ ] **Step 3: Update `handleChatCompletion` routing**

After the pre-call inspection block (around line 303), replace the forwarding section:

```go
	// --- Forward to upstream provider ---
	upstream := p.resolveProvider(req.Model)
	if upstream == nil {
		provName, _ := splitModel(req.Model)
		msg := fmt.Sprintf("provider %q is not supported by DefenseClaw guardrail — traffic blocked", provName)
		if req.Stream {
			p.writeBlockedStream(w, req.Model, msg)
		} else {
			writeOpenAIError(w, http.StatusForbidden, msg)
		}
		return
	}

	if req.Stream {
		p.handleStreamingRequest(w, r, req, mode, customBlockMsg, upstream)
	} else {
		p.handleNonStreamingRequest(w, r, req, mode, customBlockMsg, upstream)
	}
```

Add the `resolveProvider` method:

```go
func (p *GuardrailProxy) resolveProvider(model string) LLMProvider {
	prefix, _ := splitModel(model)
	if prefix != "" {
		if _, blocked := p.blockedProviders[prefix]; blocked {
			return nil
		}
		if prov, ok := p.providers[prefix]; ok {
			return prov
		}
	}
	return p.primary
}
```

- [ ] **Step 4: Update `handleNonStreamingRequest` and `handleStreamingRequest` signatures**

Add `upstream LLMProvider` parameter to both methods. Replace `p.provider.ChatCompletion` with `upstream.ChatCompletion` and `p.provider.ChatCompletionStream` with `upstream.ChatCompletionStream`.

In `handleNonStreamingRequest`:
```go
func (p *GuardrailProxy) handleNonStreamingRequest(w http.ResponseWriter, r *http.Request, req *ChatRequest, mode, customBlockMsg string, upstream LLMProvider) {
	// ... existing code ...
	resp, err := upstream.ChatCompletion(r.Context(), req)
```

In `handleStreamingRequest`:
```go
func (p *GuardrailProxy) handleStreamingRequest(w http.ResponseWriter, r *http.Request, req *ChatRequest, mode, customBlockMsg string, upstream LLMProvider) {
	// ... existing code ...
	usage, err := upstream.ChatCompletionStream(r.Context(), req, func(chunk StreamChunk) {
```

- [ ] **Step 5: Run all tests**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./internal/gateway/ -count=1 -v 2>&1 | tail -30`
Expected: All tests PASS. The `proxy_test.go` tests use `mockProvider` which still works since `newTestProxy` sets `primary` directly.

Note: You may need to update `newTestProxy` in `proxy_test.go` to set `primary` instead of `provider`:
```go
// In proxy_test.go, update newTestProxy to use new fields:
proxy.primary = prov
proxy.providers = map[string]LLMProvider{}
proxy.blockedProviders = map[string]bool{}
```

- [ ] **Step 6: Commit**

```bash
git add internal/gateway/proxy.go internal/gateway/proxy_test.go
git commit -m "feat: multi-provider routing in guardrail proxy with blocked-provider support"
```

---

## Task 9: Python CLI — config and guardrail helper updates

**Files:**
- Modify: `cli/defenseclaw/config.py:428-438, 713-727`
- Modify: `cli/defenseclaw/guardrail.py:276-313`

- [ ] **Step 1: Add `api_base` to Python `GuardrailConfig`**

In `cli/defenseclaw/config.py`, add after `block_message` field (line 437):

```python
    api_base: str = ""              # base URL override for Azure, custom endpoints
```

- [ ] **Step 2: Update `_merge_guardrail` to read `api_base`**

In `cli/defenseclaw/config.py`, add to the `GuardrailConfig()` constructor call (after line 725):

```python
        api_base=raw.get("api_base", ""),
```

- [ ] **Step 3: Update `KNOWN_PROVIDERS`**

In `cli/defenseclaw/guardrail.py`, replace line 301:

```python
KNOWN_PROVIDERS = ["anthropic", "openai", "openrouter", "azure", "gemini", "gemini-openai"]
```

- [ ] **Step 4: Update `guess_provider`**

Replace the function:

```python
def guess_provider(model: str) -> str:
    """Best-effort guess of the provider from a bare model name (no / prefix)."""
    lower = model.lower()
    if lower.startswith("claude"):
        return "anthropic"
    if lower.startswith(("gpt", "o1", "o3", "o4")):
        return "openai"
    if lower.startswith("gemini"):
        return "gemini"
    return ""
```

- [ ] **Step 5: Update `detect_api_key_env`**

Replace the function:

```python
def detect_api_key_env(model: str) -> str:
    """Guess the API key env var from the model string."""
    lower = model.lower()
    if "anthropic" in lower or "claude" in lower:
        return "ANTHROPIC_API_KEY"
    if "azure" in lower:
        return "AZURE_OPENAI_API_KEY"
    if "openrouter" in lower:
        return "OPENROUTER_API_KEY"
    if "openai" in lower or "gpt" in lower or "o1" in lower:
        return "OPENAI_API_KEY"
    if "gemini" in lower or "google" in lower:
        return "GOOGLE_API_KEY"
    if "bedrock" in lower:
        return "AWS_ACCESS_KEY_ID"
    return "LLM_API_KEY"
```

- [ ] **Step 6: Update `model_to_proxy_name`**

Replace the function:

```python
def model_to_proxy_name(model: str) -> str:
    """Derive a short model alias from a full model string like 'anthropic/claude-opus-4-5'."""
    # For multi-slash models (openrouter/anthropic/claude-opus-4-5), use last segment
    name = model.split("/")[-1] if "/" in model else model
    for prefix in ("anthropic-", "openai-", "google-", "azure-", "openrouter-", "gemini-", "gemini-openai-"):
        name = name.removeprefix(prefix)
    return name
```

- [ ] **Step 7: Run Python tests**

Run: `cd /Users/nghodki/workspace/defenseclaw && python -m pytest cli/ -x -q 2>&1 | tail -10`
Expected: All PASS.

- [ ] **Step 8: Commit**

```bash
git add cli/defenseclaw/config.py cli/defenseclaw/guardrail.py
git commit -m "feat: Python CLI support for new providers — config, detection, routing"
```

---

## Task 10: Multi-provider openclaw.json patching

**Files:**
- Modify: `cli/defenseclaw/guardrail.py:33-132`

- [ ] **Step 1: Add `detect_provider_configs` function**

Add after `detect_current_model`:

```python
def detect_provider_configs(openclaw_config_file: str) -> dict[str, dict]:
    """Read all provider configurations from openclaw.json.

    Returns {provider_name: {"base_url": ..., "api_key": ..., "models": [...]}}.
    """
    path = _expand(openclaw_config_file)
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}

    providers = cfg.get("models", {}).get("providers", {})
    result = {}
    for name, prov in providers.items():
        if name == "defenseclaw" or name == "litellm":
            continue
        result[name] = {
            "base_url": prov.get("baseUrl", ""),
            "api_key": prov.get("apiKey", ""),
            "models": [m.get("id", "") for m in prov.get("models", [])],
        }
    return result
```

- [ ] **Step 2: Update `patch_openclaw_config` for multi-provider patching**

Replace the function:

```python
def patch_openclaw_config(
    openclaw_config_file: str,
    model_name: str,
    proxy_port: int,
    master_key: str,
    original_model: str,
) -> str | None:
    """Patch openclaw.json to route ALL providers through the guardrail proxy."""
    path = _expand(openclaw_config_file)

    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    _backup(path)

    prev_model = (
        cfg.get("agents", {}).get("defaults", {}).get("model", {}).get("primary", "")
    )

    if "models" not in cfg:
        cfg["models"] = {}
    if "providers" not in cfg["models"]:
        cfg["models"]["providers"] = {}

    # Save and patch ALL existing providers
    original_providers = {}
    for name, prov in list(cfg["models"]["providers"].items()):
        if name in ("defenseclaw", "litellm"):
            continue
        original_providers[name] = prov.copy()
        # Redirect to proxy
        prov["baseUrl"] = f"http://localhost:{proxy_port}"
        prov["apiKey"] = master_key

    # Store originals for restore
    if original_providers:
        cfg["_defenseclaw_original_providers"] = original_providers

    # Add the defenseclaw provider (for the primary model alias)
    cfg["models"]["providers"]["defenseclaw"] = {
        "baseUrl": f"http://localhost:{proxy_port}",
        "apiKey": master_key,
        "api": "openai-completions",
        "models": [
            {
                "id": model_name,
                "name": f"{model_name} (via DefenseClaw)",
                "reasoning": False,
                "input": ["text", "image"],
                "contextWindow": 200000,
                "maxTokens": 64000,
            },
        ],
    }

    cfg.setdefault("agents", {}).setdefault("defaults", {}).setdefault("model", {})
    cfg["agents"]["defaults"]["model"]["primary"] = f"defenseclaw/{model_name}"

    plugins = cfg.setdefault("plugins", {})
    allow = plugins.setdefault("allow", [])
    if "defenseclaw" not in allow:
        allow.append("defenseclaw")

    oc_home = os.path.dirname(path)
    install_path = os.path.join(oc_home, "extensions", "defenseclaw")
    load = plugins.setdefault("load", {})
    paths = load.setdefault("paths", [])
    if install_path not in paths:
        paths.append(install_path)

    with open(path, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")

    _install_codeguard_skill_deferred(openclaw_config_file)

    return prev_model or original_model
```

- [ ] **Step 3: Update `restore_openclaw_config` for multi-provider restore**

Replace the function:

```python
def restore_openclaw_config(openclaw_config_file: str, original_model: str) -> bool:
    """Revert OpenClaw config — restore all original providers."""
    path = _expand(openclaw_config_file)

    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False

    _backup(path)

    if original_model:
        cfg.setdefault("agents", {}).setdefault("defaults", {}).setdefault("model", {})
        cfg["agents"]["defaults"]["model"]["primary"] = original_model

    # Restore original provider entries
    original_providers = cfg.pop("_defenseclaw_original_providers", {})
    if original_providers and "models" in cfg and "providers" in cfg["models"]:
        for name, prov in original_providers.items():
            cfg["models"]["providers"][name] = prov

    if "models" in cfg and "providers" in cfg["models"]:
        cfg["models"]["providers"].pop("defenseclaw", None)
        cfg["models"]["providers"].pop("litellm", None)

    if "plugins" in cfg and "allow" in cfg["plugins"]:
        allow = cfg["plugins"]["allow"]
        if "defenseclaw" in allow:
            allow.remove("defenseclaw")

    with open(path, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")

    return True
```

- [ ] **Step 4: Add `write_provider_configs` helper**

Add at the end of the file (before internal helpers):

```python
def write_provider_configs(
    data_dir: str,
    provider_configs: dict[str, dict],
    supported_providers: set[str],
) -> None:
    """Write guardrail_providers.json for the Go proxy to read."""
    entries = {}
    for name, cfg in provider_configs.items():
        api_key_env = detect_api_key_env(name)
        entries[name] = {
            "base_url": cfg.get("base_url", ""),
            "api_key_env": api_key_env,
            "supported": name in supported_providers,
        }

    path = os.path.join(_expand(data_dir), "guardrail_providers.json")
    with open(path, "w") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
        f.write("\n")
```

- [ ] **Step 5: Run Python tests**

Run: `cd /Users/nghodki/workspace/defenseclaw && python -m pytest cli/ -x -q 2>&1 | tail -10`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add cli/defenseclaw/guardrail.py
git commit -m "feat: multi-provider openclaw.json patching with restore support"
```

---

## Task 11: Update setup wizard for multi-provider flow

**Files:**
- Modify: `cli/defenseclaw/commands/cmd_setup.py:895-1050`
- Modify: `cli/defenseclaw/commands/cmd_setup.py:752-892`

- [ ] **Step 1: Update `_interactive_guardrail_setup` to detect all providers**

After the existing model detection block (around line 976), add multi-provider detection:

```python
    # Detect all providers in openclaw.json
    from defenseclaw.guardrail import detect_provider_configs, write_provider_configs, KNOWN_PROVIDERS as KNOWN_PROV_LIST

    all_providers = detect_provider_configs(app.cfg.claw.config_file)
    if all_providers:
        supported = {n for n in all_providers if n in KNOWN_PROV_LIST}
        unsupported = {n for n in all_providers if n not in KNOWN_PROV_LIST}

        click.echo()
        click.echo(f"  Found {len(all_providers)} provider(s) in OpenClaw config:")
        for name in sorted(all_providers):
            status = "✓ supported" if name in supported else "✗ unsupported (will be blocked)"
            models = ", ".join(all_providers[name].get("models", [])[:3])
            click.echo(f"    {name}: {models} — {status}")

        if unsupported:
            click.echo()
            click.echo(f"  ⚠ {len(unsupported)} unsupported provider(s) will have traffic BLOCKED:")
            for name in sorted(unsupported):
                click.echo(f"    • {name}")

        click.echo()
        if click.confirm("  Route all providers through the guardrail?", default=True):
            # For azure, extract base_url automatically
            for name in supported:
                base = all_providers[name].get("base_url", "")
                if name == "azure" and base:
                    gc.api_base = base
                    click.echo(f"  ✓ Azure deployment URL extracted: {base[:60]}...")
        else:
            click.echo("  Skipping multi-provider patching — only the primary model will be routed.")
            all_providers = {}
```

- [ ] **Step 2: Update `execute_guardrail_setup` to write provider configs**

After step 2 (patch openclaw config), around line 848, add:

```python
    # --- Step 2b: Write multi-provider config for Go proxy ---
    from defenseclaw.guardrail import detect_provider_configs, write_provider_configs

    all_providers = detect_provider_configs(app.cfg.claw.config_file)
    if all_providers:
        supported_set = {"anthropic", "openai", "openrouter", "azure", "gemini", "gemini-openai"}
        write_provider_configs(app.cfg.data_dir, all_providers, supported_set)
        click.echo(f"  ✓ Provider configs written to ~/.defenseclaw/guardrail_providers.json")
```

- [ ] **Step 3: Update summary rows**

In the summary section (around line 706), add after the existing rows:

```python
    if gc.api_base:
        rows.append(("guardrail.api_base", gc.api_base[:60] + "..." if len(gc.api_base) > 60 else gc.api_base))
```

- [ ] **Step 4: Run Python tests**

Run: `cd /Users/nghodki/workspace/defenseclaw && python -m pytest cli/ -x -q 2>&1 | tail -10`
Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add cli/defenseclaw/commands/cmd_setup.py
git commit -m "feat: multi-provider setup wizard with unsupported provider blocking"
```

---

## Task 12: Full integration test

**Files:**
- All modified files

- [ ] **Step 1: Run full Go test suite**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./internal/... -count=1 -v 2>&1 | tail -30`
Expected: All PASS.

- [ ] **Step 2: Run full Python test suite**

Run: `cd /Users/nghodki/workspace/defenseclaw && python -m pytest cli/ -x -q 2>&1 | tail -10`
Expected: All PASS.

- [ ] **Step 3: Verify build compiles**

Run: `cd /Users/nghodki/workspace/defenseclaw && go build ./cmd/defenseclaw 2>&1`
Expected: No errors.

- [ ] **Step 4: Run linters**

Run: `cd /Users/nghodki/workspace/defenseclaw && make lint 2>&1 | tail -20`
Expected: Clean.

- [ ] **Step 5: Final commit if any fixes were needed**

```bash
git add -A
git commit -m "fix: address lint and test issues from provider expansion"
```
