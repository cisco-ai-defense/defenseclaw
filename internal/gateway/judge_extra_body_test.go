// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/configs"
)

func TestJudgeCompatibleAliasesRequireEffectiveEndpoint(t *testing.T) {
	for _, alias := range []string{"openai-compatible", "custom-openai"} {
		t.Run(alias, func(t *testing.T) {
			for _, baseURL := range []string{"", " / "} {
				llm := &config.LLMConfig{Provider: alias, Model: "gemma-4", BaseURL: baseURL, APIKey: "fixture-key"}
				if _, err := NewProviderForLLMConfig(llm, nil); err == nil || !strings.Contains(err.Error(), "base_url") {
					t.Errorf("base_url %q: expected a named endpoint error, got %v", baseURL, err)
				}
			}
			if _, err := NewProvider(alias+"/gemma-4", "fixture-key"); err == nil {
				t.Error("direct provider without base_url was accepted")
			}
			if _, err := NewProviderWithBase(alias+"/gemma-4", "fixture-key", " / "); err == nil {
				t.Error("direct provider with empty effective base_url was accepted")
			}

			withBase := &config.LLMConfig{Provider: alias, Model: "gemma-4", BaseURL: "http://127.0.0.1:8000/v1", APIKey: "fixture-key"}
			provider, err := NewProviderForLLMConfig(withBase, nil)
			if err != nil {
				t.Fatal(err)
			}
			if bp := provider.(*bifrostProvider); bp.providerKey != schemas.OpenAI || bp.baseURL != withBase.BaseURL {
				t.Fatalf("configured provider = %#v", bp)
			}
			provider, err = NewProviderWithBase(alias+"/gemma-4", "fixture-key", withBase.BaseURL)
			if err != nil {
				t.Fatal(err)
			}
			if bp := provider.(*bifrostProvider); bp.providerKey != schemas.OpenAI || bp.baseURL != withBase.BaseURL || bp.model != "gemma-4" {
				t.Fatalf("configured direct provider = %#v", bp)
			}
		})
	}

	registry := &configs.ProvidersConfig{Providers: []configs.Provider{{
		Name: "local-judge", BaseProviderType: "openai-compatible", BaseURL: "http://127.0.0.1:8000/v1",
	}}}
	llm := &config.LLMConfig{Provider: "custom", Model: "gemma-4", InstanceName: "local-judge"}
	provider, err := NewProviderForLLMConfig(llm, registry)
	if err != nil {
		t.Fatal(err)
	}
	if bp := provider.(*bifrostProvider); bp.baseURL != registry.Providers[0].BaseURL {
		t.Fatalf("overlay base_url = %q", bp.baseURL)
	}
	registry.Providers[0].BaseURL = ""
	if _, err := NewProviderForLLMConfig(llm, registry); err == nil {
		t.Fatal("overlay without base_url was accepted")
	}
}

func TestJudgeCompatibleModelPrefixCaseRequiresEndpoint(t *testing.T) {
	for _, prefix := range []string{"OpenAI-Compatible", "CUSTOM-OPENAI", "OpenAi-Compatible"} {
		model := prefix + "/gemma-4"
		t.Run(prefix, func(t *testing.T) {
			for _, build := range []func() (LLMProvider, error){
				func() (LLMProvider, error) { return NewProvider(model, "fixture-key") },
				func() (LLMProvider, error) {
					return NewProviderForLLMConfig(&config.LLMConfig{Model: model, APIKey: "fixture-key"}, nil)
				},
			} {
				if _, err := build(); err == nil || !strings.Contains(err.Error(), "base_url") {
					t.Errorf("unconfigured model %q: expected base_url error, got %v", model, err)
				}
			}

			baseURL := "http://127.0.0.1:8000/v1"
			for _, build := range []func() (LLMProvider, error){
				func() (LLMProvider, error) { return NewProviderWithBase(model, "fixture-key", baseURL) },
				func() (LLMProvider, error) {
					return NewProviderForLLMConfig(&config.LLMConfig{Model: model, BaseURL: baseURL, APIKey: "fixture-key"}, nil)
				},
			} {
				provider, err := build()
				if err != nil {
					t.Fatal(err)
				}
				if bp := provider.(*bifrostProvider); bp.providerKey != schemas.OpenAI || bp.baseURL != baseURL || bp.model != "gemma-4" {
					t.Errorf("configured model %q: provider = %#v", model, bp)
				}
			}
		})
	}
}

func TestJudgeNativeOpenAIDefaultEndpointTwin(t *testing.T) {
	for _, build := range []func() (LLMProvider, error){
		func() (LLMProvider, error) { return NewProvider("openai/gpt-4o", "fixture-key") },
		func() (LLMProvider, error) {
			return NewProviderForLLMConfig(&config.LLMConfig{Provider: "openai", Model: "gpt-4o"}, nil)
		},
	} {
		provider, err := build()
		if err != nil {
			t.Fatal(err)
		}
		if bp := provider.(*bifrostProvider); bp.providerKey != schemas.OpenAI || bp.baseURL != "" {
			t.Fatalf("native provider = %#v", bp)
		}
	}
}

func TestJudgeExtraBodyOpenAICompatibleRequest(t *testing.T) {
	provider := &bifrostProvider{providerKey: schemas.OpenAI, baseURL: "http://127.0.0.1:8000/v1"}
	configured := &LLMJudge{
		cfg: &config.JudgeConfig{ExtraBody: map[string]any{
			"chat_template_kwargs": map[string]any{"enable_thinking": false, "labels": []any{"a", "b"}},
			"reasoning_effort":     "none",
		}},
		model: "gemma-4", provider: provider, providerName: "openai-compatible",
	}
	req := configured.judgeChatRequest([]ChatMessage{{Role: "user", Content: "ordinary note"}}, 512, "injection")
	got := toBifrostChatRequest(schemas.OpenAI, "gemma-4", req).Params.ExtraParams
	if !reflect.DeepEqual(got, configured.cfg.ExtraBody) {
		t.Fatalf("Bifrost extra fields = %#v, want %#v", got, configured.cfg.ExtraBody)
	}
	if flag := newBifrostRequestContext(t.Context(), req).Value(schemas.BifrostContextKeyPassthroughExtraParams); flag != true {
		t.Fatalf("passthrough flag = %#v, want true", flag)
	}
	if key, err := mapProviderKey("openai-compatible"); err != nil || key != schemas.OpenAI {
		t.Fatalf("openai-compatible route = %q, %v", key, err)
	}
}

func TestJudgeExtraBodyReachesOpenAICompatibleServer(t *testing.T) {
	bodyCh := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("request path = %q", r.URL.Path)
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Error(err)
		}
		bodyCh <- body
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"judge-test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"{}"},"finish_reason":"stop"}]}`)
	}))
	defer server.Close()

	llm := config.LLMConfig{Provider: "openai-compatible", Model: "gemma-4", BaseURL: server.URL + "/v1", APIKey: "fixture-key"}
	provider, err := NewProviderForLLMConfig(&llm, nil)
	if err != nil {
		t.Fatal(err)
	}
	judge := &LLMJudge{
		cfg: &config.JudgeConfig{ExtraBody: map[string]any{
			"chat_template_kwargs": map[string]any{"enable_thinking": false},
		}},
		model: "gemma-4", provider: provider, providerName: "openai-compatible",
	}
	_, err = provider.ChatCompletion(t.Context(), judge.judgeChatRequest(
		[]ChatMessage{{Role: "user", Content: "ordinary note"}}, 512, "injection",
	))
	if err != nil {
		t.Fatal(err)
	}
	body := <-bodyCh
	kwargs, ok := body["chat_template_kwargs"].(map[string]any)
	if !ok || kwargs["enable_thinking"] != false {
		t.Fatalf("server body extra fields = %#v", body)
	}
	if body["model"] != "gemma-4" || body["max_completion_tokens"] != float64(512) {
		t.Fatalf("server body judge fields = %#v", body)
	}
}

func TestJudgeExtraBodyAbsentKeepsRequestShape(t *testing.T) {
	provider := &bifrostProvider{providerKey: schemas.OpenAI, baseURL: "http://127.0.0.1:8000/v1"}
	bare := &LLMJudge{cfg: &config.JudgeConfig{}, model: "gemma-4", provider: provider, providerName: "openai-compatible"}
	empty := &LLMJudge{cfg: &config.JudgeConfig{ExtraBody: map[string]any{}}, model: "gemma-4", provider: provider, providerName: "openai-compatible"}
	messages := []ChatMessage{{Role: "user", Content: "ordinary note"}}
	first := bare.judgeChatRequest(messages, 512, "injection")
	second := empty.judgeChatRequest(messages, 512, "injection")
	if first.ExtraParams != nil || second.ExtraParams != nil {
		t.Fatalf("unset extra fields changed request: %#v, %#v", first.ExtraParams, second.ExtraParams)
	}
	firstJSON, err := json.Marshal(toBifrostChatRequest(schemas.OpenAI, "gemma-4", first))
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(toBifrostChatRequest(schemas.OpenAI, "gemma-4", second))
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("unset extra_body changed the OpenAI-compatible request body")
	}
}

func TestJudgeExtraBodyDoesNotChangeOtherProvidersOrSecureClient(t *testing.T) {
	for _, tc := range []struct {
		name         string
		provider     *bifrostProvider
		secureClient bool
	}{
		{"native OpenAI", &bifrostProvider{providerKey: schemas.OpenAI}, false},
		{"Bedrock", &bifrostProvider{providerKey: schemas.Bedrock}, false},
		{"Secure Client", &bifrostProvider{providerKey: schemas.OpenAI, baseURL: "http://127.0.0.1:8000/v1"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			judge := &LLMJudge{
				cfg:   &config.JudgeConfig{ExtraBody: map[string]any{"chat_template_kwargs": map[string]any{"enable_thinking": false}}},
				model: "gemma-4", provider: tc.provider, secureClient: tc.secureClient,
			}
			if got := judge.judgeChatRequest(nil, 512, "injection").ExtraParams; got != nil {
				t.Fatalf("extra fields = %#v, want nil", got)
			}
		})
	}
}
