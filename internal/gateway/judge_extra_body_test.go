// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

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
