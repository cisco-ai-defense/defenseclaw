// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The judge's base_url carries a model's path prefix to the provider. Bedrock
// Mantle serves Gemma 4 only under /openai/v1 and gpt-oss under /v1, so
// guardrail.judge.llm.base_url https://bedrock-mantle.<region>.api.aws/openai/v1
// must reach /openai/v1/chat/completions, and .../v1 must reach
// /v1/chat/completions, never /v1/v1/... or a path without the prefix.
func TestJudgeBaseURLKeepsTheModelPathPrefix(t *testing.T) {
	for _, tc := range []struct{ base, want string }{
		{"/openai/v1", "/openai/v1/chat/completions"},
		{"/openai/v1/", "/openai/v1/chat/completions"},
		{"/v1", "/v1/chat/completions"},
		{"", "/v1/chat/completions"},
	} {
		var path atomic.Value
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path.Store(r.URL.Path)
			if got := r.Header.Get("Authorization"); got != "Bearer fixture-key" {
				t.Errorf("Authorization = %q, want the bearer key", got)
			}
			_, _ = io.WriteString(w, judgeChatBody(escalationJudgeClean, "stop"))
		}))
		llm := config.LLMConfig{Provider: "openai-compatible", Model: "google.gemma-4-31b", BaseURL: srv.URL + tc.base, APIKey: "fixture-key"}
		provider, err := NewProviderForLLMConfig(&llm, nil)
		if err != nil {
			srv.Close()
			t.Fatal(err)
		}
		j := &LLMJudge{cfg: &config.JudgeConfig{Enabled: true, ToolInjection: true}, model: "google.gemma-4-31b", provider: provider, providerName: "openai-compatible"}
		v := j.RunToolJudge(t.Context(), "Bash", `{"command":"go test ./internal/..."}`)
		srv.Close()
		if v == nil || v.JudgeFailed {
			t.Fatalf("base %q: verdict %+v", tc.base, v)
		}
		if got, _ := path.Load().(string); got != tc.want {
			t.Fatalf("base %q: request path %q, want %q", tc.base, got, tc.want)
		}
	}
}
