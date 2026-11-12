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
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

type capturedCall struct {
	path, target, auth, aiAuth, apiKey, actorHdr, userID string
	actor                                                substrateActor
	verified                                             bool
}

func TestSubstrateLLMRoute(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bedrock"), []byte("real-bedrock-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anthropic"), []byte("real-anthropic-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	var got capturedCall
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, ok := substrateActorFrom(r.Context())
		got = capturedCall{path: r.URL.Path, target: r.Header.Get("X-DC-Target-URL"), auth: r.Header.Get("Authorization"),
			aiAuth: r.Header.Get("X-AI-Auth"), apiKey: r.Header.Get("x-api-key"), actorHdr: r.Header.Get(substrateActorHeader),
			userID: r.Header.Get("X-User-Id"), actor: a, verified: ok}
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		_, _ = w.Write([]byte("frames"))
	})
	h, err := NewSubstrateLLMHandler(SubstrateLLMConfig{
		Providers: DefaultSubstrateLLMProviders(dir, "us-east-1"), Proxy: proxy,
	})
	if err != nil {
		t.Fatal(err)
	}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.LLM = h })
	path := "/llm/bedrock/model/us.anthropic.claude-haiku-4-5-20251001-v1:0/invoke-with-response-stream"
	rec := f.do(t, f.actor, http.MethodPost, path, "tok-alice", `{"messages":[]}`,
		"Authorization", "Bearer placeholder-not-a-secret", "X-User-Id", "mallory", "X-DC-Target-URL", "https://evil.example")
	if rec.Code != 200 || rec.Body.String() != "frames" || rec.Header().Get("Content-Type") != "application/vnd.amazon.eventstream" {
		t.Fatalf("bedrock call %d %q %v", rec.Code, rec.Body, rec.Header())
	}
	if got.path != "/model/us.anthropic.claude-haiku-4-5-20251001-v1:0/invoke-with-response-stream" ||
		got.target != "https://bedrock-runtime.us-east-1.amazonaws.com" || got.auth != "Bearer real-bedrock-key" ||
		got.actorHdr != "" || got.userID != "" || !got.verified || got.actor.UID != subUID1 {
		t.Fatalf("forwarded %+v", got)
	}
	rec = f.do(t, f.actor, http.MethodPost, "/llm/anthropic/v1/messages", "tok-alice", `{}`, "x-api-key", "placeholder")
	if rec.Code != 200 || got.apiKey != "real-anthropic-key" || got.target != "https://api.anthropic.com" || got.path != "/v1/messages" {
		t.Fatalf("anthropic %d %+v", rec.Code, got)
	}
	if rec := f.do(t, f.actor, http.MethodPost, "/llm/openai/v1/responses", "tok-alice", `{}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing key %d", rec.Code)
	}
	if rec := f.do(t, f.actor, http.MethodPost, "/llm/nope/x", "tok-alice", `{}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown provider %d", rec.Code)
	}
	if rec := f.do(t, f.actor, http.MethodPost, path, "", `{}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no actor token %d", rec.Code)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	found := false
	for _, a := range f.activity {
		found = found || a == "model:"+subUID1
	}
	if !found {
		t.Fatalf("no model activity %v", f.activity)
	}
}

// GAP-0041: /llm serves only the providers' model APIs; the guardrail
// proxy's other routes are never an actor's. Haiku 5.5 inference profiles
// (us. and global.) are model paths like any other Bedrock ID.
func TestSubstrateLLMOnlyModelPaths(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"bedrock", "openai", "anthropic", "gemini"} {
		if err := os.WriteFile(filepath.Join(dir, p), []byte("k"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reached := 0
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached++; w.WriteHeader(200) })
	h, err := NewSubstrateLLMHandler(SubstrateLLMConfig{Providers: DefaultSubstrateLLMProviders(dir, ""), Proxy: proxy})
	if err != nil {
		t.Fatal(err)
	}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.LLM = h })
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/llm/openai/v1/config/providers"},
		{http.MethodPost, "/llm/openai/v1/config/providers/reload"},
		{http.MethodPost, "/llm/openai/v1/events/egress"},
		{http.MethodGet, "/llm/openai/health"},
		{http.MethodGet, "/llm/openai/v1/models"},
		{http.MethodGet, "/llm/anthropic/v1/messages"},
		{http.MethodPost, "/llm/anthropic/v1/messages/batches"},
		{http.MethodPost, "/llm/bedrock/model/x/invoke/extra"},
		{http.MethodPost, "/llm/bedrock/guardrail/g1/version/1/apply"},
		{http.MethodPost, "/llm/gemini/v1beta/models/gemini-2.5-pro:deleteEverything"},
	} {
		if rec := f.do(t, f.actor, c.method, c.path, "tok-alice", `{}`); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s: %d, want 404", c.method, c.path, rec.Code)
		}
	}
	if reached != 0 {
		t.Fatalf("%d refused calls reached the proxy", reached)
	}
	for _, p := range []string{
		"/llm/bedrock/model/us.anthropic.claude-haiku-5-5/invoke-with-response-stream",
		"/llm/bedrock/model/global.anthropic.claude-haiku-5-5/converse-stream",
		"/llm/bedrock/model/us.anthropic.claude-haiku-4-5-20251001-v1:0/invoke",
		"/llm/bedrock/model/us.anthropic.claude-haiku-5-5/count-tokens",
		"/llm/anthropic/v1/messages",
		"/llm/anthropic/v1/messages/count_tokens",
		"/llm/openai/v1/chat/completions",
		"/llm/openai/v1/responses",
		"/llm/gemini/v1beta/models/gemini-2.5-pro:streamGenerateContent",
	} {
		if rec := f.do(t, f.actor, http.MethodPost, p, "tok-alice", `{}`); rec.Code != 200 {
			t.Errorf("POST %s: %d %s", p, rec.Code, rec.Body)
		}
	}
	// An escaped Bedrock model ID (SDKs escape the colon) is still a model path.
	if rec := f.do(t, f.actor, http.MethodPost, "/llm/bedrock/model/us.anthropic.claude-haiku-4-5-20251001-v1%3A0/invoke", "tok-alice", `{}`); rec.Code != 200 {
		t.Errorf("escaped model ID: %d", rec.Code)
	}
}
