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
	"context"
	"errors"
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

type routerFunc func(SubstrateModelCaller, SubstrateLLMRoute) (SubstrateLLMRoute, error)

func (f routerFunc) RouteModelCall(_ context.Context, c SubstrateModelCaller, r SubstrateLLMRoute) (SubstrateLLMRoute, error) {
	return f(c, r)
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
	var refuse bool
	h, err := NewSubstrateLLMHandler(SubstrateLLMConfig{
		Providers: DefaultSubstrateLLMProviders(dir, "us-east-1"), Proxy: proxy,
		Router: routerFunc(func(c SubstrateModelCaller, r SubstrateLLMRoute) (SubstrateLLMRoute, error) {
			if c.UID == "" || c.Owner == "" {
				t.Errorf("router caller %+v", c)
			}
			if refuse {
				return r, errors.New("over budget")
			}
			return r, nil
		}),
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
	refuse = true
	if rec := f.do(t, f.actor, http.MethodPost, path, "tok-alice", `{}`); rec.Code != http.StatusForbidden {
		t.Fatalf("router refusal %d", rec.Code)
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
