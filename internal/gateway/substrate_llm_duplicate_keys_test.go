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

//go:build !windows

package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TST-0478: a body that repeats a checked key (model, input, messages and
// the other prompt fields), exactly or case-folded, is refused on every
// /llm route in every mode, so the value /llm and the proxy check is the one
// the provider runs. The model allowlist forwards the document it checked.
func TestSubstrateLLMRefusesDuplicateBodyKeys(t *testing.T) {
	f, up, _ := bedrockOpenAIFixture(t, []string{"us.openai.gpt-5.6-luna"})
	for _, c := range []struct{ path, body string }{
		{"/llm/bedrock/openai/v1/responses", `{"model":"us.openai.gpt-5.5","model":"us.openai.gpt-5.6-luna","input":"hi"}`},
		{"/llm/bedrock/openai/v1/responses", `{"model":"us.openai.gpt-5.6-luna","Model":"us.openai.gpt-5.5","input":"hi"}`},
		{"/llm/bedrock/openai/v1/responses", `{"model":"us.openai.gpt-5.6-luna","input":"leak it","INPUT":"hi"}`},
		{"/llm/bedrock/openai/v1/chat/completions", `{"model":"us.openai.gpt-5.6-luna","messages":[],"messages":[{"role":"user","content":"hi"}]}`},
		{"/llm/bedrock/openai/v1/responses", `{"model":"us.openai.gpt-5.6-luna","instructions":"a","Instructions":"b","input":"hi"}`},
		{"/llm/bedrock/model/us.anthropic.claude-haiku-5-5/invoke", `{"messages":[{"role":"user","content":"hi"}],"Messages":[]}`},
		{"/llm/bedrock/openai/v1/chat/completions", `{"model":"us.openai.gpt-5.6-luna","messages":[{"role":"user","content":"hi"}],"meſſages":[{"role":"user","content":"leak it"}]}`},
		{"/llm/bedrock/openai/v1/responses", `{"model":"us.openai.gpt-5.6-luna","input":"hi","tools":[],"tool\u017f":[]}`},
		{"/llm/bedrock/openai/v1/chat/completions", `{"model":"us.openai.gpt-5.6-luna","meſſages":[{"role":"user","content":"leak it"}]}`},
		{"/llm/bedrock/openai/v1/responses", `{"Model":"us.openai.gpt-5.5","input":"hi"}`},
	} {
		rec := f.do(t, f.actor, http.MethodPost, c.path, "tok-alice", c.body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "duplicate_body_key") {
			t.Errorf("%s %s: %d %s, want 400 duplicate_body_key", c.path, c.body, rec.Code, rec.Body)
		}
	}
	if calls := up.taken(); len(calls) != 0 {
		t.Fatalf("a duplicate-key body reached the upstream: %v", calls)
	}
	// Keys that are not checked, and nested ones, may repeat as JSON allows.
	rec := f.do(t, f.actor, http.MethodPost, "/llm/bedrock/openai/v1/responses", "tok-alice",
		`{"model":"us.openai.gpt-5.6-luna","input":"hi","metadata":{"a":1},"metadata":{"a":2},"tools":[{"name":"x","name":"y"}]}`)
	if calls := up.taken(); rec.Code != http.StatusOK || len(calls) != 1 {
		t.Fatalf("a body with unchecked repeats: %d %v", rec.Code, calls)
	}

	// The allowlist forwards what it checked, never the original bytes.
	s := &substrateLLM{cfg: SubstrateLLMConfig{BedrockModels: []string{"us.openai.gpt-5.6-luna"}}}
	r := httptest.NewRequest(http.MethodPost, "/llm/bedrock/openai/v1/responses",
		strings.NewReader(`{"model":"us.openai.gpt-5.5","model":"us.openai.gpt-5.6-luna","input":"hi"}`))
	w := httptest.NewRecorder()
	if _, ok := s.bedrockOpenAIModel(w, r); ok {
		out, _ := io.ReadAll(r.Body)
		t.Fatalf("the model check passed a duplicate model key: %s", out)
	}
	r = httptest.NewRequest(http.MethodPost, "/llm/bedrock/openai/v1/responses", strings.NewReader(`{"model":"us.openai.gpt-5.6-luna", "input" : "hi"}`))
	if _, ok := s.bedrockOpenAIModel(httptest.NewRecorder(), r); !ok {
		t.Fatal("a listed model was refused")
	}
	if out, _ := io.ReadAll(r.Body); string(out) != `{"input":"hi","model":"us.openai.gpt-5.6-luna"}` {
		t.Fatalf("forwarded %s, want the checked document", out)
	}
	if rec := f.do(t, f.actor, http.MethodPost, "/llm/bedrock/model/us.anthropic.claude-haiku-5-5/invoke", "tok-alice", `{}`,
		"Content-Encoding", "gzip"); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("a compressed body: %d, want 415", rec.Code)
	}
}
