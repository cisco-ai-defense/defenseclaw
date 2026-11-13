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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const lunaResponsesReply = `{"id":"resp_1","object":"response","model":"us.openai.gpt-5.6-luna","status":"completed",` +
	`"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"OK from Luna"}]}]}`

type bedrockOpenAIUpstream struct {
	mu    sync.Mutex
	calls []struct{ path, auth, model, target string }
	reply string
	ctype string
}

// bedrockOpenAIFixture is /llm in front of the real guardrail proxy, whose
// Bedrock origin is a fake upstream (labelled bedrock, as bedrock-runtime is).
func bedrockOpenAIFixture(t *testing.T, models []string) (*substrateFixture, *bedrockOpenAIUpstream, *mockInspector) {
	t.Helper()
	up := &bedrockOpenAIUpstream{reply: lunaResponsesReply, ctype: "application/json"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(b, &body)
		up.mu.Lock()
		up.calls = append(up.calls, struct{ path, auth, model, target string }{r.URL.Path, r.Header.Get("Authorization"), body.Model, r.Header.Get("X-DC-Target-URL")})
		reply, ctype := up.reply, up.ctype
		up.mu.Unlock()
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	prev := passthroughAllowPrivateForTest
	passthroughAllowPrivateForTest = true
	t.Cleanup(func() { passthroughAllowPrivateForTest = prev })
	proxy, insp := bedrockPassthroughProxy(t, srv)
	insp.setVerdict("prompt", allowVerdict("mock"))
	insp.setVerdict("completion", allowVerdict("mock"))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bedrock"), []byte("real-bedrock-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Built directly: the fake origin is plain HTTP, which
	// NewSubstrateLLMHandler refuses for a real provider.
	llm := &substrateLLM{cfg: SubstrateLLMConfig{
		Providers:     map[string]SubstrateLLMProvider{"bedrock": {Origin: srv.URL, CredentialFile: filepath.Join(dir, "bedrock")}},
		Proxy:         proxy.SubstrateHandler(),
		BedrockModels: models,
	}}
	return newSubstrateFixture(t, func(c *SubstrateConfig) { c.LLM = llm }), up, insp
}

func (u *bedrockOpenAIUpstream) taken() []struct{ path, auth, model, target string } {
	u.mu.Lock()
	defer u.mu.Unlock()
	c := u.calls
	u.calls = nil
	return c
}

// GAP-0187: Codex, OpenCode, Copilot CLI and Hermes reach GPT-5.6 Luna on
// Bedrock Runtime's OpenAI-compatible API through /llm/bedrock/openai/v1,
// with the gateway's Bedrock key and through the prompt guardrail; other
// paths under it are not served.
func TestSubstrateLLMBedrockOpenAIRoute(t *testing.T) {
	f, up, insp := bedrockOpenAIFixture(t, nil)
	for _, p := range []string{"responses", "chat/completions"} {
		rec := f.do(t, f.actor, http.MethodPost, "/llm/bedrock/openai/v1/"+p, "tok-alice",
			`{"model":"us.openai.gpt-5.6-luna","input":"say OK","messages":[{"role":"user","content":"say OK"}]}`,
			"Authorization", "Bearer placeholder-not-a-secret", "X-DC-Target-URL", "https://evil.example")
		calls := up.taken()
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "OK from Luna") {
			t.Fatalf("%s: %d %s", p, rec.Code, rec.Body)
		}
		if len(calls) != 1 || calls[0].path != "/openai/v1/"+p || calls[0].auth != "Bearer real-bedrock-key" ||
			calls[0].model != "us.openai.gpt-5.6-luna" || calls[0].target != "" {
			t.Fatalf("%s: upstream saw %+v", p, calls)
		}
	}
	if insp.promptCalls == 0 {
		t.Fatal("the prompt was not inspected")
	}

	// A prompt the guardrail blocks never reaches Bedrock.
	insp.setVerdict("prompt", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "test block"})
	rec := f.do(t, f.actor, http.MethodPost, "/llm/bedrock/openai/v1/responses", "tok-alice", `{"model":"us.openai.gpt-5.6-luna","input":"leak it"}`)
	if calls := up.taken(); len(calls) != 0 || strings.Contains(rec.Body.String(), "OK from Luna") {
		t.Fatalf("blocked prompt reached the upstream: %d %v", rec.Code, calls)
	}

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/llm/bedrock/openai/v1/models"},
		{http.MethodPost, "/llm/bedrock/openai/v1/models"},
		{http.MethodPost, "/llm/bedrock/openai/v1/files"},
		{http.MethodPost, "/llm/bedrock/openai/v1/responses/resp_1/cancel"},
		{http.MethodGet, "/llm/bedrock/openai/v1/responses"},
		{http.MethodPost, "/llm/bedrock/openai/v2/responses"},
	} {
		if rec := f.do(t, f.actor, c.method, c.path, "tok-alice", `{"model":"m"}`); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s: %d, want 404", c.method, c.path, rec.Code)
		}
	}
	if calls := up.taken(); len(calls) != 0 {
		t.Fatalf("refused paths reached the upstream: %v", calls)
	}
}

// substrate.llm.bedrock_models holds the body model of the OpenAI-compatible
// calls as it holds /model/<id>: another model goes to the first entry.
func TestSubstrateLLMBedrockOpenAIModelAllowlist(t *testing.T) {
	f, up, _ := bedrockOpenAIFixture(t, []string{"us.openai.gpt-5.6-luna"})
	for _, c := range []struct{ model, want string }{
		{"us.openai.gpt-5.6-luna", "us.openai.gpt-5.6-luna"},
		{"US.OPENAI.GPT-5.6-LUNA", "US.OPENAI.GPT-5.6-LUNA"},
		{"us.openai.gpt-5.5", "us.openai.gpt-5.6-luna"},
		{"gpt-5.6", "us.openai.gpt-5.6-luna"},
	} {
		rec := f.do(t, f.actor, http.MethodPost, "/llm/bedrock/openai/v1/responses", "tok-alice", `{"model":"`+c.model+`","input":"hi","stream":false}`)
		calls := up.taken()
		if rec.Code != http.StatusOK || len(calls) != 1 || calls[0].model != c.want {
			t.Errorf("model %s: %d -> %+v, want %s", c.model, rec.Code, calls, c.want)
		}
	}
	for _, c := range []struct {
		body, enc string
		code      int
	}{
		{`not json`, "", http.StatusBadRequest},
		{`{"input":"no model"}`, "", http.StatusBadRequest},
		{`{"model":42}`, "", http.StatusBadRequest},
		{`{"model":"us.openai.gpt-5.6-luna"}`, "gzip", http.StatusUnsupportedMediaType},
	} {
		hdr := []string{}
		if c.enc != "" {
			hdr = append(hdr, "Content-Encoding", c.enc)
		}
		if rec := f.do(t, f.actor, http.MethodPost, "/llm/bedrock/openai/v1/chat/completions", "tok-alice", c.body, hdr...); rec.Code != c.code {
			t.Errorf("body %q enc %q: %d, want %d", c.body, c.enc, rec.Code, c.code)
		}
	}
	if calls := up.taken(); len(calls) != 0 {
		t.Fatalf("refused bodies reached the upstream: %v", calls)
	}
}
