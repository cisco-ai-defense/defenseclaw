// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"
)

// TestGAP0258SplitTextPartsAreJudgedAsOneText: a prompt split across two text
// parts of one turn is judged as the model reads it, one text, on the OpenAI
// chat, Responses, Anthropic and Gemini wires: a regex-corpus row that blocks
// in one part also blocks when it is cut in two at a point where the
// line-feed join of the parts no longer matches the rule
// (substrate-1:GAP-0258, fixed on rel by rel-1-0-10:GAP-0465). The literals are
// regex corpus rows, read by row id; no message prints them. Self-contained
// (only helpers of the pre-fix tree), so it runs on the pre-fix build too.
func TestGAP0258SplitTextPartsAreJudgedAsOneText(t *testing.T) {
	cases := []struct{ row, rule string }{
		{"injection/polite-ignore-previous-instructions", "TRUST-IGNORE-PREVIOUS"},
		{"injection/override-previous-instructions", "TRUST-OVERRIDE-INSTRUCT"},
		{"injection/disable-guardrails", "TRUST-SAFETY-OVERRIDE"},
	}
	rowText := func(row string) string {
		for _, c := range readJSONL[regexCase](t, "regex", "corpus.jsonl") {
			if c.ID == row {
				return c.Content
			}
		}
		t.Fatalf("regex corpus row %s not found", row)
		return ""
	}
	hits := func(text, rule string) bool {
		for _, finding := range scanContentRuleCategoryWithGeneration(snapshotRulePackGeneration(""), text, "", ruleContentScopeUntrusted, "") {
			if finding.RuleID == rule {
				return true
			}
		}
		return false
	}
	split := func(row, rule string) []string {
		text := rowText(row)
		if !hits(text, rule) {
			t.Fatalf("row %s: %s does not match the whole row", row, rule)
		}
		for i := 1; i < len(text); i++ {
			if utf8.RuneStart(text[i]) && !hits(text[:i]+"\n"+text[i:], rule) {
				return []string{text[:i], text[i:]}
			}
		}
		t.Fatalf("row %s: no split hides %s from the line-feed join", row, rule)
		return nil
	}

	previous := liveGeneration.Load()
	liveGeneration.Store(nil)
	t.Cleanup(func() { liveGeneration.Store(previous) })
	inspector := NewGuardrailInspector("local", nil, nil)
	inspector.SetDetectionStrategy("regex_only", "", "", "", false)
	proxy := newTestProxy(t, &mockProvider{}, inspector, "action")

	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	t.Cleanup(upstream.Close)
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	original := providerDomains
	providerDomains = append(append(providerDomains[:0:0], providerDomains...), providerDomainEntry{target.Hostname(), "anthropic"})
	t.Cleanup(func() { providerDomains = original })
	passthrough := func(path string, body map[string]any) bool {
		before := forwarded.Load()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DC-Target-URL", upstream.URL)
		req.Header.Set("X-AI-Auth", "Bearer inert-test")
		req.RemoteAddr = "127.0.0.1:12345"
		proxy.handlePassthrough(httptest.NewRecorder(), req)
		return forwarded.Load() > before
	}
	typed := func(typ string, parts []string) []map[string]any {
		out := make([]map[string]any, 0, len(parts))
		for _, part := range parts {
			out = append(out, map[string]any{"type": typ, "text": part})
		}
		return out
	}
	bare := func(parts []string) []map[string]any {
		out := make([]map[string]any, 0, len(parts))
		for _, part := range parts {
			out = append(out, map[string]any{"text": part})
		}
		return out
	}
	wires := []struct {
		name string
		send func(parts []string) bool
	}{
		{"openai-chat", func(parts []string) bool {
			raw, err := json.Marshal(map[string]any{"model": "gpt-4", "messages": []map[string]any{{"role": "user", "content": typed("text", parts)}}})
			if err != nil {
				t.Fatal(err)
			}
			var resp ChatResponse
			if err := json.Unmarshal(postChat(t, proxy, raw).Body.Bytes(), &resp); err != nil {
				t.Fatalf("openai-chat: decode: %v", err)
			}
			return resp.ID != "chatcmpl-blocked"
		}},
		{"responses", func(parts []string) bool {
			return passthrough("/v1/responses", map[string]any{"input": []map[string]any{{"type": "message", "role": "user", "content": typed("input_text", parts)}}})
		}},
		{"anthropic", func(parts []string) bool {
			return passthrough("/v1/messages", map[string]any{"messages": []map[string]any{{"role": "user", "content": typed("text", parts)}}})
		}},
		{"gemini", func(parts []string) bool {
			return passthrough("/v1beta/models/gemini-2.5-pro:generateContent", map[string]any{"contents": []map[string]any{{"role": "user", "parts": bare(parts)}}})
		}},
	}
	for _, wire := range wires {
		for _, tc := range cases {
			whole := rowText(tc.row)
			if wire.send([]string{whole}) {
				t.Fatalf("%s %s: the whole row in one part is forwarded; the wire does not block %s", wire.name, tc.row, tc.rule)
			}
			parts := split(tc.row, tc.rule)
			if wire.send(parts) {
				t.Errorf("%s %s: the row split across two text parts is forwarded, want blocked as the whole row (%s)", wire.name, tc.row, tc.rule)
			}
			if !wire.send([]string{strings.Join(parts, "\n")}) {
				t.Logf("%s %s: the line-feed join is blocked too (another rule)", wire.name, tc.row)
			}
		}
	}
}
