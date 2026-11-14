// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"
)

// Property tests of the /llm passthrough (substrate-1 GAP-0189, GAP-0196).
//
// The guardrail is a test-only stub that blocks one fixed, harmless marker
// string, and the tool-call seam (toolCallVerdictForTest) blocks one dummy
// tool name, so the tests need no realistic command or attack content.
// Properties, over every supported wire format, encoding, charset and SSE
// framing:
//
//	P1  a marker in any text-bearing field of a request reaches the
//	    guardrail and the request is blocked before the upstream sees it;
//	P2  a marker in any text-bearing field of a reply (buffered, NDJSON or
//	    streamed) reaches the guardrail and the agent never receives it;
//	P3  a body the proxy cannot decode takes the fail mode (managed: refused,
//	    OSS: forwarded with an alert), never a silent forward;
//	P4  a streamed tool call is held until its verdict: no byte of it
//	    reaches the agent before then, and a blocked call never does;
//	P5  an allowed request or reply passes unchanged (the stub is not a
//	    blanket block);
//	P6  the heartbeat gates skip the heartbeat text only, never the other
//	    text of the body.

const (
	covMarker      = "dc-test-marker-4c1e"
	covBlockedTool = "dc_test_blocked_tool"
	covAllowedTool = "dc_test_allowed_tool"
)

// covInspector is the stub guardrail: it blocks the marker in any direction
// and records what it was asked to inspect.
type covInspector struct {
	mu        sync.Mutex
	prompts   []string
	completes []string
}

func (c *covInspector) Inspect(_ context.Context, direction, content string, _ []ChatMessage, _, _ string) *ScanVerdict {
	c.mu.Lock()
	if direction == "prompt" {
		c.prompts = append(c.prompts, content)
	} else {
		c.completes = append(c.completes, content)
	}
	c.mu.Unlock()
	if strings.Contains(content, covMarker) {
		return &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "dc-test-stub-block", Scanner: "test"}
	}
	return allowVerdict("test")
}
func (c *covInspector) InspectMidStream(ctx context.Context, d, content string, m []ChatMessage, model, mode string) *ScanVerdict {
	return c.Inspect(ctx, d, content, m, model, mode)
}
func (c *covInspector) SetScannerMode(string)      {}
func (c *covInspector) SetHILTConfig(bool, string) {}

func (c *covInspector) saw(direction string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	list := c.prompts
	if direction != "prompt" {
		list = c.completes
	}
	for _, s := range list {
		if strings.Contains(s, covMarker) {
			return true
		}
	}
	return false
}

// covToolVerdict is the test-only tool-call decision: the dummy tool name
// and the marker are blocked.
func covToolVerdict(_ context.Context, raw json.RawMessage) *ScanVerdict {
	s := string(raw)
	if strings.Contains(s, covBlockedTool) || strings.Contains(s, covMarker) {
		return &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "dc-test-stub-tool-block", Scanner: "test"}
	}
	return nil
}

func covSetManaged(t *testing.T, managed bool) {
	t.Helper()
	prev := managedEnterpriseActive.Load()
	managedEnterpriseActive.Store(managed)
	t.Cleanup(func() { managedEnterpriseActive.Store(prev) })
}

func covAllowPrivate(t *testing.T) {
	t.Helper()
	prev := passthroughAllowPrivateForTest
	passthroughAllowPrivateForTest = true
	t.Cleanup(func() { passthroughAllowPrivateForTest = prev })
}

// covUpstream is a scripted provider: it counts hits and answers what the
// case sets.
type covUpstream struct {
	srv   *httptest.Server
	mu    sync.Mutex
	hits  int
	ctype string
	enc   string
	body  []byte
	chunk int // >0: write the body in chunks of at most this size, flushed
}

func newCovUpstream(t *testing.T) *covUpstream {
	t.Helper()
	u := &covUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		u.mu.Lock()
		u.hits++
		ctype, enc, body, chunk := u.ctype, u.enc, u.body, u.chunk
		u.mu.Unlock()
		w.Header().Set("Content-Type", ctype)
		if enc != "" {
			w.Header().Set("Content-Encoding", enc)
		}
		if chunk <= 0 {
			_, _ = w.Write(body)
			return
		}
		fl, _ := w.(http.Flusher)
		for len(body) > 0 {
			n := chunk
			if n > len(body) {
				n = len(body)
			}
			_, _ = w.Write(body[:n])
			if fl != nil {
				fl.Flush()
			}
			body = body[n:]
		}
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *covUpstream) set(ctype, enc string, body []byte, chunk int) {
	u.mu.Lock()
	u.hits, u.ctype, u.enc, u.body, u.chunk = 0, ctype, enc, body, chunk
	u.mu.Unlock()
}

func (u *covUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits
}

// covProxy is a proxy in action mode whose upstream host is known as provider.
func covProxy(t *testing.T, up *covUpstream, provider string, insp ContentInspector) *GuardrailProxy {
	t.Helper()
	proxy := newTestProxy(t, &mockProvider{}, insp, "action")
	host := strings.TrimPrefix(up.srv.URL, "http://")
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	orig := providerDomains
	providerDomains = append(providerDomains, struct {
		domain string
		name   string
	}{host, provider})
	t.Cleanup(func() { providerDomains = orig })
	proxy.toolCallVerdictForTest = covToolVerdict
	return proxy
}

func covPost(proxy *GuardrailProxy, up *covUpstream, path string, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if hdr["Content-Type"] == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-DC-Target-URL", up.srv.URL)
	req.Header.Set("X-AI-Auth", "Bearer test-key")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	proxy.handlePassthrough(rec, req)
	return rec
}

// ---- body encodings ------------------------------------------------------

var covEncodings = []string{"", "gzip", "x-gzip", "deflate", "raw-deflate", "br", "zstd", "gzip, br"}

func covEncode(t *testing.T, enc string, plain []byte) ([]byte, string) {
	if enc == "" {
		return plain, ""
	}
	header := strings.ReplaceAll(enc, "raw-deflate", "deflate")
	return encodeReply(t, enc, plain), header
}

var covCharsets = []string{"", "bom8", "u16le", "u16be", "u16le-param", "u32le", "u32be-param", "latin1"}

// covCharset re-encodes JSON text and returns the Content-Type it needs.
func covCharset(plain []byte, cs string) ([]byte, string) {
	u16 := func(order binary.AppendByteOrder, bom []byte) []byte {
		units := utf16.Encode([]rune(string(plain)))
		out := append([]byte(nil), bom...)
		for _, u := range units {
			out = order.AppendUint16(out, u)
		}
		return out
	}
	u32 := func(order binary.AppendByteOrder, bom []byte) []byte {
		out := append([]byte(nil), bom...)
		for _, r := range string(plain) {
			out = order.AppendUint32(out, uint32(r))
		}
		return out
	}
	switch cs {
	case "u32le":
		return u32(binary.LittleEndian, []byte{0xFF, 0xFE, 0, 0}), "application/json; charset=utf-32"
	case "u32be-param":
		return u32(binary.BigEndian, nil), "application/json; charset=utf-32be"
	case "latin1":
		// The text is ASCII; the é makes the bytes differ from UTF-8.
		return bytes.Replace(plain, []byte("{"), []byte("{\"k\xe9y\":\"x\","), 1), "application/json; charset=iso-8859-1"
	case "bom8":
		return append([]byte{0xEF, 0xBB, 0xBF}, plain...), "application/json"
	case "u16le":
		return u16(binary.LittleEndian, []byte{0xFF, 0xFE}), "application/json; charset=utf-16"
	case "u16be":
		return u16(binary.BigEndian, []byte{0xFE, 0xFF}), "application/json; charset=utf-16"
	case "u16le-param":
		return u16(binary.LittleEndian, nil), "application/json; charset=utf-16le"
	}
	return plain, "application/json"
}

// ---- request shapes ------------------------------------------------------

type covWire struct {
	name     string
	provider string
	path     string
	passthru bool // served by handlePassthrough itself (the upstream is reached when allowed)
	slots    []covSlot
	benign   map[string]any
}

type covSlot struct {
	name  string
	build func(m string) map[string]any
}

func covWires() []covWire {
	user := map[string]any{"role": "user", "content": "hello there"}
	asst := map[string]any{"role": "assistant", "content": "hi"}
	chat := func(msgs ...map[string]any) map[string]any {
		list := make([]any, len(msgs))
		for i, m := range msgs {
			list[i] = m
		}
		return map[string]any{"model": "dc-test-model", "messages": list}
	}
	responses := func(items ...any) map[string]any {
		return map[string]any{"model": "dc-test-model", "input": items}
	}
	ru := map[string]any{"type": "message", "role": "user", "content": "hello there"}
	ra := map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": "hi"}}}
	rcall := map[string]any{"type": "function_call", "call_id": "c1", "name": "dc_test_read", "arguments": "{}"}
	anth := func(system any, msgs ...map[string]any) map[string]any {
		list := make([]any, len(msgs))
		for i, m := range msgs {
			list[i] = m
		}
		b := map[string]any{"model": "dc-test-model", "max_tokens": 16, "messages": list}
		if system != nil {
			b["system"] = system
		}
		return b
	}
	gem := func(contents ...map[string]any) map[string]any {
		list := make([]any, len(contents))
		for i, m := range contents {
			list[i] = m
		}
		return map[string]any{"contents": list}
	}
	gu := map[string]any{"role": "user", "parts": []any{map[string]any{"text": "hello there"}}}
	conv := func(msgs ...map[string]any) map[string]any {
		list := make([]any, len(msgs))
		for i, m := range msgs {
			list[i] = m
		}
		return map[string]any{"messages": list}
	}
	cu := map[string]any{"role": "user", "content": []any{map[string]any{"text": "hello there"}}}
	tools := func(desc string) []any {
		return []any{map[string]any{"type": "function", "function": map[string]any{"name": "dc_test_read", "description": desc,
			"parameters": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string", "description": "a path"}}}}}}
	}

	return []covWire{
		{name: "chat", provider: "openai", path: "/v1/chat/completions", benign: chat(user), slots: []covSlot{
			{"user-string", func(m string) map[string]any { return chat(map[string]any{"role": "user", "content": m}) }},
			{"user-parts", func(m string) map[string]any {
				return chat(map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": m}}})
			}},
			{"system", func(m string) map[string]any { return chat(map[string]any{"role": "system", "content": m}, user) }},
			{"developer", func(m string) map[string]any { return chat(map[string]any{"role": "developer", "content": m}, user) }},
			{"system-after-user", func(m string) map[string]any { return chat(user, map[string]any{"role": "system", "content": m}) }},
			{"tool-result", func(m string) map[string]any {
				return chat(user, map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "c1", "type": "function", "function": map[string]any{"name": "dc_test_read", "arguments": "{}"}}}},
					map[string]any{"role": "tool", "tool_call_id": "c1", "content": m})
			}},
			{"tool-result-parts", func(m string) map[string]any {
				return chat(user, asst, map[string]any{"role": "tool", "tool_call_id": "c1", "content": []any{map[string]any{"type": "text", "text": m}}})
			}},
			{"tool-description", func(m string) map[string]any { b := chat(user); b["tools"] = tools(m); return b }},
			{"message-name", func(m string) map[string]any {
				return chat(map[string]any{"role": "user", "name": m, "content": "hello there"})
			}},
			{"function-description", func(m string) map[string]any {
				b := chat(user)
				b["functions"] = []any{map[string]any{"name": "dc_test_read", "description": m}}
				return b
			}},
		}},
		{name: "responses", provider: "openai", path: "/v1/responses", passthru: true, benign: responses(ru), slots: []covSlot{
			{"input-string", func(m string) map[string]any { return map[string]any{"model": "dc-test-model", "input": m} }},
			{"user-string", func(m string) map[string]any {
				return responses(map[string]any{"type": "message", "role": "user", "content": m})
			}},
			{"user-input-text", func(m string) map[string]any {
				return responses(map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": m}}})
			}},
			{"instructions", func(m string) map[string]any { b := responses(ru); b["instructions"] = m; return b }},
			{"developer", func(m string) map[string]any {
				return responses(map[string]any{"type": "message", "role": "developer", "content": m}, ru)
			}},
			{"system-after-user", func(m string) map[string]any {
				return responses(ru, map[string]any{"type": "message", "role": "system", "content": []any{map[string]any{"type": "input_text", "text": m}}})
			}},
			{"function-output", func(m string) map[string]any {
				return responses(ru, rcall, map[string]any{"type": "function_call_output", "call_id": "c1", "output": m})
			}},
			{"function-output-parts", func(m string) map[string]any {
				return responses(rcall, map[string]any{"type": "function_call_output", "call_id": "c1", "output": []any{map[string]any{"type": "input_text", "text": m}}})
			}},
			{"custom-output", func(m string) map[string]any {
				return responses(map[string]any{"type": "custom_tool_call", "call_id": "c2", "name": "dc_test_patch", "input": "x"},
					map[string]any{"type": "custom_tool_call_output", "call_id": "c2", "output": m})
			}},
			{"mcp-output", func(m string) map[string]any {
				return responses(ru, ra, map[string]any{"type": "mcp_approval_response", "approval_request_id": "a1", "approve": true, "reason": m})
			}},
			{"tool-description", func(m string) map[string]any {
				b := responses(ru)
				b["tools"] = []any{map[string]any{"type": "function", "name": "dc_test_read", "description": m, "parameters": map[string]any{"type": "object"}}}
				return b
			}},
			{"prompt-variable", func(m string) map[string]any {
				b := responses(ru)
				b["prompt"] = map[string]any{"id": "pmpt_1", "variables": map[string]any{"v": m}}
				return b
			}},
		}},
		{name: "anthropic", provider: "anthropic", path: "/v1/messages", passthru: true, benign: anth(nil, user), slots: []covSlot{
			{"user-string", func(m string) map[string]any { return anth(nil, map[string]any{"role": "user", "content": m}) }},
			{"user-parts", func(m string) map[string]any {
				return anth(nil, map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": m}}})
			}},
			{"system-string", func(m string) map[string]any { return anth(m, user) }},
			{"system-blocks", func(m string) map[string]any {
				return anth([]any{map[string]any{"type": "text", "text": m}}, user)
			}},
			{"tool-result", func(m string) map[string]any {
				return anth(nil, user, map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "t1", "name": "dc_test_read", "input": map[string]any{}}}},
					map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": m}}})
			}},
			{"tool-result-parts", func(m string) map[string]any {
				return anth(nil, user, map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "t1", "name": "dc_test_read", "input": map[string]any{}}}},
					map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": []any{map[string]any{"type": "text", "text": m}}}}})
			}},
			{"document-text", func(m string) map[string]any {
				return anth(nil, map[string]any{"role": "user", "content": []any{map[string]any{"type": "document", "source": map[string]any{"type": "text", "media_type": "text/plain", "data": m}}}})
			}},
			{"tool-description", func(m string) map[string]any {
				b := anth(nil, user)
				b["tools"] = []any{map[string]any{"name": "dc_test_read", "description": m, "input_schema": map[string]any{"type": "object"}}}
				return b
			}},
			{"tool-schema-description", func(m string) map[string]any {
				b := anth(nil, user)
				b["tools"] = []any{map[string]any{"name": "dc_test_read", "input_schema": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string", "description": m}}}}}
				return b
			}},
			{"assistant-prefill", func(m string) map[string]any {
				return anth(nil, user, map[string]any{"role": "assistant", "content": m})
			}},
		}},
		{name: "gemini", provider: "gemini", path: "/v1beta/models/dc-test:generateContent", passthru: true, benign: gem(gu), slots: []covSlot{
			{"user-part", func(m string) map[string]any {
				return gem(map[string]any{"role": "user", "parts": []any{map[string]any{"text": m}}})
			}},
			{"second-part", func(m string) map[string]any {
				return gem(map[string]any{"role": "user", "parts": []any{map[string]any{"text": "hello"}, map[string]any{"text": m}}})
			}},
			{"system-instruction", func(m string) map[string]any {
				b := gem(gu)
				b["systemInstruction"] = map[string]any{"parts": []any{map[string]any{"text": m}}}
				return b
			}},
			{"system-instruction-snake", func(m string) map[string]any {
				b := gem(gu)
				b["system_instruction"] = map[string]any{"parts": []any{map[string]any{"text": m}}}
				return b
			}},
			{"function-response", func(m string) map[string]any {
				return gem(gu, map[string]any{"role": "model", "parts": []any{map[string]any{"functionCall": map[string]any{"name": "dc_test_read", "args": map[string]any{}}}}},
					map[string]any{"role": "user", "parts": []any{map[string]any{"functionResponse": map[string]any{"name": "dc_test_read", "response": map[string]any{"result": m}}}}})
			}},
			{"tool-description", func(m string) map[string]any {
				b := gem(gu)
				b["tools"] = []any{map[string]any{"functionDeclarations": []any{map[string]any{"name": "dc_test_read", "description": m}}}}
				return b
			}},
		}},
		{name: "converse", provider: "bedrock", path: "/model/dc-test-model/converse", passthru: true, benign: conv(cu), slots: []covSlot{
			{"user-text", func(m string) map[string]any {
				return conv(map[string]any{"role": "user", "content": []any{map[string]any{"text": m}}})
			}},
			{"system", func(m string) map[string]any {
				b := conv(cu)
				b["system"] = []any{map[string]any{"text": m}}
				return b
			}},
			{"tool-result", func(m string) map[string]any {
				return conv(cu, map[string]any{"role": "assistant", "content": []any{map[string]any{"toolUse": map[string]any{"toolUseId": "t1", "name": "dc_test_read", "input": map[string]any{}}}}},
					map[string]any{"role": "user", "content": []any{map[string]any{"toolResult": map[string]any{"toolUseId": "t1", "content": []any{map[string]any{"text": m}}}}}})
			}},
			{"tool-spec", func(m string) map[string]any {
				b := conv(cu)
				b["toolConfig"] = map[string]any{"tools": []any{map[string]any{"toolSpec": map[string]any{"name": "dc_test_read", "description": m, "inputSchema": map[string]any{"json": map[string]any{"type": "object"}}}}}}
				return b
			}},
		}},
		{name: "bedrock-invoke-anthropic", provider: "bedrock", path: "/model/us.anthropic.dc-test/invoke", passthru: true, benign: anth(nil, user), slots: []covSlot{
			{"user", func(m string) map[string]any {
				b := anth(nil, map[string]any{"role": "user", "content": m})
				b["anthropic_version"] = "bedrock-2023-05-31"
				return b
			}},
			{"system", func(m string) map[string]any {
				b := anth(nil, user)
				b["anthropic_version"], b["system"] = "bedrock-2023-05-31", m
				return b
			}},
			{"system-blocks", func(m string) map[string]any {
				b := anth(nil, user)
				b["anthropic_version"], b["system"] = "bedrock-2023-05-31", []any{map[string]any{"type": "text", "text": m}}
				return b
			}},
			{"tool-result", func(m string) map[string]any {
				b := anth(nil, user, map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "t1", "name": "dc_test_read", "input": map[string]any{}}}},
					map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": m}}})
				b["anthropic_version"] = "bedrock-2023-05-31"
				return b
			}},
		}},
		{name: "bedrock-invoke-native", provider: "bedrock", path: "/model/dc-test-model/invoke", passthru: true, benign: map[string]any{"prompt": "hello there"}, slots: []covSlot{
			{"llama-prompt", func(m string) map[string]any { return map[string]any{"prompt": m, "max_gen_len": 16} }},
			{"titan-inputText", func(m string) map[string]any {
				return map[string]any{"inputText": m, "textGenerationConfig": map[string]any{"maxTokenCount": 16}}
			}},
			{"nova-user", func(m string) map[string]any {
				return map[string]any{"messages": []any{map[string]any{"role": "user", "content": []any{map[string]any{"text": m}}}}}
			}},
			{"nova-system", func(m string) map[string]any {
				return map[string]any{"system": []any{map[string]any{"text": m}}, "messages": []any{map[string]any{"role": "user", "content": []any{map[string]any{"text": "hello there"}}}}}
			}},
			{"cohere-message", func(m string) map[string]any { return map[string]any{"message": m, "max_tokens": 16} }},
		}},
		{name: "completions-legacy", provider: "openai", path: "/v1/completions", passthru: true, benign: map[string]any{"model": "dc-test-model", "prompt": "hello there"}, slots: []covSlot{
			{"prompt-string", func(m string) map[string]any { return map[string]any{"model": "dc-test-model", "prompt": m} }},
			{"prompt-array", func(m string) map[string]any {
				return map[string]any{"model": "dc-test-model", "prompt": []any{"hello there", m}}
			}},
			{"suffix", func(m string) map[string]any {
				return map[string]any{"model": "dc-test-model", "prompt": "hello there", "suffix": m}
			}},
			{"stop-not-text-but-prompt", func(m string) map[string]any {
				return map[string]any{"model": "dc-test-model", "prompt": m, "stop": []any{"\n"}, "max_tokens": 16}
			}},
		}},
		{name: "ollama-chat", provider: "ollama", path: "/api/chat", passthru: true, benign: chat(user), slots: []covSlot{
			{"user", func(m string) map[string]any { return chat(map[string]any{"role": "user", "content": m}) }},
			{"system", func(m string) map[string]any { return chat(map[string]any{"role": "system", "content": m}, user) }},
			{"tool-result", func(m string) map[string]any {
				return chat(user, asst, map[string]any{"role": "tool", "tool_name": "dc_test_read", "content": m})
			}},
			{"tool-description", func(m string) map[string]any { b := chat(user); b["tools"] = tools(m); return b }},
		}},
		{name: "ollama-generate", provider: "ollama", path: "/api/generate", passthru: true, benign: map[string]any{"model": "dc-test-model", "prompt": "hello there"}, slots: []covSlot{
			{"prompt", func(m string) map[string]any { return map[string]any{"model": "dc-test-model", "prompt": m} }},
			{"system", func(m string) map[string]any {
				return map[string]any{"model": "dc-test-model", "prompt": "hello there", "system": m}
			}},
			{"template", func(m string) map[string]any {
				return map[string]any{"model": "dc-test-model", "prompt": "hello there", "template": m}
			}},
			{"suffix", func(m string) map[string]any {
				return map[string]any{"model": "dc-test-model", "prompt": "hello there", "suffix": m}
			}},
		}},
	}
}

func covJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// P1, P3 (undecodable), P5 for requests.
func TestPassthroughCoverageRequestProperty(t *testing.T) {
	covAllowPrivate(t)
	rnd := rand.New(rand.NewSource(0x5eed))
	for _, managed := range []bool{false, true} {
		mode := map[bool]string{false: "oss", true: "managed"}[managed]
		for _, w := range covWires() {
			up := newCovUpstream(t)
			insp := &covInspector{}
			covSetManaged(t, managed)
			proxy := covProxy(t, up, w.provider, insp)
			for _, s := range w.slots {
				// Identity first, then every encoding and charset once
				// per slot (the pair is drawn, so a fixed seed reruns it).
				// pfx is text put before the marker: a string that starts with
				// "data:<type>," is text in a text field, not binary media
				// (GAP-0238).
				type combo struct{ enc, cs, pfx string }
				combos := []combo{{"", "", ""}, {"", "", "data:x,"}, {"", "", "data:application/octet-stream,"}}
				for _, e := range covEncodings[1:] {
					combos = append(combos, combo{e, covCharsets[rnd.Intn(len(covCharsets))], ""})
				}
				for _, cs := range covCharsets[1:] {
					combos = append(combos, combo{covEncodings[rnd.Intn(len(covEncodings))], cs, ""})
				}
				for _, c := range combos {
					name := fmt.Sprintf("%s/%s/%s/%s/enc=%s,cs=%s,pfx=%s", mode, w.name, s.name, "marker", c.enc, c.cs, c.pfx)
					t.Run(name, func(t *testing.T) {
						up.set("application/json", "", []byte(`{"id":"r1"}`), 0)
						insp.mu.Lock()
						insp.prompts = nil
						insp.mu.Unlock()
						plain := covJSON(t, s.build(c.pfx+covMarker))
						body, ct := covCharset(plain, c.cs)
						body, ce := covEncode(t, c.enc, body)
						hdr := map[string]string{"Content-Type": ct}
						if ce != "" {
							hdr["Content-Encoding"] = ce
						}
						rec := covPost(proxy, up, w.path, body, hdr)
						if !insp.saw("prompt") {
							t.Errorf("the marker never reached the guardrail (status %d)", rec.Code)
						}
						if up.count() != 0 || strings.Contains(rec.Body.String(), `"id":"r1"`) {
							t.Errorf("the blocked request reached the upstream (%d hits)", up.count())
						}
					})
				}
				// P5: the same shape with benign text passes.
				t.Run(fmt.Sprintf("%s/%s/%s/benign", mode, w.name, s.name), func(t *testing.T) {
					up.set("application/json", "", []byte(`{"id":"r1"}`), 0)
					rec := covPost(proxy, up, w.path, covJSON(t, s.build("a harmless sentence")), nil)
					if w.passthru && (up.count() != 1 || !strings.Contains(rec.Body.String(), `"id":"r1"`)) {
						t.Errorf("a benign request did not reach the upstream (%d hits): %s", up.count(), rec.Body)
					}
				})
			}
		}
	}
}

// P3 for requests: what the decoder cannot read takes the fail mode.
func TestPassthroughCoverageUndecodableRequestProperty(t *testing.T) {
	covAllowPrivate(t)
	good := []byte(`{"model":"dc-test-model","input":"hello there"}`)
	garbage := []byte("\x1f\x8b\x08\x00 this is not a gzip stream at all")
	odd16 := append([]byte{0xFF, 0xFE}, []byte("{\x00\"\x00x")...)
	cases := []struct {
		name string
		body []byte
		hdr  map[string]string
	}{
		{"corrupt-gzip", garbage, map[string]string{"Content-Encoding": "gzip"}},
		{"unknown-encoding", good, map[string]string{"Content-Encoding": "dc-test-enc"}},
		{"gzip-header-on-plain-body", good, map[string]string{"Content-Encoding": "gzip"}},
		{"too-many-layers", good, map[string]string{"Content-Encoding": "gzip, gzip, gzip, gzip, gzip, gzip"}},
		{"other-charset", good, map[string]string{"Content-Type": "application/json; charset=dc-test-charset"}},
		{"odd-utf16", odd16, map[string]string{"Content-Type": "application/json; charset=utf-16"}},
		{"not-json", []byte("{input: 'hello there'}"), nil},
		{"trailing-comma", []byte(`{"model":"dc-test-model","input":"hello there",}`), nil},
		{"truncated", good[:20], nil},
		{"number-literal-nan", []byte(`{"model":"dc-test-model","input":"hello there","temperature":NaN}`), nil},
	}
	for _, managed := range []bool{false, true} {
		mode := map[bool]string{false: "oss", true: "managed"}[managed]
		up := newCovUpstream(t)
		covSetManaged(t, managed)
		proxy := covProxy(t, up, "openai", &covInspector{})
		for _, c := range cases {
			t.Run(mode+"/"+c.name, func(t *testing.T) {
				up.set("application/json", "", []byte(`{"id":"r1"}`), 0)
				rec := covPost(proxy, up, "/v1/responses", c.body, c.hdr)
				switch {
				case managed && (up.count() != 0 || !strings.Contains(rec.Body.String(), "could not be inspected")):
					t.Errorf("managed forwarded an undecodable body (%d hits): %s", up.count(), rec.Body)
				case !managed && up.count() != 1:
					t.Errorf("the OSS default did not forward with an alert (%d hits): %s", up.count(), rec.Body)
				}
			})
		}
	}
}

// P3 / the duplicate-key rule at any depth: every value of a repeated or
// case-folded key is read by the guardrail, so a marker in either reaches
// it, and the body takes the fail mode.
func TestPassthroughCoverageDuplicateKeysProperty(t *testing.T) {
	covAllowPrivate(t)
	const pre = `{"model":"dc-test-model","input":[{"type":"message","role":"user",`
	m := `"` + covMarker + `"`
	bodies := map[string]string{
		"dup-content-first": pre + `"content":` + m + `,"content":"hello"}]}`,
		"dup-content-last":  pre + `"content":"hello","content":` + m + `}]}`,
		"fold-content":      pre + `"content":"hello","CONTENT":` + m + `}]}`,
		"dup-role":          pre + `"role":"assistant","content":` + m + `}]}`,
		"nested-dup-text":   `{"model":"dc-test-model","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello","text":` + m + `}]}]}`,
		"nested-fold-text":  `{"model":"dc-test-model","input":[{"type":"message","role":"user","content":[{"type":"input_text","Text":` + m + `,"text":"hello"}]}]}`,
		"unknown-key":       `{"model":"dc-test-model","input":"hello","ınput":` + m + `}`,
	}
	for _, managed := range []bool{false, true} {
		mode := map[bool]string{false: "oss", true: "managed"}[managed]
		up := newCovUpstream(t)
		insp := &covInspector{}
		covSetManaged(t, managed)
		proxy := covProxy(t, up, "openai", insp)
		for name, b := range bodies {
			t.Run(mode+"/"+name, func(t *testing.T) {
				up.set("application/json", "", []byte(`{"id":"r1"}`), 0)
				rec := covPost(proxy, up, "/v1/responses", []byte(b), nil)
				if up.count() != 0 {
					t.Errorf("a body with a repeated key and the marker reached the upstream: %s", rec.Body)
				}
			})
		}
	}
}

// P6: a heartbeat turn skips the heartbeat text only.
func TestPassthroughCoverageHeartbeatSkipsOnlyItself(t *testing.T) {
	covAllowPrivate(t)
	const hb = "Read HEARTBEAT.md if it exists (workspace context). Follow it strictly. If nothing needs attention, reply HEARTBEAT_OK."
	if !isHeartbeatMessage(hb, nil) {
		t.Skip("the heartbeat text of this tree changed")
	}
	up := newCovUpstream(t)
	insp := &covInspector{}
	proxy := covProxy(t, up, "openai", insp)
	for name, body := range map[string]map[string]any{
		"instructions": {"model": "dc-test-model", "instructions": covMarker, "input": []any{map[string]any{"type": "message", "role": "user", "content": hb}}},
		"developer": {"model": "dc-test-model", "input": []any{map[string]any{"type": "message", "role": "developer", "content": covMarker},
			map[string]any{"type": "message", "role": "user", "content": hb}}},
		"tool-result": {"model": "dc-test-model", "input": []any{map[string]any{"type": "function_call", "call_id": "c1", "name": "dc_test_read", "arguments": "{}"},
			map[string]any{"type": "function_call_output", "call_id": "c1", "output": covMarker},
			map[string]any{"type": "message", "role": "user", "content": hb}}},
	} {
		t.Run(name, func(t *testing.T) {
			up.set("application/json", "", []byte(`{"id":"r1"}`), 0)
			covPost(proxy, up, "/v1/responses", covJSON(t, body), nil)
			if up.count() != 0 {
				t.Errorf("a heartbeat turn let the marker through (%d hits)", up.count())
			}
		})
	}
	t.Run("heartbeat alone passes", func(t *testing.T) {
		up.set("application/json", "", []byte(`{"id":"r1"}`), 0)
		covPost(proxy, up, "/v1/responses", covJSON(t, map[string]any{"model": "dc-test-model", "input": []any{map[string]any{"type": "message", "role": "user", "content": hb}}}), nil)
		if up.count() != 1 {
			t.Errorf("a pure heartbeat turn was blocked (%d hits)", up.count())
		}
	})
}

// A client keeps earlier turns in its history: a blocked prompt in the
// history is not re-inspected as the current turn (the proxy refused it when
// it was new), so one blocked prompt does not block the whole session.
func TestPassthroughCoverageHistoryIsNotReinspected(t *testing.T) {
	covAllowPrivate(t)
	up := newCovUpstream(t)
	proxy := covProxy(t, up, "openai", &covInspector{})
	body := map[string]any{"model": "dc-test-model", "input": []any{
		map[string]any{"type": "message", "role": "user", "content": covMarker},
		map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": "[DefenseClaw] blocked"}}},
		map[string]any{"type": "message", "role": "user", "content": "a harmless sentence"},
	}}
	up.set("application/json", "", []byte(`{"id":"r1"}`), 0)
	covPost(proxy, up, "/v1/responses", covJSON(t, body), nil)
	if up.count() != 1 {
		t.Errorf("a blocked turn in the history blocked a benign new turn (%d hits)", up.count())
	}
}

// ---- reply shapes --------------------------------------------------------

type covReplySlot struct {
	name  string
	build func(m string) map[string]any
}

type covReplyWire struct {
	name     string
	provider string
	path     string
	slots    []covReplySlot
	events   func(m string, slot int) []string // streamed events (SSE data) for slot i, nil: not streamed
	tool     func(name, args string) (body map[string]any, events []string)
}

func covReplyWires() []covReplyWire {
	return []covReplyWire{
		{name: "chat", provider: "openai", path: "/v1/completions", // a Chat Completions body answered on a passthrough path
			slots: []covReplySlot{
				{"content", func(m string) map[string]any {
					return map[string]any{"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": m}, "finish_reason": "stop"}}}
				}},
				{"content-parts", func(m string) map[string]any {
					return map[string]any{"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "text", "text": m}}}}}}
				}},
				{"refusal", func(m string) map[string]any {
					return map[string]any{"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": nil, "refusal": m}}}}
				}},
				{"reasoning", func(m string) map[string]any {
					return map[string]any{"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": "ok", "reasoning_content": m}}}}
				}},
				{"second-choice", func(m string) map[string]any {
					return map[string]any{"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": "ok"}},
						map[string]any{"index": 1, "message": map[string]any{"role": "assistant", "content": m}}}}
				}},
				{"audio-transcript", func(m string) map[string]any {
					return map[string]any{"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "audio": map[string]any{"id": "a1", "transcript": m}}}}}
				}},
			},
			events: func(m string, slot int) []string {
				field := []string{"content", "refusal", "reasoning_content", "content"}[slot%4]
				d, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{field: m}}}})
				return []string{`{"choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}`, string(d),
					`{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`, `[DONE]`}
			},
			tool: func(name, args string) (map[string]any, []string) {
				a, _ := json.Marshal(args)
				body := map[string]any{"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "tool_calls": []any{
					map[string]any{"id": "call_1", "type": "function", "function": map[string]any{"name": name, "arguments": args}}}}, "finish_reason": "tool_calls"}}}
				return body, []string{
					`{"choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"` + name + `","arguments":""}}]}}]}`,
					`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":` + string(a) + `}}]}}]}`,
					`{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`, `[DONE]`}
			}},
		{name: "responses", provider: "openai", path: "/v1/responses",
			slots: []covReplySlot{
				{"output-text", func(m string) map[string]any {
					return map[string]any{"object": "response", "status": "completed", "output": []any{map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": m}}}}}
				}},
				{"refusal", func(m string) map[string]any {
					return map[string]any{"object": "response", "output": []any{map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "refusal", "refusal": m}}}}}
				}},
				{"reasoning-summary", func(m string) map[string]any {
					return map[string]any{"object": "response", "output": []any{map[string]any{"type": "reasoning", "id": "rs_1", "summary": []any{map[string]any{"type": "summary_text", "text": m}}}}}
				}},
				{"second-item", func(m string) map[string]any {
					return map[string]any{"object": "response", "output": []any{
						map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": "ok"}}},
						map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": m}}}}}
				}},
				{"error-message", func(m string) map[string]any {
					return map[string]any{"object": "response", "status": "failed", "error": map[string]any{"code": "x", "message": m}}
				}},
			},
			events: func(m string, slot int) []string {
				enc := func(v any) string { b, _ := json.Marshal(v); return string(b) }
				switch slot % 4 {
				case 0:
					return []string{`{"type":"response.created","response":{"id":"resp_1","status":"in_progress","output":[]}}`,
						enc(map[string]any{"type": "response.output_text.delta", "item_id": "msg_1", "delta": m}),
						`{"type":"response.completed","response":{"id":"resp_1","status":"completed"}}`}
				case 1:
					return []string{enc(map[string]any{"type": "response.refusal.delta", "item_id": "msg_1", "delta": m}),
						`{"type":"response.completed","response":{"id":"resp_1","status":"completed"}}`}
				case 2:
					return []string{enc(map[string]any{"type": "response.reasoning_summary_text.delta", "item_id": "rs_1", "delta": m}),
						`{"type":"response.completed","response":{"id":"resp_1","status":"completed"}}`}
				}
				// Only the finished snapshot carries the text.
				return []string{enc(map[string]any{"type": "response.completed", "response": map[string]any{"id": "resp_1", "status": "completed",
					"output": []any{map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": m}}}}}})}
			},
			tool: func(name, args string) (map[string]any, []string) {
				a, _ := json.Marshal(args)
				item := `{"id":"fc_1","type":"function_call","call_id":"call_1","name":"` + name + `","arguments":` + string(a) + `}`
				return map[string]any{"object": "response", "output": []any{map[string]any{"type": "function_call", "call_id": "call_1", "name": name, "arguments": args}}},
					[]string{`{"type":"response.created","response":{"id":"resp_1","status":"in_progress","output":[]}}`,
						`{"type":"response.output_item.added","output_index":0,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"` + name + `","arguments":""}}`,
						`{"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc_1","delta":` + string(a) + `}`,
						`{"type":"response.function_call_arguments.done","output_index":0,"item_id":"fc_1","arguments":` + string(a) + `}`,
						`{"type":"response.output_item.done","output_index":0,"item":` + item + `}`,
						`{"type":"response.completed","response":{"id":"resp_1","status":"completed"}}`}
			}},
		{name: "anthropic", provider: "anthropic", path: "/v1/messages",
			slots: []covReplySlot{
				{"text", func(m string) map[string]any {
					return map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "text", "text": m}}, "stop_reason": "end_turn"}
				}},
				{"thinking", func(m string) map[string]any {
					return map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "thinking", "thinking": m, "signature": "sig"}}}
				}},
				{"second-block", func(m string) map[string]any {
					return map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "text", "text": "ok"}, map[string]any{"type": "text", "text": m}}}
				}},
				{"citation", func(m string) map[string]any {
					return map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "text", "text": "ok",
						"citations": []any{map[string]any{"type": "char_location", "cited_text": m}}}}}
				}},
				{"error", func(m string) map[string]any {
					return map[string]any{"type": "error", "error": map[string]any{"type": "invalid_request_error", "message": m}}
				}},
			},
			events: func(m string, slot int) []string {
				enc := func(v any) string { b, _ := json.Marshal(v); return string(b) }
				delta := map[string]any{"type": "text_delta", "text": m}
				if slot%2 == 1 {
					delta = map[string]any{"type": "thinking_delta", "thinking": m}
				}
				return []string{`{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}}`,
					`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
					enc(map[string]any{"type": "content_block_delta", "index": 0, "delta": delta}),
					`{"type":"content_block_stop","index":0}`, `{"type":"message_stop"}`}
			},
			tool: func(name, args string) (map[string]any, []string) {
				var in map[string]any
				_ = json.Unmarshal([]byte(args), &in)
				pj, _ := json.Marshal(args)
				return map[string]any{"type": "message", "role": "assistant", "stop_reason": "tool_use", "content": []any{map[string]any{"type": "tool_use", "id": "tu_1", "name": name, "input": in}}},
					[]string{`{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[]}}`,
						`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"tu_1","name":"` + name + `","input":{}}}`,
						`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":` + string(pj) + `}}`,
						`{"type":"content_block_stop","index":0}`, `{"type":"message_delta","delta":{"stop_reason":"tool_use"}}`, `{"type":"message_stop"}`}
			}},
		{name: "gemini", provider: "gemini", path: "/v1beta/models/dc-test:streamGenerateContent",
			slots: []covReplySlot{
				{"part", func(m string) map[string]any {
					return map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": m}}}, "finishReason": "STOP"}}}
				}},
				{"second-part", func(m string) map[string]any {
					return map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": "ok"}, map[string]any{"text": m}}}}}}
				}},
				{"second-candidate", func(m string) map[string]any {
					return map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": "ok"}}}},
						map[string]any{"content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": m}}}}}}
				}},
				{"thought", func(m string) map[string]any {
					return map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": m, "thought": true}}}}}}
				}},
				{"prompt-feedback", func(m string) map[string]any {
					return map[string]any{"promptFeedback": map[string]any{"blockReasonMessage": m}}
				}},
			},
			events: func(m string, slot int) []string {
				b, _ := json.Marshal(map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": "ok"}, map[string]any{"text": m}}}}}})
				return []string{string(b)}
			},
			tool: func(name, args string) (map[string]any, []string) {
				var in map[string]any
				_ = json.Unmarshal([]byte(args), &in)
				body := map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{map[string]any{"functionCall": map[string]any{"name": name, "args": in}}}}}}}
				b, _ := json.Marshal(body)
				return body, []string{string(b)}
			}},
		{name: "converse", provider: "bedrock", path: "/model/dc-test-model/converse",
			slots: []covReplySlot{
				{"text", func(m string) map[string]any {
					return map[string]any{"output": map[string]any{"message": map[string]any{"role": "assistant", "content": []any{map[string]any{"text": m}}}}, "stopReason": "end_turn"}
				}},
				{"second-block", func(m string) map[string]any {
					return map[string]any{"output": map[string]any{"message": map[string]any{"role": "assistant", "content": []any{map[string]any{"text": "ok"}, map[string]any{"text": m}}}}}
				}},
				{"reasoning", func(m string) map[string]any {
					return map[string]any{"output": map[string]any{"message": map[string]any{"role": "assistant", "content": []any{map[string]any{"reasoningContent": map[string]any{"reasoningText": map[string]any{"text": m}}}}}}}
				}},
			},
			tool: func(name, args string) (map[string]any, []string) {
				var in map[string]any
				_ = json.Unmarshal([]byte(args), &in)
				return map[string]any{"output": map[string]any{"message": map[string]any{"role": "assistant", "content": []any{map[string]any{"toolUse": map[string]any{"toolUseId": "t1", "name": name, "input": in}}}}}, "stopReason": "tool_use"}, nil
			}},
		{name: "ollama-chat", provider: "ollama", path: "/api/chat",
			slots: []covReplySlot{
				{"message", func(m string) map[string]any {
					return map[string]any{"model": "x", "message": map[string]any{"role": "assistant", "content": m}, "done": true}
				}},
				{"thinking", func(m string) map[string]any {
					return map[string]any{"model": "x", "message": map[string]any{"role": "assistant", "content": "ok", "thinking": m}, "done": true}
				}},
				{"generate-response", func(m string) map[string]any { return map[string]any{"model": "x", "response": m, "done": true} }},
			},
			tool: func(name, args string) (map[string]any, []string) {
				var in map[string]any
				_ = json.Unmarshal([]byte(args), &in)
				return map[string]any{"model": "x", "message": map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"function": map[string]any{"name": name, "arguments": in}}}}, "done": true}, nil
			}},
	}
}

// ---- SSE framings ---------------------------------------------------------

var covFramings = []string{"lf-space", "lf-nospace", "crlf", "cr", "multiline", "comments", "bom", "event-id"}

// covFrame writes events (SSE data payloads) in a framing.
func covFrame(events []string, framing string) []byte {
	var b bytes.Buffer
	nl := "\n"
	switch framing {
	case "crlf":
		nl = "\r\n"
	case "cr":
		nl = "\r"
	case "bom":
		b.WriteString("\xEF\xBB\xBF")
	}
	for i, e := range events {
		switch framing {
		case "lf-nospace":
			b.WriteString("data:" + e + nl + nl)
		case "multiline":
			if k := strings.Index(e, ","); k > 0 && e != "[DONE]" {
				b.WriteString("data: " + e[:k+1] + nl + "data: " + e[k+1:] + nl + nl)
			} else {
				b.WriteString("data: " + e + nl + nl)
			}
		case "comments":
			b.WriteString(": keep-alive " + fmt.Sprint(i) + nl + "event: message" + nl + "data: " + e + nl + nl)
		case "event-id":
			b.WriteString("id: " + fmt.Sprint(i) + nl + "retry: 1000" + nl + "data: " + e + nl + nl)
		default:
			b.WriteString("data: " + e + nl + nl)
		}
	}
	return b.Bytes()
}

// P2: a marker in any text-bearing field of a reply, buffered or streamed,
// reaches the guardrail and never the agent.
func TestPassthroughCoverageReplyProperty(t *testing.T) {
	covAllowPrivate(t)
	rnd := rand.New(rand.NewSource(0xfeed))
	for _, w := range covReplyWires() {
		up := newCovUpstream(t)
		insp := &covInspector{}
		proxy := covProxy(t, up, w.provider, insp)
		req := covJSON(t, map[string]any{"model": "dc-test-model", "input": "hello there", "messages": []any{map[string]any{"role": "user", "content": "hello there"}}, "contents": []any{map[string]any{"role": "user", "parts": []any{map[string]any{"text": "hello there"}}}}, "prompt": "hello there"})
		check := func(t *testing.T, rec *httptest.ResponseRecorder) {
			t.Helper()
			if !insp.saw("completion") {
				t.Errorf("the marker never reached the guardrail")
			}
			if strings.Contains(rec.Body.String(), covMarker) {
				t.Errorf("the marker reached the agent: %.200s", rec.Body)
			}
		}
		for si, s := range w.slots {
			for _, enc := range covEncodings {
				for _, cs := range []string{"", "bom8", "u16le", "u32be-param", "latin1"} {
					if cs != "" && enc != "" && rnd.Intn(2) == 0 {
						continue
					}
					name := fmt.Sprintf("body/%s/%s/enc=%s,cs=%s", w.name, s.name, enc, cs)
					t.Run(name, func(t *testing.T) {
						insp.mu.Lock()
						insp.completes = nil
						insp.mu.Unlock()
						plain, ct := covCharset(covJSON(t, s.build(covMarker)), cs)
						body, ce := covEncode(t, enc, plain)
						up.set(ct, ce, body, 0)
						check(t, covPost(proxy, up, w.path, req, nil))
					})
				}
			}
			for _, pfx := range []string{"data:x,", "data:,"} {
				pfx := pfx
				t.Run(fmt.Sprintf("body-dataprefix/%s/%s/%s", w.name, s.name, pfx), func(t *testing.T) {
					insp.mu.Lock()
					insp.completes = nil
					insp.mu.Unlock()
					up.set("application/json", "", covJSON(t, s.build(pfx+covMarker)), 0)
					check(t, covPost(proxy, up, w.path, req, nil))
				})
				if w.events == nil {
					continue
				}
				for _, fr := range []string{"lf-space", "crlf"} {
					fr := fr
					t.Run(fmt.Sprintf("stream-dataprefix/%s/%s/%s/%s", w.name, s.name, fr, pfx), func(t *testing.T) {
						insp.mu.Lock()
						insp.completes = nil
						insp.mu.Unlock()
						up.set("text/event-stream", "", covFrame(w.events(pfx+covMarker, si), fr), 11)
						check(t, covPost(proxy, up, w.path, req, nil))
					})
				}
			}
			t.Run(fmt.Sprintf("body-benign/%s/%s", w.name, s.name), func(t *testing.T) {
				plain := covJSON(t, s.build("a harmless sentence"))
				up.set("application/json", "", plain, 0)
				rec := covPost(proxy, up, w.path, req, nil)
				if !bytes.Equal(rec.Body.Bytes(), plain) {
					t.Errorf("a benign reply changed: %.200s", rec.Body)
				}
			})
			if w.name == "ollama-chat" {
				// NDJSON stream: one JSON object per line.
				t.Run(fmt.Sprintf("ndjson/%s/%s", w.name, s.name), func(t *testing.T) {
					insp.mu.Lock()
					insp.completes = nil
					insp.mu.Unlock()
					lines := covJSON(t, s.build("start")) // a leading benign line
					lines = append(lines, '\n')
					lines = append(lines, covJSON(t, s.build(covMarker))...)
					lines = append(lines, '\n')
					up.set("application/x-ndjson", "", lines, 7)
					check(t, covPost(proxy, up, w.path, req, nil))
				})
			}
			if w.events == nil {
				continue
			}
			for _, fr := range covFramings {
				for _, enc := range []string{"", "gzip", "br", "zstd"} {
					chunk := 1 + rnd.Intn(48)
					name := fmt.Sprintf("stream/%s/%s/%s/enc=%s/chunk=%d", w.name, s.name, fr, enc, chunk)
					t.Run(name, func(t *testing.T) {
						insp.mu.Lock()
						insp.completes = nil
						insp.mu.Unlock()
						raw := covFrame(w.events(covMarker, si), fr)
						body, ce := covEncode(t, enc, raw)
						up.set("text/event-stream", ce, body, chunk)
						check(t, covPost(proxy, up, w.path, req, nil))
					})
				}
			}
			t.Run(fmt.Sprintf("stream-benign/%s/%s", w.name, s.name), func(t *testing.T) {
				if w.events == nil {
					t.Skip()
				}
				raw := covFrame(w.events("a harmless sentence", si), "lf-space")
				up.set("text/event-stream", "", raw, 13)
				rec := covPost(proxy, up, w.path, req, nil)
				if !bytes.Equal(rec.Body.Bytes(), raw) {
					t.Errorf("a benign stream changed:\n%.300s", rec.Body)
				}
			})
		}
	}
}

// P2/P3 for replies: what cannot be decoded takes the fail mode.
func TestPassthroughCoverageUndecodableReplyProperty(t *testing.T) {
	covAllowPrivate(t)
	req := covJSON(t, map[string]any{"model": "dc-test-model", "input": "hello there"})
	good := []byte(`{"object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}]}`)
	cases := []struct {
		name, ctype, enc string
		body             []byte
		chunk            int
	}{
		{"corrupt-br", "application/json", "br", []byte("\x1f\x8b\x08\x00 not brotli at all"), 0},
		{"corrupt-zstd", "application/json", "zstd", []byte("not a zstd frame"), 0},
		{"unknown-encoding", "application/json", "dc-test-enc", good, 0},
		{"not-json", "application/json", "", []byte("<html>not json</html>"), 0},
		{"stream-corrupt-br", "text/event-stream", "br", []byte("\x1f\x8b\x08\x00 not brotli at all"), 5},
		{"stream-unknown-encoding", "text/event-stream", "dc-test-enc", covFrame([]string{`{"type":"response.completed"}`}, "lf-space"), 5},
		{"stream-no-data-lines", "text/event-stream", "", []byte(`{"type":"response.output_text.delta","delta":"x"}` + "\n"), 5},
	}
	for _, managed := range []bool{false, true} {
		mode := map[bool]string{false: "oss", true: "managed"}[managed]
		up := newCovUpstream(t)
		covSetManaged(t, managed)
		proxy := covProxy(t, up, "openai", &covInspector{})
		for _, c := range cases {
			t.Run(mode+"/"+c.name, func(t *testing.T) {
				up.set(c.ctype, c.enc, c.body, c.chunk)
				rec := covPost(proxy, up, "/v1/responses", req, nil)
				if managed && !strings.Contains(rec.Body.String(), "could not be inspected") {
					t.Errorf("managed forwarded an undecodable reply: %.200s", rec.Body)
				}
			})
		}
	}
}

// P2/P4 for replies: a tool call is decided by the tool-call rules on every
// wire format and framing; the dummy blocked tool never reaches the agent,
// an allowed one arrives unchanged.
func TestPassthroughCoverageToolCallProperty(t *testing.T) {
	covAllowPrivate(t)
	req := covJSON(t, map[string]any{"model": "dc-test-model", "input": "hello there", "messages": []any{map[string]any{"role": "user", "content": "hello there"}}, "contents": []any{map[string]any{"role": "user", "parts": []any{map[string]any{"text": "hello there"}}}}})
	rnd := rand.New(rand.NewSource(0xcafe))
	for _, w := range covReplyWires() {
		up := newCovUpstream(t)
		proxy := covProxy(t, up, w.provider, &covInspector{})
		for _, args := range []string{`{"note":"x"}`, `{"note":"` + covMarker + `"}`} {
			blocked := func(name string) bool { return name == covBlockedTool || strings.Contains(args, covMarker) }
			for _, name := range []string{covBlockedTool, covAllowedTool} {
				body, events := w.tool(name, args)
				t.Run(fmt.Sprintf("body/%s/%s/%v", w.name, name, strings.Contains(args, covMarker)), func(t *testing.T) {
					plain := covJSON(t, body)
					up.set("application/json", "", plain, 0)
					rec := covPost(proxy, up, w.path, req, nil)
					if blocked(name) && (strings.Contains(rec.Body.String(), name) || strings.Contains(rec.Body.String(), covMarker)) {
						t.Errorf("a blocked tool call reached the agent: %.300s", rec.Body)
					}
					if !blocked(name) && !bytes.Equal(rec.Body.Bytes(), plain) {
						t.Errorf("an allowed tool call changed: %.300s", rec.Body)
					}
				})
				if events == nil {
					continue
				}
				for _, fr := range covFramings {
					chunk := 1 + rnd.Intn(40)
					enc := []string{"", "gzip", "br"}[rnd.Intn(3)]
					t.Run(fmt.Sprintf("stream/%s/%s/%v/%s/chunk=%d,enc=%s", w.name, name, strings.Contains(args, covMarker), fr, chunk, enc), func(t *testing.T) {
						raw := covFrame(events, fr)
						wire, ce := covEncode(t, enc, raw)
						up.set("text/event-stream", ce, wire, chunk)
						rec := covPost(proxy, up, w.path, req, nil)
						out := rec.Body.String()
						if blocked(name) && (strings.Contains(out, name) || strings.Contains(out, covMarker)) {
							t.Errorf("a blocked streamed call reached the agent:\n%.400s", out)
						}
						if !blocked(name) && !bytes.Equal(rec.Body.Bytes(), raw) {
							t.Errorf("an allowed streamed call changed:\n%.400s", out)
						}
					})
				}
			}
		}
	}
}
