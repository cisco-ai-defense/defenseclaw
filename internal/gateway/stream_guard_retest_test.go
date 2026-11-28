// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The s7/response round 2 and 3 review repros (rel-1-0-10:GAP-0368, GAP-0428,
// GAP-0429, GAP-0430, GAP-0431) were written against that branch's stream
// guard (newCompletionStreamGuard, trackPEM), which rel never took: rel holds
// a streamed completion with the s7/stream-tail design (proxy_stream_tail.go,
// GAP-0212). The same inputs go here through rel's two stream entry points end
// to end, the /llm proxy (handleChatCompletion) and the passthrough stream
// (handlePassthrough), and the property each gap states is checked on what the
// client receives.

// retestFiller is ordinary assistant prose of at least n bytes.
func retestFiller(n int) string {
	sentences := []string{
		"The build passed on the second run after the cache was cleared.",
		"I updated the handler so the retry loop stops after three attempts.",
		"Next, the table test covers the empty input and the long input.",
		"The function returns early when the list is empty, which keeps the hot path short.",
		"Let me know if you want the same change in the other two packages.",
	}
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		b.WriteString(sentences[i%len(sentences)])
		if i%4 == 3 {
			b.WriteString("\n\n")
		} else {
			b.WriteByte(' ')
		}
	}
	return b.String()
}

// retestSecret is the GitHub token fixture of rules_test.go, a blocking secret
// in every pack.
func retestSecret() string {
	return runtimeDetectorSignature("gh", "p_A7b9C2d4E6f8G1h3J5k7", "L9m2N4p6Q8r1S3t5")
}

func retestInspector() *GuardrailInspector {
	return NewGuardrailInspector("local", nil, nil)
}

// retestPassthrough sends one streamed passthrough reply made of writes (each
// flushed on its own) through handlePassthrough and returns what the client got.
func retestPassthrough(t *testing.T, writes []string) string {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		for _, f := range writes {
			_, _ = w.Write([]byte(f))
			if fl != nil {
				fl.Flush()
			}
		}
	}))
	defer upstream.Close()
	orig := providerDomains
	providerDomains = append(providerDomains, struct {
		domain string
		name   string
	}{"127.0.0.1", "openai"})
	defer func() { providerDomains = orig }()
	proxy := gap0429Proxy(t, &mockProvider{}, retestInspector())
	body := mustJSON(t, map[string]interface{}{
		"model": "m", "stream": true, "max_tokens": 64,
		"messages": []map[string]interface{}{{"role": "user", "content": "summarize the change"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/passthrough-stream", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", upstream.URL)
	req.Header.Set("X-AI-Auth", "Bearer sk-test-upstream")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	proxy.handlePassthrough(rec, req)
	return rec.Body.String()
}

func retestOAIFrame(content string) string {
	b, _ := json.Marshal(map[string]interface{}{"choices": []map[string]interface{}{{"index": 0, "delta": map[string]string{"content": content}}}})
	return "data: " + string(b) + "\n\n"
}

// retestPieces cuts text into n-byte pieces.
func retestPieces(text string, n int) []string {
	var out []string
	for off := 0; off < len(text); off += n {
		out = append(out, text[off:min(off+n, len(text))])
	}
	return out
}

// retestLLM streams the content pieces as /llm chunks (default pack, action
// mode) and returns what the client got.
func retestLLM(t *testing.T, pieces []string, extra ...StreamChunk) string {
	t.Helper()
	var chunks []StreamChunk
	for _, p := range pieces {
		chunks = append(chunks, StreamChunk{ID: "c", Object: "chat.completion.chunk", Model: "gpt-4",
			Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: p}}}})
	}
	chunks = append(chunks, extra...)
	fin := "stop"
	chunks = append(chunks, StreamChunk{ID: "c", Object: "chat.completion.chunk", Model: "gpt-4",
		Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &fin}}})
	return retestLLMChunks(t, chunks)
}

func retestLLMChunks(t *testing.T, chunks []StreamChunk) string {
	t.Helper()
	reqBody := mustJSON(t, map[string]interface{}{
		"model": "gpt-4", "stream": true,
		"messages": []map[string]interface{}{{"role": "user", "content": "go"}},
	})
	proxy := gap0429Proxy(t, &mockProvider{streamChunks: chunks}, retestInspector())
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	cfg := &config.Config{}
	cfg.Guardrail.RulePack = "default"
	req = req.WithContext(withPinnedGeneration(req.Context(), &Generation{N: 1, Config: cfg}))
	rec := httptest.NewRecorder()
	proxy.handleChatCompletion(rec, req)
	return rec.Body.String()
}

// streamedContent is the assistant text a client reassembles from an SSE body
// (OpenAI chat chunk shape), so a check on it is not fooled by JSON escaping.
func streamedContent(body string) string {
	var b strings.Builder
	for _, line := range strings.Split(body, "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		var frame struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal([]byte(data), &frame) == nil {
			for _, c := range frame.Choices {
				b.WriteString(c.Delta.Content)
			}
		}
	}
	return b.String()
}

// GAP-0368: a passthrough SSE data line over 1 MiB is checked; the secret at
// its end never reaches the client.
func TestRetestGAP0368PassthroughLongLineIsChecked(t *testing.T) {
	secret := retestSecret()
	out := retestPassthrough(t, []string{retestOAIFrame(retestFiller(1100<<10) + "\n" + secret + "\n"), "data: [DONE]\n\n"})
	if strings.Contains(out, secret) || strings.Contains(streamedContent(out), secret) {
		t.Errorf("a secret at the end of a 1.1 MiB passthrough data line reached the client (%d bytes out)", len(out))
	}
}

// GAP-0428: an END line of another label inside an open private-key block
// must not stall the stream (the s7/response guard spun forever), on /llm and
// on the passthrough stream, with 24-byte pieces.
func TestRetestGAP0428PEMOtherFooterTerminates(t *testing.T) {
	key := syntheticPrivateKeyPEM("RSA PRIVATE KEY")
	header := key[:strings.IndexByte(key, '\n')+1]
	other := "-----END " + "CERTIFICATE" + "-----\n"
	text := "Layout:\n" + header + "MIIBodyLineNotReal\n" + other + retestFiller(2000)
	for name, run := range map[string]func() string{
		"llm": func() string { return retestLLM(t, retestPieces(text, 24)) },
		"passthrough": func() string {
			var writes []string
			for _, p := range retestPieces(text, 24) {
				writes = append(writes, retestOAIFrame(p))
			}
			return retestPassthrough(t, append(writes, "data: [DONE]\n\n"))
		},
	} {
		done := make(chan string, 1)
		go func() { done <- run() }()
		select {
		case out := <-done:
			if !strings.Contains(out, "[DONE]") && !strings.Contains(strings.ToLower(out), "block") {
				t.Errorf("%s: the stream ended with neither its end marker nor a block notice (%d bytes)", name, len(out))
			}
		case <-time.After(15 * time.Second):
			t.Errorf("%s: a stream with another label's END line inside an open key block did not finish within 15 s", name)
		}
	}
}

// GAP-0429: a non-key BEGIN line still open at a piece boundary, then a real
// key header in the next piece: no key body line reaches the client, on /llm
// and on the passthrough stream. The key is generated at run time.
func TestRetestGAP0429DecoyHeaderThenKey(t *testing.T) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key := string(pem.EncodeToMemory(&pem.Block{Type: "RSA " + "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)}))
	body := key[strings.IndexByte(key, '\n')+1 : strings.LastIndex(key, "-----END ")]
	leaked := func(out string) int {
		got := streamedContent(out)
		n := 0
		for _, line := range strings.Split(body, "\n") {
			if len(line) > 8 && (strings.Contains(got, line) || strings.Contains(out, line)) {
				n += len(line)
			}
		}
		return n
	}
	for _, decoy := range []bool{false, true} {
		pre := retestFiller(600) + "\n"
		var pieces []string
		if decoy {
			pieces = append(pieces, pre+"-----BEGIN ", "X-----\n"+key[:60])
		} else {
			pieces = append(pieces, pre+"-----BEGIN X-----\n", key[:60])
		}
		pieces = append(pieces, retestPieces(key[60:]+retestFiller(400), 24)...)
		if n := leaked(retestLLM(t, pieces)); n > 0 {
			t.Errorf("llm decoy=%v: %d of %d key body bytes reached the client", decoy, n, len(body))
		}
		var writes []string
		for _, p := range pieces {
			writes = append(writes, retestOAIFrame(p))
		}
		if n := leaked(retestPassthrough(t, append(writes, "data: [DONE]\n\n"))); n > 0 {
			t.Errorf("passthrough decoy=%v: %d of %d key body bytes reached the client", decoy, n, len(body))
		}
	}
}

// GAP-0430: a passthrough data line over 1 MiB, written in 4096-byte pieces,
// with a 3-byte rune across pieces 257/258 and the secret across the end of
// piece 258: the secret is withheld (and with an ASCII letter in place of the
// rune, the control).
func TestRetestGAP0430PassthroughLongLineRuneSplit(t *testing.T) {
	secret := retestSecret()
	const C = 4096
	prefix := `data: {"choices":[{"index":0,"delta":{"content":"`
	B := 257 * C
	for _, split := range []bool{false, true} {
		total := B + 3*C
		content := []byte(strings.Repeat("a ", total))[:total-len(prefix)]
		r := "e"
		if split {
			r = "€"
		}
		copy(content[B-1-len(prefix):], r)
		at := B + C - len(secret)/2 - 2 - len(prefix)
		content[at-1] = ' '
		copy(content[at:], secret)
		content[at+len(secret)] = ' '
		line := prefix + string(content) + `"}}]}` + "\n\n"
		out := retestPassthrough(t, append(retestPieces(line, C), "data: [DONE]\n\n"))
		if strings.Contains(out, secret) || strings.Contains(streamedContent(out), secret) {
			t.Errorf("split=%v: the secret near a piece end of a 1 MiB+ line reached the client", split)
		}
	}
}

// GAP-0431: on /llm, a content chunk after 10 MiB of tool-call data is checked
// before it is released (control: the same content before the tool calls).
func TestRetestGAP0431ToolCapFlushChecksContent(t *testing.T) {
	secret := retestSecret()
	bigArgs := strings.Repeat("A", 512*1024)
	for _, where := range []string{"before tools (control)", "after tools"} {
		var chunks []StreamChunk
		content := StreamChunk{ID: "c", Object: "chat.completion.chunk", Model: "gpt-4",
			Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: "\nsee " + secret + " here\n"}}}}
		if where == "before tools (control)" {
			chunks = append(chunks, StreamChunk{ID: "c", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: retestFiller(600)}}}}, content)
		}
		mk := func(args string) StreamChunk {
			tc := json.RawMessage(`[{"index":0,"id":"c1","type":"function","function":{"name":"big","arguments":"` + args + `"}}]`)
			return StreamChunk{ID: "c", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{ToolCalls: tc}}}}
		}
		size := 0
		for i := 0; i < 19; i++ {
			c := mk(bigArgs)
			d, _ := json.Marshal(c)
			size += len(d)
			chunks = append(chunks, c)
		}
		probe, _ := json.Marshal(mk(""))
		chunks = append(chunks, mk(strings.Repeat("A", (10<<20)-size-len(probe)-50)))
		if where == "after tools" {
			chunks = append(chunks, content)
			for i := 0; i < 3; i++ {
				chunks = append(chunks, StreamChunk{ID: "c", Object: "chat.completion.chunk", Model: "gpt-4",
					Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: retestFiller(300)}}}})
			}
		}
		fin := "tool_calls"
		chunks = append(chunks, StreamChunk{ID: "c", Object: "chat.completion.chunk", Model: "gpt-4",
			Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &fin}}})
		out := retestLLMChunks(t, chunks)
		if strings.Contains(out, secret) || strings.Contains(streamedContent(out), secret) {
			t.Errorf("%s: the secret reached the client", where)
		}
	}
}
