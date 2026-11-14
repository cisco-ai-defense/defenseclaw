// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRawForwardToolCapChecksContentBeforeRelease: on raw forward, the
// frames buffered behind a tool call are released at the 10 MiB bound only
// after the guard checked the text pushed before them, so a secret in the
// content that follows is withheld (rel-1-0-10:GAP-0431; the reviewer found
// the /llm case by test and this one by reading the code).
func TestRawForwardToolCapChecksContentBeforeRelease(t *testing.T) {
	secret := resprevSecret(t)
	frame := func(v interface{}) string {
		b, _ := json.Marshal(v)
		return "data: " + string(b) + "\n\n"
	}
	toolFrame := func(args string) string {
		return frame(map[string]interface{}{"id": "s1", "object": "chat.completion.chunk", "choices": []map[string]interface{}{{
			"index": 0, "delta": map[string]interface{}{"tool_calls": []map[string]interface{}{{
				"index": 0, "id": "c1", "type": "function", "function": map[string]string{"name": "big", "arguments": args}}}}}}})
	}
	contentFrame := func(text string) string {
		return frame(map[string]interface{}{"id": "s1", "object": "chat.completion.chunk",
			"choices": []map[string]interface{}{{"index": 0, "delta": map[string]string{"content": text}}}})
	}
	var body strings.Builder
	big := strings.Repeat("A", 512*1024)
	for body.Len() < streamMaxToolBytes-600*1024 {
		body.WriteString(toolFrame(big))
	}
	body.WriteString(toolFrame(strings.Repeat("A", streamMaxToolBytes-body.Len()-50)))
	body.WriteString(contentFrame("\nsee " + secret + " here\n"))
	for i := 0; i < 3; i++ {
		body.WriteString(contentFrame(streamGuardFiller(300)))
	}
	body.WriteString("data: [DONE]\n\n")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(body.String()))
	}))
	defer upstream.Close()
	registerRawForwardProviderDomain(t, upstream.URL, "openai")
	allowRawForwardPrivateTargets(t)
	_, insp := streamGuardTestCheck()
	proxy := newTestProxy(t, &mockProvider{}, insp, "action")
	srv := httptest.NewServer(http.HandlerFunc(proxy.handleChatCompletion))
	defer srv.Close()
	reqBody := mustJSON(t, map[string]interface{}{"model": "gpt-4", "stream": true,
		"messages": []map[string]interface{}{{"role": "user", "content": "go"}}})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/chat/completions", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", upstream.URL)
	req.Header.Set("X-AI-Auth", "Bearer sk-test")
	client := srv.Client()
	client.Timeout = 30 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(bufio.NewReader(resp.Body))
	resp.Body.Close()
	if strings.Contains(string(out), secret) {
		t.Fatalf("the secret after the tool-call bound reached the client (%d bytes out)", len(out))
	}
}

// TestTextSafeCutCarriesSplitRunesAndEscapes: the long-line path cuts a
// read before a rune or a JSON escape the read split (rel-1-0-10:GAP-0430).
func TestTextSafeCutCarriesSplitRunesAndEscapes(t *testing.T) {
	euro := []byte("€")
	for _, c := range []struct {
		name string
		in   []byte
		want int
	}{
		{"ascii", []byte("abc"), 3},
		{"whole rune", append([]byte("ab"), euro...), 5},
		{"rune split after 1", append([]byte("ab"), euro[:1]...), 2},
		{"rune split after 2", append([]byte("ab"), euro[:2]...), 2},
		{"trailing backslash", []byte(`ab\`), 2},
		{"escaped backslash", []byte(`ab\\`), 4},
		{"unicode escape split", []byte(`ab\u00`), 2},
		{"unicode escape whole", []byte("ab" + `\` + "u0041"), 8},
		{"simple escape whole", []byte(`ab\n`), 4},
	} {
		if got := textSafeCut(c.in); got != c.want {
			t.Errorf("%s: textSafeCut = %d, want %d", c.name, got, c.want)
		}
	}
}
