// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// The OpenCode and Amp per-user plugins send the gateway CLI's JSON request
// without --curl-output and read its JSON reply. The small helper must answer
// that request itself, through the same connected-peer transport, so a hook
// event never has to start the full gateway CLI.
func TestHookPostAnswersThePluginJSONRequest(t *testing.T) {
	var mu sync.Mutex
	var gotPath, gotAuth, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotPath, gotAuth, gotBody = r.URL.Path, r.Header.Get("Authorization"), string(data)
		mu.Unlock()
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"action":"busy"}`))
	}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "http://")
	request, err := json.Marshal(hookexec.PerUserPluginRequest{
		Path:    "/api/v1/opencode/hook",
		Headers: map[string]string{"Authorization": "Bearer plugin-test", "Content-Type": "application/json"},
		Body:    `{"hook_event_name":"PreToolUse"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"hook-post", "--api-addr", addr}, bytes.NewReader(request), &out); err != nil {
		t.Fatalf("plugin JSON request: %v", err)
	}
	var reply hookexec.PerUserHookReply
	if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
		t.Fatalf("reply is not JSON: %q: %v", out.String(), err)
	}
	if reply.Status != http.StatusTooManyRequests || reply.Body != `{"action":"busy"}` || reply.RetryAfter != "2" {
		t.Fatalf("reply = %+v", reply)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotPath != "/api/v1/opencode/hook" || gotAuth != "Bearer plugin-test" || gotBody != `{"hook_event_name":"PreToolUse"}` {
		t.Fatalf("gateway saw path %q auth %q body %q", gotPath, gotAuth, gotBody)
	}
}

// A malformed request, a request in the other mode's format, and an
// unsupported path never reach the gateway.
func TestHookPostRejectsABadRequestBeforeSending(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
	}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "http://")
	for _, tc := range []struct {
		name  string
		args  []string
		input string
	}{
		{name: "malformed JSON", args: []string{"hook-post", "--api-addr", addr}, input: `{"path":`},
		{name: "frame without curl output", args: []string{"hook-post", "--api-addr", addr}, input: "DCPOST1\x00/api/v1/opencode/hook\x00"},
		{name: "JSON with curl output", args: []string{"hook-post", "--api-addr", addr, "--curl-output"}, input: `{"path":"/api/v1/opencode/hook"}`},
		{name: "unsupported path", args: []string{"hook-post", "--api-addr", addr}, input: `{"path":"/api/v1/config","body":"x"}`},
		{name: "oversized", args: []string{"hook-post", "--api-addr", addr}, input: strings.Repeat(" ", maxInput+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := run(tc.args, strings.NewReader(tc.input), io.Discard); err == nil {
				t.Fatal("bad request was accepted")
			}
		})
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatalf("gateway received %d bad requests", hits)
	}
}
