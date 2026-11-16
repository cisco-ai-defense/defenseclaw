// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// #1395: the helper tells the gateway how long the request waits for its
// answer, so a tool-call judge answers inside it.
func TestHookPostSendsItsAnswerWait(t *testing.T) {
	got := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get(hookexec.HookAnswerWithinHeader)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "http://")
	frame := []byte("DCPOST1\x00/api/v1/claude-code/hook\x00{\"hook_event_name\":\"PreToolUse\"}\x00Content-Type\x00application/json\x00")
	for env, want := range map[string]string{"2600": "2600", "": "3000"} {
		t.Setenv(hookPostDeadlineEnv, env)
		var out bytes.Buffer
		if err := run([]string{"hook-post", "--api-addr", addr, "--max-time", "3", "--curl-output"}, bytes.NewReader(frame), &out); err != nil {
			t.Fatalf("%q: %v", env, err)
		}
		if header := <-got; header != want {
			t.Fatalf("deadline env %q: gateway saw %s=%q, want %q", env, hookexec.HookAnswerWithinHeader, header, want)
		}
	}
}
