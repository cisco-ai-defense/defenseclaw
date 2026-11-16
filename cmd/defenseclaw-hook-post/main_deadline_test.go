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
	"time"
)

// The shell hook's time left in milliseconds bounds the request, so a slow
// answer that arrives inside it is delivered although --max-time, in whole
// seconds, is shorter (GAP-2279). Without it, or with a value a whole second
// past --max-time, --max-time alone bounds the request.
func TestHookPostUsesTheShellHooksMillisecondsLeft(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(1400 * time.Millisecond)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "http://")
	frame := []byte("DCPOST1\x00/api/v1/claude-code/hook\x00{\"hook_event_name\":\"PreToolUse\"}\x00Content-Type\x00application/json\x00")
	post := func(env string) (string, error) {
		t.Setenv(hookPostDeadlineEnv, env)
		var out bytes.Buffer
		err := run([]string{"hook-post", "--api-addr", addr, "--max-time", "1", "--curl-output"}, bytes.NewReader(frame), &out)
		return out.String(), err
	}
	out, err := post("1900")
	if err != nil || !strings.HasPrefix(out, `{"action":"allow"}`) {
		t.Fatalf("1.9 s left: out=%q err=%v, want the gateway answer at 1.4 s", out, err)
	}
	for _, env := range []string{"", "2000", "abc", "0"} {
		started := time.Now()
		if out, err := post(env); err == nil {
			t.Fatalf("%q: out=%q, want the 1 s --max-time to end the request", env, out)
		}
		if elapsed := time.Since(started); elapsed > 1300*time.Millisecond {
			t.Fatalf("%q: request ran %s past the 1 s --max-time", env, elapsed)
		}
	}
}
