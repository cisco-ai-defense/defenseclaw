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

package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The core invariant that keeps Cursor from locking an agent out: the
// Cursor hook MUST NEVER write empty stdout on an allow / observe /
// fail-open outcome, because Cursor treats a failClosed:true hook with
// empty stdout as a hook failure and blocks the tool. These tests run
// the real rendered hook against a stub gateway so a future edit that
// reintroduces a silent `exit 0` fails CI instead of shipping a
// lockout.

// runCursorHookAgainst renders cursor-hook.sh pointed at apiAddr and
// runs it, returning stdout/stderr/exit error.
func runCursorHookAgainst(t *testing.T, apiAddr string) (string, string, error) {
	t.Helper()
	return runCursorHook(t, apiAddr, "closed", true)
}

// stubGatewayAddr stands up an httptest server that returns the given
// status and body for the cursor hook endpoint and returns its
// host:port (the form the hook template expects).
func stubGatewayAddr(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func TestCursorHook_ObserveEmptyHookOutputEmitsAllow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts not supported on windows")
	}
	// Observe mode: the gateway has nothing to enforce and answers 200
	// with no hook_output. This is the exact case that produced the
	// original total lockout. The hook must emit an explicit allow.
	addr := stubGatewayAddr(t, http.StatusOK, `{}`)
	stdout, stderr, err := runCursorHookAgainst(t, addr)
	if err != nil {
		t.Fatalf("expected exit 0, got %v; stderr=%s", err, stderr)
	}
	assertAllowEnvelope(t, stdout)
}

func TestCursorHook_GatewayAllowEnvelopePassedThrough(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts not supported on windows")
	}
	addr := stubGatewayAddr(t, http.StatusOK,
		`{"hook_output":{"continue":true,"permission":"allow"}}`)
	stdout, stderr, err := runCursorHookAgainst(t, addr)
	if err != nil {
		t.Fatalf("expected exit 0, got %v; stderr=%s", err, stderr)
	}
	assertAllowEnvelope(t, stdout)
}

func TestCursorHook_GatewayDenyEnvelopePassedThrough(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts not supported on windows")
	}
	// A real block decision must still reach Cursor verbatim — the
	// fail-open hardening must not swallow deny verdicts.
	addr := stubGatewayAddr(t, http.StatusOK,
		`{"hook_output":{"continue":true,"permission":"deny","user_message":"blocked by policy"}}`)
	stdout, _, err := runCursorHookAgainst(t, addr)
	if err != nil {
		t.Fatalf("expected exit 0 (decision carried in body), got %v", err)
	}
	trimmed := strings.TrimSpace(stdout)
	var obj map[string]interface{}
	if e := json.Unmarshal([]byte(trimmed), &obj); e != nil {
		t.Fatalf("stdout not JSON: %q", trimmed)
	}
	if obj["permission"] != "deny" {
		t.Fatalf(`permission = %v, want "deny"; stdout=%q`, obj["permission"], trimmed)
	}
}

// TestCursorHook_NeverEmptyStdout is the umbrella guard: across every
// scenario a Cursor agent can drive, stdout is a valid, non-empty JSON
// object carrying a permission. Empty stdout on any of these would let
// Cursor's failClosed:true guard block the tool.
func TestCursorHook_NeverEmptyStdout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts not supported on windows")
	}
	cases := []struct {
		name string
		addr func(t *testing.T) string
	}{
		{"observe_empty", func(t *testing.T) string { return stubGatewayAddr(t, http.StatusOK, `{}`) }},
		{"null_hook_output", func(t *testing.T) string { return stubGatewayAddr(t, http.StatusOK, `{"hook_output":null}`) }},
		{"server_5xx", func(t *testing.T) string { return stubGatewayAddr(t, http.StatusBadGateway, `boom`) }},
		{"gateway_unreachable", func(t *testing.T) string { return "127.0.0.1:1" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, err := runCursorHookAgainst(t, tc.addr(t))
			if err != nil {
				t.Fatalf("expected exit 0 (fail-open), got %v; stderr=%s", err, stderr)
			}
			trimmed := strings.TrimSpace(stdout)
			if trimmed == "" {
				t.Fatal("stdout empty — Cursor fail-closes on empty stdout and would block the tool")
			}
			var obj map[string]interface{}
			if e := json.Unmarshal([]byte(trimmed), &obj); e != nil {
				t.Fatalf("stdout is not a JSON object: %v\ngot: %q", e, trimmed)
			}
			if _, ok := obj["permission"]; !ok {
				t.Fatalf("stdout carries no permission field: %q", trimmed)
			}
		})
	}
}

// TestCursorHooks_ObserveModeWritesFailClosedFalse pins the config
// side: a default / observe (non-closed) install must write
// failClosed:false so an empty or slow hook can never be misread as a
// fail-closed block. Paired with TestCursorHooks_FailClosedOnlyWhenExplicit.
func TestCursorHooks_ObserveModeWritesFailClosedFalse(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hooks.json")
	prev := CursorHooksPathOverride
	CursorHooksPathOverride = cfgPath
	t.Cleanup(func() { CursorHooksPathOverride = prev })

	conn := NewCursorConnector()
	// No explicit HookFailMode => default (observe / non-closed) install.
	opts := SetupOpts{
		DataDir:  filepath.Join(dir, "dc"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read cursor hooks: %v", err)
	}
	if !strings.Contains(string(data), `"failClosed": false`) {
		t.Fatalf("observe-mode cursor hooks must write failClosed:false, got:\n%s", string(data))
	}
	if strings.Contains(string(data), `"failClosed": true`) {
		t.Fatalf("observe-mode cursor hooks must not write failClosed:true, got:\n%s", string(data))
	}
}
