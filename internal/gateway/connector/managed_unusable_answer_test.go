// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rel-1-0-3 B-20 review item 1: a managed standalone shell hook blocks a
// successful gateway answer that carries no usable verdict (no action, an
// unknown one, a block without a directive or with one that does not deny),
// with DEFENSECLAW_FAIL_MODE=open in the environment. The allow and alert
// answers of observe mode still let the call run. r104 W8 review P2 adds
// Claude Code and Codex.
func TestManagedStandaloneShellHooksBlockAnUnusableAnswer(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required to run the shell hooks")
	}
	for _, conn := range []Connector{
		NewHermesConnector(), NewKiroConnector(), NewCursorConnector(),
		NewDevinConnector(), NewAntigravityConnector(), NewClaudeCodeConnector(),
		NewCodexConnector(),
	} {
		hook := hookArgvConnectorCase(t, conn.Name())
		for _, answer := range []struct {
			name   string
			body   map[string]any
			blocks bool
		}{
			{"missing action", map[string]any{}, true},
			{"unknown action", map[string]any{"action": "proceed"}, true},
			{"block without directive", map[string]any{"action": "block"}, true},
			{"block whose directive allows", map[string]any{"action": "block", "hook_output": map[string]string{"decision": "allow"}}, true},
			{"observe allow", map[string]any{"action": "allow"}, false},
			{"observe alert", map[string]any{"action": "alert"}, false},
		} {
			t.Run(conn.Name()+" "+answer.name, func(t *testing.T) {
				f := newHookSocketFixture(t, "dcua", answer.body)
				code, stdout, stderr := runStandaloneShellHook(t, f, conn, hook.script, hook.args, hook.stdin)
				blocked := code == 2 || strings.Contains(stdout, `"deny"`) ||
					strings.Contains(stdout, `"block"`) || strings.Contains(stdout, `"continue":false`)
				if blocked != answer.blocks {
					t.Fatalf("exit %d stdout=%q stderr=%q: blocked = %v, want %v", code, stdout, stderr, blocked, answer.blocks)
				}
			})
		}
	}
}

// rel-1-0-3 GAP-0153: a per-user shell hook in fail mode closed let the call
// run on a successful gateway answer with no usable verdict (Hermes printed
// its neutral {}), because the response validation was rendered for sandbox
// and managed hooks only. In fail mode closed it now blocks like a managed
// hook; in fail mode open the call still runs, and the allow and alert
// answers run in both. Each case logs the unusable answer as a response
// failure.
func TestPerUserShellHooksHonorClosedOnAnUnusableAnswer(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required to run the shell hooks")
	}
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl is required to run the shell hooks")
	}
	for _, conn := range []Connector{
		NewHermesConnector(), NewKiroConnector(), NewCursorConnector(),
		NewDevinConnector(), NewAntigravityConnector(),
	} {
		hook := hookArgvConnectorCase(t, conn.Name())
		for _, answer := range []struct {
			name   string
			body   map[string]any
			usable bool
			block  bool
		}{
			{"missing action", map[string]any{}, false, false},
			{"unknown action", map[string]any{"action": "proceed"}, false, false},
			{"block without directive", map[string]any{"action": "block"}, true, true},
			{"block whose directive allows", map[string]any{"action": "block", "hook_output": map[string]string{"decision": "allow", "permission": "allow"}}, true, true},
			{"observe allow", map[string]any{"action": "allow"}, true, false},
			{"observe alert", map[string]any{"action": "alert"}, true, false},
		} {
			for _, failMode := range []string{"closed", "open"} {
				t.Run(conn.Name()+" "+answer.name+" "+failMode, func(t *testing.T) {
					body, _ := json.Marshal(answer.body)
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write(body)
					}))
					t.Cleanup(server.Close)
					home := t.TempDir()
					installNativeGatewayForHookTest(t, home)
					hookDir := filepath.Join(home, ".defenseclaw", "hooks")
					opts := SetupOpts{
						DataDir:            filepath.Join(home, ".defenseclaw"),
						APIAddr:            strings.TrimPrefix(server.URL, "http://"),
						HookAPIToken:       "connector-scoped-token",
						HookAPITokenScoped: true,
						HookFailMode:       failMode,
						// The operator's choice: Cursor's open outage needs it.
						GuardrailMode: "observe",
					}
					if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
						t.Fatal(err)
					}
					hookPath := filepath.Join(hookDir, hook.script)
					bakeHookPathForTest(t, hookPath, filepath.Dir(curlPath)+":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, "bash", append([]string{hookPath}, hook.args...)...)
					var env []string
					for _, kv := range os.Environ() {
						if !strings.HasPrefix(kv, "DEFENSECLAW_") {
							env = append(env, kv)
						}
					}
					// No hook reads DEFENSECLAW_FAIL_MODE (GAP-0315): the mode
					// rendered from the config decides. Cursor in observe keeps
					// its outages closed without an explicit open
					// (OutageHookFailMode), and per-user Antigravity follows
					// closed (w3-g3-hooks).
					cmd.Env = append(env, "HOME="+home, "DEFENSECLAW_FAIL_MODE="+failMode)
					cmd.Stdin = strings.NewReader(hook.stdin)
					var stdout, stderr bytes.Buffer
					cmd.Stdout, cmd.Stderr = &stdout, &stderr
					err := cmd.Run()
					code := 0
					if exitErr, ok := err.(*exec.ExitError); ok {
						code = exitErr.ExitCode()
					} else if err != nil {
						t.Fatalf("run hook: %v", err)
					}
					out := stdout.String()
					blocked := code == 2 || strings.Contains(out, `"deny"`) ||
						strings.Contains(out, `"block"`) || strings.Contains(out, `"continue":false`)
					wantBlocked := answer.block || !answer.usable
					if blocked != wantBlocked {
						t.Fatalf("exit %d stdout=%q stderr=%q: blocked = %v, want %v", code, out, stderr.String(), blocked, wantBlocked)
					}
					logged, _ := os.ReadFile(filepath.Join(home, ".defenseclaw", "logs", "hook-failures.jsonl"))
					if wantLogged := !answer.usable; strings.Contains(string(logged), `"category":"response"`) != wantLogged {
						t.Fatalf("hook-failures.jsonl = %q, want a response line: %v", logged, wantLogged)
					}
				})
			}
		}
	}
}

// r104 W4b2 review P1: a standalone managed shell hook (Linux, macOS) whose
// administrator chose hook_fail_mode open lets a call through only on a
// gateway outage (here the stopped service: no hook socket). A rate limit
// (HTTP 429 after the resends, or a resend that fails after a 429), a 5xx,
// an unusable answer and input too large to inspect are no outage and block,
// as in the native hook runner. r104 W8 review P2: Claude Code and Codex
// let a 4xx, a 429 and an unusable answer through in open.
func TestManagedStandaloneShellHooksOpenOnlyForAnOutage(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required to run the shell hooks")
	}
	answer := func(status int, body string) func(int, http.ResponseWriter) bool {
		return func(_ int, w http.ResponseWriter) bool {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return true
		}
	}
	truncatedAnswer := func(status int) func(int, http.ResponseWriter) bool {
		return func(_ int, w http.ResponseWriter) bool {
			w.Header().Set("Content-Length", "128")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"unavailable"}`))
			return true
		}
	}
	rateLimited := `{"error":"rate_limited","reason":"enterprise_managed_rate_limited","retry_after_seconds":1}`
	for _, conn := range []Connector{
		NewHermesConnector(), NewKiroConnector(), NewCursorConnector(),
		NewDevinConnector(), NewAntigravityConnector(), NewClaudeCodeConnector(), NewCopilotConnector(),
		NewCodexConnector(),
	} {
		hook := hookArgvConnectorCase(t, conn.Name())
		for _, tc := range []struct {
			name      string
			serve     func(int, http.ResponseWriter) bool
			stdin     string
			stopped   bool
			untrusted bool
			blocks    bool
		}{
			{name: "rate limited until the resends end", serve: answer(http.StatusTooManyRequests, rateLimited), blocks: true},
			{name: "rate limited, then the resend fails", serve: func(n int, w http.ResponseWriter) bool {
				if n == 1 {
					return answer(http.StatusTooManyRequests, rateLimited)(n, w)
				}
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return true
			}, blocks: true},
			{name: "gateway 5xx", serve: answer(http.StatusServiceUnavailable, `{"error":"unavailable"}`), blocks: true},
			{name: "gateway 500", serve: answer(http.StatusInternalServerError, `{"error":"internal"}`), blocks: true},
			{name: "gateway 502", serve: answer(http.StatusBadGateway, `{"error":"bad gateway"}`), blocks: true},
			{name: "gateway 4xx", serve: answer(http.StatusBadRequest, `{"error":"bad request"}`), blocks: true},
			{name: "gateway 401", serve: answer(http.StatusUnauthorized, `{"error":"unauthorized"}`), blocks: true},
			{name: "gateway 403", serve: answer(http.StatusForbidden, `{"error":"forbidden"}`), blocks: true},
			{name: "gateway 404", serve: answer(http.StatusNotFound, `{"error":"missing"}`), blocks: true},
			{name: "gateway 400 truncated", serve: truncatedAnswer(http.StatusBadRequest), blocks: true},
			{name: "gateway 503 truncated", serve: truncatedAnswer(http.StatusServiceUnavailable), blocks: true},
			{name: "unusable answer", serve: answer(http.StatusOK, `{"action":"proceed"}`), blocks: true},
			{name: "missing action", serve: answer(http.StatusOK, `{}`), blocks: true},
			{name: "input too large to inspect", stdin: `{"pad":"` + strings.Repeat("x", 1100<<10) + `"}`, blocks: true},
			{name: "gateway stopped", stopped: true, blocks: conn.Name() == "copilot"},
			{name: "socket trust failed", untrusted: true, blocks: true},
			{name: "allow verdict", serve: answer(http.StatusOK, `{"action":"allow"}`), blocks: false},
		} {
			t.Run(fmt.Sprintf("%s %s", conn.Name(), tc.name), func(t *testing.T) {
				t.Parallel()
				f := newHookSocketFixture(t, "dcoo", nil)
				f.gateway.serve = tc.serve
				if tc.stopped {
					if err := os.Remove(f.socket); err != nil {
						t.Fatal(err)
					}
				}
				if tc.untrusted {
					f.untrustSocketDir(t)
				}
				stdin := hook.stdin
				if tc.stdin != "" {
					stdin = tc.stdin
				}
				code, stdout, stderr := runStandaloneShellHookInMode(t, f, conn, hook.script, hook.args, stdin, "open")
				blocked := code == 2 || strings.Contains(stdout, `"deny"`) ||
					strings.Contains(stdout, `"block"`) || strings.Contains(stdout, `"continue":false`)
				if blocked != tc.blocks {
					t.Fatalf("admin open: exit %d stdout=%q stderr=%q: blocked = %v, want %v", code, stdout, stderr, blocked, tc.blocks)
				}
			})
		}
	}
}
