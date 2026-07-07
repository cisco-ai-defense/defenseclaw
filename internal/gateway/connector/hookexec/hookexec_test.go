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

package hookexec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubRT is an injectable http.RoundTripper returning a canned response (or a
// transport error) and capturing the outbound request for assertions.
type stubRT struct {
	status   int
	body     string
	err      error
	gotReq   *http.Request
	gotBody  []byte
	requests int
}

func (s *stubRT) RoundTrip(req *http.Request) (*http.Response, error) {
	s.requests++
	if req.Body != nil {
		s.gotBody, _ = io.ReadAll(req.Body)
	}
	s.gotReq = req
	if s.err != nil {
		return nil, s.err
	}
	return &http.Response{
		StatusCode: s.status,
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Header:     make(http.Header),
	}, nil
}

type runResult struct {
	stdout string
	stderr string
	code   int
	rt     *stubRT
}

// run executes a hook against a stub gateway with a temp Home + .token file.
func run(t *testing.T, connector string, rt *stubRT, mutate func(*Options)) runResult {
	t.Helper()
	home := t.TempDir()
	hookDir := filepath.Join(home, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatalf("mkdir hookDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".token"),
		[]byte("DEFENSECLAW_GATEWAY_TOKEN=\"tkn\"\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	var out, errb bytes.Buffer
	opts := Options{
		Connector:  connector,
		Event:      "PreToolUse",
		APIAddr:    "127.0.0.1:8787",
		FailMode:   "open",
		Home:       home,
		HookDir:    hookDir,
		Stdin:      strings.NewReader(`{"event":"x"}`),
		Stdout:     &out,
		Stderr:     &errb,
		HTTPClient: &http.Client{Transport: rt},
		Now:        func() time.Time { return time.Unix(0, 0).UTC() },
	}
	if mutate != nil {
		mutate(&opts)
	}
	code := Run(context.Background(), opts)
	return runResult{stdout: out.String(), stderr: errb.String(), code: code, rt: rt}
}

func ok(body string) *stubRT { return &stubRT{status: 200, body: body} }

func TestRunPrefersConnectorScopedToken(t *testing.T) {
	result := run(t, "codex", ok(`{"action":"allow"}`), func(opts *Options) {
		opts.Token = "generic-env"
		legacyPath := filepath.Join(opts.HookDir, ".token")
		if err := os.WriteFile(legacyPath, []byte("DEFENSECLAW_GATEWAY_TOKEN=\"legacy\"\n"), 0o600); err != nil {
			t.Fatalf("write legacy token: %v", err)
		}
		path := filepath.Join(opts.HookDir, ".hook-codex.token")
		if err := os.WriteFile(path, []byte("scoped\n"), 0o600); err != nil {
			t.Fatalf("write scoped token: %v", err)
		}
	})
	if result.code != 0 {
		t.Fatalf("Run code = %d, want 0; stderr=%s", result.code, result.stderr)
	}
	if got := result.rt.gotReq.Header.Get("Authorization"); got != "Bearer scoped" {
		t.Fatalf("Authorization = %q, want connector-scoped token", got)
	}
}

func TestMalformedLegacyTokenIsNotAcceptedAsRaw(t *testing.T) {
	result := run(t, "codex", ok(`{"action":"allow"}`), func(opts *Options) {
		if err := os.WriteFile(filepath.Join(opts.HookDir, ".token"), []byte("malformed-legacy-token\n"), 0o600); err != nil {
			t.Fatalf("write malformed legacy token: %v", err)
		}
	})
	if result.code != 0 {
		t.Fatalf("Run code = %d, want 0; stderr=%s", result.code, result.stderr)
	}
	if got := result.rt.gotReq.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want malformed legacy token rejected", got)
	}
}

func TestClaudeCodeSuppressesCursorCompatibilityImport(t *testing.T) {
	const (
		cursorPayload = `{"hook_event_name":"preToolUse","cursor_version":"3.10.17","session_id":"cursor-session","tool_name":"Shell"}`
		claudePayload = `{"hook_event_name":"PreToolUse","session_id":"claude-session","tool_name":"Bash"}`
		liveScript    = "#!/bin/bash\n# defenseclaw-managed-hook v6\nexit 0\n"
		tombstone     = "#!/bin/sh\n# defenseclaw-managed-hook v0 (disabled tombstone)\nexit 0\n"
	)

	tests := []struct {
		name              string
		payload           string
		cursorScript      string
		cursorToken       bool
		removeClaudeToken bool
		strict            bool
		wantRequests      int
	}{
		{
			name:              "live Cursor bridge suppresses before missing Claude token",
			payload:           cursorPayload,
			cursorScript:      liveScript,
			cursorToken:       true,
			removeClaudeToken: true,
			strict:            true,
			wantRequests:      0,
		},
		{
			name:         "Cursor tombstone does not suppress",
			payload:      cursorPayload,
			cursorScript: tombstone,
			cursorToken:  true,
			wantRequests: 1,
		},
		{
			name:         "missing Cursor token does not suppress",
			payload:      cursorPayload,
			cursorScript: liveScript,
			wantRequests: 1,
		},
		{
			name:         "genuine Claude payload does not suppress",
			payload:      claudePayload,
			cursorScript: liveScript,
			cursorToken:  true,
			wantRequests: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := run(t, "claudecode", ok(`{"action":"allow"}`), func(opts *Options) {
				opts.Stdin = strings.NewReader(tc.payload)
				opts.StrictAvailability = tc.strict
				if tc.removeClaudeToken {
					if err := os.Remove(filepath.Join(opts.HookDir, ".token")); err != nil {
						t.Fatalf("remove Claude token: %v", err)
					}
				}
				if tc.cursorToken {
					if err := os.WriteFile(filepath.Join(opts.HookDir, ".hook-cursor.token"), []byte("cursor-token\n"), 0o600); err != nil {
						t.Fatalf("write Cursor token: %v", err)
					}
				}
				if err := os.WriteFile(filepath.Join(opts.HookDir, "cursor-hook.sh"), []byte(tc.cursorScript), 0o700); err != nil {
					t.Fatalf("write Cursor hook: %v", err)
				}
			})

			if result.code != 0 {
				t.Fatalf("Run code = %d, want 0; stderr=%q", result.code, result.stderr)
			}
			if result.rt.requests != tc.wantRequests {
				t.Fatalf("gateway requests = %d, want %d", result.rt.requests, tc.wantRequests)
			}
			if result.stdout != "" || result.stderr != "" {
				t.Fatalf("unexpected hook output: stdout=%q stderr=%q", result.stdout, result.stderr)
			}
		})
	}
}

// --- Allow / block decision golden tests (the agent-facing contract) ---

func TestDecisionGolden(t *testing.T) {
	tests := []struct {
		name       string
		connector  string
		respBody   string
		wantStdout string
		wantStderr string // substring; "" means stderr must be empty
		wantCode   int
	}{
		{
			name:      "claudecode allow",
			connector: "claudecode",
			respBody:  `{"action":"allow"}`,
			wantCode:  0,
		},
		{
			name:       "claudecode block with structured output exits 0",
			connector:  "claudecode",
			respBody:   `{"action":"block","reason":"matched: secret","claude_code_output":{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}}`,
			wantStdout: `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}` + "\n",
			wantCode:   0,
		},
		{
			name:       "claudecode block without output exits 2 with reason on stderr",
			connector:  "claudecode",
			respBody:   `{"action":"block","reason":"matched: secret"}`,
			wantStderr: "matched: secret",
			wantCode:   2,
		},
		{
			name:       "claudecode block without output or reason uses default",
			connector:  "claudecode",
			respBody:   `{"action":"block"}`,
			wantStderr: "Blocked by DefenseClaw Claude Code policy.",
			wantCode:   2,
		},
		{
			name:      "codex allow",
			connector: "codex",
			respBody:  `{"action":"allow"}`,
			wantCode:  0,
		},
		{
			name:       "codex block with output exits 0",
			connector:  "codex",
			respBody:   `{"action":"block","codex_output":{"hookSpecificOutput":{"permissionDecision":"deny"}}}`,
			wantStdout: `{"hookSpecificOutput":{"permissionDecision":"deny"}}` + "\n",
			wantCode:   0,
		},
		{
			name:       "codex block without output emits inline json exit 0",
			connector:  "codex",
			respBody:   `{"action":"block","reason":"matched: secret"}`,
			wantStdout: `{"decision":"block","reason":"matched: secret"}` + "\n",
			wantCode:   0,
		},
		{
			name:       "codex block without output or reason uses default exit 0",
			connector:  "codex",
			respBody:   `{"action":"block"}`,
			wantStdout: `{"decision":"block","reason":"Blocked by DefenseClaw Codex policy."}` + "\n",
			wantCode:   0,
		},
		{
			name:       "cursor allow echoes hook_output exit 0",
			connector:  "cursor",
			respBody:   `{"hook_output":{"continue":true,"permission":"allow"}}`,
			wantStdout: `{"continue":true,"permission":"allow"}` + "\n",
			wantCode:   0,
		},
		{
			name:       "cursor echoes hook_output exit 0",
			connector:  "cursor",
			respBody:   `{"hook_output":{"continue":true,"permission":"deny","user_message":"no"}}`,
			wantStdout: `{"continue":true,"permission":"deny","user_message":"no"}` + "\n",
			wantCode:   0,
		},
		{
			name:       "copilot allow echoes hook_output exit 0",
			connector:  "copilot",
			respBody:   `{"hook_output":{"permissionDecision":"allow"}}`,
			wantStdout: `{"permissionDecision":"allow"}` + "\n",
			wantCode:   0,
		},
		{
			name:       "copilot echoes hook_output exit 0",
			connector:  "copilot",
			respBody:   `{"hook_output":{"permissionDecision":"deny"}}`,
			wantStdout: `{"permissionDecision":"deny"}` + "\n",
			wantCode:   0,
		},
		{
			name:      "geminicli allow with no hook_output exit 0",
			connector: "geminicli",
			respBody:  `{"action":"allow"}`,
			wantCode:  0,
		},
		{
			name:       "geminicli echoes hook_output deny exit 0",
			connector:  "geminicli",
			respBody:   `{"action":"block","hook_output":{"decision":"deny","reason":"no"}}`,
			wantStdout: `{"decision":"deny","reason":"no"}` + "\n",
			wantCode:   0,
		},
		{
			name:       "openhands deny in hook_output exits 2",
			connector:  "openhands",
			respBody:   `{"hook_output":{"decision":"deny","reason":"no"}}`,
			wantStdout: `{"decision":"deny","reason":"no"}` + "\n",
			wantCode:   2,
		},
		{
			name:       "openhands allow in hook_output exits 0",
			connector:  "openhands",
			respBody:   `{"hook_output":{"decision":"allow"}}`,
			wantStdout: `{"decision":"allow"}` + "\n",
			wantCode:   0,
		},
		{
			name:       "windsurf block writes stderr exit 2 no stdout",
			connector:  "windsurf",
			respBody:   `{"action":"block","reason":"nope"}`,
			wantStderr: "nope",
			wantCode:   2,
		},
		{
			name:      "windsurf allow exit 0",
			connector: "windsurf",
			respBody:  `{"action":"allow"}`,
			wantCode:  0,
		},
		{
			name:      "hermes allow with no hook_output exit 0",
			connector: "hermes",
			respBody:  `{"action":"allow"}`,
			wantCode:  0,
		},
		{
			name:       "hermes block echoes hook_output exit 0",
			connector:  "hermes",
			respBody:   `{"action":"block","hook_output":{"action":"block","message":"no"}}`,
			wantStdout: `{"action":"block","message":"no"}` + "\n",
			wantCode:   0,
		},
		{
			name:      "antigravity allow with no hook_output exit 0",
			connector: "antigravity",
			respBody:  `{"action":"allow"}`,
			wantCode:  0,
		},
		{
			name:       "antigravity echoes hook_output deny exit 0",
			connector:  "antigravity",
			respBody:   `{"hook_output":{"decision":"deny","reason":"no"}}`,
			wantStdout: `{"decision":"deny","reason":"no"}` + "\n",
			wantCode:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(t, tt.connector, ok(tt.respBody), nil)
			if r.code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr=%q)", r.code, tt.wantCode, r.stderr)
			}
			if r.stdout != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", r.stdout, tt.wantStdout)
			}
			if tt.wantStderr == "" {
				if r.stderr != "" {
					t.Errorf("stderr = %q, want empty", r.stderr)
				}
			} else if !strings.Contains(r.stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want substring %q", r.stderr, tt.wantStderr)
			}
		})
	}
}

// TestCodexUserPromptSubmitBlockSchema confirms the contract the .sh hook calls
// out explicitly: on a UserPromptSubmit block, Codex must receive the gateway's
// structured codex_output (which carries permissionDecision="deny") on stdout
// with exit 0 — never exit 2, which newer Codex builds treat as "hook failed"
// (fail-open) rather than "hook blocked". When the gateway omits codex_output,
// the responder synthesizes the minimal {"decision":"block"} JSON, still exit 0.
func TestCodexUserPromptSubmitBlockSchema(t *testing.T) {
	t.Run("structured codex_output passthrough exit 0", func(t *testing.T) {
		body := `{"action":"block","reason":"matched: secret","codex_output":{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","permissionDecision":"deny","permissionDecisionReason":"matched: secret"}}}`
		r := run(t, "codex", ok(body), func(o *Options) { o.Event = "UserPromptSubmit" })
		want := `{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","permissionDecision":"deny","permissionDecisionReason":"matched: secret"}}` + "\n"
		if r.code != 0 {
			t.Fatalf("exit code = %d, want 0 (exit 2 fails open on UserPromptSubmit)", r.code)
		}
		if r.stdout != want {
			t.Errorf("stdout = %q, want %q", r.stdout, want)
		}
		if r.stderr != "" {
			t.Errorf("stderr = %q, want empty (mixing stdout+stderr is a protocol violation)", r.stderr)
		}
	})

	t.Run("no codex_output falls back to inline decision exit 0", func(t *testing.T) {
		r := run(t, "codex", ok(`{"action":"block","reason":"matched: secret"}`), func(o *Options) { o.Event = "UserPromptSubmit" })
		if r.code != 0 {
			t.Fatalf("exit code = %d, want 0", r.code)
		}
		if r.stdout != `{"decision":"block","reason":"matched: secret"}`+"\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
	})
}

// --- Oversized payload: fail-open allows, fail-closed emits per-connector ---

func TestOversizedPayload(t *testing.T) {
	big := strings.Repeat("a", 64)
	t.Run("fail open allows, never calls gateway", func(t *testing.T) {
		rt := ok(`{"action":"allow"}`)
		r := run(t, "claudecode", rt, func(o *Options) {
			o.MaxBody = 8
			o.Stdin = strings.NewReader(big)
		})
		if r.code != 0 {
			t.Fatalf("code = %d, want 0", r.code)
		}
		if rt.requests != 0 {
			t.Fatalf("gateway called %d times on oversized payload, want 0", rt.requests)
		}
	})

	cases := map[string]struct {
		stdout string
		code   int
	}{
		"claudecode": {stdout: `{"decision":"block","reason":"DefenseClaw hook payload too large"}` + "\n", code: 2},
		"codex":      {stdout: `{"decision":"block","reason":"DefenseClaw hook payload too large"}` + "\n", code: 2},
		"openhands":  {stdout: `{"decision":"deny","reason":"DefenseClaw hook payload too large"}` + "\n", code: 2},
		"cursor":     {stdout: cursorDeny("DefenseClaw hook payload too large") + "\n", code: 2},
		"copilot":    {stdout: "", code: 2},
		"geminicli":  {stdout: "", code: 2},
		"hermes":     {stdout: "", code: 2},
		"windsurf":   {stdout: "", code: 2},
	}
	for connector, want := range cases {
		t.Run("fail closed "+connector, func(t *testing.T) {
			r := run(t, connector, ok(`{"action":"allow"}`), func(o *Options) {
				o.FailMode = "closed"
				o.MaxBody = 8
				o.Stdin = strings.NewReader(big)
			})
			if r.code != want.code {
				t.Errorf("code = %d, want %d", r.code, want.code)
			}
			if r.stdout != want.stdout {
				t.Errorf("stdout = %q, want %q", r.stdout, want.stdout)
			}
		})
	}
}

// --- Transport failure (unreachable + 5xx): fail-open by default ---

func TestUnreachable(t *testing.T) {
	t.Run("default fail open", func(t *testing.T) {
		r := run(t, "claudecode", &stubRT{err: errors.New("dial tcp: refused")}, nil)
		if r.code != 0 {
			t.Fatalf("code = %d, want 0 (DefenseClaw outage must not brick agent)", r.code)
		}
		if !strings.Contains(r.stderr, "allowing claude-code tool") {
			t.Errorf("stderr = %q, want allow notice", r.stderr)
		}
	})

	t.Run("strict availability fails closed", func(t *testing.T) {
		r := run(t, "openhands", &stubRT{err: errors.New("refused")}, func(o *Options) {
			o.StrictAvailability = true
		})
		if r.code != 2 {
			t.Fatalf("code = %d, want 2", r.code)
		}
		if r.stdout != `{"decision":"deny","reason":"DefenseClaw hook failed closed"}`+"\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
	})

	t.Run("5xx treated as transport", func(t *testing.T) {
		r := run(t, "codex", &stubRT{status: 503, body: "boom"}, func(o *Options) {
			o.StrictAvailability = true
		})
		if r.code != 2 {
			t.Fatalf("code = %d, want 2", r.code)
		}
	})
}

// --- Response-layer failure (4xx / bad JSON): honors FAIL_MODE ---

func TestResponseFailure(t *testing.T) {
	t.Run("4xx fail open allows", func(t *testing.T) {
		r := run(t, "claudecode", &stubRT{status: 401, body: "unauthorized"}, nil)
		if r.code != 0 {
			t.Fatalf("code = %d, want 0", r.code)
		}
	})

	t.Run("4xx fail closed blocks per connector", func(t *testing.T) {
		r := run(t, "cursor", &stubRT{status: 401, body: "unauthorized"}, func(o *Options) {
			o.FailMode = "closed"
		})
		// cursor's response-closed path emits the deny body but exits 0.
		if r.code != 0 {
			t.Fatalf("code = %d, want 0", r.code)
		}
		if r.stdout != cursorDeny("DefenseClaw hook failed closed")+"\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
		if !strings.Contains(r.stderr, "possible token drift") {
			t.Errorf("stderr should explain possible token drift, got %q", r.stderr)
		}
		if !strings.Contains(r.stderr, "defenseclaw doctor --fix") {
			t.Errorf("stderr should suggest doctor --fix, got %q", r.stderr)
		}
	})

	t.Run("invalid JSON body is a response failure", func(t *testing.T) {
		r := run(t, "codex", ok("this is not json"), func(o *Options) {
			o.FailMode = "closed"
		})
		if r.code != 2 {
			t.Fatalf("code = %d, want 2", r.code)
		}
		if !strings.Contains(r.stderr, "invalid JSON response") {
			t.Errorf("stderr = %q, want invalid JSON", r.stderr)
		}
	})
}

// --- Missing token ---

func TestMissingToken(t *testing.T) {
	noToken := func(o *Options) {
		o.Token = ""
		o.HookDir = filepath.Join(o.Home, "empty") // no .token here
	}

	t.Run("default allows without calling gateway", func(t *testing.T) {
		rt := ok(`{"action":"allow"}`)
		r := run(t, "claudecode", rt, noToken)
		if r.code != 0 {
			t.Fatalf("code = %d, want 0", r.code)
		}
		if rt.requests != 0 {
			t.Fatalf("gateway called %d times, want 0", rt.requests)
		}
	})

	t.Run("strict availability blocks", func(t *testing.T) {
		r := run(t, "claudecode", ok(`{"action":"allow"}`), func(o *Options) {
			noToken(o)
			o.StrictAvailability = true
		})
		if r.code != 2 {
			t.Fatalf("code = %d, want 2", r.code)
		}
		if !strings.Contains(r.stderr, "missing gateway token") {
			t.Errorf("stderr = %q", r.stderr)
		}
	})
}

// --- Request wiring: endpoint, method, auth, trace, body ---

func TestRequestWiring(t *testing.T) {
	rt := ok(`{"action":"allow"}`)
	run(t, "claudecode", rt, func(o *Options) {
		o.TraceParent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
		o.TraceState = "vendor=value"
	})
	if rt.gotReq == nil {
		t.Fatal("no request captured")
	}
	if rt.gotReq.Method != http.MethodPost {
		t.Errorf("method = %s, want POST", rt.gotReq.Method)
	}
	if got := rt.gotReq.URL.String(); got != "http://127.0.0.1:8787/api/v1/claude-code/hook" {
		t.Errorf("url = %s", got)
	}
	if got := rt.gotReq.Header.Get("Authorization"); got != "Bearer tkn" {
		t.Errorf("authorization = %q, want Bearer tkn", got)
	}
	if got := rt.gotReq.Header.Get("X-DefenseClaw-Client"); got != "claude-code-hook/1.0" {
		t.Errorf("client header = %q", got)
	}
	if got := rt.gotReq.Header.Get("traceparent"); got == "" {
		t.Error("valid traceparent not forwarded")
	}
	if got := rt.gotReq.Header.Get("tracestate"); got != "vendor=value" {
		t.Errorf("tracestate = %q", got)
	}
	if string(rt.gotBody) != `{"event":"x"}` {
		t.Errorf("body = %q", string(rt.gotBody))
	}
}

func TestNativeConnectorEndpointMatrix(t *testing.T) {
	tests := map[string]string{
		"codex":       "/api/v1/codex/hook",
		"claudecode":  "/api/v1/claude-code/hook",
		"cursor":      "/api/v1/cursor/hook",
		"windsurf":    "/api/v1/windsurf/hook",
		"geminicli":   "/api/v1/geminicli/hook",
		"copilot":     "/api/v1/copilot/hook",
		"antigravity": "/api/v1/antigravity/hook",
		"hermes":      "/api/v1/hermes/hook",
	}
	for connector, endpoint := range tests {
		t.Run(connector, func(t *testing.T) {
			rt := ok(`{"action":"allow"}`)
			r := run(t, connector, rt, nil)
			if r.code != 0 {
				t.Fatalf("allow exit = %d, want 0", r.code)
			}
			if rt.gotReq == nil {
				t.Fatal("no request captured")
			}
			if got := rt.gotReq.URL.Path; got != endpoint {
				t.Errorf("endpoint = %q, want %q", got, endpoint)
			}
			if got := rt.gotReq.Header.Get("Authorization"); got != "Bearer tkn" {
				t.Errorf("authorization = %q", got)
			}
			if got := string(rt.gotBody); got != `{"event":"x"}` {
				t.Errorf("JSON stdin body = %q", got)
			}
		})
	}
}

func TestCodexNotifyRequestWiring(t *testing.T) {
	home := t.TempDir()
	hookDir := filepath.Join(home, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".token"),
		[]byte("DEFENSECLAW_GATEWAY_TOKEN=\"notify-token\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rt := ok(`{"status":"ok"}`)
	payload := []byte(`{"type":"agent-turn-complete","last-assistant-message":"done"}`)
	code := RunCodexNotify(context.Background(), Options{
		APIAddr:    "127.0.0.1:8787",
		Home:       home,
		HookDir:    hookDir,
		HTTPClient: &http.Client{Transport: rt},
		TraceParent: "00-0af7651916cd43dd8448eb211c80319c-" +
			"b7ad6b7169203331-01",
	}, payload)
	if code != 0 {
		t.Fatalf("exit code = %d, want best-effort 0", code)
	}
	if rt.gotReq == nil {
		t.Fatal("no request captured")
	}
	if got := rt.gotReq.URL.String(); got != "http://127.0.0.1:8787/api/v1/codex/notify" {
		t.Errorf("url = %s", got)
	}
	if got := rt.gotReq.Header.Get("Authorization"); got != "Bearer notify-token" {
		t.Errorf("authorization = %q", got)
	}
	if got := rt.gotReq.Header.Get("X-DefenseClaw-Client"); got != "codex-notify/1.0" {
		t.Errorf("client header = %q", got)
	}
	if got := rt.gotReq.Header.Get("x-defenseclaw-source"); got != "codex-notify" {
		t.Errorf("source header = %q", got)
	}
	if !bytes.Equal(rt.gotBody, payload) {
		t.Errorf("body = %q, want %q", rt.gotBody, payload)
	}

	// Notify remains telemetry-only: a gateway failure must never fail the
	// Codex process or turn a completed turn into an agent error.
	failing := &stubRT{err: errors.New("offline")}
	if got := RunCodexNotify(context.Background(), Options{
		APIAddr: "127.0.0.1:8787", Home: home, HookDir: hookDir,
		HTTPClient: &http.Client{Transport: failing},
	}, payload); got != 0 {
		t.Fatalf("transport failure exit = %d, want 0", got)
	}
}

func TestCodexNotifyPrefersScopedTokenSidecar(t *testing.T) {
	home := t.TempDir()
	hookDir := filepath.Join(home, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".token"),
		[]byte("DEFENSECLAW_GATEWAY_TOKEN=\"generic-token\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".hook-codex.token"),
		[]byte("scoped-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rt := ok(`{"status":"ok"}`)
	code := RunCodexNotify(context.Background(), Options{
		APIAddr:    "127.0.0.1:8787",
		Home:       home,
		HookDir:    hookDir,
		Token:      "environment-token",
		HTTPClient: &http.Client{Transport: rt},
	}, []byte(`{"type":"agent-turn-complete"}`))
	if code != 0 {
		t.Fatalf("exit code = %d, want best-effort 0", code)
	}
	if rt.gotReq == nil {
		t.Fatal("no request captured")
	}
	if got := rt.gotReq.Header.Get("Authorization"); got != "Bearer scoped-token" {
		t.Errorf("authorization = %q, want scoped token", got)
	}
}

func TestEnvTokenTakesPrecedence(t *testing.T) {
	rt := ok(`{"action":"allow"}`)
	run(t, "codex", rt, func(o *Options) { o.Token = "env-wins" })
	if got := rt.gotReq.Header.Get("Authorization"); got != "Bearer env-wins" {
		t.Errorf("authorization = %q, want env token to win over .token file", got)
	}
}

func TestInvalidTraceparentDropped(t *testing.T) {
	rt := ok(`{"action":"allow"}`)
	run(t, "codex", rt, func(o *Options) { o.TraceParent = "not-a-valid-traceparent" })
	if got := rt.gotReq.Header.Get("traceparent"); got != "" {
		t.Errorf("invalid traceparent forwarded: %q", got)
	}
}

// --- DEFENSECLAW_HOME guard ---

func TestDisabledHomeIsNoop(t *testing.T) {
	rt := ok(`{"action":"block","reason":"x"}`)
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".disabled"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := Run(context.Background(), Options{
		Connector: "claudecode", APIAddr: "127.0.0.1:1", Home: home,
		HookDir: filepath.Join(home, "hooks"), Token: "t",
		Stdin: strings.NewReader("{}"), Stdout: &out, Stderr: &errb,
		HTTPClient: &http.Client{Transport: rt},
	})
	if code != 0 {
		t.Fatalf("code = %d, want 0 when .disabled present", code)
	}
	if rt.requests != 0 {
		t.Fatalf("gateway called %d times despite .disabled", rt.requests)
	}
}

func TestUnknownConnector(t *testing.T) {
	var out, errb bytes.Buffer
	home := t.TempDir()
	code := Run(context.Background(), Options{
		Connector: "nope", Home: home, HookDir: home, Token: "t",
		Stdin: strings.NewReader("{}"), Stdout: &out, Stderr: &errb,
	})
	if code != 2 {
		t.Fatalf("code = %d, want 2 for unknown connector", code)
	}
}

func TestReadTokenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".token")
	if err := os.WriteFile(path, []byte(`DEFENSECLAW_GATEWAY_TOKEN="abc123"`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readTokenFile(path, false); got != "abc123" {
		t.Errorf("token = %q, want abc123", got)
	}
	if err := os.WriteFile(path, []byte(" opaque-token \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readTokenFile(path, true); got != " opaque-token " {
		t.Errorf("raw token = %q, want opaque surrounding spaces preserved", got)
	}
}

func TestSupportedConnectorsSorted(t *testing.T) {
	got := SupportedConnectors()
	want := []string{"antigravity", "claudecode", "codex", "copilot", "cursor", "geminicli", "hermes", "openhands", "windsurf"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// TestDefaultHTTPClientDoesNotFollowRedirects pins the no-follow-redirect
// contract: the native hook must behave like `curl` without `-L` (the .sh
// hooks never passed -L). A gateway hook endpoint never legitimately
// redirects, so following a 3xx to a different host/port would needlessly
// widen the SSRF surface and risk forwarding the gateway bearer token to an
// unintended target. The redirect target sets a sentinel header so a
// regression (client follows the redirect) is detectable.
func TestDefaultHTTPClientDoesNotFollowRedirects(t *testing.T) {
	followed := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	resp, err := defaultHTTPClient().Get(redirector.URL)
	if err != nil {
		t.Fatalf("Get returned error (redirect should not be followed, not error): %v", err)
	}
	defer resp.Body.Close()

	if followed {
		t.Fatal("client followed redirect to a second host; hook must not follow redirects")
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 (redirect surfaced, not followed)", resp.StatusCode)
	}
}
