// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The actor kit runs in Linux actor images only (kit.Config refuses other systems); its tests render and
// resolve paths for Linux.
//go:build linux

package kit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func init() { requireRootOwned = false }

func testConfig(url string) Config {
	c := DefaultConfig()
	c.GatewayURL = url
	c.CAFiles = nil
	c.MaxTimeMS, c.RetryMaxTimeMS, c.ConnectTimeoutMS = 2000, 2000, 500
	c.KitVersion = "test"
	c.HookContracts = map[string]string{"codex": "codex-hooks-v4", "claudecode": "claudecode-hooks-v1"}
	return c
}

type answer struct {
	status int
	body   string
}

func run(t *testing.T, connector, event, payload string, a *answer, failMode string) (string, string, int, Request) {
	t.Helper()
	cfg := testConfig("https://defenseclaw-actor.defenseclaw-system.svc")
	cfg.FailMode = failMode
	var got Request
	var out, errb bytes.Buffer
	code := RunHook(context.Background(), HookOptions{
		Connector: connector, Event: event, Config: cfg,
		Stdin: strings.NewReader(payload), Stdout: &out, Stderr: &errb,
		Getenv: func(string) string { return "" },
		Send: func(_ context.Context, r Request) (Response, string, error) {
			got = r
			if a == nil {
				return Response{}, "", ErrUnreachable
			}
			return Response{Status: a.status, Body: []byte(a.body)}, "", nil
		},
	})
	return out.String(), errb.String(), code, got
}

const ccPre = `{"session_id":"s1","hook_event_name":"PreToolUse","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"echo hi"}}`

// The verdict formats are the host hooks' (hookexec): these pin that the kit
// hands every answer to that code unchanged.
func TestHookAnswersInConnectorFormat(t *testing.T) {
	for _, tc := range []struct {
		name, connector, event, payload string
		a                               *answer
		failMode                        string
		wantOut, wantErr                string
		wantCode                        int
	}{
		{"cc allow", "claudecode", "", ccPre, &answer{200, `{"action":"allow"}`}, "closed", "", "", 0},
		{"cc block native", "claudecode", "", ccPre,
			&answer{200, `{"action":"block","reason":"BLOCKME is not allowed","claude_code_output":{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"BLOCKME is not allowed"}}}`},
			"closed", `"permissionDecision":"deny"`, "", 0},
		{"cc block plain", "claudecode", "", ccPre, &answer{200, `{"action":"block","reason":"no"}`}, "closed", "", "no", 2},
		{"cc not json", "claudecode", "", ccPre, &answer{200, `nope`}, "open", "", "", 2},
		{"cc refused 403", "claudecode", "", ccPre, &answer{403, `{}`}, "open", "", "", 2},
		{"cc outage closed", "claudecode", "", ccPre, nil, "closed", "", "", 2},
		{"cc outage open", "claudecode", "", ccPre, nil, "open", "", "", 0},
		{"cc 503 closed", "claudecode", "", ccPre, &answer{503, `{}`}, "closed", "", "", 2},
		{"codex block pre", "codex", "PreToolUse", `{"hook_event_name":"PreToolUse","cwd":"/tmp","tool_name":"shell","tool_input":{"command":["rm","-rf","/"]}}`,
			&answer{200, `{"action":"block","reason":"denied by policy"}`}, "closed", "denied by policy", "", 0},
		{"codex allow", "codex", "PreToolUse", `{"hook_event_name":"PreToolUse","cwd":"/tmp"}`, &answer{200, `{"action":"allow"}`}, "closed", "", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, code, _ := run(t, tc.connector, tc.event, tc.payload, tc.a, tc.failMode)
			if code != tc.wantCode {
				t.Fatalf("exit %d, want %d (stdout %q stderr %q)", code, tc.wantCode, out, errOut)
			}
			if tc.wantOut != "" && !strings.Contains(out, tc.wantOut) {
				t.Fatalf("stdout %q lacks %q", out, tc.wantOut)
			}
			if tc.wantOut == "" && tc.wantCode == 0 && strings.Contains(out, "deny") {
				t.Fatalf("unexpected deny on stdout: %q", out)
			}
			if tc.wantErr != "" && !strings.Contains(errOut, tc.wantErr) {
				t.Fatalf("stderr %q lacks %q", errOut, tc.wantErr)
			}
		})
	}
}

func TestHookEnvelopeAndHeaders(t *testing.T) {
	_, _, _, r := run(t, "codex", "PreToolUse", `{"hook_event_name":"PreToolUse","cwd":"/tmp"}`, &answer{200, `{"action":"allow"}`}, "closed")
	if r.Path != "/api/v1/substrate/hook/codex" {
		t.Fatalf("path %q", r.Path)
	}
	if r.Header["X-DefenseClaw-Hook-Event"] != "PreToolUse" || r.Header["X-DefenseClaw-Hook-Contract"] != "codex-hooks-v4" ||
		r.Header["X-DefenseClaw-Actor-Mode"] != ModeInteract {
		t.Fatalf("headers %v", r.Header)
	}
	var env HookEnvelope
	if err := json.Unmarshal(r.Body, &env); err != nil {
		t.Fatal(err)
	}
	if env.V != EnvelopeVersion || env.Connector != "codex" || env.Event != "PreToolUse" || env.HookContract != "codex-hooks-v4" ||
		string(env.Payload) != `{"hook_event_name":"PreToolUse","cwd":"/tmp"}` {
		t.Fatalf("envelope %+v", env)
	}
}

func TestOversizedAndInvalidPayloadsCloseInEveryMode(t *testing.T) {
	big := `{"hook_event_name":"PreToolUse","x":"` + strings.Repeat("a", int(maxPayloadBytes)) + `"}`
	called := false
	cfg := testConfig("https://gw")
	cfg.FailMode = "open"
	var out, errb bytes.Buffer
	code := RunHook(context.Background(), HookOptions{Connector: "claudecode", Config: cfg, Stdin: strings.NewReader(big),
		Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" },
		Send: func(context.Context, Request) (Response, string, error) { called = true; return Response{}, "", nil }})
	if code != 2 || called {
		t.Fatalf("oversized: exit %d sent %v", code, called)
	}
	_, _, code, _ = run(t, "claudecode", "", `{not json`, &answer{200, `{"action":"allow"}`}, "open")
	if code != 2 {
		t.Fatalf("invalid payload: exit %d", code)
	}
}

func TestUnattendedFailsClosed(t *testing.T) {
	cfg := testConfig("https://gw")
	cfg.FailMode = "open"
	var out, errb bytes.Buffer
	code := RunHook(context.Background(), HookOptions{Connector: "claudecode", Config: cfg, Stdin: strings.NewReader(ccPre),
		Stdout: &out, Stderr: &errb, Getenv: func(k string) string {
			if k == ModeEnv {
				return ModeUnattend
			}
			return ""
		},
		Send: func(context.Context, Request) (Response, string, error) { return Response{}, "", ErrUnreachable }})
	if code != 2 {
		t.Fatalf("unattended outage: exit %d, want 2", code)
	}
	// The gateway naming the run unattended closes it too.
	code = RunHook(context.Background(), HookOptions{Connector: "claudecode", Config: cfg, Stdin: strings.NewReader(ccPre),
		Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" },
		Send: func(context.Context, Request) (Response, string, error) {
			return Response{Status: 503, Mode: ModeUnattend, FailMode: "open"}, "", nil
		}})
	if code != 2 {
		t.Fatalf("gateway-unattended outage: exit %d, want 2", code)
	}
	if Mode(func(string) string { return "interactive" }) != ModeInteract || Mode(func(string) string { return "" }) != ModeInteract {
		t.Fatal("the environment must not loosen the mode")
	}
}

func TestConfigErrorRefusesClosed(t *testing.T) {
	var out, errb bytes.Buffer
	code := RunHook(context.Background(), HookOptions{Connector: "claudecode", ConfigErr: os.ErrNotExist,
		Stdin: strings.NewReader(ccPre), Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" }})
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
}

func TestConfigValidation(t *testing.T) {
	good := DefaultConfig()
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mut := range []func(*Config){
		func(c *Config) { c.GatewayURL = "ftp://x" },
		func(c *Config) { c.GatewayURL = "https://u:p@x" },
		func(c *Config) { c.FailMode = "maybe" },
		func(c *Config) { c.MaxTimeMS = 20000; c.RetryMaxTimeMS = 20000 },
		func(c *Config) { c.MaxAttachBytes = 2 << 20 },
	} {
		c := DefaultConfig()
		mut(&c)
		if c.Validate() == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "k.json")
	os.WriteFile(p, []byte(`{"gateway_url":"https://gw","unknown":1}`), 0o644)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("unknown key accepted")
	}
	requireRootOwned = true
	defer func() { requireRootOwned = false }()
	os.WriteFile(p, []byte(`{}`), 0o644)
	if os.Getuid() != 0 {
		if _, err := LoadConfig(p); err == nil || !strings.Contains(err.Error(), "root") {
			t.Fatalf("a user-owned config was accepted: %v", err)
		}
	}
}

func TestTransportPlaceholderRetryAndProxy(t *testing.T) {
	var mu sync.Mutex
	var keys []string
	var actorHeaders []string
	n := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		n++
		keys = append(keys, r.Header.Get("X-DefenseClaw-Hook-Idempotency-Key"))
		actorHeaders = append(actorHeaders, strings.Join(r.Header.Values(PlaceholderHeader), ","))
		if n == 1 {
			w.WriteHeader(503)
			return
		}
		io.WriteString(w, `{"action":"allow"}`)
	}))
	defer srv.Close()
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	cfg := testConfig(srv.URL)
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tr.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	resp, err := tr.Post(context.Background(), Request{Path: "/api/v1/substrate/hook/claudecode",
		Header: map[string]string{PlaceholderHeader: "forged", "Authorization": "Bearer x"}, Body: []byte(`{}`)})
	if err != nil || resp.Status != 200 || resp.Attempts != 2 {
		t.Fatalf("resp %+v err %v", resp, err)
	}
	if len(keys) != 2 || keys[0] == "" || keys[0] != keys[1] {
		t.Fatalf("idempotency keys %v", keys)
	}
	for _, h := range actorHeaders {
		if h != PlaceholderValue {
			t.Fatalf("actor header %q, want only the placeholder", h)
		}
	}
	srv.Close()
	if _, err := tr.Post(context.Background(), Request{Path: "/x", Body: []byte(`{}`)}); err == nil || !strings.Contains(err.Error(), ErrUnreachable.Error()) {
		t.Fatalf("closed server: %v", err)
	}
	if _, err := tr.Post(context.Background(), Request{Path: "../x"}); err == nil {
		t.Fatal("relative path accepted")
	}
}

// GAP-0047: there is nothing for the agent to stand in for. The hook opens
// its own connection per call; the kit listens on nothing.
func TestHookPostsOnItsOwnConnection(t *testing.T) {
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if r.Header.Get(PlaceholderHeader) != PlaceholderValue {
			t.Errorf("placeholder %q", r.Header.Get(PlaceholderHeader))
		}
		w.Header().Set(FailModeHeader, "closed")
		io.WriteString(w, `{"action":"allow"}`)
	}))
	defer srv.Close()
	t.Setenv("TMPDIR", t.TempDir())
	var out, errb bytes.Buffer
	code := RunHook(context.Background(), HookOptions{Connector: "claudecode", Config: testConfig(srv.URL),
		Stdin: strings.NewReader(ccPre), Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" }})
	if code != 0 || n != 1 {
		t.Fatalf("code %d posts %d stderr %q", code, n, errb.String())
	}
	if entries, _ := os.ReadDir(os.Getenv("TMPDIR")); len(entries) != 0 {
		t.Fatalf("the hook left %d entries in TMPDIR (a socket?)", len(entries))
	}
}

func TestGatewayNamesTheOutageMode(t *testing.T) {
	for _, tc := range []struct {
		cfg, gw, env, want string
	}{
		{"closed", "", "", "closed"}, {"closed", "open", "", "open"}, {"open", "closed", "", "closed"},
		{"open", "open", ModeUnattend, "closed"}, {"open", "bogus", "", "open"},
	} {
		if got := outageMode(tc.cfg, Response{FailMode: tc.gw}, tc.env); got != tc.want {
			t.Errorf("%+v: %s", tc, got)
		}
	}
	if got := outageMode("open", Response{Mode: ModeUnattend, FailMode: "open"}, ""); got != "closed" {
		t.Errorf("gateway-unattended run: %s", got)
	}
}

func TestHookPostIsThePluginTransport(t *testing.T) {
	cfg := testConfig("https://gw")
	cfg.HookContracts["opencode"] = "opencode-v1"
	var got Request
	var out, errb bytes.Buffer
	in := `{"path":"/api/v1/opencode/hook","headers":{"Authorization":"Bearer leaked","X-DefenseClaw-Client":"opencode-plugin/1.0"},"body":"{\"event\":\"tool.execute.before\",\"tool\":\"bash\"}"}`
	code := RunHookPost(context.Background(), cfg, strings.NewReader(in), &out, &errb,
		func(_ context.Context, r Request) (Response, string, error) {
			got = r
			return Response{Status: 200, Body: []byte(`{"action":"block","hook_output":{"decision":"deny"}}`)}, "", nil
		})
	if code != 0 || got.Path != HookPathPrefix+"opencode" || got.Header["Authorization"] != "" || got.Header["X-DefenseClaw-Client"] != "opencode-plugin/1.0" {
		t.Fatalf("code %d request %+v stderr %q", code, got, errb.String())
	}
	var env HookEnvelope
	if json.Unmarshal(got.Body, &env) != nil || env.V != EnvelopeVersion || env.Connector != "opencode" || env.Event != "tool.execute.before" || env.HookContract != "opencode-v1" {
		t.Fatalf("envelope %s", got.Body)
	}
	var ans struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	if json.Unmarshal(out.Bytes(), &ans) != nil || ans.Status != 200 || !strings.Contains(ans.Body, `"deny"`) {
		t.Fatalf("answer %q", out.String())
	}
	code = RunHookPost(context.Background(), cfg, strings.NewReader(in), &out, &errb,
		func(context.Context, Request) (Response, string, error) { return Response{}, "", ErrUnreachable })
	if code == 0 {
		t.Fatal("an outage must be the plugin's failure")
	}
	for _, bad := range []string{`{"path":"/api/v1/claude-code/hook","body":"{}"}`, `{"path":"/api/v1/opencode/hook","body":"not json"}`, `nope`} {
		if RunHookPost(context.Background(), cfg, strings.NewReader(bad), &out, &errb, nil) != 2 {
			t.Fatalf("accepted %s", bad)
		}
	}
}
