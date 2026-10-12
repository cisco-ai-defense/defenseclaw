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

//go:build unix

package sandboxrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// relayTestServer serves handler on a unix socket in a fresh 0700
// directory and returns the socket path.
func relayTestServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "srt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "hook.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return path
}

func newTestClient(t *testing.T, path string) *UnixClient {
	t.Helper()
	c, err := NewClient(ClientOptions{SocketPath: path, TrustedOwners: []int{os.Getuid()}})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestCheckSocketRefusesUntrustedSockets(t *testing.T) {
	path := relayTestServer(t, http.NotFoundHandler())
	if err := CheckSocket(path, []int{os.Getuid()}); err != nil {
		t.Fatalf("trusted socket refused: %v", err)
	}
	if os.Getuid() != 0 {
		// A socket owned by the caller (a user-owned impostor) when only
		// root and the service account are trusted.
		if _, err := NewClient(ClientOptions{SocketPath: path, TrustedOwners: []int{os.Getuid() + 1}}); !errors.Is(err, ErrSocketUntrusted) {
			t.Fatalf("user-owned socket: err = %v", err)
		}
	}
	dir := filepath.Dir(path)
	for _, mode := range []os.FileMode{0o777, 0o770, 0o722} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := CheckSocket(path, []int{os.Getuid()}); !errors.Is(err, ErrSocketUntrusted) {
			t.Fatalf("directory mode %o: err = %v", mode, err)
		}
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckSocket(filepath.Join(link, "hook.sock"), []int{os.Getuid()}); !errors.Is(err, ErrSocketUntrusted) {
		t.Fatalf("symlinked directory: err = %v", err)
	}
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckSocket(plain, []int{os.Getuid()}); !errors.Is(err, ErrSocketUntrusted) {
		t.Fatalf("regular file: err = %v", err)
	}
	for _, bad := range []string{"", "relative/hook.sock", dir + "/../x/hook.sock"} {
		if err := CheckSocket(bad, nil); !errors.Is(err, ErrSocketUntrusted) {
			t.Fatalf("path %q: err = %v", bad, err)
		}
	}
}

// The socket check runs on every redial, not only at construction.
func TestRelayChecksTheSocketOnRedial(t *testing.T) {
	path := relayTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, `{"v":1}`)
	}))
	c := newTestClient(t, path)
	if _, err := c.Settings(context.Background()); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(path), 0o700) })
	if _, err := c.Settings(context.Background()); !errors.Is(err, ErrSocketUntrusted) {
		t.Fatalf("redial after the directory became writable: err = %v", err)
	}
}

func TestRelayForwardsOnlyTheAllowlist(t *testing.T) {
	body := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`)
	decision := HookDecision{
		V: WireVersion, Event: "PreToolUse", Tool: "Bash", ToolUseID: "toolu_1", SessionID: "s-1",
		CallRef: "ref-1", ResultStatus: "done", Action: "block", WouldBlock: true, Severity: "HIGH",
		Reason: "rule r1", ModelError: "rate_limit", ModelStatus: 429,
	}
	var got *http.Request
	var gotBody []byte
	path := relayTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Trailer", DecisionTrailer)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(ProfileHeader, "contractors")
		w.Header().Set(GenerationHeader, "7")
		w.Header().Set("X-Defenseclaw-Request-Id", "minted")
		_, _ = io.WriteString(w, `{"decision":"block"}`)
		raw, _ := json.Marshal(decision)
		w.Header().Set(DecisionTrailer, string(raw))
	}))
	c := newTestClient(t, path)

	in := http.Header{}
	for _, name := range ForwardHeaders {
		in.Set(name, "v-"+name)
	}
	for _, name := range DroppedHeaders {
		in.Set(name, "forged")
	}
	in.Set(FilesHeader, "forged")
	in.Set(RegistrationHeader, "reg-forged")
	in.Set("X-Defenseclaw-Sandbox-Anything", "forged")
	resp, err := c.Relay(context.Background(), RelayCall{
		Class: RouteHook, Target: "claudecode", Registration: "reg-own", Header: in, Body: body,
	})
	if err != nil {
		t.Fatalf("Relay: %v", err)
	}
	if got.URL.Path != PathHookPrefix+"claudecode" || got.Method != http.MethodPost {
		t.Fatalf("relayed to %s %s", got.Method, got.URL.Path)
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("body changed: %q", gotBody)
	}
	for _, name := range ForwardHeaders {
		if got.Header.Get(name) != "v-"+name {
			t.Fatalf("allowlisted %s = %q", name, got.Header.Get(name))
		}
	}
	for _, name := range DroppedHeaders {
		switch name {
		case http.CanonicalHeaderKey(ClientHeader), http.CanonicalHeaderKey(AgentSurfaceHeader):
			continue
		}
		if v := got.Header.Get(name); v != "" {
			t.Fatalf("%s reached the gateway: %q", name, v)
		}
	}
	for name := range got.Header {
		if strings.HasPrefix(name, http.CanonicalHeaderKey(SandboxHeaderPrefix)) && name != http.CanonicalHeaderKey(RegistrationHeader) {
			t.Fatalf("%s reached the gateway", name)
		}
	}
	if got.Header.Get(RegistrationHeader) != "reg-own" || got.Header.Get(ClientHeader) != ClientHeaderValue ||
		got.Header.Get(AgentSurfaceHeader) != AgentSurfaceValue {
		t.Fatalf("relay-set headers: %v", got.Header)
	}
	if resp.Status != http.StatusOK || string(resp.Body) != `{"decision":"block"}` {
		t.Fatalf("answer %d %q", resp.Status, resp.Body)
	}
	if resp.Header.Get(ProfileHeader) != "contractors" || resp.Header.Get(GenerationHeader) != "7" ||
		resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("X-Defenseclaw-Request-Id") != "" {
		t.Fatalf("answer headers: %v", resp.Header)
	}
	if resp.Decision == nil || *resp.Decision != decision {
		t.Fatalf("decision = %+v, want %+v", resp.Decision, decision)
	}
}

func TestRelayAnswersWithoutTrailerAndPassesRefusals(t *testing.T) {
	status := http.StatusOK
	path := relayTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "3")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"error":"enterprise_managed_rate_limited"}`)
	}))
	c := newTestClient(t, path)
	call := RelayCall{Class: RouteInspect, Target: "tool", Registration: "reg-1", Header: http.Header{}}
	resp, err := c.Relay(context.Background(), call)
	if err != nil || resp.Decision != nil || resp.Status != http.StatusOK {
		t.Fatalf("2xx without trailer: %+v %v", resp, err)
	}
	status = http.StatusTooManyRequests
	resp, err = c.Relay(context.Background(), call)
	if err != nil || resp.Status != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "3" {
		t.Fatalf("429: %+v %v", resp, err)
	}
}

func TestRelayRefusesBadCallsBeforeSending(t *testing.T) {
	sent := false
	path := relayTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { sent = true }))
	c := newTestClient(t, path)
	big := http.Header{}
	big.Set("Traceparent", strings.Repeat("a", MaxForwardHeaderBytes))
	for _, call := range []RelayCall{
		{Class: RouteHook, Target: "../admin", Registration: "reg-1"},
		{Class: RouteInspect, Target: "everything", Registration: "reg-1"},
		{Class: "otlp", Target: "logs", Registration: "reg-1"},
		{Class: RouteHook, Target: "codex", Registration: "../reg"},
		{Class: RouteHook, Target: "codex", Registration: ""},
	} {
		if _, err := c.Relay(context.Background(), call); err == nil {
			t.Fatalf("call %+v was sent", call)
		}
	}
	if _, err := c.Relay(context.Background(), RelayCall{Class: RouteHook, Target: "codex", Registration: "reg-1", Header: big}); !errors.Is(err, ErrHeadersTooLarge) {
		t.Fatalf("large headers: %v", err)
	}
	if sent {
		t.Fatal("a refused call reached the gateway")
	}
}

// A batch without a registration carries only foreign sandbox and
// container records; any other record is refused before it is sent.
func TestEventsWithoutRegistration(t *testing.T) {
	var bodies []string
	path := relayTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(raw))
		w.WriteHeader(http.StatusAccepted)
	}))
	c := newTestClient(t, path)
	if err := c.Events(context.Background(), EventBatch{Events: []Event{{Kind: EventForeignSandbox}, {Kind: EventForeignContainer}}}); err != nil {
		t.Fatalf("foreign records: %v", err)
	}
	if err := c.Events(context.Background(), EventBatch{Events: []Event{{Kind: EventForeignSandbox}, {Kind: EventSettingsDrift}}}); err == nil {
		t.Fatal("a settings drift record went out without a registration")
	}
	if len(bodies) != 1 || !strings.Contains(bodies[0], `"registration":""`) {
		t.Fatalf("sent %q", bodies)
	}
}

func TestClientErrors(t *testing.T) {
	path := relayTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(ClientHeader) != ClientHeaderValue {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone)
		_, _ = io.WriteString(w, `{"error":"sandbox_registration_revoked","message":"stopped"}`)
	}))
	c := newTestClient(t, path)
	_, err := c.Current(context.Background(), "reg-1")
	var relayErr *Error
	if !errors.As(err, &relayErr) || relayErr.Status != http.StatusGone || relayErr.Reason != ReasonRegistrationRevoked || relayErr.Message != "stopped" {
		t.Fatalf("Current: %v", err)
	}

	// A socket nobody answers on: the gateway is unreachable.
	dir, err := os.MkdirTemp("", "srt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	_ = os.Chmod(dir, 0o700)
	dead := filepath.Join(dir, "hook.sock")
	ln, err := net.Listen("unix", dead)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()
	dc := newTestClient(t, dead)
	if _, err := dc.Relay(context.Background(), RelayCall{Class: RouteHook, Target: "codex", Registration: "reg-1"}); !errors.Is(err, ErrGatewayUnreachable) {
		t.Fatalf("dead socket: %v", err)
	}
}

// GAP-0579: a pack name that is a path is the caller's input refused before
// the gateway is asked, not an unreachable gateway.
func TestPackRefusesAPathNameAsInvalidInput(t *testing.T) {
	c := newTestClient(t, relayTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the gateway was asked about a pack name that is a path")
	})))
	_, err := c.Pack(context.Background(), "", "claudecode", "../contractors")
	var invalid *InvalidRequestError
	if !errors.As(err, &invalid) || errors.Is(err, ErrGatewayUnreachable) || !strings.Contains(invalid.Message, `"../contractors"`) {
		t.Fatalf("Pack(../contractors) = %v", err)
	}
}

func TestParseHookDecisionBounds(t *testing.T) {
	if ParseHookDecision("") != nil || ParseHookDecision(`{"v":2,"action":"allow"}`) != nil ||
		ParseHookDecision(`{"v":1}`) != nil || ParseHookDecision("{") != nil {
		t.Fatal("accepted a bad trailer")
	}
	if ParseHookDecision(`{"v":1,"action":"allow","reason":"`+strings.Repeat("x", MaxHookDecisionBytes)+`"}`) != nil {
		t.Fatal("accepted an oversized trailer")
	}
	d := ParseHookDecision(`{"v":1,"action":"alert","tool":"` + strings.Repeat("é", 100) + `","reason":"` + strings.Repeat("r", 300) + `"}`)
	if d == nil || len(d.Tool) > MaxHookDecisionStringBytes || len(d.Reason) != MaxHookDecisionReasonBytes {
		t.Fatalf("truncation: %+v", d)
	}
}

// Every call the daemon makes carries the hook socket's CSRF client header,
// GET included (the gateway refuses any sandbox route without it), and a
// packs call names its scope in the headers the gateway reads (GAP-0211,
// GAP-0181).
func TestEveryCallSendsTheClientHeader(t *testing.T) {
	type seen struct{ method, path, client, registration, connector string }
	var got []seen
	path := relayTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, seen{r.Method, r.URL.Path, r.Header.Get(ClientHeader), r.Header.Get(RegistrationHeader), r.Header.Get(ConnectorHeader)})
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == PathPolicyPacks || r.URL.Path == PathDecisions && r.Method == http.MethodGet:
			_, _ = io.WriteString(w, `[]`)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	c := newTestClient(t, path)
	ctx := context.Background()
	calls := []func() error{
		func() error { _, err := c.Settings(ctx); return err },
		func() error { _, err := c.Resolve(ctx, ResolveRequest{Connector: "codex"}); return err },
		func() error { _, err := c.Bind(ctx, "reg-1", BindRequest{}); return err },
		func() error { return c.Deleted(ctx, "reg-1") },
		func() error { _, err := c.Current(ctx, "reg-1"); return err },
		func() error { _, err := c.Explain(ctx, ExplainRequest{Connector: "codex"}); return err },
		func() error { _, err := c.PolicyTest(ctx, PolicyTestRequest{Registration: "reg-1"}); return err },
		func() error { _, err := c.Packs(ctx, "", "codex"); return err },
		func() error { _, err := c.Pack(ctx, "reg-1", "", "strict"); return err },
		func() error { _, err := c.Decide(ctx, DecisionRequest{Registration: "reg-1"}); return err },
		func() error { _, err := c.Decisions(ctx, "reg-1"); return err },
		func() error { return c.Events(ctx, EventBatch{Registration: "reg-1"}) },
		func() error { return c.OTLP(ctx, OTLPCall{Signal: OTLPLogs, Registration: "reg-1"}) },
		func() error {
			_, err := c.Relay(ctx, RelayCall{Class: RouteHook, Target: "codex", Registration: "reg-1"})
			return err
		},
	}
	for i, call := range calls {
		if err := call(); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if len(got) != len(calls) {
		t.Fatalf("%d of %d calls reached the gateway", len(got), len(calls))
	}
	for _, s := range got {
		if s.client != ClientHeaderValue {
			t.Fatalf("%s %s without the client header (%q)", s.method, s.path, s.client)
		}
	}
	if list, one := got[7], got[8]; list.connector != "codex" || list.registration != "" || one.registration != "reg-1" || one.path != PathPolicyPacks+"/strict" {
		t.Fatalf("packs scope: list %+v, one %+v", list, one)
	}
	if _, err := c.Packs(ctx, "Bad/ID", "codex"); err == nil {
		t.Fatal("a malformed registration went into a header")
	}
}
