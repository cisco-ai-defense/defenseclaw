// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// Values are built at run time: no credential-shaped literal in the tree.
func vaultTestAnthropicKey() string { return "sk-" + "ant-api03-" + strings.Repeat("aB3dE5", 8) }
func vaultTestStripeKey() string    { return "sk" + "_live_" + strings.Repeat("Zx9Qw2", 5) }

func withTestVault(st *vault.Store) func(*SandboxIngressConfig) {
	return func(c *SandboxIngressConfig) { c.Vault = st }
}

func codexHookHeaders(event string) []string {
	return []string{"X-DefenseClaw-Hook-Event", event, "X-DefenseClaw-Hook-Contract", "codex-hooks-v1"}
}

// A secret pasted into a sandboxed Claude Code prompt goes into the vault,
// the prompt is stopped before the model sees it, and nothing the gateway
// answers or records carries the value.
func TestSandboxVaultCapturesPromptSecret(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	var obs sandboxObserver
	f := newSandboxIngressFixture(t, obs.observe, withTestVault(st))
	key := vaultTestAnthropicKey()
	rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok,
		`{"hook_event_name":"UserPromptSubmit","session_id":"sess-v1","prompt":"call the API with `+key+` please","cwd":"/work/app"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("hook: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), key) {
		t.Fatal("the answer carries the secret")
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	out, _ := resp["claude_code_output"].(map[string]interface{})
	reason, _ := resp["reason"].(string)
	if resp["action"] != "block" || out["decision"] != "block" || !strings.Contains(reason, "ANTHROPIC_API_KEY") ||
		!strings.Contains(reason, "--vault ANTHROPIC_API_KEY") || !strings.Contains(reason, "vault confirm ANTHROPIC_API_KEY") {
		t.Fatalf("answer = %v", resp)
	}
	e, err := st.Get("ANTHROPIC_API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if e.Source != vault.SourceCaptured || e.Exposed || e.Target() != "api.anthropic.com" || !strings.Contains(e.CapturedFrom, "dc-claude-app") {
		t.Fatalf("entry = %+v", e)
	}
	if _, _, err := st.Resolve("ANTHROPIC_API_KEY"); !errors.Is(err, vault.ErrUnconfirmed) {
		t.Fatalf("a captured entry resolved before confirmation: %v", err)
	}
	if _, err := st.Confirm("ANTHROPIC_API_KEY"); err != nil {
		t.Fatal(err)
	}
	if _, v, _ := st.Resolve("ANTHROPIC_API_KEY"); v != key {
		t.Fatal("the vault does not hold the captured value")
	}
	decisions, _ := obs.take()
	for _, d := range decisions {
		if strings.Contains(d.Reason, key) || strings.Contains(string(d.ToolInput), key) {
			t.Fatalf("a decision carries the secret: %+v", d)
		}
	}
}

// A secret a sandboxed Codex agent writes into a tool call is captured,
// marked exposed (the model wrote it) and the call is denied.
func TestSandboxVaultCapturesToolCallSecret(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	f := newSandboxIngressFixture(t, withTestVault(st))
	key := vaultTestStripeKey()
	rec := f.do(t, http.MethodPost, "/api/v1/codex/hook", f.codexTok,
		`{"hook_event_name":"PreToolUse","session_id":"sess-v2","tool_name":"Bash","tool_input":{"command":"curl -u `+key+`: https://api.stripe.com/v1/charges"},"tool_use_id":"call_v2","cwd":"/work/app"}`,
		codexHookHeaders("PreToolUse")...)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), key) {
		t.Fatalf("hook: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	out, _ := resp["codex_output"].(map[string]interface{})
	specific, _ := out["hookSpecificOutput"].(map[string]interface{})
	if resp["action"] != "block" || specific["permissionDecision"] != "deny" {
		t.Fatalf("answer = %v", resp)
	}
	e, err := st.Get("STRIPE_API_KEY")
	if err != nil || e.Status() != vault.StatusExposed {
		t.Fatalf("entry = %+v (%v)", e, err)
	}
}

// With auto-capture off (no vault on the ingress) nothing is written.
func TestSandboxVaultCaptureOffWritesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	f := newSandboxIngressFixture(t)
	f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok,
		`{"hook_event_name":"UserPromptSubmit","session_id":"sess-v3","prompt":"`+vaultTestAnthropicKey()+`","cwd":"/work/app"}`)
	if list, err := vault.Open(dir).List(); err != nil || len(list) != 0 {
		t.Fatalf("vault = %v %v", list, err)
	}
	if f.api.sandboxVaultStore() != nil {
		t.Fatal("an ingress without a vault reports one")
	}
}

// Only sandbox calls of the harnesses that run in a sandbox are captured;
// every event of theirs is read, a tool's output stored exposed.
func TestCaptureSandboxVaultScope(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	body := []byte(`{"hook_event_name":"UserPromptSubmit","prompt":"` + vaultTestAnthropicKey() + `"}`)
	if out, c := captureSandboxVault(context.Background(), st, "claudecode", nil, body, nil); c != nil || string(out) != string(body) {
		t.Fatal("a host call (no sandbox binding) was captured")
	}
	ctx := sandboxauth.WithRequest(context.Background(), sandboxauth.Binding{SandboxName: "sb", Connector: "openclaw"}, nil)
	if _, c := captureSandboxVault(ctx, st, "openclaw", nil, body, nil); c != nil {
		t.Fatal("a connector that runs in no sandbox was captured")
	}
	ctx = sandboxauth.WithRequest(context.Background(), sandboxauth.Binding{SandboxName: "sb", Connector: "claudecode"}, nil)
	post := []byte(`{"hook_event_name":"PostToolUse","tool_response":"` + vaultTestStripeKey() + `"}`)
	if out, c := captureSandboxVault(ctx, st, "claudecode", nil, post, nil); c == nil || len(c.Entries) != 1 || !c.Entries[0].Exposed ||
		!c.stops() || strings.Contains(string(out), vaultTestStripeKey()) {
		t.Fatalf("a post-tool event was not captured exposed: %+v", c)
	}
	if _, c := captureSandboxVault(ctx, nil, "claudecode", nil, body, nil); c != nil {
		t.Fatal("captured with no vault")
	}
	out, c := captureSandboxVault(ctx, st, "claudecode", nil, body, nil)
	if c == nil || len(c.Entries) != 1 || strings.Contains(string(out), vaultTestAnthropicKey()) || !strings.Contains(string(out), "[vault:ANTHROPIC_API_KEY]") {
		t.Fatalf("capture = %+v body %s", c, out)
	}
	var probe map[string]interface{}
	if err := json.Unmarshal(out, &probe); err != nil {
		t.Fatalf("the redacted body is not JSON: %v", err)
	}
}

func TestSandboxVaultCaptureMessageNamesTheBind(t *testing.T) {
	c := &sandboxVaultCapture{Connector: "claudecode", Event: "UserPromptSubmit", Entries: []vault.Entry{{Name: "GOOGLE_API_KEY"}}}
	if m := c.message(); !strings.Contains(m, "vault bind GOOGLE_API_KEY --host HOST") || !strings.Contains(m, "before it reached the model") {
		t.Fatalf("message = %s", m)
	}
	c = &sandboxVaultCapture{Connector: "claudecode", Event: "PreToolUse", Entries: []vault.Entry{{Name: "STRIPE_API_KEY", Host: "api.stripe.com", Port: 443}}}
	if m := c.message(); !strings.Contains(m, "vault replace STRIPE_API_KEY") || !strings.Contains(m, "rotate") || strings.Contains(m, "--vault") {
		t.Fatalf("message = %s", m)
	}
}

// vaultRelay records relayed calls and answers allow.
type vaultRelay struct {
	*fakeRelay
	mu    sync.Mutex
	calls []sandboxrelay.RelayCall
}

func (r *vaultRelay) Relay(_ context.Context, call sandboxrelay.RelayCall) (sandboxrelay.RelayResponse, error) {
	r.mu.Lock()
	r.calls = append(r.calls, call)
	r.mu.Unlock()
	h := http.Header{}
	h.Set("Content-Length", "999")
	return sandboxrelay.RelayResponse{
		Status: http.StatusOK, Header: h,
		Body:     []byte(`{"action":"allow","severity":"NONE","mode":"action","would_block":false,"delivery_receipt":"rcpt-1"}` + "\n"),
		Decision: &sandboxrelay.HookDecision{V: 1, Event: "UserPromptSubmit", Action: "allow"},
	}, nil
}

// On a managed host the daemon captures before it relays: the managed
// gateway gets only the tagged body, and its allow becomes the capture's
// block, keeping the delivery receipt.
func TestSandboxVaultCaptureBeforeRelay(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	relay := &vaultRelay{fakeRelay: &fakeRelay{}}
	var obs sandboxObserver
	f := newSandboxIngressFixture(t, obs.observe, withTestVault(st), func(c *SandboxIngressConfig) {
		c.Relay = relay
		c.Registration = func(sandboxauth.Binding) (string, bool) { return "reg-1", true }
	})
	key := vaultTestAnthropicKey()
	rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok,
		`{"hook_event_name":"UserPromptSubmit","session_id":"sess-v4","prompt":"key `+key+`","cwd":"/work/app"}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), key) {
		t.Fatalf("hook: %d %s", rec.Code, rec.Body.String())
	}
	relay.mu.Lock()
	calls := relay.calls
	relay.mu.Unlock()
	if len(calls) != 1 || strings.Contains(string(calls[0].Body), key) || !strings.Contains(string(calls[0].Body), "[vault:ANTHROPIC_API_KEY]") ||
		calls[0].Header.Get(sandboxrelay.VaultCaptureHeader) != "UserPromptSubmit ANTHROPIC_API_KEY=api.anthropic.com" {
		t.Fatalf("relayed calls = %d, body %s", len(calls), func() string {
			if len(calls) == 0 {
				return ""
			}
			return string(calls[0].Body)
		}())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	out, _ := resp["claude_code_output"].(map[string]interface{})
	if resp["action"] != "block" || out["decision"] != "block" || resp["delivery_receipt"] != "rcpt-1" {
		t.Fatalf("answer = %v", resp)
	}
	if got := rec.Header().Get("Content-Length"); got == "999" {
		t.Fatal("the relayed Content-Length was kept for a rewritten body")
	}
	decisions, _ := obs.take()
	if len(decisions) != 1 || decisions[0].Action != "block" || !decisions[0].WouldBlock {
		t.Fatalf("decisions = %+v", decisions)
	}
	if _, err := st.Get("ANTHROPIC_API_KEY"); err != nil {
		t.Fatal(err)
	}
}

// A relayed reply event the daemon captured is alerted, not blocked (a
// Claude Code Stop answered block would restart the turn), and the value
// the vault holds is marked exposed.
func TestSandboxVaultCaptureBeforeRelayAlertsAReply(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	if _, err := st.Add(vault.AddInput{Name: "STRIPE_API_KEY", Value: vaultTestStripeKey(), Host: "api.stripe.com"}); err != nil {
		t.Fatal(err)
	}
	relay := &vaultRelay{fakeRelay: &fakeRelay{}}
	var obs sandboxObserver
	f := newSandboxIngressFixture(t, obs.observe, withTestVault(st), func(c *SandboxIngressConfig) {
		c.Relay = relay
		c.Registration = func(sandboxauth.Binding) (string, bool) { return "reg-1", true }
	})
	key := vaultTestStripeKey()
	rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok,
		`{"hook_event_name":"Stop","session_id":"sess-v5","stop_hook_active":false,"last_assistant_message":"wrote `+key+`","cwd":"/work/app"}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), key) {
		t.Fatalf("hook: %d %s", rec.Code, rec.Body.String())
	}
	relay.mu.Lock()
	calls := relay.calls
	relay.mu.Unlock()
	if len(calls) != 1 || strings.Contains(string(calls[0].Body), key) ||
		calls[0].Header.Get(sandboxrelay.VaultCaptureHeader) != "Stop STRIPE_API_KEY=api.stripe.com" {
		t.Fatalf("relayed calls = %+v", calls)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	out, _ := resp["claude_code_output"].(map[string]interface{})
	if resp["action"] != "alert" || out["decision"] == "block" || resp["delivery_receipt"] != "rcpt-1" {
		t.Fatalf("answer = %v", resp)
	}
	decisions, _ := obs.take()
	if len(decisions) != 1 || decisions[0].Action != "alert" || decisions[0].WouldBlock {
		t.Fatalf("decisions = %+v", decisions)
	}
	if e, err := st.Get("STRIPE_API_KEY"); err != nil || !e.Exposed {
		t.Fatalf("entry = %+v (%v)", e, err)
	}
}
