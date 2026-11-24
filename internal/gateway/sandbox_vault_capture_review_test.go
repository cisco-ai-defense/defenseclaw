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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// A secret pasted on its own line reaches the hook JSON-escaped (a \n just
// before it): it is still found, because capture scans decoded strings.
func TestSandboxVaultCapturesAfterAnEscapedNewline(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	ctx := sandboxauth.WithRequest(context.Background(), sandboxauth.Binding{SandboxName: "sb", Connector: "claudecode"}, nil)
	prompt := "my key:\n" + vaultTestAnthropicKey() + "\tthanks"
	body, err := json.Marshal(map[string]string{"hook_event_name": "UserPromptSubmit", "prompt": prompt})
	if err != nil {
		t.Fatal(err)
	}
	out, c := captureSandboxVault(ctx, st, "claudecode", nil, body, nil)
	if c == nil || len(c.Entries) != 1 || strings.Contains(string(out), vaultTestAnthropicKey()) {
		t.Fatalf("capture = %+v body %s", c, out)
	}
	var doc map[string]string
	if err := json.Unmarshal(out, &doc); err != nil || doc["prompt"] != "my key:\n[vault:ANTHROPIC_API_KEY]\tthanks" {
		t.Fatalf("redacted prompt = %q (%v)", doc["prompt"], err)
	}
}

// The relay header round-trips names and hosts, never values, and anything
// malformed is ignored.
func TestVaultCaptureHeaderRoundTrip(t *testing.T) {
	c := &sandboxVaultCapture{Connector: "claudecode", Event: "PreToolUse", Entries: []vault.Entry{
		{Name: "GITHUB_TOKEN", Host: "api.github.com", Port: 443}, {Name: "GOOGLE_API_KEY"},
	}}
	got := vaultCaptureFromHeader("claudecode", c.header())
	if got == nil || got.Event != "PreToolUse" || len(got.Entries) != 2 || got.Entries[0].Target() != "api.github.com" ||
		got.Entries[1].Target() != "" || !got.Entries[0].Exposed {
		t.Fatalf("round trip = %+v", got)
	}
	failed := vaultCaptureFromHeader("claudecode", (&sandboxVaultCapture{Connector: "claudecode", Event: "UserPromptSubmit"}).header())
	if failed == nil || failed.Err == nil || len(failed.Entries) != 0 {
		t.Fatalf("failed capture header = %+v", failed)
	}
	for _, bad := range []string{"", "UserPromptSubmit", "Stop/x A=x.example.com", "UserPromptSubmit 1BAD=x.example.com",
		"UserPromptSubmit A=https://x.example.com", "UserPromptSubmit A"} {
		if vaultCaptureFromHeader("claudecode", bad) != nil {
			t.Fatalf("header %q was accepted", bad)
		}
	}
	// Any event of a sandbox harness is read; a reply is stored exposed and
	// alerted, a connector that runs in no sandbox is ignored.
	if stop := vaultCaptureFromHeader("claudecode", "Stop A=x.example.com"); stop == nil || !stop.Entries[0].Exposed || stop.stops() {
		t.Fatalf("Stop header = %+v", stop)
	}
	if vaultCaptureFromHeader("openclaw", "PreToolUse A=x.example.com") != nil {
		t.Fatal("a header for a connector capture does not read was accepted")
	}
}

// A capture header the sandbox itself sends never reaches the managed
// gateway; only the daemon sets one.
func TestSandboxSentVaultCaptureHeaderIsDropped(t *testing.T) {
	relay := &vaultRelay{fakeRelay: &fakeRelay{}}
	f := newSandboxIngressFixture(t, withTestVault(vault.Open(filepath.Join(t.TempDir(), "vault"))), func(c *SandboxIngressConfig) {
		c.Relay = relay
		c.Registration = func(sandboxauth.Binding) (string, bool) { return "reg-1", true }
	})
	f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok,
		`{"hook_event_name":"UserPromptSubmit","session_id":"sess-v5","prompt":"hello","cwd":"/work/app"}`,
		sandboxrelay.VaultCaptureHeader, "UserPromptSubmit GITHUB_TOKEN=api.github.com")
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if len(relay.calls) != 1 {
		t.Fatalf("relayed calls = %d", len(relay.calls))
	}
	if got := relay.calls[0].Header.Get(sandboxrelay.VaultCaptureHeader); got != "" {
		t.Fatalf("relayed capture header = %q", got)
	}
}

func TestVaultCaptureErrorsNameNoPath(t *testing.T) {
	c := &sandboxVaultCapture{Connector: "claudecode", Event: "UserPromptSubmit", Err: errors.New("read the vault /home/dev/.defenseclaw/vault/vault.json: boom")}
	if m := c.message(); strings.Contains(m, "/home/dev") || !strings.Contains(m, "not sent on") {
		t.Fatalf("message = %s", m)
	}
}

// A managed gateway answers a relayed call the daemon captured as a block,
// so its own answer and audit match what the agent got.
func TestManagedGatewayBlocksARelayedCapture(t *testing.T) {
	prev := relayedSandboxRequest
	relayedSandboxRequest = func(context.Context) bool { return true }
	t.Cleanup(func() { relayedSandboxRequest = prev })
	f := newSandboxIngressFixture(t)
	resp := f.hook(t, "/api/v1/claude-code/hook", f.claudeTok,
		`{"hook_event_name":"UserPromptSubmit","session_id":"sess-v6","prompt":"use [vault:ANTHROPIC_API_KEY]","cwd":"/work/app"}`,
		sandboxrelay.VaultCaptureHeader, "UserPromptSubmit ANTHROPIC_API_KEY=api.anthropic.com")
	out, _ := resp["claude_code_output"].(map[string]interface{})
	reason, _ := resp["reason"].(string)
	if resp["action"] != "block" || out["decision"] != "block" || !strings.Contains(reason, "ANTHROPIC_API_KEY") {
		t.Fatalf("answer = %v", resp)
	}
}

// A secret used as an object key is captured and redacted too.
func TestSandboxVaultCapturesASecretInAKey(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	ctx := sandboxauth.WithRequest(context.Background(), sandboxauth.Binding{SandboxName: "sb", Connector: "claudecode"}, nil)
	body := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"headers":{"` + vaultTestAnthropicKey() + `":"x"}}}`)
	out, c := captureSandboxVault(ctx, st, "claudecode", nil, body, nil)
	if c == nil || len(c.Entries) != 1 || strings.Contains(string(out), vaultTestAnthropicKey()) || !strings.Contains(string(out), "[vault:ANTHROPIC_API_KEY]") {
		t.Fatalf("capture = %+v body %s", c, out)
	}
	// Two keys that redact to one tag: the body is replaced, never a value forwarded.
	k2 := "sk-" + "ant-api03-" + strings.Repeat("Zy7Xw6", 8)
	body = []byte(`{"hook_event_name":"PreToolUse","tool_input":{"[vault:ANTHROPIC_API_KEY]":"a","` + k2 + `":"b"}}`)
	out, c = captureSandboxVault(ctx, vault.Open(filepath.Join(t.TempDir(), "other")), "claudecode", nil, body, nil)
	if c == nil || string(out) != `{"hook_event_name":"PreToolUse"}` {
		t.Fatalf("collision capture = %+v body %s", c, out)
	}
}

// A prompt whose secret the vault already holds as exposed does not point
// the person at --vault for it.
func TestPromptWithAnExposedSecretNamesTheReplace(t *testing.T) {
	c := &sandboxVaultCapture{Connector: "claudecode", Event: "UserPromptSubmit", Entries: []vault.Entry{{Name: "STRIPE_API_KEY", Host: "api.stripe.com", Port: 443, Exposed: true}}}
	m := c.message()
	if strings.Contains(m, "--vault") || !strings.Contains(m, "vault replace STRIPE_API_KEY") {
		t.Fatalf("message = %s", m)
	}
}

// A body with a duplicate key or trailing data forwards none of itself, on
// any route: what is left is still ambiguous, so the gateway's
// ambiguous-JSON handling answers it as before, and nothing is stored.
func TestCaptureAmbiguousJSONForwardsNothing(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	ctx := sandboxauth.WithRequest(context.Background(), sandboxauth.Binding{SandboxName: "sb", Connector: "claudecode"}, nil)
	key := vaultTestAnthropicKey()
	for _, body := range []string{
		`{"hook_event_name":"UserPromptSubmit","prompt":"` + key + `","prompt":"x"}`,
		`{"hook_event_name":"Stop","last_assistant_message":"` + key + `"}{"x":1}`,
	} {
		out, c := captureSandboxVault(ctx, st, "claudecode", nil, []byte(body), nil)
		if c == nil || !errors.Is(c.Err, errVaultCaptureAmbiguous) || strings.Contains(string(out), key) || hookToolCallJSONUnambiguous("claudecode", out) {
			t.Fatalf("ambiguous body -> %s (%+v)", out, c)
		}
		if m := c.message(); strings.Contains(m, key) || !strings.Contains(m, "ambiguous") {
			t.Fatalf("message = %s", m)
		}
	}
	if list, _ := st.List(); len(list) != 0 {
		t.Fatalf("an ambiguous body stored %+v", list)
	}
	// Relayed for a managed gateway: the relayed body carries no value.
	relay := &vaultRelay{fakeRelay: &fakeRelay{}}
	f := newSandboxIngressFixture(t, withTestVault(st), func(c *SandboxIngressConfig) {
		c.Relay = relay
		c.Registration = func(sandboxauth.Binding) (string, bool) { return "reg-1", true }
	})
	rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok,
		`{"hook_event_name":"Stop","session_id":"s-amb","last_assistant_message":"`+key+`","last_assistant_message":"x","cwd":"/work/app"}`)
	if strings.Contains(rec.Body.String(), key) {
		t.Fatalf("answer: %d %s", rec.Code, rec.Body.String())
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	for _, call := range relay.calls {
		if strings.Contains(string(call.Body), key) {
			t.Fatal("an ambiguous body was relayed with its value")
		}
	}
}
