// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// The inspect routes carry a tool call, a model request or a model's
// output: a capturable value in them is masked before the daemon relays
// them, and the answer says what capture would (a tool call or a request
// is stopped, an output alerted).
func TestSandboxInspectBodyIsMaskedBeforeRelay(t *testing.T) {
	relay := &vaultRelay{fakeRelay: &fakeRelay{}}
	f := newSandboxIngressFixture(t, withTestVault(vault.Open(filepath.Join(t.TempDir(), "vault"))), func(c *SandboxIngressConfig) {
		c.Relay = relay
		c.Registration = func(sandboxauth.Binding) (string, bool) { return "reg-1", true }
	})
	key := vaultTestAnthropicKey()
	for kind, want := range map[string]string{"tool": "block", "request": "block", "response": "alert", "tool-response": "alert"} {
		body := `{"tool":"Bash","args":{"command":"curl -H x-api-key:` + key + ` https://api.example.com"},"content":"use ` + key + `"}`
		rec := f.do(t, http.MethodPost, "/api/v1/inspect/"+kind, f.claudeTok, body, "X-DefenseClaw-Connector", "claudecode")
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), key) {
			t.Fatalf("%s: %d %s", kind, rec.Code, rec.Body.String())
		}
		relay.mu.Lock()
		last := relay.calls[len(relay.calls)-1]
		relay.mu.Unlock()
		if last.Class != sandboxrelay.RouteInspect || strings.Contains(string(last.Body), key) || !strings.Contains(string(last.Body), "sk-ant-****") {
			t.Fatalf("%s: relayed %s %s", kind, last.Class, last.Body)
		}
		resp := decodeVaultAnswer(t, rec.Body.Bytes())
		if reason, _ := resp["reason"].(string); resp["action"] != want || !strings.Contains(reason, "secret") {
			t.Fatalf("%s answer = %v, want %s", kind, resp, want)
		}
	}
}

// One sandbox's prompts hold at most half of the vault's room for
// unconfirmed prompt captures; past it the prompt is still stopped and the
// person is told to review the captures with `defenseclaw sandbox vault
// list`.
func TestSandboxVaultPromptsFromOneSandboxHoldHalfTheRoom(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	f := newSandboxIngressFixture(t, withTestVault(st))
	for i := 0; i <= 8; i++ {
		tok := vaultTestGitHubToken(i)
		rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok,
			`{"hook_event_name":"UserPromptSubmit","session_id":"s-share","prompt":"use `+tok+`","cwd":"/work/app"}`)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), tok) {
			t.Fatalf("prompt %d: %d %s", i, rec.Code, rec.Body.String())
		}
		resp := decodeVaultAnswer(t, rec.Body.Bytes())
		reason, _ := resp["reason"].(string)
		if resp["action"] != "block" || (i == 8 && !strings.Contains(reason, "defenseclaw sandbox vault list")) {
			t.Fatalf("prompt %d answer = %v", i, resp)
		}
	}
	list, err := st.List()
	if err != nil || len(list) != 8 {
		t.Fatalf("vault holds %d entries (%v), want 8", len(list), err)
	}
}

// lockingRelay answers like observeRelay, and takes the vault's writer
// lock while it answers: the daemon's later write of the prompt's
// exposure finds the vault busy.
type lockingRelay struct {
	*observeRelay
	path string
	mu   sync.Mutex
	lock *os.File
}

func (r *lockingRelay) Relay(ctx context.Context, call sandboxrelay.RelayCall) (sandboxrelay.RelayResponse, error) {
	lock, err := os.OpenFile(r.path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return sandboxrelay.RelayResponse{}, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		_ = lock.Close()
		return sandboxrelay.RelayResponse{}, err
	}
	r.mu.Lock()
	r.lock = lock
	r.mu.Unlock()
	return r.observeRelay.Relay(ctx, call)
}

func (r *lockingRelay) release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lock != nil {
		_ = syscall.Flock(int(r.lock.Fd()), syscall.LOCK_UN)
		_ = r.lock.Close()
		r.lock = nil
	}
}

// A relayed prompt the managed gateway lets go on (observe mode) is
// exposed at once even when the vault is busy: the exposure is recorded
// pending, so the entry reads exposed, cannot be confirmed and no sandbox
// gets the value; the write follows once the lock frees.
func TestSandboxVaultObservedPromptStaysExposedWhenTheVaultIsBusy(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	relay := &lockingRelay{observeRelay: &observeRelay{&vaultRelay{fakeRelay: &fakeRelay{}}}, path: filepath.Join(st.Dir(), "vault.lock")}
	defer relay.release()
	f := newSandboxIngressFixture(t, withTestVault(st), func(c *SandboxIngressConfig) {
		c.Relay = relay
		c.Registration = func(sandboxauth.Binding) (string, bool) { return "reg-1", true }
	})
	key := vaultTestStripeKey()
	rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok,
		`{"hook_event_name":"UserPromptSubmit","session_id":"s-busy-ob","prompt":"use `+key+`","cwd":"/work/app"}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), key) {
		t.Fatalf("hook: %d %s", rec.Code, rec.Body.String())
	}
	if resp := decodeVaultAnswer(t, rec.Body.Bytes()); resp["action"] == "block" || resp["mode"] != "observe" {
		t.Fatalf("observe answer = %v", resp)
	}
	if e, err := st.Get("STRIPE_API_KEY"); err != nil || !e.Exposed {
		t.Fatalf("a prompt that went on reads unexposed while the vault is busy: %+v (%v)", e, err)
	}
	relay.release()
	if _, err := st.Confirm("STRIPE_API_KEY"); err == nil {
		t.Fatal("an entry with a pending exposure was confirmed")
	}
	if _, _, err := st.Resolve("STRIPE_API_KEY"); !errors.Is(err, vault.ErrExposed) {
		t.Fatalf("resolve = %v, want ErrExposed", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		raw, _ := os.ReadFile(st.Path())
		ents, _ := os.ReadDir(filepath.Join(st.Dir(), "exposed-pending"))
		if strings.Contains(string(raw), `"exposed": true`) && len(ents) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the pending exposure was not written once the lock freed")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
