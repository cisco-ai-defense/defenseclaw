// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// Values are built at run time: no credential-shaped literal in the tree.
func unitGitHubToken() string { return "gh" + "p_" + strings.Repeat("Ww", 16) + "zz00" }
func unitStripeKey() string   { return "sk" + "_live_" + strings.Repeat("Qx7Wv3", 5) }

// An event name shaped like a credential is never carried on: it would
// land unredacted in the entry, the relay header and the messages.
func TestVaultCaptureEventNameShapedLikeACredentialIsHook(t *testing.T) {
	tok := unitGitHubToken()
	if got := sandboxVaultCaptureEventName("claudecode", http.Header{}, map[string]interface{}{"hook_event_name": tok}); got != "hook" {
		t.Fatalf("event name = %q, want hook", got)
	}
	if got := sandboxVaultCaptureEventName("claudecode", http.Header{}, map[string]interface{}{"hook_event_name": "UserPromptSubmit"}); got != "UserPromptSubmit" {
		t.Fatalf("event name = %q", got)
	}
	if vaultCaptureFromHeader("claudecode", tok+" GITHUB_TOKEN=api.github.com") != nil {
		t.Fatal("a relay header with a credential-shaped event was accepted")
	}
}

// The relay header carries that a value was removed but not kept, so the
// managed gateway's message and audit say so.
func TestVaultCaptureHeaderCarriesUnkept(t *testing.T) {
	c := &sandboxVaultCapture{Connector: "claudecode", Event: "PreToolUse", Unkept: true,
		Entries: []vault.Entry{{Name: "GITHUB_TOKEN", Host: "api.github.com", Port: 443}}}
	got := vaultCaptureFromHeader("claudecode", c.header())
	if got == nil || !got.Unkept || len(got.Entries) != 1 || !strings.Contains(got.message(), "is not in the vault") {
		t.Fatalf("round trip = %+v", got)
	}
	if kept := vaultCaptureFromHeader("claudecode", "PreToolUse GITHUB_TOKEN=api.github.com"); kept == nil || kept.Unkept {
		t.Fatalf("kept-only header = %+v", kept)
	}
	if vaultCaptureFromHeader("claudecode", "PreToolUse - "+vaultCaptureUnkeptField) != nil {
		t.Fatal("an unkept marker after nothing kept was accepted")
	}
}

// An inspect answer whose request carried a masked secret says what
// capture would; a block is kept, observe mode is respected.
func TestMaskedInspectAnswer(t *testing.T) {
	for _, tc := range []struct {
		kind, in, mode, want string
		wouldBlock           bool
	}{
		{"tool", "allow", "action", "block", true},
		{"request", "alert", "action", "block", true},
		{"tool", "allow", "observe", "allow", true},
		{"response", "allow", "action", "alert", false},
		{"tool-response", "block", "action", "block", false},
	} {
		in := `{"action":"` + tc.in + `","severity":"NONE","mode":"` + tc.mode + `","reason":"","findings":["x"]}`
		var out map[string]interface{}
		if err := json.Unmarshal(maskedInspectAnswer(tc.kind, []byte(in)), &out); err != nil {
			t.Fatal(err)
		}
		wb, _ := out["would_block"].(bool)
		if out["action"] != tc.want || out["severity"] != "HIGH" || (tc.wouldBlock && !wb) {
			t.Fatalf("%s %s in %s mode = %v", tc.kind, tc.in, tc.mode, out)
		}
	}
	if got := maskedInspectAnswer("tool", []byte("not json")); string(got) != "not json" {
		t.Fatalf("a non-verdict answer was changed: %s", got)
	}
}

// Where the answer will not stop a prompt (observe mode), the prompt's
// secret is stored exposed in the capture's one write.
func TestSandboxVaultPromptThatGoesOnIsStoredExposedInOneWrite(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	ctx := sandboxauth.WithRequest(context.Background(), sandboxauth.Binding{SandboxName: "sb", Connector: "claudecode"}, nil)
	body, _ := json.Marshal(map[string]string{"hook_event_name": "UserPromptSubmit", "prompt": "use " + unitStripeKey()})
	_, c := captureSandboxVault(ctx, st, "claudecode", nil, body, func() bool { return true })
	if c == nil || len(c.Entries) != 1 || !c.Entries[0].Exposed || !c.NotStopped {
		t.Fatalf("capture = %+v", c)
	}
	raw, _ := os.ReadFile(st.Path())
	if !strings.Contains(string(raw), `"exposed": true`) || !strings.Contains(string(raw), `"sandbox": "sb"`) {
		t.Fatal("the capture's write did not store the prompt exposed with its sandbox")
	}
	// The verdict that follows writes nothing more.
	c.markExposed = func(time.Duration) error { t.Fatal("a second write"); return nil }
	(&APIServer{}).markVaultCaptureExposed(c)
}

// An exposure the vault could not write is retried; when the retries give
// up it is logged and audited (MEDIUM while the pending record keeps the
// value from any sandbox, HIGH at once when it could not be recorded).
func TestVaultExposureRetryGiveUpIsAudited(t *testing.T) {
	saved := vaultExposureRetryDelays
	vaultExposureRetryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	defer func() { vaultExposureRetryDelays = saved }()
	for _, tc := range []struct {
		name, severity, reason string
		cause                  error
	}{
		{"pending", "MEDIUM", "retries_exhausted_pending", errors.Join(vault.ErrBusy, vault.ErrExposurePending)},
		{"not recorded", "HIGH", "not_recorded", errors.Join(vault.ErrBusy, vault.ErrExposureNotRecorded)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, logger := testStoreAndLogger(t)
			api := &APIServer{store: store, logger: logger}
			done := make(chan struct{}, 4)
			c := &sandboxVaultCapture{Connector: "claudecode", Event: "PostToolUse", Sandbox: "sb",
				Entries:     []vault.Entry{{Name: "STRIPE_API_KEY"}},
				markExposed: func(time.Duration) error { done <- struct{}{}; return tc.cause }}
			api.followVaultExposure(c, tc.cause)
			deadline := time.Now().Add(10 * time.Second)
			for {
				events, err := store.ListEvents(100)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, e := range events {
					if strings.Contains(e.Details, sandboxVaultExposureRuleID) && strings.Contains(e.Details, tc.reason) {
						if e.Severity != tc.severity || strings.Contains(e.Details, unitStripeKey()) {
							t.Fatalf("alert = %+v", e)
						}
						found = true
					}
				}
				if found && len(done) == len(vaultExposureRetryDelays) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("no %s alert after the retries (%d tries)", tc.reason, len(done))
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}
