// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/vault"
)

func vaultTestGitHubToken(i int) string {
	return "gh" + "p_" + strings.Repeat("Ww", 16) + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "00"
}

func claudePostToolUse(session, output string) string {
	return `{"hook_event_name":"PostToolUse","session_id":"` + session + `","cwd":"/work/app","tool_name":"Bash","tool_input":{"command":"sh gen.sh"},` +
		`"tool_response":{"stdout":"` + output + `\n","stderr":"","interrupted":false,"isImage":false},"tool_use_id":"toolu_` + session + `"}`
}

func decodeVaultAnswer(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("answer %s: %v", body, err)
	}
	return resp
}

// A secret pasted in a prompt, confirmed, then seen in a tool's output is
// marked exposed end to end: no sandbox gets it until it is rotated.
func TestSandboxVaultPromptThenOutputExposesTheEntry(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	f := newSandboxIngressFixture(t, withTestVault(st))
	key := vaultTestStripeKey()
	rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok,
		`{"hook_event_name":"UserPromptSubmit","session_id":"s-po","prompt":"use `+key+`","cwd":"/work/app"}`)
	if rec.Code != http.StatusOK || decodeVaultAnswer(t, rec.Body.Bytes())["action"] != "block" {
		t.Fatalf("prompt: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := st.Confirm("STRIPE_API_KEY"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Resolve("STRIPE_API_KEY"); err != nil {
		t.Fatalf("the confirmed entry is not ready: %v", err)
	}
	rec = f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok, claudePostToolUse("s-po", "KEY="+key))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), key) {
		t.Fatalf("output: %d %s", rec.Code, rec.Body.String())
	}
	resp := decodeVaultAnswer(t, rec.Body.Bytes())
	if reason, _ := resp["reason"].(string); resp["action"] != "block" || !strings.Contains(reason, "vault replace STRIPE_API_KEY") {
		t.Fatalf("answer = %v", resp)
	}
	if _, _, err := st.Resolve("STRIPE_API_KEY"); !errors.Is(err, vault.ErrExposed) {
		t.Fatalf("an entry the model saw still resolves: %v", err)
	}
	if list, _ := st.List(); len(list) != 1 {
		t.Fatalf("entries = %+v", list)
	}
}

// At a tool's output with the model-side room used up, a held ready value
// is still marked exposed, the new value is removed and not stored (its
// exposure is recorded pending), and the same secret pasted in a prompt
// afterwards is captured exposed: the model saw it in the output.
func TestSandboxVaultFullVaultAtOutput(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	ready := vaultTestStripeKey()
	if _, err := st.Add(vault.AddInput{Name: "STRIPE_LIVE", Value: ready, Host: "api.stripe.com"}); err != nil {
		t.Fatal(err)
	}
	// The fixture's Claude Code sandbox fills its own model-side room.
	for i := 0; i < vault.MaxCapturedFromModelPerSandbox; i++ {
		if _, err := st.Capture(vault.CaptureInput{Value: vaultTestGitHubToken(i), Kind: "github-token", Exposed: true, FromModel: true, Sandbox: "dc-claude-app"}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	f := newSandboxIngressFixture(t, withTestVault(st))
	fresh := vaultTestAnthropicKey()
	rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok, claudePostToolUse("s-full", "A="+ready+" B="+fresh))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), ready) || strings.Contains(rec.Body.String(), fresh) {
		t.Fatalf("output: %d %s", rec.Code, rec.Body.String())
	}
	resp := decodeVaultAnswer(t, rec.Body.Bytes())
	reason, _ := resp["reason"].(string)
	if resp["action"] != "block" || !strings.Contains(reason, "STRIPE_LIVE") || !strings.Contains(reason, "not in the vault") {
		t.Fatalf("answer = %v", resp)
	}
	if e, err := st.Get("STRIPE_LIVE"); err != nil || !e.Exposed {
		t.Fatalf("held entry = %+v (%v)", e, err)
	}
	if _, err := st.Get("ANTHROPIC_API_KEY"); !vault.IsNotFound(err) {
		t.Fatalf("a value past the model-side bound was stored: %v", err)
	}
	rec = f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok,
		`{"hook_event_name":"UserPromptSubmit","session_id":"s-full","prompt":"use `+fresh+`","cwd":"/work/app"}`)
	if rec.Code != http.StatusOK || decodeVaultAnswer(t, rec.Body.Bytes())["action"] != "block" {
		t.Fatalf("prompt: %d %s", rec.Code, rec.Body.String())
	}
	if e, err := st.Get("ANTHROPIC_API_KEY"); err != nil || !e.Exposed || e.FromModel {
		t.Fatalf("prompt entry with the model-side room full = %+v (%v)", e, err)
	}
}

// With the vault lock held by another process at a tool's output, the call
// is still answered with the held entry's name and the value removed, and
// the exposure is written once the lock frees.
func TestSandboxVaultBusyVaultAtOutput(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	ready := vaultTestStripeKey()
	if _, err := st.Add(vault.AddInput{Name: "STRIPE_LIVE", Value: ready, Host: "api.stripe.com"}); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(st.Dir(), "vault.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	f := newSandboxIngressFixture(t, withTestVault(st))
	rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok, claudePostToolUse("s-busy", "A="+ready))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), ready) {
		t.Fatalf("output: %d %s", rec.Code, rec.Body.String())
	}
	resp := decodeVaultAnswer(t, rec.Body.Bytes())
	if reason, _ := resp["reason"].(string); resp["action"] != "block" || !strings.Contains(reason, "STRIPE_LIVE") {
		t.Fatalf("answer = %v", resp)
	}
	if raw, _ := os.ReadFile(st.Path()); strings.Contains(string(raw), `"exposed": true`) {
		t.Fatal("written through a held lock")
	}
	// The exposure is pending: it reads exposed at once.
	if e, _ := st.Get("STRIPE_LIVE"); !e.Exposed {
		t.Fatal("the pending exposure does not read as exposed")
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if raw, _ := os.ReadFile(st.Path()); strings.Contains(string(raw), `"exposed": true`) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the exposure was not written after the lock freed")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// On a managed host the daemon captures another connector's calls before
// it relays them too: Copilot CLI's tool call and tool output.
func TestSandboxVaultRelaysACopilotCapture(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	relay := &vaultRelay{fakeRelay: &fakeRelay{}}
	f := newSandboxIngressFixture(t, withTestVault(st), func(c *SandboxIngressConfig) {
		c.Relay = relay
		c.Registration = func(sandboxauth.Binding) (string, bool) { return "reg-1", true }
	})
	version := harness.Copilot.DefaultVersion
	contract := connector.ResolveSandboxHookContract("copilot", version)
	if contract.Status != connector.HookCompatibilityKnown {
		t.Fatalf("no copilot sandbox contract: %s", contract.Reason)
	}
	_, token := f.mint(t, "dc-vc-copilot", "copilot", version, contract.Contract.ContractID, "")
	key := vaultTestStripeKey()
	const session = `"sessionId":"506e99d3-3a4f-4a7c-9d0e-0f2c6d1e8b11","timestamp":1790483549431,"cwd":"/work/app"`
	for _, tc := range []struct{ event, body, action string }{
		{"postToolUse", `{` + session + `,"toolName":"bash","toolArgs":{"command":"sh gen.sh","description":"generate"},` +
			`"toolResult":{"resultType":"success","textResultForLlm":"KEY=` + key + `\n"}}`, "alert"},
		{"preToolUse", `{` + session + `,"toolName":"bash","toolArgs":{"command":"printf 'KEY=` + key + `\\n' > local.env","description":"write env"}}`, "block"},
	} {
		rec := f.do(t, http.MethodPost, "/api/v1/copilot/hook", token, tc.body, "X-DefenseClaw-Copilot-Event", tc.event)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), key) {
			t.Fatalf("%s: %d %s", tc.event, rec.Code, rec.Body.String())
		}
		relay.mu.Lock()
		last := relay.calls[len(relay.calls)-1]
		relay.mu.Unlock()
		if strings.Contains(string(last.Body), key) || last.Header.Get(sandboxrelay.VaultCaptureHeader) != tc.event+" STRIPE_API_KEY=api.stripe.com" {
			t.Fatalf("%s relayed header %q", tc.event, last.Header.Get(sandboxrelay.VaultCaptureHeader))
		}
		if resp := decodeVaultAnswer(t, rec.Body.Bytes()); resp["action"] != tc.action || resp["delivery_receipt"] != "rcpt-1" {
			t.Fatalf("%s answer = %v", tc.event, resp)
		}
	}
	if e, err := st.Get("STRIPE_API_KEY"); err != nil || !e.Exposed || !e.FromModel {
		t.Fatalf("entry = %+v (%v)", e, err)
	}
}

// observeRelay answers like a managed gateway whose guardrail profile puts
// the sandbox in observe mode.
type observeRelay struct{ *vaultRelay }

func (r *observeRelay) Relay(ctx context.Context, call sandboxrelay.RelayCall) (sandboxrelay.RelayResponse, error) {
	resp, err := r.vaultRelay.Relay(ctx, call)
	resp.Body = []byte(`{"action":"allow","severity":"NONE","mode":"observe","would_block":false,"delivery_receipt":"rcpt-1"}` + "\n")
	return resp, err
}

// The configured mode is never overridden: in observe mode a prompt's
// secret is still captured and reported but the prompt is not stopped, so
// the entry is marked exposed (Claude Code and Codex alike).
func TestSandboxVaultCaptureObserveModeStopsNothing(t *testing.T) {
	for _, tc := range []struct {
		name, path, out string
		headers         []string
		body            func(string) string
	}{
		{"claudecode", "/api/v1/claude-code/hook", "claude_code_output", nil, func(k string) string {
			return `{"hook_event_name":"UserPromptSubmit","session_id":"s-ob","prompt":"use ` + k + `","cwd":"/work/app"}`
		}},
		{"codex", "/api/v1/codex/hook", "codex_output", codexHookHeaders("UserPromptSubmit"), func(k string) string {
			return `{"hook_event_name":"UserPromptSubmit","session_id":"s-ob","turn_id":"t1","prompt":"use ` + k + `","cwd":"/work/app"}`
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := vault.Open(filepath.Join(t.TempDir(), "vault"))
			relay := &observeRelay{&vaultRelay{fakeRelay: &fakeRelay{}}}
			var obs sandboxObserver
			f := newSandboxIngressFixture(t, obs.observe, withTestVault(st), func(c *SandboxIngressConfig) {
				c.Relay = relay
				c.Registration = func(sandboxauth.Binding) (string, bool) { return "reg-1", true }
			})
			token := f.claudeTok
			if tc.name == "codex" {
				token = f.codexTok
			}
			key := vaultTestStripeKey()
			rec := f.do(t, http.MethodPost, tc.path, token, tc.body(key), tc.headers...)
			if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), key) {
				t.Fatalf("hook: %d %s", rec.Code, rec.Body.String())
			}
			resp := decodeVaultAnswer(t, rec.Body.Bytes())
			out, _ := resp[tc.out].(map[string]interface{})
			reason, _ := resp["reason"].(string)
			if resp["action"] == "block" || resp["mode"] != "observe" || resp["would_block"] != true || out["decision"] == "block" ||
				!strings.Contains(reason, "observe mode") || !strings.Contains(reason, "STRIPE_API_KEY") {
				t.Fatalf("observe answer = %v", resp)
			}
			if e, err := st.Get("STRIPE_API_KEY"); err != nil || !e.Exposed {
				t.Fatalf("a prompt that went on left its entry unexposed: %+v (%v)", e, err)
			}
			decisions, _ := obs.take()
			if len(decisions) != 1 || decisions[0].Action == "block" || !decisions[0].WouldBlock {
				t.Fatalf("decisions = %+v", decisions)
			}
		})
	}
}

// The capture's answer only raises: an allow becomes an alert, a confirm
// stays a confirm, and action mode blocks where the event stops.
func TestApplySandboxVaultCaptureOnlyRaises(t *testing.T) {
	f := newSandboxIngressFixture(t)
	ctx := context.Background()
	profile := f.api.hookProfileForRequest(ctx, "kiro")
	c := &sandboxVaultCapture{Connector: "kiro", Event: "postToolUse", Entries: []vault.Entry{{Name: "STRIPE_API_KEY", Exposed: true}}}
	req := agentHookRequest{ConnectorName: "kiro", HookEventName: "postToolUse"}
	for _, tc := range []struct{ in, mode, want string }{
		{"allow", "action", "alert"},
		{"confirm", "action", "confirm"},
		{"block", "action", "block"},
		{"allow", "observe", "allow"},
	} {
		resp := f.api.applySandboxVaultCapture(ctx, profile, req, []byte(`{}`), map[string]interface{}{},
			agentHookResponse{Action: tc.in, RawAction: tc.in, Mode: tc.mode}, c)
		if resp.Action != tc.want || resp.Mode != tc.mode {
			t.Fatalf("%s in %s mode answered %s (%s), want %s", tc.in, tc.mode, resp.Action, resp.Mode, tc.want)
		}
	}
	c = &sandboxVaultCapture{Connector: "claudecode", Event: "UserPromptSubmit", Entries: []vault.Entry{{Name: "STRIPE_API_KEY"}}}
	profile = f.api.hookProfileForRequest(ctx, "claudecode")
	resp := f.api.applySandboxVaultCapture(ctx, profile, agentHookRequest{ConnectorName: "claudecode"}, []byte(`{}`), map[string]interface{}{},
		agentHookResponse{Action: "allow", Mode: "observe"}, c)
	if resp.Action != "allow" || !resp.WouldBlock || resp.RawAction != "block" || !c.NotStopped || !c.Entries[0].Exposed {
		t.Fatalf("observe prompt answer = %+v (capture %+v)", resp, c)
	}
	c = &sandboxVaultCapture{Connector: "claudecode", Event: "UserPromptSubmit", Entries: []vault.Entry{{Name: "STRIPE_API_KEY"}}}
	resp = f.api.applySandboxVaultCapture(ctx, profile, agentHookRequest{ConnectorName: "claudecode"}, []byte(`{}`), map[string]interface{}{},
		agentHookResponse{Action: "allow", Mode: "action"}, c)
	if resp.Action != "block" || c.NotStopped || c.Entries[0].Exposed {
		t.Fatalf("action prompt answer = %+v (capture %+v)", resp, c)
	}
}

// A reply stores nothing new: a value the vault does not hold is only
// removed, and the agent is told to have it rotated.
func TestSandboxVaultReplyStoresNothingNew(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	f := newSandboxIngressFixture(t, withTestVault(st))
	key := vaultTestStripeKey()
	rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok,
		`{"hook_event_name":"Stop","session_id":"s-rp","stop_hook_active":false,"last_assistant_message":"wrote `+key+`","cwd":"/work/app"}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), key) {
		t.Fatalf("hook: %d %s", rec.Code, rec.Body.String())
	}
	resp := decodeVaultAnswer(t, rec.Body.Bytes())
	out, _ := resp["claude_code_output"].(map[string]interface{})
	if reason, _ := resp["reason"].(string); resp["action"] != "alert" || out["decision"] == "block" || !strings.Contains(reason, "rotate") {
		t.Fatalf("answer = %v", resp)
	}
	if list, err := st.List(); err != nil || len(list) != 0 {
		t.Fatalf("a reply stored %+v (%v)", list, err)
	}
}

// Cursor's stop answers carry no message (its only output starts a new
// turn); its subagentStart is a tool call and is denied; Amp's agent.start
// carries the prompt, stored exposed with a note for the model.
func TestSandboxVaultCursorAndAmpEvents(t *testing.T) {
	st := vault.Open(filepath.Join(t.TempDir(), "vault"))
	f := newSandboxIngressFixture(t, withTestVault(st))
	mint := func(spec *harness.Spec) string {
		contract := connector.ResolveSandboxHookContract(spec.Name, spec.DefaultVersion)
		if contract.Status != connector.HookCompatibilityKnown {
			t.Fatalf("%s: no sandbox contract: %s", spec.Name, contract.Reason)
		}
		_, token := f.mint(t, "dc-vc3-"+spec.Name, spec.Name, spec.DefaultVersion, contract.Contract.ContractID, "")
		return token
	}
	cursor, amp := mint(harness.Cursor), mint(harness.Amp)
	key := vaultTestStripeKey()
	if _, err := st.Add(vault.AddInput{Name: "STRIPE_LIVE", Value: key, Host: "api.stripe.com"}); err != nil {
		t.Fatal(err)
	}
	const turn = `"conversation_id":"conv-vc3","generation_id":"gen-vc3","cwd":"/work/app"`
	rec := f.do(t, http.MethodPost, "/api/v1/cursor/hook", cursor, `{"hook_event_name":"stop",`+turn+`,"status":"completed","loop_count":0,"note":"`+key+`"}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), key) || strings.Contains(rec.Body.String(), "followup_message") {
		t.Fatalf("cursor stop: %d %s", rec.Code, rec.Body.String())
	}
	if resp := decodeVaultAnswer(t, rec.Body.Bytes()); resp["action"] == "block" {
		t.Fatalf("cursor stop answer = %v", resp)
	}
	if e, _ := st.Get("STRIPE_LIVE"); !e.Exposed {
		t.Fatal("cursor stop did not mark the held value exposed")
	}
	rec = f.do(t, http.MethodPost, "/api/v1/cursor/hook", cursor,
		`{"hook_event_name":"subagentStart",`+turn+`,"subagent_type":"generalPurpose","task":"call the API with `+vaultTestGitHubToken(1)+`"}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), vaultTestGitHubToken(1)) {
		t.Fatalf("cursor subagentStart: %d %s", rec.Code, rec.Body.String())
	}
	if resp := decodeVaultAnswer(t, rec.Body.Bytes()); resp["action"] != "block" {
		t.Fatalf("cursor subagentStart answer = %v", resp)
	}
	anth := vaultTestAnthropicKey()
	rec = f.do(t, http.MethodPost, "/api/v1/amp/hook", amp,
		`{"hook_event_name":"agent.start","thread_id":"T-vc3","session_id":"T-vc3","turn_id":"t1","message_id":"t1","prompt":"call the API with `+anth+` please","cwd":"/work/app"}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), anth) {
		t.Fatalf("amp agent.start: %d %s", rec.Code, rec.Body.String())
	}
	resp := decodeVaultAnswer(t, rec.Body.Bytes())
	if note, _ := resp["additional_context"].(string); !strings.Contains(note, "ANTHROPIC_API_KEY") {
		t.Fatalf("amp agent.start answer carries no note for the model: %v", resp)
	}
	if e, err := st.Get("ANTHROPIC_API_KEY"); err != nil || !e.Exposed || e.FromModel {
		t.Fatalf("amp prompt entry = %+v (%v)", e, err)
	}
}
