// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// failingAuditEmitter fails every audit write of the logger once fail is set,
// with the error a store returns after its busy timeout and retries.
type failingAuditEmitter struct {
	audit.RuntimeV8Emitter
	fail bool
}

func (emitter *failingAuditEmitter) EmitRuntimeV8(
	ctx context.Context,
	metadata router.Metadata,
	builder audit.RuntimeV8Builder,
) (audit.RuntimeV8EmitOutcome, error) {
	if emitter.fail {
		return audit.RuntimeV8EmitOutcome{}, errors.New("audit: persist runtime record: database is locked (5) (SQLITE_BUSY)")
	}
	return emitter.RuntimeV8Emitter.EmitRuntimeV8(ctx, metadata, builder)
}

type auditFailureHookFixture struct {
	api     *APIServer
	path    string
	emitter *failingAuditEmitter
}

// A receipt has already committed the answer to the agent. Its durable
// pending occurrence can be retried after an audit write fault; changing the
// in-memory verdict to a block would falsely report an enforcement.
func TestManagedReceiptedHookAuditFaultKeepsTheCommittedVerdict(t *testing.T) {
	fixture := newAuditFailureHookFixture(t, "closed")
	fixture.emitter.fail = true
	result := fixture.api.finalizeAgentHook(t.Context(), "claudecode", agentHookRequest{
		ConnectorName: "claudecode", HookEventName: "PreToolUse", ToolName: "Bash",
		pendingOccurrenceID: "00000000-0000-4000-8000-000000000001",
	}, agentHookResponse{Action: "allow", RawAction: "allow", Mode: "action"}, nil, nil, 0, false, nil)
	if result.Response.Action != "allow" || result.AuditFailedClosed || result.AuditPersisted {
		t.Fatalf("committed answer after audit failure = %+v, want pending allow without a false block", result)
	}
}

func newAuditFailureHookFixture(t *testing.T, failMode string) auditFailureHookFixture {
	t.Helper()
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	fixture := newSidecarRuntimeFixture(t, true)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	emitter := &failingAuditEmitter{RuntimeV8Emitter: &sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints}}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(emitter)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.HookFailMode = failMode
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	bindHookLifecycleV8(t, api, fixture.runtime)
	return auditFailureHookFixture{api: api, path: fixture.path, emitter: emitter}
}

// preToolUseBody is a Claude Code PreToolUse of "echo ok".
func preToolUseBody(t *testing.T, toolUseID string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "s-audit-" + toolUseID, "cwd": t.TempDir(),
		"tool_name": "Bash", "tool_use_id": toolUseID, "tool_input": map[string]any{"command": "echo ok"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func (fixture auditFailureHookFixture) preToolUse(t *testing.T, toolUseID string) map[string]any {
	t.Helper()
	body := preToolUseBody(t, toolUseID)
	recorder := httptest.NewRecorder()
	fixture.api.handleAgentHook("claudecode").ServeHTTP(recorder,
		httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// lastHookDecisionAction is the action of the newest hook_decision record.
func lastHookDecisionAction(t *testing.T, path string) string {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var raw string
	if err := database.QueryRow(`SELECT projected_record_json FROM audit_events WHERE event_name = 'hook_decision' ORDER BY rowid DESC LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var record struct {
		Body map[string]any `json:"body"`
	}
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"defenseclaw.guardrail.effective_action"} {
		if action, ok := record.Body[key].(string); ok {
			return action
		}
	}
	return raw
}

// Review of G-flood-wal (P1): an accepted hook whose audit row could not be
// written answered with its computed allow, so a call ran with no durable
// record. Outside Secure Client the fail mode is closed: the call is denied,
// and the exported hook_decision says so.
func TestHookAuditWriteFailureDeniesTheCall(t *testing.T) {
	t.Run("store refuses the row (disk full)", func(t *testing.T) {
		fixture := newAuditFailureHookFixture(t, "")
		if got := fixture.preToolUse(t, "toolu-before")["action"]; got != "allow" {
			t.Fatalf("healthy store: action %v, want allow", got)
		}
		database, err := sql.Open("sqlite", fixture.path)
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		if _, err := database.Exec(`CREATE TRIGGER zz_audit_disk_full BEFORE INSERT ON audit_events
			WHEN NEW.action = 'connector-hook' BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END`); err != nil {
			t.Fatal(err)
		}
		out := fixture.preToolUse(t, "toolu-full")
		reason, _ := out["reason"].(string)
		if out["action"] != "block" || !strings.Contains(reason, "could not write the call's audit record") {
			t.Fatalf("full store: action %v reason %q, want a fail-closed block", out["action"], reason)
		}
		if got := lastHookDecisionAction(t, fixture.path); got != "block" {
			t.Fatalf("hook_decision action %q, want block", got)
		}
		// Review round 2 (P1): the agent gets Claude Code's own PreToolUse
		// denial, not a generic decision:block it may not honor.
		assertClaudeCodePreToolUseDenial(t, out["claude_code_output"])
		// Review round 2 (P2): status counts the block the agent got.
		if blocks := fixture.api.health.statsFor("claudecode").toolBlocks.Load(); blocks != 1 {
			t.Fatalf("status tool blocks = %d after a fail-closed audit write, want 1", blocks)
		}
	})
	t.Run("store stays busy", func(t *testing.T) {
		fixture := newAuditFailureHookFixture(t, "")
		fixture.emitter.fail = true
		if out := fixture.preToolUse(t, "toolu-busy"); out["action"] != "block" {
			t.Fatalf("busy store: action %v, want block", out["action"])
		}
	})
	t.Run("legacy per-user open still denies", func(t *testing.T) {
		fixture := newAuditFailureHookFixture(t, "open")
		fixture.emitter.fail = true
		if out := fixture.preToolUse(t, "toolu-open"); out["action"] != "block" {
			t.Fatalf("per-user open fail mode: action %v, want block", out["action"])
		}
	})
}

// A failed audit write keeps a block, a session-ending event and an event the
// agent cannot block; only an exact replay is not audited at all.
func TestHookAuditFailureResponseKeepsWhatItCannotTighten(t *testing.T) {
	fixture := newAuditFailureHookFixture(t, "")
	fixture.emitter.fail = true
	api := fixture.api
	allow := agentHookResponse{Action: "allow", RawAction: "allow", Mode: "action", EvaluationID: "eval-1"}
	finalize := func(req agentHookRequest, resp agentHookResponse) hookFinalizationResult {
		t.Helper()
		req.ConnectorName = "claudecode"
		return api.finalizeAgentHook(t.Context(), "claudecode", req, resp, nil, []byte(`{}`), time.Millisecond, false, nil)
	}
	denied := finalize(agentHookRequest{HookEventName: "PreToolUse", SessionID: "s-1", ToolName: "Bash",
		Payload: map[string]interface{}{"tool_name": "Bash"}}, allow)
	if !denied.AuditFailedClosed || denied.Response.Action != "block" || !denied.Enforced || denied.AuditPersisted ||
		denied.Response.EvaluationID != "eval-1" {
		t.Fatalf("PreToolUse allow with a failed audit write: %+v", denied)
	}
	block := agentHookResponse{Action: "block", RawAction: "block", Mode: "action", Reason: "policy"}
	if kept := finalize(agentHookRequest{HookEventName: "PreToolUse", SessionID: "s-1", ToolName: "Bash"}, block); kept.AuditFailedClosed || kept.Response.Reason != "policy" {
		t.Fatalf("a block was replaced: %+v", kept)
	}
	if kept := finalize(agentHookRequest{HookEventName: "Stop", SessionID: "s-1"}, allow); kept.AuditFailedClosed || kept.Response.Action != "allow" {
		t.Fatalf("a Stop was denied: %+v", kept)
	}
	if kept := finalize(agentHookRequest{HookEventName: "PostToolUse", SessionID: "s-1", ToolName: "Bash"}, allow); kept.AuditFailedClosed {
		t.Fatalf("a PostToolUse was denied: %+v", kept)
	}
	if replay := finalize(agentHookRequest{HookEventName: "PreToolUse", SessionID: "s-1", SuppressCorrelationEmit: true}, allow); replay.AuditFailedClosed || replay.Response.Action != "allow" {
		t.Fatalf("an exact replay was denied: %+v", replay)
	}
}

// assertClaudeCodePreToolUseDenial checks output is Claude Code's native
// PreToolUse denial with the audit failure's reason.
func assertClaudeCodePreToolUseDenial(t *testing.T, output any) {
	t.Helper()
	fields, _ := output.(map[string]any)
	specific, _ := fields["hookSpecificOutput"].(map[string]any)
	reason, _ := specific["permissionDecisionReason"].(string)
	if specific["hookEventName"] != "PreToolUse" || specific["permissionDecision"] != "deny" ||
		!strings.Contains(reason, "could not write the call's audit record") || fields["decision"] != nil {
		t.Fatalf("Claude Code output %v; want hookSpecificOutput PreToolUse permissionDecision deny with the audit reason", output)
	}
}

// handlerTransport serves every request with handler, so a hook runner talks
// to the gateway's own hook handler without a listener.
type handlerTransport struct{ handler http.Handler }

func (transport handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	transport.handler.ServeHTTP(recorder, req)
	return recorder.Result(), nil
}

// Review of G-flood-wal round 2 (P1): the fail-closed verdict of a failed
// audit write was rendered without the request body, so Claude Code got a
// generic {"decision":"block"} for a PreToolUse. The Unix hook script prints
// whatever the gateway rendered and exits 0, and Claude Code may run the call.
// End to end through the native hook runner, the agent now reads the
// gateway's own PreToolUse denial.
func TestHookAuditWriteFailureReachesClaudeCodeAsANativeDenial(t *testing.T) {
	fixture := newAuditFailureHookFixture(t, "")
	fixture.emitter.fail = true
	home := t.TempDir()
	hookDir := filepath.Join(home, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".token"), []byte("DEFENSECLAW_GATEWAY_TOKEN=\"tkn\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := hookexec.Run(t.Context(), hookexec.Options{
		Connector:  "claudecode",
		Event:      "PreToolUse",
		APIAddr:    "127.0.0.1:8787",
		FailMode:   "closed",
		Home:       home,
		HookDir:    hookDir,
		Stdin:      bytes.NewReader(preToolUseBody(t, "toolu-native")),
		Stdout:     &stdout,
		Stderr:     &stderr,
		HTTPClient: &http.Client{Transport: handlerTransport{handler: fixture.api.handleAgentHook("claudecode")}},
	})
	var output map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &output); err != nil {
		t.Fatalf("hook exit %d stdout %q stderr %q: %v", code, stdout.String(), stderr.String(), err)
	}
	if code != 0 {
		t.Fatalf("hook exit %d, want 0 with a structured denial (stderr %q)", code, stderr.String())
	}
	// The reason is the gateway's, so the runner relayed the gateway's own
	// native output rather than replacing an output it could not use.
	assertClaudeCodePreToolUseDenial(t, output)
}

// Review of G-flood-wal round 2 (P2): the sandbox recorded a hook's verdict
// before its audit write failed, so a call the agent was refused showed as
// allowed in the sandbox's record. It now records the verdict the agent got.
func TestHookAuditFailureRecordsTheSandboxDecisionTheAgentGot(t *testing.T) {
	fixture := newAuditFailureHookFixture(t, "")
	fixture.emitter.fail = true
	sink := &sandboxRelayDecisionSink{}
	ctx := sandboxauth.WithRequest(t.Context(), sandboxauth.Binding{ID: "binding-1", SandboxName: "sbx", Connector: "claudecode"}, nil)
	ctx = context.WithValue(ctx, sandboxRelayStateKey{}, &sandboxRelayState{sink: sink})
	req := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse", SessionID: "s-sbx", ToolName: "Bash",
		ToolInvocationID: "toolu-sbx", Payload: map[string]interface{}{"tool_name": "Bash", "tool_input": map[string]interface{}{"command": "echo ok"}}}
	allow := agentHookResponse{Action: "allow", RawAction: "allow", Mode: "action", EvaluationID: "eval-sbx"}
	result := fixture.api.finalizeAgentHook(ctx, "claudecode", req, allow, nil, preToolUseBody(t, "toolu-sbx"), time.Millisecond, false, nil)
	if !result.AuditFailedClosed || result.Response.Action != "block" {
		t.Fatalf("sandbox PreToolUse with a failed audit write: %+v", result)
	}
	raw, ok := sink.trailer()
	decision := sandboxrelay.ParseHookDecision(raw)
	if !ok || decision == nil || decision.Action != "block" {
		t.Fatalf("sandbox decision %q; want the block the agent got", raw)
	}
}
