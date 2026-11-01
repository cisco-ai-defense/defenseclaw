// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// lateAnswerTransport lets the gateway decide and record a hook call, then
// holds the answer until the hook stops waiting for it: the decision is in
// the audit, the answer never reaches the agent. That is how a loaded host
// answers a per-user hook after its answer budget (GAP-0271).
type lateAnswerTransport struct{ handler http.Handler }

func (transport lateAnswerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	transport.handler.ServeHTTP(recorder, req.WithContext(context.WithoutCancel(req.Context())))
	select {
	case <-req.Context().Done():
		return nil, context.Cause(req.Context())
	case <-time.After(10 * time.Second):
		return recorder.Result(), nil
	}
}

// deliveredVerdicts is, per tool id, the verdict the audit says the agent
// got: a guardrail-block row of the hook's own block wins over the gateway's
// decision row.
func deliveredVerdicts(t *testing.T, store *audit.Store) map[string]string {
	t.Helper()
	events, err := store.ListEvents(500)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		switch event.Action {
		case string(audit.ActionConnectorHook):
			id := strings.TrimSpace(event.ToolID)
			if action, _ := event.Structured["action"].(string); id != "" && out[id] == "" {
				out[id] = action
			}
		case string(audit.ActionGuardrailBlock):
			if id := strings.TrimSpace(event.ToolID); id != "" {
				out[id] = "block"
			}
		}
	}
	return out
}

// GAP-0271: under an 18000-call flood, 16 benign calls came back denied to
// the agent while the audit held 17999 allow and 1 block. A per-user hook
// gives up at its answer budget and blocks the call; the gateway had already
// decided allow and recorded it. The hook's block is now in the audit, under
// the call's tool id, so the audit says what the agent got.
func TestHookBlockAfterTheAnswerBudgetIsAuditedAsTheBlockTheAgentGot(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	fixture := newAuditFailureHookFixture(t, "")
	home := t.TempDir()
	hookDir := filepath.Join(home, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".token"), []byte("DEFENSECLAW_GATEWAY_TOKEN=\"tkn\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const onTime, late = "toolu_0271_on_time", "toolu_0271_late"
	runHook := func(toolUseID string, transport http.RoundTripper, startedAt time.Time) (int, string) {
		var stdout, stderr bytes.Buffer
		code := hookexec.Run(t.Context(), hookexec.Options{
			Connector: "claudecode", Event: "PreToolUse", APIAddr: "127.0.0.1:8787", FailMode: "open",
			Home: home, HookDir: hookDir, Stdin: bytes.NewReader(preToolUseBody(t, toolUseID)),
			Stdout: &stdout, Stderr: &stderr, HTTPClient: &http.Client{Transport: transport},
			// All but 300 ms of the 3.5 s answer budget is spent, as on a
			// loaded host where the call waited for its turn.
			StartedAt: startedAt,
		})
		return code, stdout.String() + stderr.String()
	}
	handler := fixture.api.handleAgentHook("claudecode")
	if code, out := runHook(onTime, handlerTransport{handler: handler}, time.Now()); code != 0 || strings.Contains(out, "deny") {
		t.Fatalf("on-time call: exit %d %q, want the gateway's allow", code, out)
	}
	code, out := runHook(late, lateAnswerTransport{handler: handler}, time.Now().Add(-3200*time.Millisecond))
	if code == 0 && !strings.Contains(out, "deny") {
		t.Fatalf("late call: exit %d %q, want the hook's block at its answer budget", code, out)
	}
	// The injected divergence: the gateway recorded allow for both calls.
	if got := deliveredVerdicts(t, fixture.api.store); got[onTime] != "allow" || got[late] != "allow" {
		t.Fatalf("gateway rows before the report = %v, want allow for both", got)
	}
	logDir := filepath.Join(home, "logs")
	for range 2 {
		if err := reportHookFailOpenCallsIn(logDir, fixture.api.logger, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	got := deliveredVerdicts(t, fixture.api.store)
	if got[onTime] != "allow" || got[late] != "block" {
		t.Fatalf("audit verdicts = %v, want %s allow and %s block, as the agent got them", got, onTime, late)
	}
	events, err := fixture.api.store.ListEvents(500)
	if err != nil {
		t.Fatal(err)
	}
	blocks := 0
	for _, event := range events {
		if event.Action != string(audit.ActionGuardrailBlock) {
			continue
		}
		blocks++
		if event.ToolID != late || event.SessionID != "s-audit-"+late || event.RequestID != late ||
			event.Severity != "MEDIUM" || !strings.Contains(event.Details, "hook blocked the call itself") {
			t.Fatalf("hook block row = %+v", event)
		}
	}
	if blocks != 1 {
		t.Fatalf("%d hook block rows after two reports, want 1", blocks)
	}
	if alerts := degradedAlerts(t, fixture.api.store); len(alerts) != 0 {
		t.Fatalf("a call the hook blocked was reported as fail-open: %+v", alerts)
	}
}

// A hook-failure line of a 1.0.6 hook has no tool_id: its block still gets a
// row, under the call id, and a fail-open line keeps its unchecked-call row.
func TestHookBlockedCallRowWithoutAToolID(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	logDir := filepath.Join(t.TempDir(), "logs")
	now := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	appendHookFailures(t, logDir,
		`{"ts":"2026-11-01T00:59:01Z","connector":"claudecode","hook":"claude-code-hook","reason":"gateway did not answer in time","category":"transport","fail_mode":"open","outcome":"fail_closed","session_id":"s1","call_id":"123-456"}`+"\n",
		`{"ts":"2026-11-01T00:59:02Z","connector":"claudecode","hook":"claude-code-hook","reason":"gateway unreachable","category":"transport","fail_mode":"open","outcome":"fail_open","session_id":"s1","call_id":"c2","tool_id":"c2"}`+"\n",
		`{"ts":"2026-11-01T00:59:03Z","connector":"claudecode","hook":"claude-code-hook","reason":"gateway unreachable","category":"transport","fail_mode":"closed","session_id":"s1","call_id":"c3"}`+"\n",
	)
	if err := reportHookFailOpenCallsIn(logDir, logger, now); err != nil {
		t.Fatal(err)
	}
	events, err := store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	var blocks, warns []audit.Event
	for _, event := range events {
		switch event.Action {
		case string(audit.ActionGuardrailBlock):
			blocks = append(blocks, event)
		case string(audit.ActionGuardrailWarn):
			warns = append(warns, event)
		}
	}
	if len(blocks) != 1 || blocks[0].RequestID != "123-456" || blocks[0].ToolID != "" {
		t.Fatalf("hook block rows = %+v, want one under the call id and no tool id", blocks)
	}
	if len(warns) != 1 || warns[0].RequestID != "c2" || warns[0].ToolID != "" {
		t.Fatalf("unchecked-call rows = %+v, want the fail-open call only", warns)
	}
	if alerts := degradedAlerts(t, store); len(alerts) != 1 || !strings.Contains(alerts[0].Details, "1 claudecode hook call ") {
		t.Fatalf("fail-open alerts = %+v, want the one call that ran unchecked", alerts)
	}
}
