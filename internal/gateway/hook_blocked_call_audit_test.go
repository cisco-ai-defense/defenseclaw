// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
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
			// Only the hook's own block of a pre-execution event is the
			// call's verdict (GAP-0271 review).
			if id := strings.TrimSpace(event.ToolID); id != "" && strings.Contains(event.Details, "hook blocked the call itself") {
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
		if err := reportHookFailureCallsIn(logDir, fixture.api.logger, time.Now().UTC()); err != nil {
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
	if err := reportHookFailureCallsIn(logDir, logger, now); err != nil {
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

// blockedHookLine is a hook-failures.jsonl line of a call the hook blocked
// itself, as the 1.0.7 hooks write it.
func blockedHookLine(ts, event, session, toolID string) string {
	return fmt.Sprintf(`{"ts":%q,"connector":"claudecode","hook":"claude-code-hook","event":%q,"reason":"gateway did not answer in time","category":"transport","fail_mode":"open","outcome":"fail_closed","session_id":%q,"call_id":%q,"tool_id":%q}`+"\n",
		ts, event, session, toolID, toolID)
}

// GAP-0271 review, P2: Claude Code allowed a PreToolUse and the tool ran;
// the PostToolUse of the same call (same tool_use_id) then failed closed.
// Its row said "the agent got this block" under the tool id of a call that
// ran. A post-execution block now says the tool had already run, names the
// event, and is not the call's verdict.
func TestPostExecutionHookBlockIsNotTheVerdictOfACallThatRan(t *testing.T) {
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
	const ran, blocked = "toolu_0271_ran", "toolu_0271_pre"
	var stdout, stderr bytes.Buffer
	if code := hookexec.Run(t.Context(), hookexec.Options{
		Connector: "claudecode", Event: "PreToolUse", APIAddr: "127.0.0.1:8787", FailMode: "open",
		Home: home, HookDir: hookDir, Stdin: bytes.NewReader(preToolUseBody(t, ran)),
		Stdout: &stdout, Stderr: &stderr, HTTPClient: &http.Client{Transport: handlerTransport{handler: fixture.api.handleAgentHook("claudecode")}},
	}); code != 0 || strings.Contains(stdout.String(), "deny") {
		t.Fatalf("PreToolUse: exit %d %q %q, want the gateway's allow", code, stdout.String(), stderr.String())
	}
	logDir := filepath.Join(home, "logs")
	now := time.Now().UTC()
	appendHookFailures(t, logDir,
		blockedHookLine(now.Format(time.RFC3339), "PostToolUse", "s-audit-"+ran, ran),
		blockedHookLine(now.Format(time.RFC3339), "PreToolUse", "s-pre", blocked),
		blockedHookLine(now.Format(time.RFC3339), "UserPromptSubmit", "s-prompt", ""),
	)
	if err := reportHookFailureCallsIn(logDir, fixture.api.logger, now); err != nil {
		t.Fatal(err)
	}
	if got := deliveredVerdicts(t, fixture.api.store); got[ran] != "allow" || got[blocked] != "block" {
		t.Fatalf("verdicts = %v, want %s allow (it ran) and %s block", got, ran, blocked)
	}
	events, err := fixture.api.store.ListEvents(500)
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]audit.Event{}
	for _, event := range events {
		if event.Action == string(audit.ActionGuardrailBlock) {
			rows[event.Target] = event
		}
	}
	post, pre, prompt := rows["claudecode:PostToolUse"], rows["claudecode:PreToolUse"], rows["claudecode:UserPromptSubmit"]
	if post.ToolID != ran || !strings.Contains(post.Details, "the tool had already run; the hook blocked its result (fail-closed, PostToolUse)") ||
		strings.Contains(post.Details, "agent got this block") {
		t.Fatalf("PostToolUse row = %+v, want it to say the tool had already run", post)
	}
	if pre.ToolID != blocked || !strings.Contains(pre.Details, "hook blocked the call itself (fail-closed, PreToolUse): the agent got this block") {
		t.Fatalf("PreToolUse row = %+v", pre)
	}
	if !strings.Contains(prompt.Details, "hook blocked its UserPromptSubmit event itself (fail-closed), not a tool call") {
		t.Fatalf("UserPromptSubmit row = %+v", prompt)
	}
}

// Review note 5: after a long strict or install-window outage the backlog
// (up to 16 MiB of lines) was written row by row on the audit writer the
// resuming hooks need, so one run writes at most hookFailureRowsPerReport
// rows. rel-1-0-6:GAP-0370: the rest got one summary row and never their own
// rows, so after a par-128 flood 691 calls the agent saw denied kept only
// their allow row. A capped run now leaves the rest to the next one, which
// records them once; the fail-open alert counts the unchecked call once.
func TestHookFailureReportLeavesTheCallsOverItsCapToTheNextRun(t *testing.T) {
	previous := hookFailureRowsPerReport
	hookFailureRowsPerReport = 3
	t.Cleanup(func() { hookFailureRowsPerReport = previous })
	store, logger := testStoreAndLogger(t)
	logDir := filepath.Join(t.TempDir(), "logs")
	now := time.Date(2026, 11, 1, 4, 0, 0, 0, time.UTC)
	for i := range 5 {
		appendHookFailures(t, logDir, blockedHookLine("2026-11-01T03:59:00Z", "PreToolUse", "s", fmt.Sprintf("toolu_cap_%d", i)))
	}
	appendHookFailures(t, logDir,
		`{"ts":"2026-11-01T03:59:01Z","connector":"claudecode","hook":"claude-code-hook","event":"PreToolUse","reason":"gateway unreachable","category":"transport","fail_mode":"open","outcome":"fail_open","session_id":"s","call_id":"open-1"}`+"\n")
	count := func() (blocks, warns int, tools map[string]int) {
		events, err := store.ListEvents(200)
		if err != nil {
			t.Fatal(err)
		}
		tools = map[string]int{}
		for _, event := range events {
			switch event.Action {
			case string(audit.ActionGuardrailBlock):
				blocks++
				tools[event.ToolID]++
			case string(audit.ActionGuardrailWarn):
				if strings.HasPrefix(event.Details, "hook failure report:") {
					t.Fatalf("summary row instead of the calls' own rows: %+v", event)
				}
				warns++
			}
		}
		return
	}
	if err := reportHookFailureCallsIn(logDir, logger, now); err != nil {
		t.Fatal(err)
	}
	if blocks, warns, _ := count(); blocks != 3 || warns != 0 || !readHookFailuresReported(logDir).AuditPending {
		t.Fatalf("first run: blocks=%d warns=%d pending=%t, want the 3 rows of its cap and the rest pending",
			blocks, warns, readHookFailuresReported(logDir).AuditPending)
	}
	for range 2 {
		if err := reportHookFailureCallsIn(logDir, logger, now); err != nil {
			t.Fatal(err)
		}
	}
	blocks, warns, tools := count()
	if blocks != 5 || warns != 1 || readHookFailuresReported(logDir).AuditPending {
		t.Fatalf("after the backlog: blocks=%d warns=%d pending=%t, want every call's own row", blocks, warns,
			readHookFailuresReported(logDir).AuditPending)
	}
	for i := range 5 {
		if id := fmt.Sprintf("toolu_cap_%d", i); tools[id] != 1 {
			t.Fatalf("tool %s has %d block rows, want 1 (rows %v)", id, tools[id], tools)
		}
	}
	if alerts := degradedAlerts(t, store); len(alerts) != 1 || !strings.Contains(alerts[0].Details, "1 claudecode hook call") {
		t.Fatalf("fail-open alert = %+v, want the one unchecked call counted once", alerts)
	}
}

// rel-1-0-6:GAP-0370: a running gateway reported only when hook-failures.jsonl
// changed, so the calls a capped run left after the flood's last line were
// never recorded. It goes on every hookFailureBacklogInterval while a run
// left calls pending, also when no line was added.
func TestRunningGatewayRecordsTheWholeHookFailureBacklog(t *testing.T) {
	previous, interval, backlog := hookFailureRowsPerReport, hookFailOpenReportInterval, hookFailureBacklogInterval
	hookFailureRowsPerReport, hookFailOpenReportInterval, hookFailureBacklogInterval = 2, 10*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() {
		hookFailureRowsPerReport, hookFailOpenReportInterval, hookFailureBacklogInterval = previous, interval, backlog
	})
	store, logger := testStoreAndLogger(t)
	dataDir := t.TempDir()
	ts := time.Now().UTC().Format(time.RFC3339)
	for i := range 7 {
		appendHookFailures(t, filepath.Join(dataDir, "logs"), blockedHookLine(ts, "PreToolUse", "s", fmt.Sprintf("toolu_backlog_%d", i)))
	}
	s := &Sidecar{logger: logger, cfg: &config.Config{DataDir: dataDir}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.watchHookFailureCalls(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	blocks := func() int {
		events, err := store.ListEvents(200)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, event := range events {
			if event.Action == string(audit.ActionGuardrailBlock) {
				n++
			}
		}
		return n
	}
	deadline := time.Now().Add(20 * time.Second)
	for blocks() < 7 {
		if time.Now().After(deadline) {
			t.Fatalf("a running gateway recorded %d of the 7 hook-blocked calls", blocks())
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if n := blocks(); n != 7 {
		t.Fatalf("block rows = %d, want 7, each call once", n)
	}
}

// countingFailEmitter fails every audit emit after failAfter of them.
type countingFailEmitter struct {
	audit.RuntimeV8Emitter
	emits, failAfter atomic.Int64
}

func (emitter *countingFailEmitter) EmitRuntimeV8(
	ctx context.Context, metadata router.Metadata, builder audit.RuntimeV8Builder,
) (audit.RuntimeV8EmitOutcome, error) {
	if limit := emitter.failAfter.Load(); limit > 0 && emitter.emits.Load() >= limit {
		return audit.RuntimeV8EmitOutcome{}, errors.New("audit: persist runtime record: database is locked (5) (SQLITE_BUSY)")
	}
	emitter.emits.Add(1)
	return emitter.RuntimeV8Emitter.EmitRuntimeV8(ctx, metadata, builder)
}

// Review note 3 (mutant M2 survived): a run whose second row write fails
// keeps Offset and records how far its rows got (AuditOffset). The next run
// reads the same lines again and must not record the first call twice.
func TestHookFailureReportDoesNotRecordACallTwiceAfterAFailedWrite(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	emitter := &countingFailEmitter{RuntimeV8Emitter: &sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints}}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(emitter)
	now := time.Date(2026, 11, 1, 4, 0, 0, 0, time.UTC)
	// How many emits one row takes.
	probe := filepath.Join(t.TempDir(), "logs")
	appendHookFailures(t, probe, blockedHookLine("2026-11-01T03:59:00Z", "PreToolUse", "s", "toolu_probe"))
	if err := reportHookFailureCallsIn(probe, logger, now); err != nil {
		t.Fatal(err)
	}
	perRow := emitter.emits.Load()
	if perRow == 0 {
		t.Fatal("a hook failure row made no audit emit")
	}
	logDir := filepath.Join(t.TempDir(), "logs")
	appendHookFailures(t, logDir,
		blockedHookLine("2026-11-01T03:59:01Z", "PreToolUse", "s", "toolu_first"),
		blockedHookLine("2026-11-01T03:59:02Z", "PreToolUse", "s", "toolu_second"))
	emitter.failAfter.Store(emitter.emits.Load() + perRow)
	if err := reportHookFailureCallsIn(logDir, logger, now); err == nil {
		t.Fatal("the second row's failed write was not reported")
	}
	emitter.failAfter.Store(0)
	for range 2 {
		if err := reportHookFailureCallsIn(logDir, logger, now); err != nil {
			t.Fatal(err)
		}
	}
	events, err := fixture.store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]int{}
	for _, event := range events {
		if event.Action == string(audit.ActionGuardrailBlock) {
			rows[event.ToolID]++
		}
	}
	if rows["toolu_first"] != 1 || rows["toolu_second"] != 1 {
		t.Fatalf("rows per tool id = %v, want one each", rows)
	}
}
