// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/google/uuid"
)

var pendingAllow = agentHookResponse{Action: "allow", Mode: "action", Severity: "NONE"}

func pendingToolRequest(session string) agentHookRequest {
	return agentHookRequest{
		ConnectorName: "claudecode", HookEventName: "PreToolUse", SessionID: session,
		ToolName: "Bash", ToolInvocationID: session + "-tool",
	}
}

// orphanPendingHook journals an offered answer as a gateway that died before
// its records would, and returns the occurrence.
func orphanPendingHook(t *testing.T, f managedHookAuditFixture, session string, proposed agentHookResponse) *pendingHookOccurrence {
	t.Helper()
	req := pendingToolRequest(session)
	p, err := f.api.journalHookDelivery(t.Context(), &req, proposed, nil, 64, time.Millisecond, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// restartedAPI is a server of the next gateway process on the same store.
func (f managedHookAuditFixture) restartedAPI(t *testing.T, bindDecisions bool) *APIServer {
	t.Helper()
	restarted := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, f.store, f.api.logger, f.api.scannerCfg)
	restarted.hookDeliveryProcessID = uuid.NewString()
	if bindDecisions {
		bindHookLifecycleV8(t, restarted, f.runtime)
	}
	return restarted
}

// runAPIUntil runs the API and fails if it stops before cond holds, or within
// a short window after it holds: recovery must never end Run.
func runAPIUntil(t *testing.T, a *APIServer, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached while the gateway served")
		}
		select {
		case err := <-runDone:
			t.Fatalf("gateway stopped during hook delivery recovery: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	select {
	case err := <-runDone:
		t.Fatalf("gateway stopped after hook delivery recovery: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	cancel()
	<-runDone
}

func (f managedHookAuditFixture) hookRows(t *testing.T, session string) int {
	t.Helper()
	rows, err := f.store.ListEvents(1000)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, row := range rows {
		if row.Action == string(audit.ActionConnectorHook) && row.SessionID == session {
			count++
		}
	}
	return count
}

// journalEntries is every journal row, of any process, oldest first.
func journalEntries(t *testing.T, f managedHookAuditFixture) []audit.HookDeliveryJournalEntry {
	t.Helper()
	var all []audit.HookDeliveryJournalEntry
	var after audit.HookDeliveryJournalEntry
	for {
		entries, err := f.store.HookDeliveries(t.Context(), after, 100)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, entries...)
		if len(entries) < 100 {
			return all
		}
		after = entries[len(entries)-1]
	}
}

// pendingEntries is the id of every journal row, of any process.
func pendingEntries(t *testing.T, f managedHookAuditFixture) []string {
	t.Helper()
	entries := journalEntries(t, f)
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		ids = append(ids, entry.ID)
	}
	return ids
}

// refuseAuditInserts makes the store refuse inserts into table that match
// when (a SQL condition on NEW), until the returned function lifts it.
func refuseAuditInserts(t *testing.T, f managedHookAuditFixture, table, when string) func() {
	t.Helper()
	return refuseAuditWrites(t, f, "INSERT", table, when)
}

// refuseAuditWrites makes the store refuse the statements of kind (INSERT
// or UPDATE) on table that match when, until the returned function lifts
// it.
func refuseAuditWrites(t *testing.T, f managedHookAuditFixture, kind, table, when string) func() {
	t.Helper()
	database, err := sql.Open("sqlite", f.path)
	if err != nil {
		t.Fatal(err)
	}
	name := "test_refuse_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := database.Exec(`CREATE TRIGGER ` + name + ` BEFORE ` + kind + ` ON ` + table + `
		WHEN ` + when + `
		BEGIN SELECT RAISE(ABORT, 'refused by the test'); END`); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	return func() {
		defer database.Close()
		if _, err := database.Exec(`DROP TRIGGER IF EXISTS ` + name); err != nil {
			t.Fatal(err)
		}
	}
}

// refuseConnectorHookAuditRows makes the store refuse connector audit rows,
// not hook_decision records, until the returned function lifts it.
func refuseConnectorHookAuditRows(t *testing.T, f managedHookAuditFixture) func() {
	t.Helper()
	return refuseAuditInserts(t, f, "audit_events", `NEW.action = '`+string(audit.ActionConnectorHook)+`'`)
}

// refuseHookDeliveryJournal makes the store refuse journal rows, as a full
// or read-only store does, until the returned function lifts it.
func refuseHookDeliveryJournal(t *testing.T, f managedHookAuditFixture) func() {
	t.Helper()
	// The table is created on first use.
	if err := f.store.JournalHookDelivery(t.Context(), "create", "test", []byte("{}"), 1); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ForgetHookDelivery(t.Context(), "create"); err != nil {
		t.Fatal(err)
	}
	return refuseAuditInserts(t, f, "hook_delivery_journal", "1")
}

// refuseHookDeliveryDecision makes the store refuse to record the decision
// of a journal row, until the returned function lifts it.
func refuseHookDeliveryDecision(t *testing.T, f managedHookAuditFixture) func() {
	t.Helper()
	if err := f.store.JournalHookDelivery(t.Context(), "create", "test", []byte("{}"), 1); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ForgetHookDelivery(t.Context(), "create"); err != nil {
		t.Fatal(err)
	}
	return refuseAuditWrites(t, f, "UPDATE", "hook_delivery_journal", "1")
}

// ackedHookCall sends one claudecode tool call whose hook acknowledges the
// answer it got.
func ackedHookCall(t *testing.T, api *APIServer, session string, w http.ResponseWriter) {
	t.Helper()
	body := managedHookBody(session, "PreToolUse")
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook",
		strings.NewReader(body+hookexec.HookDeliveryReceiptAck))
	request.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
	request.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len(body)))
	request.Header.Set("Content-Type", "application/json")
	api.handleAgentHook("claudecode").ServeHTTP(w, request)
}

// Stop the handler after its occurrence is journaled and before the answer
// is offered: offer sets the receipt deadline first.
type exitBeforeHookAnswerWriter struct{ *httptest.ResponseRecorder }

func (w *exitBeforeHookAnswerWriter) EnableFullDuplex() error { return nil }
func (w *exitBeforeHookAnswerWriter) SetReadDeadline(time.Time) error {
	runtime.Goexit()
	return nil
}

// A gateway that dies after journaling a call and before offering its
// answer leaves exactly one journal row and no answer, and the next process
// audits the call once: the closed hook took its fallback, which the
// gateway cannot tell from an answer it never sent, so it is unconfirmed.
func TestPendingHookSurvivesGatewayDeathBeforeTheAnswer(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	const session = "died-before-answer"
	reply := &exitBeforeHookAnswerWriter{ResponseRecorder: httptest.NewRecorder()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ackedHookCall(t, f.api, session, reply)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not reach the answer")
	}
	if strings.Contains(reply.Body.String(), `"action"`) {
		t.Fatalf("an answer left the gateway before it died: %q", reply.Body.String())
	}
	if left := pendingEntries(t, f); len(left) != 1 {
		t.Fatalf("journal rows = %v, want one", left)
	}
	if rows := f.hookRows(t, session); rows != 0 {
		t.Fatalf("connector rows before the restart = %d, want none", rows)
	}
	runAPIUntil(t, f.restartedAPI(t, true), func() bool { return len(pendingEntries(t, f)) == 0 })
	if got := f.audited(t, session)[session]; got != "unconfirmed/no_answer" {
		t.Fatalf("recovered audit = %q, want unconfirmed/no_answer", got)
	}
	if got := f.decisions(t); strings.Join(got, ",") != "unconfirmed/ok" {
		t.Fatalf("hook_decision records = %v, want [unconfirmed/ok]", got)
	}
	if rows := f.hookRows(t, session); rows != 1 {
		t.Fatalf("connector rows = %d, want one", rows)
	}
}

// Without a durable journal row no answer is offered: the call is answered
// 503, which a managed hook resolves closed, and the block it enforces is
// the only record under the occurrence IDs. That holds when the audit is
// refused too (nothing is recorded, nothing is left behind, and the gateway
// keeps serving), and when the journal row landed although the write
// reported a failure: recovery then completes the block, never a second
// decision.
func TestPendingHookUnwritableStoreNeverOffersAnAnswer(t *testing.T) {
	for _, tc := range []struct {
		name         string
		refuseAudit  bool
		rowLanded    bool
		want         string
		wantDecision string
	}{
		{"journal refused", false, false, "block/no_answer", "block/ok"},
		{"journal row landed anyway", false, true, "block/no_answer", "block/ok"},
		{"journal and audit refused", true, false, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newManagedHookAuditFixture(t, nil)
			session := "unwritable-" + strings.ReplaceAll(tc.name, " ", "-")
			liftJournal := refuseHookDeliveryJournal(t, f)
			liftAudit := func() {}
			if tc.refuseAudit {
				liftAudit = refuseAuditInserts(t, f, "audit_events", "1")
			}
			reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
			ackedHookCall(t, f.api, session, reply)
			liftAudit()
			liftJournal()
			if reply.finalStatus != http.StatusServiceUnavailable || strings.Contains(reply.Body.String(), `"action"`) {
				t.Fatalf("response = status %d body %q, want 503 and no answer", reply.finalStatus, reply.Body.String())
			}
			if left := pendingEntries(t, f); len(left) != 0 {
				t.Fatalf("journal rows = %v, want none", left)
			}
			if tc.rowLanded {
				// The row of the refused write, as a commit that reported
				// an error would have left it.
				rows, err := f.store.ListEvents(50)
				if err != nil {
					t.Fatal(err)
				}
				id := ""
				for _, row := range rows {
					if row.Action == string(audit.ActionConnectorHook) && row.SessionID == session {
						id = row.ID
					}
				}
				req := pendingToolRequest(session)
				data, err := json.Marshal(pendingHookOccurrence{
					ID: id, Request: pendingRequest(req), Proposed: pendingResponse(pendingAllow),
					NoReceipt: pendingResponse(unconfirmedHookDelivery(pendingAllow)), BodyBytes: 64,
				})
				if err != nil || id == "" {
					t.Fatalf("connector row id %q: %v", id, err)
				}
				if err := f.store.JournalHookDelivery(t.Context(), id, "the failed process", data, 1); err != nil {
					t.Fatal(err)
				}
				f.restartedAPI(t, true).recoverPendingHooks(t.Context())
			}
			got, decisions := f.audited(t, session)[session], strings.Join(f.decisions(t), ",")
			if got != tc.want || decisions != tc.wantDecision {
				t.Fatalf("records: connector %q, hook_decision %q; want %q, %q", got, decisions, tc.want, tc.wantDecision)
			}
			if want := map[bool]int{false: 1, true: 0}[tc.refuseAudit]; f.hookRows(t, session) != want {
				t.Fatalf("connector rows = %d, want %d", f.hookRows(t, session), want)
			}
			if left := pendingEntries(t, f); len(left) != 0 {
				t.Fatalf("journal rows after recovery = %v, want none", left)
			}
			// The gateway still answers the next call.
			next := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
			ackedHookCall(t, f.api, session+"-next", next)
			if !strings.Contains(next.Body.String(), hookexec.HookDeliveryConfirmed) {
				t.Fatalf("next call = %q, want a confirmed answer", next.Body.String())
			}
		})
	}
}

// An occurrence the audit cannot take yet (hook_decision not admitted) stays
// journaled while the gateway serves, and a later start audits it once.
func TestPendingHookRecoveryKeepsServingWhenTheAuditIsNotReady(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	const session = "audit-not-ready"
	orphanPendingHook(t, f, session, pendingAllow)

	runAPIUntil(t, f.restartedAPI(t, false), func() bool { return f.hookRows(t, session) == 1 })
	if left := pendingEntries(t, f); len(left) != 1 {
		t.Fatalf("journal rows = %v, want the one whose hook_decision was not persisted", left)
	}

	runAPIUntil(t, f.restartedAPI(t, true), func() bool { return len(pendingEntries(t, f)) == 0 })
	if got := f.hookRows(t, session); got != 1 {
		t.Fatalf("connector audit rows = %d, want one", got)
	}
	if got := f.decisions(t); strings.Join(got, ",") != "unconfirmed/ok" {
		t.Fatalf("hook_decision records = %v, want [unconfirmed/ok]", got)
	}
}

// Hold the handler right after it confirms the hook's receipt, before its
// terminal audit.
type pauseAfterHookConfirmationWriter struct {
	*httptest.ResponseRecorder
	paused, resume chan struct{}
	once           sync.Once
}

func (w *pauseAfterHookConfirmationWriter) EnableFullDuplex() error         { return nil }
func (w *pauseAfterHookConfirmationWriter) SetReadDeadline(time.Time) error { return nil }
func (w *pauseAfterHookConfirmationWriter) Flush() {
	w.ResponseRecorder.Flush()
	if strings.Contains(w.Body.String(), hookexec.HookDeliveryConfirmed) {
		w.once.Do(func() {
			close(w.paused)
			<-w.resume
		})
	}
}

// A config reload starts a new APIServer in the same process while a hook
// handler of the old one is still finishing. The new server's recovery must
// leave that handler's journal row alone, so the audit keeps the
// acknowledged allow instead of an unconfirmed takeover.
func TestPendingHookRecoveryLeavesLiveHandlersOfThisProcessAlone(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	const session = "live-during-api-restart"
	reply := &pauseAfterHookConfirmationWriter{
		ResponseRecorder: httptest.NewRecorder(),
		paused:           make(chan struct{}), resume: make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ackedHookCall(t, f.api, session, reply)
	}()
	select {
	case <-reply.paused:
	case <-time.After(10 * time.Second):
		t.Fatal("gateway did not confirm the receipt")
	}
	live := pendingEntries(t, f)

	reloaded := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, f.store, f.api.logger, f.api.scannerCfg)
	bindHookLifecycleV8(t, reloaded, f.runtime)
	reloaded.recoverPendingHooks(t.Context())
	takenOver := f.audited(t, session)[session]
	stillThere := len(pendingEntries(t, f))
	close(reply.resume)
	<-done
	if len(live) != 1 || takenOver != "" || stillThere != 1 {
		t.Fatalf("recovery during a live handler: journal %v, audit %q, rows kept %d; want one row kept and no audit",
			live, takenOver, stillThere)
	}
	if got := f.audited(t, session)[session]; got != "allow" {
		t.Fatalf("audit after the handler finished = %q, want allow", got)
	}
	if got := f.hookRows(t, session); got != 1 {
		t.Fatalf("connector audit rows = %d, want one", got)
	}
	if got := f.decisions(t); strings.Join(got, ",") != "allow/ok" {
		t.Fatalf("hook_decision records = %v, want [allow/ok]", got)
	}
	if left := pendingEntries(t, f); len(left) != 0 {
		t.Fatalf("journal rows left after the handler finalized = %v", left)
	}
}

// A journal write failure answers 503 without offering the evaluated
// answer; the managed hook resolves that closed in every fail mode.
func TestPendingFailureHookDecisionIsTheClosedFallback(t *testing.T) {
	allow := pendingFailureHookDecision(agentHookResponse{Action: "allow", Reason: "evaluated"})
	if allow.Action != "block" || allow.RawAction != "allow" || allow.Reason != hookexec.ManagedGatewayNoAnswerReason {
		t.Fatalf("allow after journal failure = %+v, want closed fallback", allow)
	}
	block := pendingFailureHookDecision(agentHookResponse{Action: "block", Reason: "policy rule"})
	if block.Action != "block" || block.Reason != "policy rule" {
		t.Fatalf("policy block after journal failure = %+v, want the policy block", block)
	}
	for _, action := range []string{"alert", "warn", hookActionUnconfirmed} {
		if got := pendingFailureHookDecision(agentHookResponse{Action: action}); got.Action != "block" {
			t.Fatalf("%s after journal failure = %q, want block", action, got.Action)
		}
	}
}

// A call without a receipt keeps a policy block under a closed hook: the
// hook blocks whether the answer reached it or it took its fallback. So a
// recovered policy block is audited as the block, not as unconfirmed.
// Anything the receipt alone could prove is unconfirmed.
func TestPendingHookNoReceiptDecisionKeepsAClosedPolicyBlock(t *testing.T) {
	policyBlock := agentHookResponse{Action: "block", RawAction: "block", Mode: "action", Severity: "HIGH"}
	for _, tc := range []struct {
		name     string
		mode     string
		proposed agentHookResponse
		want     string
	}{
		{"closed policy block", "closed", policyBlock, "block"},
		{"closed allow", "closed", pendingAllow, "unconfirmed/no_answer"},
		{"open policy block", "open", policyBlock, "unconfirmed/no_answer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newManagedHookAuditFixture(t, nil)
			f.api.scannerCfg.Guardrail.HookFailMode = tc.mode
			session := "no-receipt-" + strings.ReplaceAll(tc.name, " ", "-")
			orphanPendingHook(t, f, session, tc.proposed)
			f.restartedAPI(t, true).recoverPendingHooks(t.Context())
			if got := f.audited(t, session)[session]; got != tc.want {
				t.Fatalf("recovered audit = %q, want %q", got, tc.want)
			}
			if left := pendingEntries(t, f); len(left) != 0 {
				t.Fatalf("journal rows after recovery = %v, want none", left)
			}
		})
	}
}

// With guardrail.evaluation log collection off no hook_decision record is
// ever kept, so none can hold a journal row back: once the audit logger has
// taken the connector row (the same collection policy keeps it out of the
// local store), the row is settled, on the live path and in recovery.
func TestPendingHookSettlesWhenHookDecisionCollectionIsOff(t *testing.T) {
	f := newManagedHookAuditFixtureCollectingNo(t, nil, observability.BucketGuardrailEvaluation)
	sessions := []string{"collection-off-1", "collection-off-2", "collection-off-3"}
	for _, session := range sessions {
		reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
		ackedHookCall(t, f.api, session, reply)
		if !strings.Contains(reply.Body.String(), hookexec.HookDeliveryConfirmed) {
			t.Fatalf("%s: gateway response = %q, want the receipt confirmation", session, reply.Body.String())
		}
	}
	if left := pendingEntries(t, f); len(left) != 0 {
		t.Fatalf("journal rows after acknowledged calls = %v, want none", left)
	}
	audited := f.audited(t, sessions...)
	for _, session := range sessions {
		if got := audited[session]; got != "" && got != "allow" {
			t.Fatalf("%s: audit = %q, want allow or no local row", session, got)
		}
	}
	if got := f.decisions(t); len(got) != 0 {
		t.Fatalf("hook_decision records = %v, want none with collection off", got)
	}

	const recovered = "collection-off-recovered"
	orphanPendingHook(t, f, recovered, pendingAllow)
	f.restartedAPI(t, true).recoverPendingHooks(t.Context())
	if left := pendingEntries(t, f); len(left) != 0 {
		t.Fatal("recovery kept a journal row whose hook_decision is not collected")
	}
	if got := f.audited(t, recovered)[recovered]; got != "" && got != "unconfirmed/no_answer" {
		t.Fatalf("recovered audit = %q, want unconfirmed/no_answer or no local row", got)
	}
}

type fixedHookDecisionEmitter struct {
	outcome pipeline.LocalLogOutcome
	err     error
}

func (e fixedHookDecisionEmitter) Emit(
	context.Context, router.Metadata, observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	return e.outcome, e.err
}

// A hook_decision result holds a journal row only while a retry can still
// keep the record.
func TestHookDecisionLogResultSettlesOnlyWhatARetryCannotChange(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	req := pendingToolRequest("decision-results")
	for _, tc := range []struct {
		name    string
		emitter sidecarRuntimeEmitter
		resp    agentHookResponse
		want    hookDecisionLogResult
	}{
		{"persisted", f.runtime, pendingAllow, hookDecisionLogPersisted},
		{"runtime not bound", nil, pendingAllow, hookDecisionLogFailed},
		{"local write failed", fixedHookDecisionEmitter{err: errors.New("disk full")}, pendingAllow, hookDecisionLogFailed},
		{"collection off", fixedHookDecisionEmitter{}, pendingAllow, hookDecisionLogNotCollected},
		{"managed-only projection", fixedHookDecisionEmitter{
			outcome: pipeline.NewManagedOptionalFailureOutcomeForTest(pipeline.OptionalFailureOutputLimit),
		}, pendingAllow, hookDecisionLogNotCollected},
		{"invalid severity", f.runtime, agentHookResponse{Action: "allow", Mode: "action", Severity: "not-a-severity"},
			hookDecisionLogUnbuildable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := f.restartedAPI(t, false)
			if tc.emitter != nil {
				bindHookLifecycleV8(t, api, tc.emitter)
			}
			got := api.emitHookDecisionObservabilityV8(t.Context(), req, tc.resp, HookAuditEnvelope{ElapsedMs: 1}, false)
			if got != tc.want || got.settled() != (tc.want != hookDecisionLogFailed) {
				t.Fatalf("result = %d (settled %t), want %d", got, got.settled(), tc.want)
			}
		})
	}
}

// busyHookDecisionEmitter holds every hook_decision record until release
// is closed, as a busy audit store does.
type busyHookDecisionEmitter struct {
	inner   sidecarRuntimeEmitter
	seen    atomic.Int32
	release chan struct{}
}

func (e *busyHookDecisionEmitter) Emit(
	ctx context.Context, metadata router.Metadata, builder observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	if metadata.Identity().Name == observability.EventName(observability.TelemetryEventHookDecision) {
		e.seen.Add(1)
		select {
		case <-e.release:
		case <-ctx.Done():
			return pipeline.LocalLogOutcome{}, ctx.Err()
		}
	}
	return e.inner.Emit(ctx, metadata, builder)
}

// Recovery behind a busy audit store does not hold the listeners: the
// sandbox ingress serves while recovery waits, and the rows are audited once
// the store frees up.
func TestPendingHookRecoveryDoesNotHoldListenersBehindABusyAudit(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	var sessions []string
	for i := range 3 {
		session := fmt.Sprintf("busy-%d", i)
		orphanPendingHook(t, f, session, pendingAllow)
		sessions = append(sessions, session)
	}
	busy := &busyHookDecisionEmitter{inner: f.runtime, release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(busy.release) }) }
	defer release()
	restarted := f.restartedAPI(t, false)
	bindHookLifecycleV8(t, restarted, busy)
	if err := restarted.SetSandboxIngress(SandboxIngressConfig{
		Addr: "127.0.0.1:18971", Bindings: pendingHookRejectBindings{},
	}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- restarted.RunSandboxIngressOn(ctx, listener) }()
	deadline := time.Now().Add(10 * time.Second)
	for busy.seen.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Get("http://" + listener.Addr().String() + "/health")
	if err != nil {
		t.Fatalf("sandbox ingress did not serve while recovery waited on the audit: %v", err)
	}
	_ = response.Body.Close()
	if left := pendingEntries(t, f); len(left) != 3 {
		t.Fatalf("journal rows while serving = %v, want all three still waiting", left)
	}
	release()
	for len(pendingEntries(t, f)) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("journal rows left after the audit freed up: %v", pendingEntries(t, f))
		}
		select {
		case err := <-runDone:
			t.Fatalf("gateway stopped during background recovery: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	audited := f.audited(t, sessions...)
	for _, session := range sessions {
		if audited[session] != "unconfirmed/no_answer" {
			t.Fatalf("%s: recovered audit = %q, want unconfirmed/no_answer", session, audited[session])
		}
	}
	cancel()
	<-runDone
}

// The connector audit row and the hook_decision of one call never disagree
// when the next process writes what the live handler could not, and they
// keep the decision the hook enforced, which the journal row records before
// the live handler writes them. Only when that record was refused too does a
// stored record decide its companion, and with neither stored both say
// unconfirmed.
func TestPendingHookTerminalRecordsAgreeWhenTheAuditRowIsRecovered(t *testing.T) {
	for _, tc := range []struct {
		name           string
		refuseAll      bool
		refuseDecision bool
		want           string
		wantDecision   string
	}{
		{"connector row refused", false, false, "allow", "allow/ok"},
		{"both records refused", true, false, "allow", "allow/ok"},
		{"connector row and the decision refused", false, true, "allow", "allow/ok"},
		{"both records and the decision refused", true, true, "unconfirmed/no_answer", "unconfirmed/ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newManagedHookAuditFixture(t, nil)
			session := "agree-" + strings.ReplaceAll(tc.name, " ", "-")
			var lift func()
			if tc.refuseAll {
				lift = refuseAuditInserts(t, f, "audit_events", "1")
			} else {
				lift = refuseConnectorHookAuditRows(t, f)
			}
			liftDecision := func() {}
			if tc.refuseDecision {
				liftDecision = refuseHookDeliveryDecision(t, f)
			}
			reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
			ackedHookCall(t, f.api, session, reply)
			lift()
			liftDecision()
			if !strings.Contains(reply.Body.String(), hookexec.HookDeliveryConfirmed) {
				t.Fatalf("gateway response = %q, want the receipt confirmation", reply.Body.String())
			}
			if got := f.audited(t, session)[session]; got != "" {
				t.Fatalf("audit row written although the store refused it: %q", got)
			}
			if left := pendingEntries(t, f); len(left) != 1 {
				t.Fatalf("journal rows = %v, want the one whose audit row failed", left)
			}
			f.restartedAPI(t, true).recoverPendingHooks(t.Context())
			if got := f.audited(t, session)[session]; got != tc.want {
				t.Fatalf("recovered audit = %q, want %q", got, tc.want)
			}
			if got := strings.Join(f.decisions(t), ","); got != tc.wantDecision {
				t.Fatalf("hook_decision records = %q, want %q", got, tc.wantDecision)
			}
			if left := pendingEntries(t, f); len(left) != 0 {
				t.Fatalf("journal rows after recovery = %v, want none", left)
			}
		})
	}
}

// A record of the occurrence that is already stored decides its missing
// companion, whatever the live handler recorded: the acknowledged allow,
// the closed fallback, or unconfirmed.
func TestPendingHookRecoveryTakesAStoredRecordAsTheAuthority(t *testing.T) {
	for _, tc := range []struct {
		name         string
		stored       agentHookResponse
		decisionOnly bool
		want         string
		wantDecision string
	}{
		{"connector row allow", pendingAllow, false, "allow", "allow/ok"},
		{"hook_decision allow", pendingAllow, true, "allow", "allow/ok"},
		{"connector row closed fallback", pendingFailureHookDecision(pendingAllow), false, "block/no_answer", "block/ok"},
		{"hook_decision closed fallback", pendingFailureHookDecision(pendingAllow), true, "block/no_answer", "block/ok"},
		{"connector row unconfirmed", unconfirmedHookDelivery(pendingAllow), false, "unconfirmed/no_answer", "unconfirmed/ok"},
		{"hook_decision unconfirmed", unconfirmedHookDelivery(pendingAllow), true, "unconfirmed/no_answer", "unconfirmed/ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newManagedHookAuditFixture(t, nil)
			session := "authority-" + strings.ReplaceAll(tc.name, " ", "-")
			p := orphanPendingHook(t, f, session, pendingAllow)
			// The live handler's records under the occurrence IDs, one of
			// them refused.
			writer := f.restartedAPI(t, tc.decisionOnly)
			lift := func() {}
			if tc.decisionOnly {
				lift = refuseConnectorHookAuditRows(t, f)
			}
			req := p.Request.request(p.ID, p.BodyBytes)
			req.pendingRecovery = false
			writer.finalizeAgentHook(enrichAgentHookContext(t.Context(), req), req.ConnectorName, req, tc.stored,
				nil, nil, time.Millisecond, false, nil)
			lift()
			if stored := len(f.decisions(t)) + f.hookRows(t, session); stored != 1 {
				t.Fatalf("stored records before recovery = %d, want one", stored)
			}

			f.restartedAPI(t, true).recoverPendingHooks(t.Context())
			got, decisions := f.audited(t, session)[session], strings.Join(f.decisions(t), ",")
			if got != tc.want || decisions != tc.wantDecision {
				t.Fatalf("records after recovery: connector %q, hook_decision %q; want %q, %q",
					got, decisions, tc.want, tc.wantDecision)
			}
			if rows := f.hookRows(t, session); rows != 1 {
				t.Fatalf("connector rows = %d, want one", rows)
			}
			if left := pendingEntries(t, f); len(left) != 0 {
				t.Fatalf("journal rows after recovery = %v, want none", left)
			}
		})
	}
}

// hookRemoteRecorder is a remote destination that keeps every record it
// gets, by record id.
type hookRemoteRecorder struct {
	mu      sync.Mutex
	records map[string][]string
}

func newHookRemoteRecorder() *hookRemoteRecorder {
	return &hookRemoteRecorder{records: map[string][]string{}}
}

func (*hookRemoteRecorder) EncodedSize(sizes []int) (int, bool) {
	return delivery.DelimitedEncodedSize(sizes, 0, 1, 0)
}

func (r *hookRemoteRecorder) Deliver(_ context.Context, batch delivery.Batch) delivery.DeliveryResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, item := range batch.Items() {
		id := item.Identity().RecordID
		r.records[id] = append(r.records[id], string(item.Bytes()))
	}
	return delivery.DeliveryResult{Outcome: delivery.OutcomeDelivered}
}

// decisions is the decision of every copy of the record id the destination
// got, in order: unconfirmed, or the delivered answer.
func (r *hookRemoteRecorder) decisions(id string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var got []string
	for _, record := range r.records[id] {
		if strings.Contains(record, hookActionUnconfirmed) {
			got = append(got, hookActionUnconfirmed)
		} else {
			got = append(got, "answer")
		}
	}
	return got
}

// settled waits for the destination to get want copies of each id, then a
// little longer, so a late extra copy is seen too.
func (r *hookRemoteRecorder) settled(t *testing.T, want int, ids ...string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ready := true
		for _, id := range ids {
			if len(r.decisions(id)) < want {
				ready = false
			}
		}
		if ready || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
}

// The remote destinations get one decision per record of a call, the one
// the local store ends up with, however the live handler's writes fail. A
// record the local store refuses still leaves for them (GAP-1536), so the
// journal row records the decision before the records are written and
// recovery replays it locally only; where that record is refused too, the
// records wait for the local store, and recovery's decision is the only one
// sent.
func TestPendingHookRemoteDestinationsGetOneDecisionPerRecord(t *testing.T) {
	for _, tc := range []struct {
		name           string
		refuseAll      bool
		refuseDecision bool
		want           string
		wantDecision   string
		live           []string // the remote decision of each record before recovery
		remote         []string // and after it
	}{
		{"connector row refused", false, false, "allow", "allow/ok", []string{"answer"}, []string{"answer"}},
		{"both records refused", true, false, "allow", "allow/ok", []string{"answer"}, []string{"answer"}},
		{"both records and the decision refused", true, true, "unconfirmed/no_answer", "unconfirmed/ok",
			nil, []string{hookActionUnconfirmed}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			remote := newHookRemoteRecorder()
			f := newManagedHookAuditFixtureExportingTo(t, nil, remote)
			session := "remote-" + strings.ReplaceAll(tc.name, " ", "-")
			var lift func()
			if tc.refuseAll {
				lift = refuseAuditInserts(t, f, "audit_events", "1")
			} else {
				lift = refuseConnectorHookAuditRows(t, f)
			}
			liftDecision := func() {}
			if tc.refuseDecision {
				liftDecision = refuseHookDeliveryDecision(t, f)
			}
			reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
			ackedHookCall(t, f.api, session, reply)
			if !strings.Contains(reply.Body.String(), hookexec.HookDeliveryConfirmed) {
				t.Fatalf("gateway response = %q, want the receipt confirmation", reply.Body.String())
			}
			entries := journalEntries(t, f)
			if len(entries) != 1 {
				t.Fatalf("journal rows = %v, want the one whose records failed", entries)
			}
			id := entries[0].ID
			ids := []string{id, id + "-decision"}
			remote.settled(t, len(tc.live), ids...)
			for _, record := range ids {
				if got := remote.decisions(record); strings.Join(got, ",") != strings.Join(tc.live, ",") {
					t.Fatalf("remote copies of %s before recovery = %v, want %v", record, got, tc.live)
				}
			}
			lift()
			liftDecision()

			f.restartedAPI(t, true).recoverPendingHooks(t.Context())
			if got, decisions := f.audited(t, session)[session], strings.Join(f.decisions(t), ","); got != tc.want || decisions != tc.wantDecision {
				t.Fatalf("records after recovery: connector %q, hook_decision %q; want %q, %q", got, decisions, tc.want, tc.wantDecision)
			}
			remote.settled(t, len(tc.remote), ids...)
			for _, record := range ids {
				if got := remote.decisions(record); strings.Join(got, ",") != strings.Join(tc.remote, ",") {
					t.Fatalf("remote copies of %s after recovery = %v, want %v", record, got, tc.remote)
				}
			}
			if left := pendingEntries(t, f); len(left) != 0 {
				t.Fatalf("journal rows after recovery = %v, want none", left)
			}
		})
	}
}

// A journal that keeps filling because the records cannot be written stops
// at its limit: the next call is answered 503, which the managed hook
// resolves closed, and nothing is journaled for it. The refusal starts a
// recovery pass in this process, so once the store takes records again the
// rows its handlers left are audited with the answers the hooks
// acknowledged, the journal empties, and calls are answered again.
func TestPendingHookFullJournalAnswersClosedAndDrains(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	rows, interval := pendingHookJournalRows, pendingHookDrainInterval
	t.Cleanup(func() { pendingHookJournalRows, pendingHookDrainInterval = rows, interval })
	pendingHookJournalRows, pendingHookDrainInterval = 2, 0
	pendingHookDrainAt.Store(0)

	lift := refuseConnectorHookAuditRows(t, f)
	sessions := []string{"full-0", "full-1"}
	for _, session := range sessions {
		reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
		ackedHookCall(t, f.api, session, reply)
		if !strings.Contains(reply.Body.String(), hookexec.HookDeliveryConfirmed) {
			t.Fatalf("%s: gateway response = %q, want the receipt confirmation", session, reply.Body.String())
		}
	}
	if left := pendingEntries(t, f); len(left) != 2 {
		t.Fatalf("journal rows = %v, want the two whose connector rows failed", left)
	}
	refused := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
	ackedHookCall(t, f.api, "full-refused", refused)
	if refused.finalStatus != http.StatusServiceUnavailable || strings.Contains(refused.Body.String(), `"action"`) {
		t.Fatalf("call past the limit = status %d body %q, want 503 and no answer", refused.finalStatus, refused.Body.String())
	}
	if left := pendingEntries(t, f); len(left) != 2 {
		t.Fatalf("journal rows after the refusal = %v, want the limit", left)
	}

	lift()
	deadline := time.Now().Add(10 * time.Second)
	for retry := 0; len(pendingEntries(t, f)) != 0; retry++ {
		if time.Now().After(deadline) {
			t.Fatalf("journal rows left after the store recovered: %v", pendingEntries(t, f))
		}
		reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
		ackedHookCall(t, f.api, fmt.Sprintf("full-retry-%d", retry), reply)
		time.Sleep(20 * time.Millisecond)
	}
	audited := f.audited(t, sessions...)
	for _, session := range sessions {
		if audited[session] != "allow" || f.hookRows(t, session) != 1 {
			t.Fatalf("%s: audit %q in %d rows, want the acknowledged allow once", session, audited[session], f.hookRows(t, session))
		}
	}
	next := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
	ackedHookCall(t, f.api, "full-next", next)
	if !strings.Contains(next.Body.String(), hookexec.HookDeliveryConfirmed) {
		t.Fatalf("call after the drain = %q, want a confirmed answer", next.Body.String())
	}
}

// countingHookDecisionEmitter counts the hook_decision records offered to
// the audit.
type countingHookDecisionEmitter struct {
	inner sidecarRuntimeEmitter
	seen  atomic.Int32
}

func (e *countingHookDecisionEmitter) Emit(
	ctx context.Context, metadata router.Metadata, builder observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	if metadata.Identity().Name == observability.EventName(observability.TelemetryEventHookDecision) {
		e.seen.Add(1)
	}
	return e.inner.Emit(ctx, metadata, builder)
}

// Recovery reads the journal in batches, so a journal of any size never
// sits in memory at once, and a pass ends after a few rows the store
// refuses instead of retrying every row against it; the next pass audits
// every row once.
func TestPendingHookRecoveryReadsBatchesAndStopsOnARefusingStore(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	total := pendingHookRecoveryBatch + 3
	sessions := make([]string, 0, total)
	for i := range total {
		session := fmt.Sprintf("batch-%03d", i)
		orphanPendingHook(t, f, session, pendingAllow)
		sessions = append(sessions, session)
	}
	lift := refuseAuditInserts(t, f, "audit_events", "1")
	refusing := f.restartedAPI(t, false)
	counted := &countingHookDecisionEmitter{inner: f.runtime}
	bindHookLifecycleV8(t, refusing, counted)
	refusing.recoverPendingHooks(t.Context())
	lift()
	if got := counted.seen.Load(); got != pendingHookRecoveryFailures {
		t.Fatalf("rows tried against a refusing store = %d, want %d", got, pendingHookRecoveryFailures)
	}
	if left := pendingEntries(t, f); len(left) != total {
		t.Fatalf("journal rows after the refused pass = %d, want %d", len(left), total)
	}

	f.restartedAPI(t, true).recoverPendingHooks(t.Context())
	if left := pendingEntries(t, f); len(left) != 0 {
		t.Fatalf("journal rows after recovery = %d, want none", len(left))
	}
	audited := f.audited(t, sessions...)
	for _, session := range sessions {
		if audited[session] != "unconfirmed/no_answer" {
			t.Fatalf("%s: recovered audit = %q, want unconfirmed/no_answer", session, audited[session])
		}
	}
}
