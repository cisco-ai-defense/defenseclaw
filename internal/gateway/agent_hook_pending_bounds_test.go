// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/google/uuid"
)

// evictedRows counts, by session, the unconfirmed-evicted audit rows, and
// rows whose ID is one of ids plus "-evicted".
func (f managedHookAuditFixture) evictedRows(t *testing.T, ids ...string) map[string]int {
	t.Helper()
	events, err := f.store.ListEvents(5000)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, event := range events {
		if event.Action != string(audit.ActionConnectorHook) || !strings.HasSuffix(event.ID, "-evicted") {
			continue
		}
		if !strings.Contains(event.Details, "action="+pendingHookEvictedAction) {
			t.Fatalf("evicted row %s details %q, want action %s", event.ID, event.Details, pendingHookEvictedAction)
		}
		got[event.SessionID]++
		for _, id := range ids {
			if event.ID == id+"-evicted" {
				got[id]++
			}
		}
	}
	return got
}

// A gateway that pinned the verdict of a call and died before any record
// of it was written leaves the verdict in the journal row. The next process
// writes that verdict, under the call's IDs, locally and to the remote
// destinations, once; a later start writes nothing more.
func TestPendingHookRestartPublishesThePinnedVerdict(t *testing.T) {
	remote := newHookRemoteRecorder()
	f := newManagedHookAuditFixtureExportingTo(t, nil, remote)
	const session = "pinned-then-died"
	p := orphanPendingHook(t, f, session, pendingAllow)
	acknowledged := f.api.deliveredHookDecision("claudecode", pendingAllow, hookexec.HookDeliveryReceiptAck)
	f.api.pendingHookDecidedContext(t.Context(), p, acknowledged)
	ids := []string{p.ID, p.ID + "-decision"}
	remote.settled(t, 0, ids...)
	for _, id := range ids {
		if got := remote.decisions(id); len(got) != 0 {
			t.Fatalf("remote copies of %s before the restart = %v, want none", id, got)
		}
	}

	for start := range 2 {
		f.restartedAPI(t, true).recoverPendingHooks(t.Context())
		if got := f.audited(t, session)[session]; got != "allow" {
			t.Fatalf("start %d: local audit = %q, want the pinned allow", start, got)
		}
		if got := strings.Join(f.decisions(t), ","); got != "allow/ok" {
			t.Fatalf("start %d: hook_decision records = %q, want allow/ok", start, got)
		}
		remote.settled(t, 1, ids...)
		for _, id := range ids {
			if got := strings.Join(remote.decisions(id), ","); got != "answer" {
				t.Fatalf("start %d: remote copies of %s = %q, want the pinned answer once", start, id, got)
			}
		}
		if left := pendingEntries(t, f); len(left) != 0 {
			t.Fatalf("start %d: journal rows = %v, want none", start, left)
		}
	}
}

// metricCountingEmitter counts the metric batches the hook path records.
type metricCountingEmitter struct {
	inner   sidecarRuntimeEmitter
	batches atomic.Int32
}

func (e *metricCountingEmitter) Emit(
	ctx context.Context, metadata router.Metadata, builder observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	return e.inner.Emit(ctx, metadata, builder)
}

func (e *metricCountingEmitter) RecordGeneratedMetricBatch(
	ctx context.Context, items []observabilityruntime.GeneratedMetricBatchItem,
) ([]telemetry.V8MetricRecordResult, error) {
	e.batches.Add(1)
	if runtime, ok := e.inner.(hookLifecycleMetricV8Runtime); ok {
		return runtime.RecordGeneratedMetricBatch(ctx, items)
	}
	return nil, nil
}

// The hook_decision record a later process writes names the policy the call
// was evaluated under, as journaled with it: the managed sandbox
// registration and its sandbox policy generation and digest, and the
// account's exempt enrollment, though the recovering server has no
// registration and no exempt account on its context. Recovery writes the
// two records only: none of the call's metrics are counted a second time
// under the recovering server's state.
func TestPendingHookRecoveryNamesTheJournaledPolicyAndRepeatsNoLiveSideEffects(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	const session = "journaled-policy"
	reg := managedTelemetryTestRegistration()
	ctx := withEnterpriseExemptUser(withSandboxRelayRegistration(t.Context(), reg))
	ctx = audit.ContextWithEnvelope(ctx, audit.CorrelationEnvelope{SessionID: session, SandboxID: reg.SandboxID, SandboxName: reg.SandboxName})
	req := pendingToolRequest(session)
	if _, err := f.api.journalHookDelivery(ctx, &req, pendingAllow, nil, 64, time.Millisecond, false, nil); err != nil {
		t.Fatal(err)
	}

	restarted := f.restartedAPI(t, false)
	counted := &metricCountingEmitter{inner: f.runtime}
	bindHookLifecycleV8(t, restarted, counted)
	restarted.recoverPendingHooks(t.Context())
	if left := pendingEntries(t, f); len(left) != 0 {
		t.Fatalf("journal rows = %v, want none", left)
	}
	var bodies []map[string]any
	for _, record := range readClaudeCodeReplayRows(t, f.path) {
		if record.event == "hook_decision" {
			bodies = append(bodies, record.body)
		}
	}
	if len(bodies) != 1 {
		t.Fatalf("hook_decision records = %d, want one", len(bodies))
	}
	for key, want := range map[string]any{
		"defenseclaw.sandbox.registration.id":   reg.ID,
		"defenseclaw.sandbox.policy.digest":     reg.EffectiveDigest,
		"defenseclaw.sandbox.policy.generation": float64(reg.Generation),
		"defenseclaw.user.enrollment":           "exempt",
	} {
		if got := bodies[0][key]; got != want {
			t.Errorf("recovered hook_decision %s = %v, want the journaled %v", key, got, want)
		}
	}
	if got := counted.batches.Load(); got != 0 {
		t.Fatalf("recovery recorded %d metric batches, want none", got)
	}

	// The same server counts a live call.
	reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
	ackedHookCall(t, restarted, session+"-live", reply)
	if !strings.Contains(reply.Body.String(), hookexec.HookDeliveryConfirmed) {
		t.Fatalf("live call = %q, want a confirmed answer", reply.Body.String())
	}
	if counted.batches.Load() == 0 {
		t.Fatal("a live call recorded no metric batch: the emitter does not see the hook metrics")
	}
}

// A row recovery cannot audit leaves the journal after
// pendingHookRecoveryAttempts tries, its tries counted across gateway
// restarts, as one unconfirmed-evicted audit row: never a second record
// under the call's own IDs, and never a second evicted row. A row no build
// can read, and one over the occurrence limit (which is never loaded),
// leave at the first pass. Rows the store takes are audited as usual.
func TestPendingHookEvictsRowsItCannotAudit(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	ctx := t.Context()
	stuck := []string{"stuck-1", "stuck-2"}
	var stuckIDs []string
	for _, session := range stuck {
		stuckIDs = append(stuckIDs, orphanPendingHook(t, f, session, pendingAllow).ID)
	}
	orphanPendingHook(t, f, "writable", pendingAllow)
	if err := f.store.JournalHookDelivery(ctx, "unreadable", "an older process", []byte(`{"ID":`), pendingHookJournalLimits); err != nil {
		t.Fatal(err)
	}
	wide := pendingHookJournalLimits
	wide.OccurrenceBytes = 4 * pendingHookJournalLimits.OccurrenceBytes
	oversized := fmt.Sprintf(`{"ID":"oversized","Extra":{"x":%q}}`, strings.Repeat("x", 2*pendingHookJournalLimits.OccurrenceBytes))
	if err := f.store.JournalHookDelivery(ctx, "oversized", "an older build", []byte(oversized), wide); err != nil {
		t.Fatal(err)
	}
	lift := refuseAuditInserts(t, f, "audit_events", `NEW.session_id LIKE 'stuck-%' AND NEW.id NOT LIKE '%-evicted'`)
	defer lift()

	for pass := 1; pass <= pendingHookRecoveryAttempts+1; pass++ {
		f.restartedAPI(t, true).recoverPendingHooks(ctx)
		left := pendingEntries(t, f)
		want := len(stuck)
		if pass >= pendingHookRecoveryAttempts {
			want = 0
		}
		if len(left) != want {
			t.Fatalf("pass %d: journal rows = %v, want %d", pass, left, want)
		}
		if pass == 1 {
			if got := f.audited(t, "writable")["writable"]; got != "unconfirmed/no_answer" {
				t.Fatalf("writable row audited %q, want unconfirmed/no_answer", got)
			}
		}
	}
	evicted := f.evictedRows(t, append([]string{"unreadable", "oversized"}, stuckIDs...)...)
	for _, key := range append([]string{"unreadable", "oversized"}, append(stuck, stuckIDs...)...) {
		if evicted[key] != 1 {
			t.Fatalf("evicted rows of %s = %d, want one (all: %v)", key, evicted[key], evicted)
		}
	}
	if evicted["writable"] != 0 {
		t.Fatalf("the audited row was evicted too: %v", evicted)
	}
	for _, session := range stuck {
		if rows := f.hookRows(t, session); rows != 1 {
			t.Fatalf("%s: connector rows = %d, want only its evicted row", session, rows)
		}
	}
	if got := strings.Join(f.decisions(t), ","); got != "unconfirmed/ok" {
		t.Fatalf("hook_decision records = %q, want the writable call's only", got)
	}
}

// A try the store does not let recovery record in the row (the journal
// refuses updates) still counts, so such a row also leaves after
// pendingHookRecoveryAttempts tries.
func TestPendingHookEvictsARowWhoseTriesTheStoreWillNotRecord(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	const session = "unrecorded-tries"
	p := orphanPendingHook(t, f, session, pendingAllow)
	liftUpdate := refuseHookDeliveryDecision(t, f)
	defer liftUpdate()
	liftAudit := refuseAuditInserts(t, f, "audit_events", `NEW.id NOT LIKE '%-evicted'`)
	defer liftAudit()
	recovering := f.restartedAPI(t, true)
	for pass := 1; pass <= pendingHookRecoveryAttempts; pass++ {
		if left := pendingEntries(t, f); len(left) != 1 {
			t.Fatalf("pass %d: journal rows = %v, want the one row", pass, left)
		}
		recovering.recoverPendingHooks(t.Context())
	}
	if left := pendingEntries(t, f); len(left) != 0 {
		t.Fatalf("journal rows after %d tries = %v, want none", pendingHookRecoveryAttempts, left)
	}
	if got := f.evictedRows(t, p.ID)[p.ID]; got != 1 {
		t.Fatalf("evicted rows = %d, want one", got)
	}
}

// A journal at its row limit while the store keeps refusing the records
// still drains: the full journal starts recovery passes, its rows are
// evicted after their tries, and calls are answered again without the
// store recovering.
func TestPendingHookFullJournalDrainsWhileTheStoreRefusesRecords(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	limits, interval := pendingHookJournalLimits, pendingHookDrainInterval
	t.Cleanup(func() { pendingHookJournalLimits, pendingHookDrainInterval = limits, interval })
	awaitPendingHookDrain(t)
	pendingHookJournalLimits.Rows, pendingHookDrainInterval = 2, 0
	pendingHookDrainAt.Store(0)
	lift := refuseAuditInserts(t, f, "audit_events", `NEW.session_id LIKE 'stuck-full-%' AND NEW.id NOT LIKE '%-evicted'`)
	defer lift()
	stuck := []string{"stuck-full-0", "stuck-full-1"}
	for _, session := range stuck {
		reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
		ackedHookCall(t, f.api, session, reply)
		if !strings.Contains(reply.Body.String(), hookexec.HookDeliveryConfirmed) {
			t.Fatalf("%s: gateway response = %q, want the receipt confirmation", session, reply.Body.String())
		}
	}
	deadline := time.Now().Add(15 * time.Second)
	for call := 0; ; call++ {
		if time.Now().After(deadline) {
			t.Fatalf("the full journal never drained: rows %v", pendingEntries(t, f))
		}
		reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
		ackedHookCall(t, f.api, fmt.Sprintf("full-call-%d", call), reply)
		if strings.Contains(reply.Body.String(), hookexec.HookDeliveryConfirmed) {
			break
		}
		if reply.finalStatus != http.StatusServiceUnavailable {
			t.Fatalf("call %d against the full journal = status %d, want 503", call, reply.finalStatus)
		}
		time.Sleep(20 * time.Millisecond)
	}
	evicted := f.evictedRows(t)
	for _, session := range stuck {
		if evicted[session] != 1 || f.hookRows(t, session) != 1 {
			t.Fatalf("%s: evicted rows %d, connector rows %d; want its one evicted row", session, evicted[session], f.hookRows(t, session))
		}
	}
}

// One pass takes at most pendingHookRecoveryPassRows rows, over several
// batch reads, so a pass against a store that refuses every record has a
// fixed cost; later passes take the rows after them.
func TestPendingHookRecoveryPassIsBounded(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	passRows := pendingHookRecoveryPassRows
	t.Cleanup(func() { pendingHookRecoveryPassRows = passRows })
	pendingHookRecoveryPassRows = pendingHookRecoveryBatch + 3
	total := 2*pendingHookRecoveryBatch + 10
	sessions := make([]string, 0, total)
	for i := range total {
		session := fmt.Sprintf("bounded-%03d", i)
		orphanPendingHook(t, f, session, pendingAllow)
		sessions = append(sessions, session)
	}
	lift := refuseAuditInserts(t, f, "audit_events", "1")
	refusing := f.restartedAPI(t, false)
	counted := &countingHookDecisionEmitter{inner: f.runtime}
	bindHookLifecycleV8(t, refusing, counted)
	refusing.recoverPendingHooks(t.Context())
	lift()
	if got := counted.seen.Load(); got != int32(pendingHookRecoveryPassRows) {
		t.Fatalf("rows tried in one pass = %d, want %d", got, pendingHookRecoveryPassRows)
	}
	recovering := f.restartedAPI(t, true)
	for pass := 0; pass < 3 && len(pendingEntries(t, f)) != 0; pass++ {
		recovering.recoverPendingHooks(t.Context())
	}
	if left := pendingEntries(t, f); len(left) != 0 {
		t.Fatalf("journal rows after three more passes = %d, want none", len(left))
	}
	audited := f.audited(t, sessions...)
	for _, session := range sessions {
		if audited[session] != "unconfirmed/no_answer" {
			t.Fatalf("%s: recovered audit = %q, want unconfirmed/no_answer", session, audited[session])
		}
	}
	if evicted := f.evictedRows(t); len(evicted) != 0 {
		t.Fatalf("rows evicted = %v, want none", evicted)
	}
}

// Large hook fields are truncated, with a marker, before an occurrence is
// stored, so the journal row fits its limit and decodes: IDs, numbers and
// short fields are kept exactly, a long string keeps its first bytes on a
// rune boundary and ends with a marker, long lists and Extra keep their
// first entries, and Extra says the occurrence was truncated. An occurrence
// within the limit is stored as it is.
func TestPendingHookOccurrenceTruncatesLargeFieldsWithAMarker(t *testing.T) {
	small := &pendingHookOccurrence{ID: uuid.NewString(), Request: pendingRequest(pendingToolRequest("small"))}
	data, err := encodePendingHookOccurrence(small)
	plain, _ := json.Marshal(small)
	if err != nil || string(data) != string(plain) {
		t.Fatalf("small occurrence = %s, %v; want it as it is", data, err)
	}

	huge := strings.Repeat("é", 50<<10)
	extra := map[string]string{}
	var rawIDs, rules []string
	for i := range 5000 {
		extra[fmt.Sprintf("key-%05d", i)] = huge[:64]
		rawIDs = append(rawIDs, fmt.Sprintf("raw-%05d", i))
		rules = append(rules, fmt.Sprintf("rule-%05d", i))
	}
	req := pendingToolRequest("huge")
	req.ToolName, req.AgentName = huge, huge
	p := &pendingHookOccurrence{
		ID: uuid.NewString(), Request: pendingRequest(req),
		Proposed:   pendingHookResponse{Action: "allow", Reason: huge, RuleIDs: rules},
		NoReceipt:  pendingHookResponse{Action: hookActionUnconfirmed},
		Provenance: pendingHookProvenance{StepIdx: 7, ConfigGeneration: math.MaxUint64, PolicyDigest: "sha256:" + strings.Repeat("c", 64)},
		Envelope:   audit.CorrelationEnvelope{SessionID: "huge", ToolName: huge},
		Extra:      extra, RawEventIDs: rawIDs, BodyBytes: 1 << 40, ElapsedNanos: math.MaxInt64,
	}
	data, err = encodePendingHookOccurrence(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > pendingHookJournalLimits.OccurrenceBytes || !utf8.Valid(data) {
		t.Fatalf("truncated occurrence is %d bytes (valid UTF-8 %t), want at most %d", len(data), utf8.Valid(data), pendingHookJournalLimits.OccurrenceBytes)
	}
	var got pendingHookOccurrence
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != p.ID || got.Request.ConnectorName != "claudecode" || got.Request.SessionID != "huge" ||
		got.ElapsedNanos != math.MaxInt64 || got.BodyBytes != 1<<40 || got.Provenance.ConfigGeneration != math.MaxUint64 ||
		got.Provenance.StepIdx != 7 || got.Provenance.PolicyDigest != p.Provenance.PolicyDigest ||
		got.Proposed.Action != "allow" || got.NoReceipt.Action != hookActionUnconfirmed {
		t.Fatalf("kept fields changed: %+v", got)
	}
	for name, value := range map[string]string{
		"tool name": got.Request.ToolName, "agent name": got.Request.AgentName,
		"reason": got.Proposed.Reason, "envelope tool": got.Envelope.ToolName,
	} {
		prefix, _, marked := strings.Cut(value, "…[truncated ")
		if !marked || !strings.HasPrefix(huge, prefix) || !strings.HasSuffix(value, " bytes]") || len(value) >= len(huge) {
			t.Fatalf("%s = %.80q…, want a prefix with a truncation marker", name, value)
		}
	}
	if got.Extra[pendingHookTruncatedExtra] != "true" || len(got.Extra) > 65 ||
		len(got.RawEventIDs) > 64 || len(got.Proposed.RuleIDs) > 64 || got.RawEventIDs[0] != "raw-00000" {
		t.Fatalf("Extra %d entries (marker %q), raw ids %d, rules %d; want the first entries and a marker",
			len(got.Extra), got.Extra[pendingHookTruncatedExtra], len(got.RawEventIDs), len(got.Proposed.RuleIDs))
	}
}

// A call with large hook fields is answered: its journal row holds the
// truncated occurrence, within the limit, and recovery audits it.
func TestPendingHookAnswersACallWithLargeHookFields(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	const session = "large-fields"
	lift := refuseConnectorHookAuditRows(t, f)
	reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
	ackedHookToolCall(t, f.api, session, strings.Repeat("x", 2*pendingHookJournalLimits.OccurrenceBytes), reply)
	lift()
	if reply.finalStatus == http.StatusServiceUnavailable || !strings.Contains(reply.Body.String(), hookexec.HookDeliveryConfirmed) {
		t.Fatalf("call with large fields = status %d body %.200q, want a confirmed answer", reply.finalStatus, reply.Body.String())
	}
	entries := journalEntries(t, f)
	if len(entries) != 1 || len(entries[0].Occurrence) > pendingHookJournalLimits.OccurrenceBytes ||
		!strings.Contains(string(entries[0].Occurrence), "…[truncated ") {
		t.Fatalf("journal = %d rows, want one truncated row within the limit", len(entries))
	}
	f.restartedAPI(t, true).recoverPendingHooks(t.Context())
	if left := pendingEntries(t, f); len(left) != 0 {
		t.Fatalf("journal rows after recovery = %v, want none", left)
	}
	if rows := f.hookRows(t, session); rows != 1 {
		t.Fatalf("connector rows = %d, want one", rows)
	}
}

// The journal stays bounded in bytes: a call that would take it past its
// total is refused with a 503 the managed hook resolves closed, and is
// audited as that block.
func TestPendingHookRefusesAnOverBudgetCallClosed(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	limits := pendingHookJournalLimits
	t.Cleanup(func() { pendingHookJournalLimits = limits })
	awaitPendingHookDrain(t)
	pendingHookDrainAt.Store(time.Now().UnixNano())

	lift := refuseConnectorHookAuditRows(t, f)
	first := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
	ackedHookCall(t, f.api, "budget-1", first)
	if !strings.Contains(first.Body.String(), hookexec.HookDeliveryConfirmed) {
		t.Fatalf("first call = %q, want a confirmed answer", first.Body.String())
	}
	entries := journalEntries(t, f)
	if len(entries) != 1 {
		t.Fatalf("journal rows = %d, want the one whose audit row failed", len(entries))
	}
	// The row stays: no recovery pass runs in this test.
	lift()
	pendingHookJournalLimits.Bytes = int64(len(entries[0].Occurrence) * 3 / 2)
	second := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
	ackedHookCall(t, f.api, "budget-2", second)
	if second.finalStatus != http.StatusServiceUnavailable || strings.Contains(second.Body.String(), `"action"`) {
		t.Fatalf("over-budget call: status %d body %.200q, want 503 and no answer", second.finalStatus, second.Body.String())
	}
	if got := f.audited(t, "budget-2")["budget-2"]; got != "block/no_answer" {
		t.Fatalf("over-budget call audit = %q, want block/no_answer", got)
	}
	if left := pendingEntries(t, f); len(left) != 1 {
		t.Fatalf("journal rows after the over-budget call = %d, want 1", len(left))
	}
}
