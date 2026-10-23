// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/google/uuid"
)

// orphanPendingHook leaves the pending occurrence of an offered allow on disk
// as a gateway that exited before its terminal audit would.
func orphanPendingHook(t *testing.T, f managedHookAuditFixture, session string) string {
	t.Helper()
	req := agentHookRequest{
		ConnectorName: "claudecode", HookEventName: "PreToolUse", SessionID: session,
		ToolName: "Bash", ToolInvocationID: session + "-tool",
	}
	p, err := f.api.beginPendingHookOccurrence(t.Context(), req,
		agentHookResponse{Action: "allow", Mode: "action", Severity: "NONE"},
		nil, 64, time.Millisecond, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.release()
	return p.path
}

func (f managedHookAuditFixture) restartedAPI(t *testing.T, bindDecisions bool) *APIServer {
	t.Helper()
	restarted := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, f.store, f.api.logger, f.api.scannerCfg)
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
			t.Fatalf("gateway stopped during pending hook recovery: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	select {
	case err := <-runDone:
		t.Fatalf("gateway stopped after pending hook recovery: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	cancel()
	<-runDone
}

func (f managedHookAuditFixture) hookRows(t *testing.T, session string) int {
	t.Helper()
	rows, err := f.store.ListEvents(500)
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

func pendingPathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// A stray or invalid entry in the pending directory is skipped or
// quarantined; it never stops the gateway, and valid occurrences beside it
// are still audited.
func TestPendingHookRecoverySkipsStrayAndQuarantinesInvalidEntries(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	const session = "recovered-beside-strays"
	valid := orphanPendingHook(t, f, session)
	dir := filepath.Dir(valid)
	finder := filepath.Join(dir, ".DS_Store")
	if err := os.WriteFile(finder, []byte("finder"), 0o644); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "notes")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(dir, uuid.NewString()+".json")
	if err := safefile.WritePrivate(garbage, []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	mismatched := filepath.Join(dir, uuid.NewString()+".json")
	if err := safefile.WritePrivate(mismatched, []byte(`{"ID":"`+uuid.NewString()+`"}`)); err != nil {
		t.Fatal(err)
	}
	occupied := filepath.Join(dir, uuid.NewString()+".json")
	if err := os.Mkdir(occupied, 0o700); err != nil {
		t.Fatal(err)
	}
	quarantined := []string{garbage, mismatched, occupied}
	if runtime.GOOS != "windows" {
		link := filepath.Join(dir, uuid.NewString()+".json")
		if err := os.Symlink(valid, link); err != nil {
			t.Fatal(err)
		}
		quarantined = append(quarantined, link)
	}

	runAPIUntil(t, f.restartedAPI(t, true), func() bool { return !pendingPathExists(valid) })

	if got := f.audited(t, session)[session]; got != "unconfirmed/no_answer" {
		t.Fatalf("recovered audit = %q, want unconfirmed/no_answer", got)
	}
	for _, kept := range []string{finder, subdir} {
		if !pendingPathExists(kept) {
			t.Errorf("foreign entry %s was removed, want it left alone", filepath.Base(kept))
		}
	}
	for _, bad := range quarantined {
		if pendingPathExists(bad) || !pendingPathExists(bad+pendingHookQuarantineSuffix) {
			t.Errorf("invalid occurrence %s was not quarantined", filepath.Base(bad))
		}
	}
	// A later start skips the quarantined files and still serves.
	again := orphanPendingHook(t, f, session+"-again")
	runAPIUntil(t, f.restartedAPI(t, true), func() bool { return !pendingPathExists(again) })
}

// An occurrence the audit cannot take yet (hook_decision not admitted) stays
// on disk while the gateway serves, and a later pass audits it once.
func TestPendingHookRecoveryKeepsServingWhenTheAuditIsNotReady(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	const session = "audit-not-ready"
	path := orphanPendingHook(t, f, session)

	runAPIUntil(t, f.restartedAPI(t, false), func() bool { return f.hookRows(t, session) == 1 })
	if !pendingPathExists(path) {
		t.Fatal("pending occurrence removed although its hook_decision was not persisted")
	}

	runAPIUntil(t, f.restartedAPI(t, true), func() bool { return !pendingPathExists(path) })
	if got := f.hookRows(t, session); got != 1 {
		t.Fatalf("connector audit rows = %d, want one", got)
	}
	if got := f.decisions(t); strings.Join(got, ",") != "unconfirmed/ok" {
		t.Fatalf("hook_decision records = %v, want [unconfirmed/ok]", got)
	}
}

// A pending directory whose protection drifted is not trusted: the gateway
// serves, and the background retry audits the occurrence once it is repaired.
func TestPendingHookRecoveryRetriesAfterDirectoryDriftIsRepaired(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory drift is a mode change here; Windows uses DACLs")
	}
	f := newManagedHookAuditFixture(t, nil)
	const session = "drifted-directory"
	path := orphanPendingHook(t, f, session)
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	restarted := f.restartedAPI(t, true)
	restarted.pendingHookRetryInterval = 20 * time.Millisecond
	repaired := false
	runAPIUntil(t, restarted, func() bool {
		if !repaired {
			// One pass ran and refused the drifted directory.
			time.Sleep(200 * time.Millisecond)
			if !pendingPathExists(path) || f.hookRows(t, session) != 0 {
				t.Fatal("drifted pending directory was trusted")
			}
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			repaired = true
		}
		return !pendingPathExists(path)
	})
	if got := f.audited(t, session)[session]; got != "unconfirmed/no_answer" {
		t.Fatalf("recovered audit = %q, want unconfirmed/no_answer", got)
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
// leave that handler's occurrence alone, so the audit keeps the acknowledged
// allow instead of an unconfirmed takeover.
func TestPendingHookRecoveryLeavesLiveHandlersOfThisProcessAlone(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	const session = "live-during-api-restart"
	body := managedHookBody(session, "PreToolUse")
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook",
		strings.NewReader(body+hookexec.HookDeliveryReceiptAck))
	request.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
	request.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len(body)))
	request.Header.Set("Content-Type", "application/json")
	reply := &pauseAfterHookConfirmationWriter{
		ResponseRecorder: httptest.NewRecorder(),
		paused:           make(chan struct{}), resume: make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.api.handleAgentHook("claudecode").ServeHTTP(reply, request)
	}()
	select {
	case <-reply.paused:
	case <-time.After(10 * time.Second):
		t.Fatal("gateway did not confirm the receipt")
	}
	dir := filepath.Join(f.api.scannerCfg.DataDir, pendingHookDirName)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		close(reply.resume)
		t.Fatalf("pending occurrences = %v (%v), want one", entries, err)
	}
	live := filepath.Join(dir, entries[0].Name())

	restarted := f.restartedAPI(t, true)
	restarted.recoverPendingHookOccurrences(t.Context(), nil)
	takenOver := f.audited(t, session)[session]
	stillThere := pendingPathExists(live)
	close(reply.resume)
	<-done
	if takenOver != "" || !stillThere {
		t.Fatalf("recovery during a live handler: audit = %q, file kept = %t; want no audit and the file kept", takenOver, stillThere)
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
	if pendingPathExists(live) {
		t.Fatal("pending occurrence left after the handler finalized it")
	}
}

// A pending-state write failure answers 503 without offering the evaluated
// answer; the managed hook resolves that closed in every fail mode.
func TestPendingFailureHookDecisionIsTheClosedFallback(t *testing.T) {
	allow := pendingFailureHookDecision(agentHookResponse{Action: "allow", Reason: "evaluated"})
	if allow.Action != "block" || allow.RawAction != "allow" || allow.Reason != hookexec.ManagedGatewayNoAnswerReason {
		t.Fatalf("allow after pending failure = %+v, want closed fallback", allow)
	}
	block := pendingFailureHookDecision(agentHookResponse{Action: "block", Reason: "policy rule"})
	if block.Action != "block" || block.Reason != "policy rule" {
		t.Fatalf("policy block after pending failure = %+v, want the policy block", block)
	}
	for _, action := range []string{"alert", "warn", hookActionUnconfirmed} {
		if got := pendingFailureHookDecision(agentHookResponse{Action: action}); got.Action != "block" {
			t.Fatalf("%s after pending failure = %q, want block", action, got.Action)
		}
	}
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

func pendingEntries(t *testing.T, f managedHookAuditFixture) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(f.api.scannerCfg.DataDir, pendingHookDirName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// With guardrail.evaluation log collection off no hook_decision record is
// ever kept, so none can hold an occurrence back: once the audit logger has
// taken the connector row (the same collection policy keeps it out of the
// local store), the occurrence is settled, on the live path and in recovery.
// Before, every acknowledged call left its occurrence behind until the
// pending writes failed and every managed call was answered 503.
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
		t.Fatalf("pending occurrences after acknowledged calls = %v, want none", left)
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
	path := orphanPendingHook(t, f, recovered)
	f.restartedAPI(t, true).recoverPendingHookOccurrences(t.Context(), nil)
	if pendingPathExists(path) {
		t.Fatal("recovery kept an occurrence whose hook_decision is not collected")
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

// A hook_decision result holds a pending occurrence only while a retry can
// still keep the record.
func TestHookDecisionLogResultSettlesOnlyWhatARetryCannotChange(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	req := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse",
		SessionID: "decision-results", ToolName: "Bash", ToolInvocationID: "decision-results-tool"}
	allow := agentHookResponse{Action: "allow", Mode: "action", Severity: "NONE"}
	for _, tc := range []struct {
		name    string
		emitter sidecarRuntimeEmitter
		resp    agentHookResponse
		want    hookDecisionLogResult
	}{
		{"persisted", f.runtime, allow, hookDecisionLogPersisted},
		{"runtime not bound", nil, allow, hookDecisionLogFailed},
		{"local write failed", fixedHookDecisionEmitter{err: errors.New("disk full")}, allow, hookDecisionLogFailed},
		{"collection off", fixedHookDecisionEmitter{}, allow, hookDecisionLogNotCollected},
		{"managed-only projection", fixedHookDecisionEmitter{
			outcome: pipeline.NewManagedOptionalFailureOutcomeForTest(pipeline.OptionalFailureOutputLimit),
		}, allow, hookDecisionLogNotCollected},
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

// busyHookDecisionEmitter holds every hook_decision record after the first
// free ones until release is closed, as a busy audit store does.
type busyHookDecisionEmitter struct {
	inner   sidecarRuntimeEmitter
	free    int32
	seen    atomic.Int32
	release chan struct{}
}

func (e *busyHookDecisionEmitter) Emit(
	ctx context.Context, metadata router.Metadata, builder observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	if metadata.Identity().Name == observability.EventName(observability.TelemetryEventHookDecision) &&
		e.seen.Add(1) > e.free {
		select {
		case <-e.release:
		case <-ctx.Done():
			return pipeline.LocalLogOutcome{}, ctx.Err()
		}
	}
	return e.inner.Emit(ctx, metadata, builder)
}

// A backlog behind a busy audit store does not hold the listeners: they
// serve once the first pass has handled its startup share of entries or its
// time budget has passed, and the rest is recovered while they serve.
// Before, Run replayed every entry before it bound a listener.
func TestPendingHookRecoveryDoesNotHoldListenersBehindABusyAudit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		free    int32
		budget  time.Duration
		entries int
	}{
		{"time budget", 0, 100 * time.Millisecond, 1000},
		{"entry count", 1, time.Hour, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newManagedHookAuditFixture(t, nil)
			var sessions []string
			for i := range 3 {
				session := fmt.Sprintf("busy-%s-%d", strings.ReplaceAll(tc.name, " ", "-"), i)
				orphanPendingHook(t, f, session)
				sessions = append(sessions, session)
			}
			busy := &busyHookDecisionEmitter{inner: f.runtime, free: tc.free, release: make(chan struct{})}
			released := false
			release := func() {
				if !released {
					released = true
					close(busy.release)
				}
			}
			defer release()
			restarted := f.restartedAPI(t, false)
			bindHookLifecycleV8(t, restarted, busy)
			restarted.pendingHookStartupBudget = tc.budget
			restarted.pendingHookStartupEntries = tc.entries
			restarted.pendingHookRetryInterval = 20 * time.Millisecond
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
			client := &http.Client{Timeout: 10 * time.Second}
			response, err := client.Get("http://" + listener.Addr().String() + "/health")
			if err != nil {
				t.Fatalf("sandbox ingress did not serve while recovery waited on the audit: %v", err)
			}
			_ = response.Body.Close()
			if left := pendingEntries(t, f); len(left) < 2 {
				t.Fatalf("pending occurrences while serving = %v, want the busy ones still waiting", left)
			}
			release()
			deadline := time.Now().Add(10 * time.Second)
			for len(pendingEntries(t, f)) != 0 {
				if time.Now().After(deadline) {
					t.Fatalf("pending occurrences left after the audit freed up: %v", pendingEntries(t, f))
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
		})
	}
}

// refuseConnectorHookAuditRows makes the store refuse connector audit rows,
// not hook_decision records, until the returned function lifts it.
func refuseConnectorHookAuditRows(t *testing.T, f managedHookAuditFixture) func() {
	t.Helper()
	database, err := sql.Open("sqlite", f.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TRIGGER test_refuse_connector_hook BEFORE INSERT ON audit_events
		WHEN NEW.action = '` + string(audit.ActionConnectorHook) + `'
		BEGIN SELECT RAISE(ABORT, 'connector audit refused by the test'); END`); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	return func() {
		defer database.Close()
		if _, err := database.Exec(`DROP TRIGGER IF EXISTS test_refuse_connector_hook`); err != nil {
			t.Fatal(err)
		}
	}
}

type onHookConfirmationWriter struct {
	*httptest.ResponseRecorder
	confirmed func()
	once      sync.Once
}

func (w *onHookConfirmationWriter) EnableFullDuplex() error         { return nil }
func (w *onHookConfirmationWriter) SetReadDeadline(time.Time) error { return nil }
func (w *onHookConfirmationWriter) Flush() {
	w.ResponseRecorder.Flush()
	if strings.Contains(w.Body.String(), hookexec.HookDeliveryConfirmed) {
		w.once.Do(w.confirmed)
	}
}

// The connector audit row and the hook_decision of one occurrence never
// disagree when recovery writes the row the live handler could not. With the
// hook's final answer published, recovery writes that answer. When the final
// answer could not be published, the records the handler writes carry the
// published (unconfirmed) answer, which is all recovery can write. Before,
// the hook_decision said allow and the recovered audit row said unconfirmed.
func TestPendingHookTerminalRecordsAgreeWhenTheAuditRowIsRecovered(t *testing.T) {
	for _, tc := range []struct {
		name         string
		unpublished  bool
		want         string
		wantDecision string
	}{
		{"final answer published", false, "allow", "allow/ok"},
		{"final answer not published", true, "unconfirmed/no_answer", "unconfirmed/ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.unpublished && (runtime.GOOS == "windows" || os.Geteuid() == 0) {
				t.Skip("needs a directory mode this user cannot write through")
			}
			f := newManagedHookAuditFixture(t, nil)
			session := "agree-" + strings.ReplaceAll(tc.name, " ", "-")
			dir := filepath.Join(f.api.scannerCfg.DataDir, pendingHookDirName)
			lift := refuseConnectorHookAuditRows(t, f)
			reply := &onHookConfirmationWriter{ResponseRecorder: httptest.NewRecorder(), confirmed: func() {
				if tc.unpublished {
					if err := os.Chmod(dir, 0o500); err != nil {
						t.Error(err)
					}
				}
			}}
			ackedHookCall(t, f.api, session, reply)
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			lift()
			if !strings.Contains(reply.Body.String(), hookexec.HookDeliveryConfirmed) {
				t.Fatalf("gateway response = %q, want the receipt confirmation", reply.Body.String())
			}
			if got := f.audited(t, session)[session]; got != "" {
				t.Fatalf("audit row written although the store refused it: %q", got)
			}
			if left := pendingEntries(t, f); len(left) != 1 {
				t.Fatalf("pending occurrences = %v, want the one whose audit row failed", left)
			}
			f.restartedAPI(t, true).recoverPendingHookOccurrences(t.Context(), nil)
			if got := f.audited(t, session)[session]; got != tc.want {
				t.Fatalf("recovered audit = %q, want %q", got, tc.want)
			}
			if got := strings.Join(f.decisions(t), ","); got != tc.wantDecision {
				t.Fatalf("hook_decision records = %q, want %q", got, tc.wantDecision)
			}
			if left := pendingEntries(t, f); len(left) != 0 {
				t.Fatalf("pending occurrences after recovery = %v, want none", left)
			}
		})
	}
}
