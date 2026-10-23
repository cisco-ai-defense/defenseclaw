// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
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
	restarted.ensurePendingHookRecovery(t.Context())
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
