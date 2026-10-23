// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

type managedHookAuditFixture struct {
	api     *APIServer
	server  *httptest.Server
	path    string
	store   *audit.Store
	runtime sidecarRuntimeEmitter
}

// newManagedHookAuditFixture serves the claudecode hook of a standalone
// managed gateway with its audit store and hook_decision records. wrap, when
// set, wraps the hook's response writer.
func newManagedHookAuditFixture(t *testing.T, wrap func(http.ResponseWriter) http.ResponseWriter) managedHookAuditFixture {
	t.Helper()
	return newManagedHookAuditFixtureCollectingNo(t, wrap)
}

// newManagedHookAuditFixtureCollectingNo is newManagedHookAuditFixture with
// log collection off for each bucket in off.
func newManagedHookAuditFixtureCollectingNo(
	t *testing.T, wrap func(http.ResponseWriter) http.ResponseWriter, off ...observability.Bucket,
) managedHookAuditFixture {
	t.Helper()
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	fixture := newSidecarRuntimeFixtureCollectingNo(t, nil, off...)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
	cfg := &config.Config{DeploymentMode: "managed_enterprise", Enterprise: config.EnterpriseConfig{Profile: "standalone"}}
	cfg.DataDir = filepath.Dir(fixture.path)
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	bindHookLifecycleV8(t, api, fixture.runtime)
	hook := api.handleUnifiedConnectorHook("claudecode")
	server := httptest.NewServer(apiBodyLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rw http.ResponseWriter = &statusWriter{ResponseWriter: w}
		if wrap != nil {
			rw = wrap(rw)
		}
		hook.ServeHTTP(rw, r)
	}), apiRequestBodyMaxBytes, otlpRequestBodyMaxBytes))
	t.Cleanup(server.Close)
	return managedHookAuditFixture{api: api, server: server, path: fixture.path, store: fixture.store, runtime: fixture.runtime}
}

// Stop the handler after it has confirmed the hook's receipt, exactly where
// an abrupt gateway exit used to lose both terminal records.
type exitAfterHookConfirmationWriter struct{ *httptest.ResponseRecorder }

func (w *exitAfterHookConfirmationWriter) EnableFullDuplex() error         { return nil }
func (w *exitAfterHookConfirmationWriter) SetReadDeadline(time.Time) error { return nil }
func (w *exitAfterHookConfirmationWriter) Flush() {
	w.ResponseRecorder.Flush()
	if strings.Contains(w.Body.String(), hookexec.HookDeliveryConfirmed) {
		runtime.Goexit()
	}
}

type recordFullDuplexStatusWriter struct {
	*httptest.ResponseRecorder
	finalStatus int
}

type pendingHookRejectBindings struct{}

func (pendingHookRejectBindings) Match(string) (sandboxauth.Binding, error) {
	return sandboxauth.Binding{}, sandboxauth.ErrUnauthenticated
}

func (w *recordFullDuplexStatusWriter) EnableFullDuplex() error         { return nil }
func (w *recordFullDuplexStatusWriter) SetReadDeadline(time.Time) error { return nil }
func (w *recordFullDuplexStatusWriter) WriteHeader(status int) {
	if status >= http.StatusOK {
		w.finalStatus = status
	}
	w.ResponseRecorder.WriteHeader(status)
}

func TestManagedHookConfirmedAnswerSurvivesGatewayExitBeforeFinalization(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	const session = "confirmed-before-exit"
	body := managedHookBody(session, "PreToolUse")
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook",
		strings.NewReader(body+hookexec.HookDeliveryReceiptAck))
	request.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
	request.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len(body)))
	request.Header.Set("Content-Type", "application/json")
	reply := &exitAfterHookConfirmationWriter{ResponseRecorder: httptest.NewRecorder()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.api.handleAgentHook("claudecode").ServeHTTP(reply, request)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("gateway did not confirm the receipt")
	}
	if !strings.Contains(reply.Body.String(), hookexec.HookDeliveryConfirmed) {
		t.Fatalf("gateway response = %q, want receipt confirmation", reply.Body.String())
	}
	if got := f.audited(t, session)[session]; got != "" {
		t.Fatalf("audit before recovery = %q, want no finalized row", got)
	}
	entries, err := f.store.UnauditedHookDeliveries(t.Context(), "the next process")
	if err != nil || len(entries) != 1 {
		t.Fatalf("journal rows before recovery = %v (%v), want one", entries, err)
	}
	// The sandbox ingress can start before the main API, and recovers too.
	restarted := f.restartedAPI(t, true)
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
	for len(pendingEntries(t, f)) != 0 && time.Now().Before(deadline) {
		select {
		case err := <-runDone:
			t.Fatalf("restarted gateway stopped before recovery: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	<-runDone
	if got := f.audited(t, session)[session]; got != "unconfirmed/no_answer" {
		t.Fatalf("audit after recovery = %q, want unconfirmed/no_answer", got)
	}
	if got := f.decisions(t); strings.Join(got, ",") != "unconfirmed/ok" {
		t.Fatalf("hook_decision after recovery = %v, want [unconfirmed/ok]", got)
	}
	if left := pendingEntries(t, f); len(left) != 0 {
		t.Fatalf("journal rows after recovery = %v, want none", left)
	}
	// A crash after the records but before the journal row was deleted
	// must not produce a second record of this occurrence on the next
	// start of the main API.
	if err := f.store.JournalHookDelivery(t.Context(), entries[0].ID, "the restarted process", entries[0].Occurrence); err != nil {
		t.Fatal(err)
	}
	runAPIUntil(t, f.restartedAPI(t, true), func() bool { return len(pendingEntries(t, f)) == 0 })
	if got := f.decisions(t); strings.Join(got, ",") != "unconfirmed/ok" {
		t.Fatalf("hook_decision records after replay = %v, want one", got)
	}
	rows, err := f.store.ListEvents(200)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, row := range rows {
		if row.Action == string(audit.ActionConnectorHook) && row.SessionID == session {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("connector audit rows after replay = %d, want one", count)
	}
}

// audited returns the audited action of each session's hook call.
func (f managedHookAuditFixture) audited(t *testing.T, sessions ...string) map[string]string {
	t.Helper()
	events, err := f.store.ListEvents(200)
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]string)
	for _, event := range events {
		if event.Action != string(audit.ActionConnectorHook) {
			continue
		}
		for _, session := range sessions {
			if event.SessionID != session {
				continue
			}
			for _, field := range strings.Fields(event.Details) {
				if action, ok := strings.CutPrefix(field, "action="); ok {
					got[session] = action
				}
			}
			if strings.Contains(event.Details, hookexec.ManagedGatewayNoAnswerReason) {
				got[session] += "/no_answer"
			}
			if strings.Contains(event.Details, "managed hook rejected the proposed answer") {
				got[session] += "/rejected"
			}
		}
	}
	return got
}

// decisions returns the effective action and hook result of every
// hook_decision record, sorted.
func (f managedHookAuditFixture) decisions(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, row := range readClaudeCodeReplayRows(t, f.path) {
		if row.event == "hook_decision" {
			action, _ := row.body["defenseclaw.guardrail.effective_action"].(string)
			result, _ := row.body["defenseclaw.hook.result"].(string)
			out = append(out, action+"/"+result)
		}
	}
	sort.Strings(out)
	return out
}

func managedHookBody(session, event string) string {
	if event == "UserPromptSubmit" {
		return `{"hook_event_name":"UserPromptSubmit","session_id":"` + session + `","cwd":"/tmp","prompt":"list the files"}`
	}
	return `{"hook_event_name":"PreToolUse","session_id":"` + session + `","cwd":"/tmp","tool_name":"Bash","tool_use_id":"` + session + `-tool","tool_input":{"command":"echo ok"}}`
}

// GAP-0286: a managed hook can receive a proposed allow, then give no receipt.
// Audit and hook_decision record a known block or an unconfirmed result, never
// an allow the gateway cannot prove the hook gave to the agent.
func TestManagedHookAuditWaitsForTheAnswerActuallyGiven(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	call := func(session, receipt string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		reader, writer := io.Pipe()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.server.URL+"/api/v1/claudecode/hook", reader)
		if err != nil {
			t.Fatal(err)
		}
		body := managedHookBody(session, "PreToolUse")
		request.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
		request.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len(body)))
		request.Header.Set("Content-Type", "application/json")
		responseCh := make(chan *http.Response, 1)
		errorCh := make(chan error, 1)
		go func() {
			response, requestErr := f.server.Client().Do(request)
			if requestErr != nil {
				errorCh <- requestErr
				return
			}
			responseCh <- response
		}()
		if _, err := io.WriteString(writer, body); err != nil {
			t.Fatal(err)
		}
		var response *http.Response
		select {
		case response = <-responseCh:
		case err := <-errorCh:
			t.Fatalf("gateway did not offer the hook a decision: %v", err)
		case <-ctx.Done():
			t.Fatal("gateway waited for the hook to finish before offering its decision")
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status %d", response.StatusCode)
		}
		line, err := bufio.NewReader(response.Body).ReadString('\n')
		if err != nil || !strings.Contains(line, `"action":"allow"`) {
			t.Fatalf("proposed answer %q: %v", line, err)
		}
		if receipt != "" {
			if _, err := io.WriteString(writer, receipt); err != nil {
				t.Fatal(err)
			}
		}
		_ = writer.Close()
		_, _ = io.Copy(io.Discard, response.Body)
	}
	legacy := func(session, event string, ctx context.Context) string {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(managedHookBody(session, event))).WithContext(ctx)
		reply := httptest.NewRecorder()
		f.api.handleAgentHook("claudecode").ServeHTTP(reply, request)
		return reply.Body.String()
	}

	call("timeout", "")
	call("delivered", hookexec.HookDeliveryReceiptAck)
	call("rejected", hookexec.HookDeliveryReceiptBlock)
	gone, hangUp := context.WithCancel(t.Context())
	hangUp()
	legacy("disconnected", "PreToolUse", gone)
	// An earlier hook binary still gets the evaluated answer on the wire.
	if reply := legacy("legacy-no-receipt", "PreToolUse", t.Context()); !strings.Contains(reply, `"action":"allow"`) {
		t.Fatalf("upgrade response to earlier hook = %q, want the evaluated proposal", reply)
	}
	// A prompt has no answer deadline and sends no receipt: its evaluated
	// decision is what the agent got.
	legacy("prompt", "UserPromptSubmit", t.Context())
	f.api.scannerCfg.Guardrail.HookFailMode = "open"
	call("open-timeout", "")

	sessions := []string{"timeout", "delivered", "rejected", "disconnected", "legacy-no-receipt", "prompt", "open-timeout"}
	want := map[string]string{
		"timeout":           "unconfirmed/no_answer",
		"delivered":         "allow",
		"rejected":          "block/rejected",
		"disconnected":      "block/no_answer",
		"legacy-no-receipt": "unconfirmed/no_answer",
		"prompt":            "allow",
		"open-timeout":      "unconfirmed/no_answer",
	}
	got := f.audited(t, sessions...)
	for _, session := range sessions {
		if got[session] != want[session] {
			t.Errorf("audited %s = %q, want %q", session, got[session], want[session])
		}
	}
	// Every call has its hook_decision, an unconfirmed one included: the
	// hook result stays a technical ok (schema enum ok|panic).
	wantDecisions := []string{"allow/ok", "allow/ok", "block/ok", "block/ok", "unconfirmed/ok", "unconfirmed/ok", "unconfirmed/ok"}
	if got := f.decisions(t); strings.Join(got, ",") != strings.Join(wantDecisions, ",") {
		t.Errorf("hook_decision records = %v, want %v", got, wantDecisions)
	}
	// If the call cannot be journaled, the gateway never offers the
	// evaluated allow. A managed hook resolves the 503 closed in both fail
	// modes (only a transport outage can open), so both audit a block.
	defer refuseHookDeliveryJournal(t, f)()
	for _, mode := range []string{"closed", "open"} {
		f.api.scannerCfg.Guardrail.HookFailMode = mode
		if got := f.api.scannerCfg.EffectiveHookFailModeForConnector("claudecode"); got != mode {
			t.Fatalf("effective hook fail mode = %q, want %q", got, mode)
		}
		pendingFailureSession := "pending-write-failed-" + mode
		body := managedHookBody(pendingFailureSession, "PreToolUse")
		request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook",
			strings.NewReader(body+hookexec.HookDeliveryReceiptAck))
		request.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
		request.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len(body)))
		request.Header.Set("Content-Type", "application/json")
		reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
		f.api.handleAgentHook("claudecode").ServeHTTP(reply, request)
		if reply.finalStatus != http.StatusServiceUnavailable || strings.Contains(reply.Body.String(), `"action":"allow"`) {
			t.Fatalf("%s: offered response = status %d body %q, want no answer", mode, reply.finalStatus, reply.Body.String())
		}
		if got := f.audited(t, pendingFailureSession)[pendingFailureSession]; got != "block/no_answer" {
			t.Fatalf("%s: audited outage = %q, want block/no_answer", mode, got)
		}
	}
}

// The release marker is sent before the gateway's answer. Once that answer
// has been flushed, closing the HTTP response also cancels the request
// context; that normal close does not mean the hook failed closed.
func TestManagedHookReleasedAnswerClosedAfterDeliveryIsUnconfirmed(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	const session = "released-answer-taken"
	body := managedHookBody(session, "PreToolUse")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(body+hookexec.HookDeliveryReleased)).WithContext(ctx)
	request.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
	request.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len(body)))
	request.Header.Set("Content-Type", "application/json")
	reply := &cancelOnHookAnswerFlushWriter{ResponseRecorder: httptest.NewRecorder(), cancel: cancel}
	f.api.handleAgentHook("claudecode").ServeHTTP(reply, request)
	if !strings.Contains(reply.Body.String(), `"action":"allow"`) {
		t.Fatalf("answer sent to hook = %q, want allow", reply.Body.String())
	}
	if got := f.audited(t, session)[session]; got != "unconfirmed/no_answer" {
		t.Fatalf("audited %s = %q, want unconfirmed/no_answer", session, got)
	}
	if got := f.decisions(t); strings.Join(got, ",") != "unconfirmed/ok" {
		t.Fatalf("hook_decision records = %v, want [unconfirmed/ok]", got)
	}
}

type cancelOnHookAnswerFlushWriter struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
}

func (w *cancelOnHookAnswerFlushWriter) EnableFullDuplex() error { return nil }
func (w *cancelOnHookAnswerFlushWriter) SetReadDeadline(time.Time) error {
	return nil
}
func (w *cancelOnHookAnswerFlushWriter) Flush() {
	w.ResponseRecorder.Flush()
	w.cancel()
}

// The real managed hook and the real gateway: an answer given in time is
// confirmed and audited as given. A late answer is blocked by the hook; the
// gateway has no receipt proving whether that proposal reached the hook, so
// it records an unconfirmed result rather than the proposed allow.
func TestManagedHookAndGatewayAuditTheAnswerTheAgentGot(t *testing.T) {
	var late atomic.Bool
	f := newManagedHookAuditFixture(t, func(w http.ResponseWriter) http.ResponseWriter {
		return &lateAnswerWriter{ResponseWriter: w, late: &late}
	})
	run := func(session string) (int, string) {
		t.Helper()
		home := t.TempDir()
		token := "authenticated-generation-token"
		var stdout, stderr bytes.Buffer
		code := hookexec.Run(t.Context(), hookexec.Options{
			Connector:                 "claudecode",
			Event:                     "PreToolUse",
			APIAddr:                   f.server.Listener.Addr().String(),
			FailMode:                  "closed",
			ManagedEnterprise:         true,
			AuthenticatedManagedToken: &token,
			Home:                      home,
			HookDir:                   filepath.Join(home, "hooks"),
			Stdin:                     strings.NewReader(managedHookBody(session, "PreToolUse")),
			Stdout:                    &stdout,
			Stderr:                    &stderr,
			HTTPClient:                &http.Client{},
			StartedAt:                 time.Now(),
		})
		return code, stdout.String() + stderr.String()
	}
	if code, out := run("hook-in-time"); code != 0 || strings.Contains(out, "deny") {
		t.Fatalf("answer in time: code=%d output=%q", code, out)
	}
	late.Store(true)
	if code, out := run("hook-late"); code == 0 && !strings.Contains(out, "deny") {
		t.Fatalf("late answer was taken: code=%d output=%q", code, out)
	}
	want := map[string]string{"hook-in-time": "allow", "hook-late": "unconfirmed/no_answer"}
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := f.audited(t, "hook-in-time", "hook-late")
		if got["hook-in-time"] == want["hook-in-time"] && got["hook-late"] == want["hook-late"] {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("audited = %v, want %v", got, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A 103 the gateway sends after the hook's capability wait (a slow peer
// lookup at handler start) does not turn an answer given in time into a
// block: the hook takes it, and the audit records the unconfirmed decision,
// never a block the agent did not get.
func TestManagedHookAndGatewayAfterALateEarlyHint(t *testing.T) {
	f := newManagedHookAuditFixture(t, func(w http.ResponseWriter) http.ResponseWriter {
		return &lateHintWriter{ResponseWriter: w}
	})
	home := t.TempDir()
	token := "authenticated-generation-token"
	var stdout, stderr bytes.Buffer
	code := hookexec.Run(t.Context(), hookexec.Options{
		Connector:                 "claudecode",
		Event:                     "PreToolUse",
		APIAddr:                   f.server.Listener.Addr().String(),
		FailMode:                  "closed",
		ManagedEnterprise:         true,
		AuthenticatedManagedToken: &token,
		Home:                      home,
		HookDir:                   filepath.Join(home, "hooks"),
		Stdin:                     strings.NewReader(managedHookBody("late-hint", "PreToolUse")),
		Stdout:                    &stdout,
		Stderr:                    &stderr,
		HTTPClient:                &http.Client{},
		StartedAt:                 time.Now(),
	})
	if out := stdout.String() + stderr.String(); code != 0 || strings.Contains(out, "deny") {
		t.Fatalf("answer after a late 103 was not taken: code=%d output=%q", code, out)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := f.audited(t, "late-hint")["late-hint"]
		if got == "unconfirmed/no_answer" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("audited late-hint = %q, want unconfirmed/no_answer", got)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// lateHintWriter sends 103 after the hook's capability wait.
type lateHintWriter struct{ http.ResponseWriter }

func (w *lateHintWriter) WriteHeader(code int) {
	if code == http.StatusEarlyHints {
		time.Sleep(time.Second)
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *lateHintWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// lateAnswerWriter holds the next hook answer, once late is set, until the
// hook's answer budget (3.5 s) has run out.
type lateAnswerWriter struct {
	http.ResponseWriter
	late *atomic.Bool
}

func (w *lateAnswerWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(`"action"`)) && w.late.CompareAndSwap(true, false) {
		time.Sleep(4 * time.Second)
	}
	return w.ResponseWriter.Write(p)
}

func (w *lateAnswerWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *lateAnswerWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// A call that sends no receipt keeps its evaluated decision unless it is a
// native hook's tool call (an earlier hook binary) or its caller hung up.
// The managed OpenCode plugin runs the native hook; the Amp plugin and the
// Omnigent bridge never send one.
func TestUnreceiptedManagedHookDecisions(t *testing.T) {
	cfg := &config.Config{DeploymentMode: "managed_enterprise", Enterprise: config.EnterpriseConfig{Profile: "standalone"}}
	api := &APIServer{scannerCfg: cfg}
	allow := agentHookResponse{Action: "allow"}
	for _, tc := range []struct {
		connector, event string
		hungUp           bool
		want             string
	}{
		{"opencode", "tool.execute.before", false, "unconfirmed"},
		{"amp", "tool.call", false, "allow"},
		{"omnigent", "PreToolUse", false, "allow"},
		{"claudecode", "UserPromptSubmit", false, "allow"},
		{"claudecode", "Stop", true, "allow"},
		{"codex", "PreToolUse", false, "unconfirmed"},
		{"copilot", "preToolUse", false, "unconfirmed"},
		{"opencode", "tool.execute.before", true, "block"},
		{"claudecode", "UserPromptSubmit", true, "block"},
	} {
		if got := api.unreceiptedHookDecision(tc.hungUp, tc.connector, tc.event, allow).Action; got != tc.want {
			t.Errorf("%s %s (hung up %v) = %q, want %q", tc.connector, tc.event, tc.hungUp, got, tc.want)
		}
	}
	if got := api.unreceiptedHookDecision(false, "codex", "PreToolUse", agentHookResponse{Action: "block", Reason: "policy"}); got.Action != "block" || got.Reason != "policy" {
		t.Errorf("policy block = %+v, want it kept", got)
	}
	secureClient := &APIServer{scannerCfg: &config.Config{DeploymentMode: "managed_enterprise", Enterprise: config.EnterpriseConfig{Profile: "secure_client"}}}
	if got := secureClient.unreceiptedHookDecision(true, "codex", "PreToolUse", allow).Action; got != "allow" {
		t.Errorf("Secure Client = %q, want its response contract unchanged", got)
	}
}

func TestManagedHookMissingReceiptRecordsOnlyKnownEnforcement(t *testing.T) {
	cfg := &config.Config{DeploymentMode: "managed_enterprise", Enterprise: config.EnterpriseConfig{Profile: "standalone"}}
	api := &APIServer{scannerCfg: cfg}
	allow := agentHookResponse{Action: "allow"}
	block := agentHookResponse{Action: "block", Reason: "policy"}
	for _, tc := range []struct {
		name    string
		mode    string
		hungUp  bool
		offered agentHookResponse
		receipt string
		want    string
	}{
		{name: "allow without receipt", offered: allow, want: "unconfirmed"},
		{name: "pre-answer hang-up", hungUp: true, offered: allow, want: "block"},
		{name: "policy block without receipt", offered: block, want: "block"},
		{name: "open outage cannot confirm policy block", mode: "open", offered: block, want: "unconfirmed"},
		{name: "open outage before answer", mode: "open", hungUp: true, offered: allow, want: "unconfirmed"},
		{name: "acknowledged allow", offered: allow, receipt: hookexec.HookDeliveryReceiptAck, want: "allow"},
		{name: "hook rejected allow", offered: allow, receipt: hookexec.HookDeliveryReceiptBlock, want: "block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg.Guardrail.HookFailMode = tc.mode
			got := api.deliveredHookDecision(tc.hungUp, "codex", tc.offered, tc.receipt)
			if got.Action != tc.want {
				t.Fatalf("audited action = %q, want %q", got.Action, tc.want)
			}
			if tc.want == "unconfirmed" && (got.RawAction != tc.offered.Action || got.Reason != hookexec.ManagedGatewayNoAnswerReason) {
				t.Fatalf("unconfirmed answer = %+v, want raw %s and no-answer reason", got, tc.offered.Action)
			}
			if tc.offered.Action == "block" && tc.want == "block" && got.Reason != "policy" {
				t.Fatalf("policy block reason = %q, want policy", got.Reason)
			}
		})
	}
}
