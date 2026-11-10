// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// perUserHookFixture is the managed audit fixture served as an ordinary
// per-user install: no deployment mode and no enterprise profile, which is
// what a validated per-user config holds.
func perUserHookFixture(t *testing.T) managedHookAuditFixture {
	t.Helper()
	f := newManagedHookAuditFixture(t, nil)
	f.api.scannerCfg.DeploymentMode = ""
	f.api.scannerCfg.Enterprise = config.EnterpriseConfig{}
	return f
}

// serveScriptHook posts a tool call the way a script hook does: no delivery
// receipt. A call whose client has already left carries a cancelled context.
func serveScriptHook(t *testing.T, f managedHookAuditFixture, session string, clientLeft bool) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook",
		strings.NewReader(managedHookBody(session, "PreToolUse")))
	if clientLeft {
		gone, hangUp := context.WithCancel(t.Context())
		hangUp()
		request = request.WithContext(gone)
	}
	reply := httptest.NewRecorder()
	f.api.handleAgentHook("claudecode").ServeHTTP(reply, request)
}

// GAP-1028: a script hook whose curl timed out exits 0 in the default and
// permissive tiers, so the agent ran the call. The gateway that finishes the
// call for a client that has left cannot show which answer the agent got; it
// recorded a connector-hook block (4 to 1568 of 4800 calls per flood run).
// The row is unconfirmed and keeps the evaluated allow.
func TestScriptHookCallWhoseClientLeftIsUnconfirmedWhenTheHookMayFailOpen(t *testing.T) {
	f := perUserHookFixture(t)
	const session = "left-open"
	serveScriptHook(t, f, session, true)
	if got := f.audited(t, session)[session]; got != "unconfirmed/no_answer" {
		t.Fatalf("audited = %q, want unconfirmed/no_answer, never a block for a call the hook may have allowed", got)
	}
	if got := f.decisions(t); len(got) != 1 || got[0] != "unconfirmed/ok" {
		t.Fatalf("hook_decision = %v, want [unconfirmed/ok]", got)
	}
}

// A hook that fails closed (the strict tier, or a saved closed mode) blocks
// the call when it leaves, so the block row is the answer the agent got.
func TestScriptHookCallWhoseClientLeftStaysBlockedWhenTheHookFailsClosed(t *testing.T) {
	f := perUserHookFixture(t)
	f.api.scannerCfg.Guardrail.HookFailMode = "closed"
	const session = "left-closed"
	serveScriptHook(t, f, session, true)
	if got := f.audited(t, session)[session]; got != "block" {
		t.Fatalf("audited = %q, want the fail-closed block", got)
	}
}

// The benign twin: a call whose client is still there when the answer is
// written is an allow, never unconfirmed.
func TestScriptHookCallAnsweredToItsClientStaysAllowed(t *testing.T) {
	f := perUserHookFixture(t)
	const session = "left-never"
	serveScriptHook(t, f, session, false)
	if got := f.audited(t, session)[session]; got != "allow" {
		t.Fatalf("audited = %q, want allow", got)
	}
}

// The extended write window of an answered call applies to the per-user
// install a validated config describes (it compared a deployment mode no
// config can hold), and never to a managed one.
func TestPerUserInstallKeepsTheLongRecordWindowOfAnAnsweredCall(t *testing.T) {
	f := perUserHookFixture(t)
	ctx, cancel := f.api.hookDeliveredPersistenceContext(t.Context(), true)
	if cancel == nil {
		t.Fatal("a per-user answered call got the ordinary window")
	}
	defer cancel()
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) < 20*time.Second {
		t.Fatalf("window deadline = %v, want about 30 s", deadline)
	}
	if _, none := f.api.hookDeliveredPersistenceContext(t.Context(), false); none != nil {
		t.Fatal("a call without a receipt got the answered-call window")
	}
	f.api.scannerCfg.DeploymentMode = "managed_enterprise"
	if _, none := f.api.hookDeliveredPersistenceContext(t.Context(), true); none != nil {
		t.Fatal("a managed call got the per-user window")
	}
}

// The late and open tokens name the per-user reason on a per-user install.
func TestPerUserInstallNamesThePerUserReasonForALateHook(t *testing.T) {
	f := perUserHookFixture(t)
	proposal := agentHookResponse{Action: "allow", RawAction: "allow", Mode: "action"}
	if got := f.api.deliveredHookDecision("claudecode", proposal, hookexec.HookDeliveryReceiptLate); got.Action != "block" || got.Reason != hookexec.PerUserGatewayNoAnswerReason {
		t.Fatalf("late = %+v, want the per-user no-answer block", got)
	}
	if got := f.api.deliveredHookDecision("claudecode", proposal, hookexec.HookDeliveryReceiptOpen); got.Action != "allow" || got.Reason != hookexec.PerUserGatewayNoAnswerReason {
		t.Fatalf("open = %+v, want the per-user no-answer allow", got)
	}
	f.api.scannerCfg.DeploymentMode = "managed_enterprise"
	if got := f.api.deliveredHookDecision("claudecode", proposal, hookexec.HookDeliveryReceiptLate); got.Reason != hookexec.ManagedGatewayNoAnswerReason {
		t.Fatalf("managed late = %+v, want the managed reason", got)
	}
}

// GAP-1031: a call the hook allowed because the gateway did not answer has
// its line in hook-failures.jsonl and, from the report, one row. The row of a
// pre-execution event names the agent tool call id, so it is found like the
// gateway decision rows; a post-execution line and a line that names no event
// are not a tool call and keep the id off.
func TestReportedFailOpenToolCallNamesItsToolID(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	logDir := filepath.Join(t.TempDir(), "logs")
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	appendHookFailures(t, logDir,
		`{"ts":"2026-11-10T08:59:01Z","connector":"claudecode","hook":"claude-code-hook","event":"PreToolUse","session_id":"s-pre","call_id":"toolu_pre","tool_id":"toolu_pre","reason":"gateway unreachable","category":"transport","fail_mode":"open","outcome":"fail_open"}`+"\n",
		`{"ts":"2026-11-10T08:59:02Z","connector":"claudecode","hook":"claude-code-hook","event":"PostToolUse","session_id":"s-post","call_id":"toolu_post","tool_id":"toolu_post","reason":"gateway unreachable","category":"transport","fail_mode":"open","outcome":"fail_open"}`+"\n",
		`{"ts":"2026-11-10T08:59:03Z","connector":"codex","hook":"codex-hook","session_id":"s-old","call_id":"call-old","reason":"gateway unreachable","category":"transport","fail_mode":"open","outcome":"fail_open"}`+"\n",
	)
	if err := reportHookFailureCallsIn(logDir, logger, now); err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	toolIDs := map[string]string{}
	details := map[string]string{}
	for _, row := range rows {
		if row.Action == string(audit.ActionGuardrailWarn) && strings.Contains(row.Details, "unchecked hook call") {
			toolIDs[row.SessionID] = row.ToolID
			details[row.SessionID] = row.Details
		}
	}
	if len(toolIDs) != 3 {
		t.Fatalf("rows = %v, want one per call", toolIDs)
	}
	if toolIDs["s-pre"] != "toolu_pre" || !strings.Contains(details["s-pre"], "the hook allowed this tool call") {
		t.Fatalf("pre-execution row: tool id %q, details %q", toolIDs["s-pre"], details["s-pre"])
	}
	if toolIDs["s-post"] != "" || toolIDs["s-old"] != "" || strings.Contains(details["s-post"], "the hook allowed this tool call") {
		t.Fatalf("a line that is no tool call named one: %v", toolIDs)
	}
}

// GAP-1029: the unconfirmed row of a call whose client left before admission
// names the tool id in the row field, not only in its details, so a join by
// tool id finds it.
func TestCallerGoneRowNamesItsToolID(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	r := goneRequest(t, managedHookBody("gone-tool", "PreToolUse"), AgentIdentity{UserID: "1005", UserName: "gone-bob"}, nil)
	serveGoneOnSocket(t, f, machinePolicyAuthorizer(), r)
	events, err := f.store.ListEvents(1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == string(audit.ActionConnectorHook) && event.SessionID == "gone-tool" {
			if event.ToolID != "gone-tool-tool" {
				t.Fatalf("row tool id = %q, want gone-tool-tool", event.ToolID)
			}
			return
		}
	}
	t.Fatal("no row for the call whose client left")
}
