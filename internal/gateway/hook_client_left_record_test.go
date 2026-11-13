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
	serveScriptHookBody(t, f, managedHookBody(session, "PreToolUse"), clientLeft)
}

// protectedWriteBody is a tool call the default policy blocks: it appends to
// the account's authorized_keys file, a named protected target.
func protectedWriteBody(session string) string {
	return `{"hook_event_name":"PreToolUse","session_id":"` + session + `","cwd":"/tmp","tool_name":"Bash","tool_use_id":"` +
		session + `-tool","tool_input":{"command":"echo 'ssh-ed25519 AAAA x' >> ~/.ssh/authorized_keys"}}`
}

func serveScriptHookBody(t *testing.T, f managedHookAuditFixture, body string, clientLeft bool) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(body))
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

// GAP-1028 (the policy-block half): when the gateway's own proposal for a call
// whose client left is a block, the row is still unconfirmed under a hook that
// may fail open: the hook is the only one that can have delivered a block,
// and nothing shows it did. The call that is still answered is the control: a
// block delivered to a present client stays a block.
func TestScriptHookCallWhoseClientLeftWithAPolicyBlockIsUnconfirmedWhenTheHookMayFailOpen(t *testing.T) {
	f := perUserHookFixture(t)
	serveScriptHookBody(t, f, protectedWriteBody("left-block-open"), false)
	if got := f.audited(t, "left-block-open")["left-block-open"]; got != "block" {
		t.Fatalf("control: the protected write answered to its client audited %q, want block", got)
	}
	serveScriptHookBody(t, f, protectedWriteBody("left-block-gone"), true)
	if got := f.audited(t, "left-block-gone")["left-block-gone"]; got != "unconfirmed/no_answer" {
		t.Fatalf("audited = %q, want unconfirmed/no_answer: no delivery proof for the block", got)
	}
}

// GAP-1028 (the prompt events): the script hook of a prompt or an expansion
// fails open on a curl timeout too, and sends no delivery receipt, so a call
// of those events whose client left is unconfirmed whatever the gateway
// proposed. The tool-gate spelling alone left an open-mode prompt block
// recorded as a block nobody proved delivered.
func TestOpenModePromptCallWhoseClientLeftIsUnconfirmedWhateverTheProposal(t *testing.T) {
	f := perUserHookFixture(t)
	for _, event := range []string{"UserPromptSubmit", "UserPromptExpansion", "PreToolUse"} {
		for _, proposal := range []string{"allow", "block"} {
			got := f.api.clientLeftHookDecision(t.Context(), "claudecode", agentHookRequest{HookEventName: event}, nil,
				agentHookResponse{Action: proposal, RawAction: proposal, Mode: "action"})
			if got.Action != hookActionUnconfirmed || got.RawAction != proposal {
				t.Errorf("%s with a proposed %s: action %q raw %q, want unconfirmed keeping the proposal", event, proposal, got.Action, got.RawAction)
			}
		}
	}
	serveScriptHookBody(t, f, managedHookBody("prompt-left", "UserPromptSubmit"), true)
	if got := f.audited(t, "prompt-left")["prompt-left"]; got != "unconfirmed/no_answer" {
		t.Fatalf("audited prompt = %q, want unconfirmed/no_answer", got)
	}
}

// The twins: a hook that fails closed keeps the proposed block of a prompt,
// a lifecycle event the hook cannot deny is not rewritten, and a prompt
// answered to its client stays an allow.
func TestPromptCallWhoseClientLeftKeepsItsBlockWhenTheHookFailsClosed(t *testing.T) {
	f := perUserHookFixture(t)
	f.api.scannerCfg.Guardrail.HookFailMode = "closed"
	got := f.api.clientLeftHookDecision(t.Context(), "claudecode", agentHookRequest{HookEventName: "UserPromptSubmit"}, nil,
		agentHookResponse{Action: "block", RawAction: "block", Mode: "action"})
	if got.Action != "block" {
		t.Fatalf("closed prompt block = %q, want block", got.Action)
	}
	f.api.scannerCfg.Guardrail.HookFailMode = ""
	if got := f.api.clientLeftHookDecision(t.Context(), "claudecode", agentHookRequest{HookEventName: "SessionEnd"}, nil,
		agentHookResponse{Action: "allow", RawAction: "allow", Mode: "action"}); got.Action != "allow" {
		t.Fatalf("a lifecycle event the hook cannot deny = %q, want allow", got.Action)
	}
	serveScriptHookBody(t, f, managedHookBody("prompt-answered", "UserPromptSubmit"), false)
	if got := f.audited(t, "prompt-answered")["prompt-answered"]; got != "allow" {
		t.Fatalf("answered prompt = %q, want allow", got)
	}
}

// Under a hook that fails closed the policy block is the answer the agent got
// whether or not the hook heard the gateway, so the block row stays.
func TestScriptHookPolicyBlockWhoseClientLeftStaysBlockedWhenTheHookFailsClosed(t *testing.T) {
	f := perUserHookFixture(t)
	f.api.scannerCfg.Guardrail.HookFailMode = "closed"
	serveScriptHookBody(t, f, protectedWriteBody("left-block-closed"), true)
	if got := f.audited(t, "left-block-closed")["left-block-closed"]; got != "block" {
		t.Fatalf("audited = %q, want block", got)
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
// pre-execution event is the call's decision row (connector-hook, action=allow)
// and names the agent tool call id, so it is found like the gateway decision
// rows; a post-execution line and a line that names no event are not a tool
// call: they keep the unchecked-call warning and no tool id.
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
	actions := map[string]string{}
	for _, row := range rows {
		switch row.Action {
		case string(audit.ActionConnectorHook), string(audit.ActionGuardrailWarn):
			toolIDs[row.SessionID] = row.ToolID
			details[row.SessionID] = row.Details
			actions[row.SessionID] = row.Action
		}
	}
	if len(toolIDs) != 3 {
		t.Fatalf("rows = %v, want one per call", toolIDs)
	}
	if toolIDs["s-pre"] != "toolu_pre" || actions["s-pre"] != string(audit.ActionConnectorHook) ||
		!strings.Contains(details["s-pre"], "action=allow") || strings.Contains(details["s-pre"], "unconfirmed") {
		t.Fatalf("pre-execution row: action %q, tool id %q, details %q", actions["s-pre"], toolIDs["s-pre"], details["s-pre"])
	}
	for _, session := range []string{"s-post", "s-old"} {
		if toolIDs[session] != "" || actions[session] != string(audit.ActionGuardrailWarn) {
			t.Fatalf("%s: a line that is no tool call got action %q and tool id %q", session, actions[session], toolIDs[session])
		}
	}
}

// joinByToolID reads the outcome of each tool id from the audit rows the way
// the flood lane's join does: a connector-hook row gives its action= field,
// a guardrail-block row gives block, and a row that says unconfirmed gives
// unconfirmed.
func joinByToolID(t *testing.T, store *audit.Store) map[string][]string {
	t.Helper()
	rows, err := store.ListEvents(1000)
	if err != nil {
		t.Fatal(err)
	}
	outcomes := map[string][]string{}
	// A benign per-user allow keeps only its hook_decision row (#1384): it
	// is the call's row when no connector-hook row names the call.
	hookRowOf := map[string]bool{}
	for _, row := range rows {
		if row.ToolID != "" && row.Action == string(audit.ActionConnectorHook) {
			hookRowOf[row.ToolID] = true
		}
	}
	for _, row := range rows {
		if row.ToolID != "" && row.Action == "hook_decision" && !hookRowOf[row.ToolID] {
			action, _ := row.Structured["defenseclaw.guardrail.effective_action"].(string)
			outcomes[row.ToolID] = append(outcomes[row.ToolID], action)
			continue
		}
		if row.ToolID == "" || (row.Action != string(audit.ActionConnectorHook) && row.Action != string(audit.ActionGuardrailBlock)) {
			continue
		}
		outcome := ""
		for _, field := range strings.Fields(row.Details) {
			if value, ok := strings.CutPrefix(field, "action="); ok {
				outcome = value
			}
		}
		if row.Action == string(audit.ActionGuardrailBlock) {
			outcome = "block"
		}
		if strings.Contains(strings.ToLower(row.Details), "unconfirmed") {
			outcome = "unconfirmed"
		}
		outcomes[row.ToolID] = append(outcomes[row.ToolID], outcome)
	}
	return outcomes
}

// The flood lane's call-to-row check on the real script route (GAP-1028,
// GAP-1031): every call has a row, and only a call the script denied has a
// block row. The gateway's own rows come from script calls it served or whose
// client left; the calls it never read have only the hook's line, and the
// report turns that line into the call's row.
func TestScriptFloodEveryCallHasARowAndOnlyTheDeniedCallsAreBlocked(t *testing.T) {
	f := perUserHookFixture(t)
	saw := map[string]string{} // tool id -> what the script gave the agent
	serve := func(session, body string, left bool, saw_ string) {
		serveScriptHookBody(t, f, body, left)
		saw[session+"-tool"] = saw_
	}
	serve("flood-served", managedHookBody("flood-served", "PreToolUse"), false, "allow")
	serve("flood-left", managedHookBody("flood-left", "PreToolUse"), true, "allow")
	serve("flood-left-protected", protectedWriteBody("flood-left-protected"), true, "allow")
	saw["flood-unread-tool"], saw["flood-unread-denied-tool"] = "allow", "deny"

	logDir := filepath.Join(t.TempDir(), "logs")
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	appendHookFailures(t, logDir,
		`{"ts":"2026-11-10T08:59:01Z","connector":"claudecode","hook":"claude-code-hook","event":"PreToolUse","session_id":"flood-left","call_id":"flood-left-tool","tool_id":"flood-left-tool","reason":"gateway unreachable","category":"transport","fail_mode":"open","outcome":"fail_open"}`+"\n",
		`{"ts":"2026-11-10T08:59:02Z","connector":"claudecode","hook":"claude-code-hook","event":"PreToolUse","session_id":"flood-left-protected","call_id":"flood-left-protected-tool","tool_id":"flood-left-protected-tool","reason":"gateway unreachable","category":"transport","fail_mode":"open","outcome":"fail_open"}`+"\n",
		`{"ts":"2026-11-10T08:59:03Z","connector":"claudecode","hook":"claude-code-hook","event":"PreToolUse","session_id":"flood-unread","call_id":"flood-unread-tool","tool_id":"flood-unread-tool","reason":"gateway unreachable","category":"transport","fail_mode":"open","outcome":"fail_open"}`+"\n",
		`{"ts":"2026-11-10T08:59:04Z","connector":"claudecode","hook":"claude-code-hook","event":"PreToolUse","session_id":"flood-unread-denied","call_id":"flood-unread-denied-tool","tool_id":"flood-unread-denied-tool","reason":"gateway unreachable","category":"transport","fail_mode":"closed","outcome":"fail_closed"}`+"\n",
	)
	if err := reportHookFailureCallsIn(logDir, f.api.logger, now); err != nil {
		t.Fatal(err)
	}

	joined := joinByToolID(t, f.store)
	for id, saw := range saw {
		outcomes := joined[id]
		if len(outcomes) == 0 {
			t.Errorf("%s: no row (calls_without_any_row)", id)
		}
		blocked := false
		for _, outcome := range outcomes {
			blocked = blocked || outcome == "block"
		}
		if blocked != (saw == "deny") {
			t.Errorf("%s: the script gave %q and the rows say %v (block_for_allowed_call / delivered block)", id, saw, outcomes)
		}
	}
	if got := joined["flood-served-tool"]; len(got) != 1 || got[0] != "allow" {
		t.Errorf("the benign served call = %v, want one allow row", got)
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
