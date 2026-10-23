// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// ackedHookToolCall is ackedHookCall for a tool call to toolName.
func ackedHookToolCall(t *testing.T, api *APIServer, session, toolName string, w http.ResponseWriter) {
	t.Helper()
	body := `{"hook_event_name":"PreToolUse","session_id":"` + session + `","cwd":"/tmp","tool_name":"` + toolName +
		`","tool_use_id":"` + session + `-tool","tool_input":{"command":"echo ok"}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook",
		strings.NewReader(body+hookexec.HookDeliveryReceiptAck))
	request.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
	request.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len(body)))
	request.Header.Set("Content-Type", "application/json")
	api.handleAgentHook("claudecode").ServeHTTP(w, request)
}

// connectorHookRow is the connector audit row of session's call.
func (f managedHookAuditFixture) connectorHookRow(t *testing.T, session string) audit.Event {
	t.Helper()
	events, err := f.store.ListEvents(1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == string(audit.ActionConnectorHook) && event.SessionID == session {
			return event
		}
	}
	t.Fatalf("no connector audit row for %s", session)
	return audit.Event{}
}

// Where the decision of a call could not be journaled, its records are held
// for the local store, and a local write a power loss can take back is not
// enough: recovery would then audit the call differently under the same IDs.
// So while the store cannot flush its writes, the records stay local, and
// the remote destinations get no decision of the call at all.
func TestPendingHookUnjournaledDecisionLeavesOnlyOnceStoredDurably(t *testing.T) {
	remote := newHookRemoteRecorder()
	f := newManagedHookAuditFixtureExportingTo(t, nil, remote)
	const session = "unflushed"
	liftDecision := refuseHookDeliveryDecision(t, f)
	liftFlush := refuseAuditWrites(t, f, "UPDATE", "observability_store_readiness", "1")
	reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
	ackedHookCall(t, f.api, session, reply)
	liftDecision()
	liftFlush()
	if !strings.Contains(reply.Body.String(), hookexec.HookDeliveryConfirmed) {
		t.Fatalf("gateway response = %q, want the receipt confirmation", reply.Body.String())
	}
	if got := f.audited(t, session)[session]; got != "allow" {
		t.Fatalf("local audit = %q, want the acknowledged allow", got)
	}
	id := f.connectorHookRow(t, session).ID
	remote.settled(t, 0, id, id+"-decision")
	for _, record := range []string{id, id + "-decision"} {
		if got := remote.decisions(record); len(got) != 0 {
			t.Fatalf("remote copies of %s = %v, want none of a record a power loss can take back", record, got)
		}
	}

	// Once the store flushes again, a held record leaves.
	liftDecision = refuseHookDeliveryDecision(t, f)
	defer liftDecision()
	const flushed = "flushed"
	ackedHookCall(t, f.api, flushed, &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()})
	id = f.connectorHookRow(t, flushed).ID
	remote.settled(t, 1, id, id+"-decision")
	for _, record := range []string{id, id + "-decision"} {
		if got := strings.Join(remote.decisions(record), ","); got != "answer" {
			t.Fatalf("remote copies of %s = %q, want the answer once", record, got)
		}
	}
}

// The records of a journaled call name the policy and the turn it was
// evaluated under, also when the next gateway process writes them under
// another rule pack, another configuration and a fresh turn counter.
func TestPendingHookRecoveryKeepsTheProvenanceTheCallWasEvaluatedUnder(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	t.Cleanup(func() { version.SetContentHash(nil) })
	const session = "provenance"
	f.api.scannerCfg.Guardrail.RulePackDir = filepath.Join(t.TempDir(), "pack-evaluated")
	version.SetContentHash([]byte("configuration the call was evaluated under"))
	version.BumpGeneration()
	evaluated := version.Current()
	evaluatedPack := f.api.effectiveRulePackDir(t.Context(), "claudecode")
	// Two earlier turns: the call is the session's step 2.
	for range 2 {
		f.api.stepIndexForTurn(session, "", "UserPromptSubmit")
	}
	orphanPendingHook(t, f, session, pendingAllow)

	restarted := f.restartedAPI(t, true)
	f.api.scannerCfg.Guardrail.RulePackDir = filepath.Join(t.TempDir(), "pack-after-restart")
	version.SetContentHash([]byte("configuration after the restart"))
	version.BumpGeneration()
	if current := restarted.effectiveRulePackDir(t.Context(), "claudecode"); current == evaluatedPack {
		t.Fatalf("the restarted server resolves the evaluated rule pack %q", current)
	}
	restarted.recoverPendingHooks(t.Context())

	row := f.connectorHookRow(t, session)
	if row.StepIdx != 2 || row.RulePackDir != evaluatedPack ||
		row.ContentHash != evaluated.ContentHash || row.Generation != evaluated.Generation {
		t.Fatalf("recovered row step %d pack %q config %q/%d; want step 2 pack %q config %q/%d",
			row.StepIdx, row.RulePackDir, row.ContentHash, row.Generation,
			evaluatedPack, evaluated.ContentHash, evaluated.Generation)
	}
	var steps []string
	for _, record := range readClaudeCodeReplayRows(t, f.path) {
		if record.event == "hook_decision" {
			steps = append(steps, fmt.Sprint(record.body["defenseclaw.connector.step_idx"]))
		}
	}
	if strings.Join(steps, ",") != "2" {
		t.Fatalf("recovered hook_decision steps = %v, want [2]", steps)
	}
}
