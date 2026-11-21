// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestGAP0524DeliveredPerUserKeepsBothDecisionRecordsAfterEarlierDeadline(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	f.api.scannerCfg.DeploymentMode = "per_user"
	delayNext := delayDeliveredStage(t)
	call := func(session string) {
		t.Helper()
		deliverAckedHookCall(t, f, session)
	}
	call("g524-benign")
	if got := f.audited(t, "g524-benign")["g524-benign"]; got != "allow" {
		t.Fatalf("ordinary benign call audit = %q, want allow", got)
	}
	delayNext()
	call("g524-delayed")
	if got := f.audited(t, "g524-delayed")["g524-delayed"]; got != "allow" {
		t.Fatalf("delivered call audit = %q, want allow", got)
	}
	if decisions := f.decisions(t); len(decisions) != 2 || decisions[0] != "allow/ok" || decisions[1] != "allow/ok" {
		t.Fatalf("both decision records = %v, want two allows", decisions)
	}
}

func TestGAP0524QueuedPerUserDecisionSurvivesExpiredForegroundContext(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	f.api.scannerCfg.DeploymentMode = "per_user"
	const session = "g524-queued"
	p := orphanPendingHook(t, f, session, pendingAllow)
	baseCtx := audit.ContextWithEnvelope(ContextWithSessionID(t.Context(), session),
		audit.CorrelationEnvelope{Connector: "claudecode", SessionID: session, RequestID: session + "-tool", ToolID: session + "-tool"})
	durableCtx, cancelDurable := f.api.hookDeliveredPersistenceContext(baseCtx, p != nil)
	if cancelDurable == nil {
		t.Fatal("receipt-confirmed per-user call has no durable write context")
	}
	defer cancelDurable()
	f.api.pendingHookDecidedContext(durableCtx, p, pendingAllow)
	batchCtx := audit.WithCallWriteBatch(durableCtx, f.store)
	foregroundCtx, cancelForeground := context.WithTimeout(batchCtx, 100*time.Millisecond)
	defer cancelForeground()
	db, err := sql.Open("sqlite", f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	rawBody := preToolUseBody(t, session+"-tool")
	resultCh := make(chan hookFinalizationResult, 1)
	go func() {
		req := p.request()
		req.pendingRecovery = false
		resultCh <- f.api.finalizeAgentHookAnswer(foregroundCtx, "claudecode", req, pendingAllow,
			nil, rawBody, time.Millisecond, false, nil, true)
	}()
	<-foregroundCtx.Done()
	if _, err := conn.ExecContext(t.Context(), "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-resultCh:
		if !result.AuditPersisted || !result.DecisionSettled {
			t.Fatalf("expired foreground context lost terminal records: %+v", result)
		}
	case <-time.After(max(30*time.Second, testenv.Scale(5*time.Second, 3*testenv.HostSlowdown()))):
		// The records settle as soon as the writer returns, so this is the
		// wait for a signal, not a speed limit: it stretches with the host
		// (GAP-0510: a box at load 100 took 3.7 s of a 5 s window).
		t.Fatal("queued terminal records did not settle after the writer returned")
	}
	audit.CloseCallWrites(batchCtx)
	for _, id := range []string{p.ID, p.ID + "-decision"} {
		present, err := f.store.HasAuditEventID(t.Context(), id)
		if err != nil || !present {
			t.Fatalf("queued terminal record %s present=%t error=%v", id, present, err)
		}
	}
	if decisions := f.decisions(t); len(decisions) != 1 || decisions[0] != "allow/ok" {
		t.Fatalf("queued decision rows = %v, want one allow", decisions)
	}
}
