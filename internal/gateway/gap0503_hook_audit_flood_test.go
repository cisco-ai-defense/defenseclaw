// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// TestGAP0503HookToolRowsSurviveExpiredCompletionDuringFlood reproduces a
// timed-out hook client whose tool attempt must still be audited. Five clients
// disconnect before PreToolUse reaches the production handler; their PostToolUse
// partners and the other 25 pairs keep the 25/s flood going.
//
// The live flood that found rel-1-0-6:GAP-0503 sent 1000 pairs, and 5 of its
// PreToolUse calls lost their tool rows. The loss is per call: a PreToolUse
// whose client is gone before the handler runs emitted its tool rows with the
// cancelled request context. The handler runs each call to its end before the
// next one starts, so the calls around a disconnected one only interleave it
// with live pairs on the same store; 30 pairs at the flood's 25/s, with the
// five disconnected PreToolUse calls spread across them and live pairs after
// the last one, keep that shape at a thirtieth of the cost. With the fix
// reverted (emission on the request context) this flood records 25 of 30
// tool_start rows, as the 1000-pair one recorded 995.
func TestGAP0503HookToolRowsSurviveExpiredCompletionDuringFlood(t *testing.T) {
	grace := agentHookDisconnectGrace
	agentHookDisconnectGrace = 0
	t.Cleanup(func() { agentHookDisconnectGrace = grace })
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	fixture := newSidecarRuntimeFixture(t, true)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	bindHookLifecycleV8(t, api, fixture.runtime)
	handler := api.handleAgentHook("claudecode")
	const pairs = 30
	const disconnectEvery = 6
	const interval = time.Second / 25
	next := time.Now()
	for index := range pairs {
		if wait := time.Until(next); wait > 0 {
			time.Sleep(wait)
		}
		next = next.Add(interval)
		toolID := fmt.Sprintf("toolu_gap0503_%04d", index)
		pre := claudePreToolUseForOperationTest("gap0503-flood", toolID)
		post := claudePreToolUseForOperationTest("gap0503-flood", toolID)
		post.HookEventName = "PostToolUse"
		post.Payload["hook_event_name"] = "PostToolUse"
		for _, req := range []claudeCodeHookRequest{pre, post} {
			body, err := json.Marshal(req.Payload)
			if err != nil {
				t.Fatal(err)
			}
			client, disconnect := context.WithCancel(t.Context())
			if index%disconnectEvery == 0 && req.HookEventName == "PreToolUse" {
				disconnect()
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)).WithContext(client)
			handler.ServeHTTP(httptest.NewRecorder(), request)
			disconnect()
		}
	}
	db, err := sql.Open("sqlite", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// A PreToolUse keeps its tool call in its hook_decision row; its
	// tool_start and tool.invocation.requested records are exported only
	// (#1384). The completion keeps its tool_end and completed rows.
	for _, event := range []string{"tool_end", "tool.invocation.completed"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_name = ?`, event).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != pairs {
			t.Errorf("%s rows = %d, want %d", event, count, pairs)
		}
	}
	var requested int
	if err := db.QueryRow(`SELECT COUNT(DISTINCT json_extract(projected_record_json,'$.correlation.tool_invocation_id')) FROM audit_events WHERE event_name = 'hook_decision'
		AND json_extract(projected_record_json,'$.body."defenseclaw.hook.event"') = 'PreToolUse'
		`).Scan(&requested); err != nil {
		t.Fatal(err)
	}
	if requested != pairs {
		t.Errorf("PreToolUse hook_decision rows naming their tool call = %d, want %d", requested, pairs)
	}
}

// heldWriterSigner pauses inside an event-history transaction, after that
// transaction has acquired the store's only SQLite connection.
type heldWriterSigner struct {
	entered chan struct{}
	release chan struct{}
	armed   atomic.Bool
}

func (signer *heldWriterSigner) KeyID() string { return "gap0503-stall-v1" }

func (signer *heldWriterSigner) HMACSHA256(_ context.Context, message []byte) ([]byte, error) {
	if signer.armed.CompareAndSwap(true, false) {
		close(signer.entered)
		<-signer.release
	}
	mac := hmac.New(sha256.New, []byte("gap0503-test-signing-key"))
	_, _ = mac.Write(message)
	return mac.Sum(nil), nil
}

// The real handler's flushes must leave the held connection after their
// persistence deadlines, and the lost tool rows must appear in local SQLite's
// dropped counter while the connection is still held.
func TestGAP0503HandlerHeldSQLiteReportsDroppedToolRows(t *testing.T) {
	grace := agentHookDisconnectGrace
	agentHookDisconnectGrace = 0
	t.Cleanup(func() { agentHookDisconnectGrace = grace })
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	signer := &heldWriterSigner{entered: make(chan struct{}), release: make(chan struct{})}
	fixture := newSidecarRuntimeFixtureWithSigner(t, true, signer)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	bindHookLifecycleV8(t, api, fixture.runtime)
	handler := api.handleAgentHook("claudecode")

	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(signer.release) }) }
	defer release()
	signer.armed.Store(true)
	holderDone := make(chan struct{})
	go func() {
		defer close(holderDone)
		api.emitClaudeCodeHookLLMEvent(context.Background(), claudePreToolUseForOperationTest("gap0503-holder", "toolu_holder"), nil, nil)
	}()
	select {
	case <-signer.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("holder did not reach the signer with the SQLite connection")
	}

	const calls = 300
	const interval = time.Second / 25
	started := time.Now()
	var active, completed atomic.Int64
	var wg sync.WaitGroup
	for index := range calls {
		body, err := json.Marshal(claudePreToolUseForOperationTest("gap0503-stall", fmt.Sprintf("toolu_stall_%03d", index)).Payload)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			active.Add(1)
			defer active.Add(-1)
			defer completed.Add(1)
			client, disconnect := context.WithCancel(t.Context())
			disconnect()
			request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)).WithContext(client)
			handler.ServeHTTP(httptest.NewRecorder(), request)
		}()
		if wait := time.Until(started.Add(time.Duration(index+1) * interval)); wait > 0 {
			time.Sleep(wait)
		}
	}
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	if wait := time.Until(started.Add(15 * time.Second)); wait > 0 {
		time.Sleep(wait)
	}
	remainingAt15 := active.Load()
	completedBy15 := completed.Load()
	select {
	case <-finished:
	case <-time.After(12 * time.Second):
	}
	snapshot, snapshotErr := fixture.runtime.DestinationHealthSnapshot(t.Context())
	remainingAtEnd := active.Load()
	release()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("hook handlers did not drain after the SQLite connection was released")
	}
	select {
	case <-holderDone:
	case <-time.After(10 * time.Second):
		t.Fatal("connection holder did not drain")
	}
	if snapshotErr != nil {
		t.Fatal(snapshotErr)
	}
	var dropped uint64
	for _, destination := range snapshot.Destinations {
		if destination.Name == config.ObservabilityV8LocalDestinationName {
			dropped = destination.Counters.Dropped
		}
	}
	if completedBy15 < 100 || remainingAt15 > 200 || remainingAtEnd != 0 || dropped < calls {
		t.Errorf("held SQLite connection: completed at 15s=%d, active at 15s=%d, active at end=%d, local rows dropped=%d; want >=100, <=200, 0, >=%d", completedBy15, remainingAt15, remainingAtEnd, dropped, calls)
	}
	locker, err := sql.Open("sqlite", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close()
	var committed int
	if err := locker.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_name = 'tool_start'`).Scan(&committed); err != nil {
		t.Fatal(err)
	}
	if committed != 1 {
		t.Errorf("tool_start rows after the connection returned = %d, want only the holder's row", committed)
	}
}
