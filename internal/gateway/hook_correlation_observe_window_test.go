// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

type ledgerCallResult struct {
	ctx     context.Context
	req     agentHookRequest
	err     error
	elapsed time.Duration
}

// holdCorrelationLedger takes the audit store's one connection with an open
// correlation transaction, as a burst of concurrent hooks does, and returns
// the function that gives it back.
func holdCorrelationLedger(t *testing.T, f managedHookAuditFixture, semantic string) func() {
	t.Helper()
	repo, err := f.store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	hold, _, err := repo.BeginExistingOccurrence(context.Background(), audit.SemanticEventID(semantic))
	if err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			_ = hold.Rollback()
		}
	}
	t.Cleanup(release)
	return release
}

func startBoundedLedgerCall(f managedHookAuditFixture, ctx context.Context, session string) <-chan ledgerCallResult {
	done := make(chan ledgerCallResult, 1)
	go func() {
		start := time.Now()
		req := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse",
			SessionID: session, ToolName: "Bash", ToolInvocationID: session + "-tool", CWD: "/tmp"}
		outCtx, out, err := f.api.correlateHookOccurrence(ctx, f.api.hookProfileForRequest(ctx, "claudecode"), req,
			[]byte(managedHookBody(session, "PreToolUse")))
		done <- ledgerCallResult{ctx: outCtx, req: out, err: err, elapsed: time.Since(start)}
	}()
	return done
}

// rel-1-0-6 GAP-0152: in a 32-way burst of benign hook calls the calls
// queued on the audit store's one connection for the correlation ledger, past
// the hook's 4 s, and the hook denied them as "the gateway is running but did
// not answer" in observe mode. An observe-mode call whose hook bounds its
// answer now gives the ledger only its share of the answer window and goes on
// without the cross-call join IDs; action mode still waits for the ledger.
func TestObserveHookCallDoesNotWaitPastItsAnswerWindowForTheCorrelationLedger(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	f.api.scannerCfg.Guardrail.Mode = "observe"
	if mode := f.api.agentHookMode(t.Context(), "claudecode"); mode != "observe" {
		t.Fatalf("fixture hook mode = %q, want observe", mode)
	}
	seed := <-startBoundedLedgerCall(f, t.Context(), "ledger-window-seed")
	if seed.err != nil || seed.req.SemanticEventID == "" {
		t.Fatalf("seed correlation: err=%v semantic=%q", seed.err, seed.req.SemanticEventID)
	}

	t.Run("observe call answers inside its window", func(t *testing.T) {
		release := holdCorrelationLedger(t, f, seed.req.SemanticEventID)
		ctx := context.WithValue(t.Context(), shellToolGateKey{}, time.Now().Add(2*time.Second))
		done := startBoundedLedgerCall(f, ctx, "ledger-window-observe")
		select {
		case got := <-done:
			release()
			if !errors.Is(got.err, errHookCorrelationLate) {
				t.Fatalf("err = %v, want the late-ledger error", got.err)
			}
			if got.elapsed > 1500*time.Millisecond {
				t.Fatalf("the ledger held the call %s, past its share of a 2 s answer window", got.elapsed)
			}
			if got.ctx == nil || got.ctx.Err() != nil {
				t.Fatalf("the call's context ended with the ledger's deadline: %v", got.ctx)
			}
		case <-time.After(5 * time.Second):
			release()
			<-done
			t.Fatal("an observe-mode call waited for the held correlation ledger past its answer window")
		}
	})

	t.Run("observe call keeps its context and ledger values", func(t *testing.T) {
		ctx := context.WithValue(t.Context(), shellToolGateKey{}, time.Now().Add(2*time.Second))
		got := <-startBoundedLedgerCall(f, ctx, "ledger-window-free")
		if got.err != nil || got.req.SemanticEventID == "" {
			t.Fatalf("free ledger: err=%v semantic=%q", got.err, got.req.SemanticEventID)
		}
		if got.ctx.Err() != nil {
			t.Fatalf("the call's context ended with the ledger's deadline: %v", got.ctx.Err())
		}
		if env := audit.EnvelopeFromContext(got.ctx); env.SemanticEventID != got.req.SemanticEventID {
			t.Fatalf("envelope semantic = %q, want %q", env.SemanticEventID, got.req.SemanticEventID)
		}
	})

	t.Run("action call still waits for the ledger", func(t *testing.T) {
		f.api.scannerCfg.Guardrail.Mode = "action"
		t.Cleanup(func() { f.api.scannerCfg.Guardrail.Mode = "observe" })
		release := holdCorrelationLedger(t, f, seed.req.SemanticEventID)
		ctx := context.WithValue(t.Context(), shellToolGateKey{}, time.Now().Add(2*time.Second))
		done := startBoundedLedgerCall(f, ctx, "ledger-window-action")
		select {
		case got := <-done:
			t.Fatalf("an action-mode call left the held ledger early: err=%v after %s", got.err, got.elapsed)
		case <-time.After(1500 * time.Millisecond):
		}
		release()
		got := <-done
		if got.err != nil {
			t.Fatalf("action-mode correlation after the ledger was free: %v", got.err)
		}
	})
}

// The per-user Claude Code and Codex shell hooks bound a tool-gate call's
// wait without asking for progress reports; their calls get the shell
// tool-gate bound only after the correlation ledger step, so that step gets
// the same answer end on its own context (rel-1-0-6 GAP-0152).
func TestShellToolGateCallBoundsItsCorrelationLedgerInObserveMode(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	f.api.scannerCfg.Guardrail.Mode = "observe"
	start := time.Now()
	request := func(event string, progress bool) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", nil)
		r.Header.Set(hookexec.HookAnswerWithinHeader, "2900")
		if progress {
			r.Header.Set(hookexec.HookProgressHeader, "1")
		}
		return r.WithContext(context.WithValue(t.Context(), hookRequestStartKey{}, start))
	}
	r := request("PreToolUse", false)
	end, ok := f.api.observeHookCorrelationEnd(f.api.hookCorrelationBoundContext(r.Context(), "claudecode", "PreToolUse", r), "claudecode")
	if want := start.Add(2900*time.Millisecond - shellToolGateAnswerMargin - hookCorrelationAnswerReserve); !ok || !end.Equal(want) {
		t.Fatalf("shell tool gate ledger end = %v, %v; want %v", end, ok, want)
	}
	for _, c := range []struct {
		name, connector, event string
		progress               bool
	}{
		{"prompt event", "claudecode", "UserPromptSubmit", false},
		{"progress hook", "claudecode", "PreToolUse", true},
		{"other connector", "copilot", "PreToolUse", false},
	} {
		r := request(c.event, c.progress)
		if _, ok := f.api.observeHookCorrelationEnd(f.api.hookCorrelationBoundContext(r.Context(), c.connector, c.event, r), c.connector); ok {
			t.Fatalf("%s: the correlation ledger got a shell tool-gate bound", c.name)
		}
	}
	f.api.scannerCfg.Guardrail.Mode = "action"
	r = request("PreToolUse", false)
	if _, ok := f.api.observeHookCorrelationEnd(f.api.hookCorrelationBoundContext(r.Context(), "claudecode", "PreToolUse", r), "claudecode"); ok {
		t.Fatal("action mode: the correlation ledger got an observe bound")
	}
}
