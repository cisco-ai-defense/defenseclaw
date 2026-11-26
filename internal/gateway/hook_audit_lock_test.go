// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// hookAnswerWithHeldAuditLock bounds the answer to a benign hook call while
// another process holds audit.db's write lock. The OSS per-user Claude Code
// hook gives up about 2.1 s after it starts and spends about 1 s itself on a
// 4-vCPU host (GAP-1021 red: every call refused "the gateway is running but
// did not answer").
const hookAnswerWithHeldAuditLock = time.Second

// The first locked call pays the audit store's busy timeout (750 ms), then the
// store answers degraded at once (a later locked call takes about 24 ms), so
// the bound leaves the call 250 ms of its own work and of host scheduling.
// On a native Windows box that runs a second test process, one such call took
// 1.10 s (GAP-2209). A call is judged against the bound stretched by the host
// slowdown, read before the lock and again after a call that ran over (the
// larger reading counts); a product that waits longer than its busy timeout
// (a second busy wait is 1.5 s, the lock itself 5 s) is over the stretched bound at
// any slowdown the host reports, because the stretch is capped at
// hookAnswerHostStretch.
const hookAnswerHostStretch = 1.4

// hookAnswerWindow is the bound on a locked call at a host slowdown.
func hookAnswerWindow(slowdown float64) time.Duration {
	return testenv.Scale(hookAnswerWithHeldAuditLock, min(max(1, slowdown), hookAnswerHostStretch))
}

// TestBenignHookAnswersWhileAnotherProcessHoldsTheAuditLock: with audit.db
// write-locked by another connection (sqlite3, a CLI or backup tool in a
// transaction), a benign PreToolUse is answered allow inside the hook's
// budget, in observe and in action mode, with the audit-degraded notice; once
// the lock is released the next call is answered and audited as usual
// (GAP-1021).
func TestBenignHookAnswersWhileAnotherProcessHoldsTheAuditLock(t *testing.T) {
	for _, mode := range []string{"observe", "action"} {
		t.Run(mode, func(t *testing.T) {
			installCorrelationHMACForTest(t)
			installDefaultProfileConnector(t, "claudecode")
			fixture := newSidecarRuntimeFixture(t, true)
			fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
			if err != nil {
				t.Fatal(err)
			}
			logger := audit.NewLogger(fixture.store)
			logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
			cfg := &config.Config{}
			cfg.Guardrail.Mode = mode
			cfg.Guardrail.Connector = "claudecode"
			api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
			bindHookLifecycleV8(t, api, fixture.runtime)
			cwd := t.TempDir()
			call := func(index int) (*httptest.ResponseRecorder, time.Duration) {
				body, err := json.Marshal(map[string]any{
					"session_id": "audit-lock-" + mode, "transcript_path": filepath.Join(cwd, "transcript.jsonl"),
					"cwd": cwd, "permission_mode": "default", "hook_event_name": "PreToolUse", "tool_name": "Bash",
					"tool_use_id": fmt.Sprintf("toolu_lock_%06d", index),
					"tool_input":  map[string]any{"command": "echo ok", "description": "Print ok"},
				})
				if err != nil {
					t.Fatal(err)
				}
				recorder := httptest.NewRecorder()
				started := time.Now()
				api.handleAgentHook("claudecode").ServeHTTP(recorder,
					httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
				return recorder, time.Since(started)
			}
			for index := 0; index < 3; index++ {
				if recorder, _ := call(index); recorder.Code != http.StatusOK {
					t.Fatalf("warm call %d: status %d", index, recorder.Code)
				}
			}
			locker, err := sql.Open("sqlite", "file:"+fixture.path)
			if err != nil {
				t.Fatal(err)
			}
			defer locker.Close()
			conn, err := locker.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
				t.Fatal(err)
			}
			var releaseOnce sync.Once
			release := func() {
				releaseOnce.Do(func() {
					_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
					_ = conn.Close()
				})
			}
			defer release()
			// Bound a run without the fix: the lock goes after 5 s.
			releaseLater := time.AfterFunc(5*time.Second, release)
			defer releaseLater.Stop()
			slowdown := testenv.HostSlowdown()
			for index := 10; index < 14; index++ {
				recorder, took := call(index)
				if took > hookAnswerWithHeldAuditLock {
					slowdown = max(slowdown, testenv.HostSlowdown())
				}
				if recorder.Code != http.StatusOK {
					t.Fatalf("locked call %d: status %d body %s", index, recorder.Code, recorder.Body.String())
				}
				var answer map[string]any
				if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
					t.Fatal(err)
				}
				if answer["action"] != "allow" {
					t.Fatalf("locked call %d: action %v, want allow: %s", index, answer["action"], recorder.Body.String())
				}
				if !strings.Contains(recorder.Body.String(), "audit is degraded") {
					t.Errorf("locked call %d: no audit-degraded notice: %s", index, recorder.Body.String())
				}
				if window := hookAnswerWindow(slowdown); took > window {
					t.Errorf("locked call %d answered after %v; the hook gives up first (bound %v, %v at host slowdown x%.1f)", index, took, hookAnswerWithHeldAuditLock, window, slowdown)
				}
				t.Logf("locked call %d: %v", index, took)
			}
			release()
			recorder, took := call(20)
			if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "audit is degraded") {
				t.Fatalf("after release: status %d body %s", recorder.Code, recorder.Body.String())
			}
			if took > hookAnswerWithHeldAuditLock {
				t.Errorf("after release the call took %v", took)
			}
		})
	}
}
