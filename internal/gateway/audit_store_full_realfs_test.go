// Copyright 2026 Cisco Systems, Inc. and its affiliates
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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// substrate-1:GAP-0554: LIVEGATE filled a gateway's audit volume for real
// (tmpfs, cap 64 MiB). No "ALERT audit_store_full" line was ever logged: the
// failures said only "audit WAL checkpoint failed ... database or disk is
// full", "hook correlation unavailable ... database or disk is full" and
// "hook audit persistence failed ... insert v8 event-history row failed",
// because the alert lived on one health-transition line of the event-history
// writer that the real fill path does not take. The store here sits on a real
// tmpfs filled to ENOSPC by the kernel (no injected error). While it is full,
// a sandbox PreToolUse is either audited or blocked with the named
// audit-store reason, never an unaudited allow; a Stop stays a neutral allow
// (a denied stop keeps the agent running); the operator gets one
// "ALERT audit_store_full" line (rate-limited), and one line when the store
// has room again.
func TestSandboxHookOnARealFullAuditStoreFailsClosedWithOneAlert(t *testing.T) {
	dir := testenv.RealSmallFilesystem(t, 40)
	installCorrelationHMACForTest(t)
	installDefaultProfileConnector(t, "claudecode")
	fixture := newSidecarRuntimeFixtureExportingToInDir(t, dir, nil, nil)
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

	sandboxCtx := sandboxauth.WithRequest(context.Background(),
		sandboxauth.Binding{ID: "binding-real-full", SandboxName: "sbx", Connector: "claudecode"}, nil)
	sandboxCtx = context.WithValue(sandboxCtx, sandboxRelayStateKey{}, &sandboxRelayState{sink: &sandboxRelayDecisionSink{}})
	call := func(body []byte) map[string]any {
		t.Helper()
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)).WithContext(sandboxCtx)
		api.handleAgentHook("claudecode").ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	audited := func(toolUseID string) bool {
		t.Helper()
		database, err := sql.Open("sqlite", "file:"+fixture.path+"?mode=ro")
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		var n int
		if err := database.QueryRow(`SELECT count(*) FROM audit_events WHERE event_name = 'hook_decision'
			AND json_extract(projected_record_json,'$.correlation.tool_invocation_id') = ?`, toolUseID).Scan(&n); err != nil {
			t.Fatalf("read the audit store: %v", err)
		}
		return n > 0
	}
	if out := call(preToolUseBody(t, "toolu-room")); out["action"] != "allow" {
		t.Fatalf("store with room: verdict %v, want allow", out)
	}

	release := testenv.FillFilesystem(t, dir)
	var blocked map[string]any
	var allowedAudited int
	full := captureStderr(t, func() {
		for i := 0; i < 400 && blocked == nil; i++ {
			id := fmt.Sprintf("toolu-full-%d", i)
			out := call(preToolUseBody(t, id))
			switch out["action"] {
			case "block":
				blocked = out
			case "allow":
				// The store took the record in space it already had.
				if !audited(id) {
					t.Errorf("full store: %s was allowed with no audit record: %v", id, out)
					return
				}
				allowedAudited++
			default:
				t.Errorf("full store: %s verdict %v, want allow (audited) or block", id, out)
				return
			}
		}
		stop, err := json.Marshal(map[string]any{"hook_event_name": "Stop", "session_id": "s-real-full", "cwd": t.TempDir(), "stop_hook_active": false})
		if err != nil {
			t.Fatal(err)
		}
		if out := call(stop); out["action"] != "allow" {
			t.Errorf("full store: Stop verdict %v, want the neutral allow (a denied stop keeps the agent running)", out)
		}
		for i := 0; i < 3; i++ {
			if out := call(preToolUseBody(t, fmt.Sprintf("toolu-still-full-%d", i))); out["action"] != "block" {
				t.Errorf("still full: verdict %v, want block", out)
			}
		}
	})
	t.Logf("full store: %d calls audited in space the store already had before the first block", allowedAudited)
	if blocked == nil {
		t.Fatalf("400 sandbox calls on a full audit store were all allowed and audited; the store never refused a write\n%s", full)
	}
	if reason, _ := blocked["reason"].(string); reason != sandboxAuditFailureReason {
		t.Fatalf("full store block reason = %q, want the audit-store reason %q", reason, sandboxAuditFailureReason)
	}
	if n := strings.Count(full, "ALERT audit_store_full"); n != 1 {
		t.Fatalf("full store: %d \"ALERT audit_store_full\" lines, want exactly 1 (rate-limited); stderr:\n%s", n, full)
	}
	for _, line := range strings.Split(full, "\n") {
		if strings.Contains(line, "ALERT audit_store_full") {
			t.Logf("operator signal: %s", line)
		}
	}
	for _, want := range []string{"fail closed", "max_store_mb"} {
		if !strings.Contains(full, want) {
			t.Fatalf("the ALERT line lacks %q; stderr:\n%s", want, full)
		}
	}

	release()
	recovered := captureStderr(t, func() {
		if out := call(preToolUseBody(t, "toolu-room-again")); out["action"] != "allow" {
			t.Errorf("store with room again: verdict %v, want allow", out)
		}
	})
	if !audited("toolu-room-again") {
		t.Fatal("store with room again: the allowed call has no audit record")
	}
	if !strings.Contains(recovered, "audit_store_full cleared") {
		t.Fatalf("no recovery line once the store had room again; stderr:\n%s", recovered)
	}
}
