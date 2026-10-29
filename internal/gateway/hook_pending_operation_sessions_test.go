// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// GAP-0673, GAP-1792: under a 10/s hook flood calls 28-95 of every run were
// closed by a pending-operation identity collision. Five sessions reuse the
// same tool ids, and every call is delivered twice at once (the overlapping
// redelivery of the flood): every answer is a benign allow, and each
// (session, tool id) keeps its own pending operation, never one shared
// across sessions.
func TestPendingOperationsStayPerSessionUnderReusedToolIDs(t *testing.T) {
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
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	bindHookLifecycleV8(t, api, fixture.runtime)
	cwd := t.TempDir()
	const sessions, toolIDs, copies = 5, 20, 2
	var mu sync.Mutex
	answers := map[string]int{}
	var calls sync.WaitGroup
	for index := range toolIDs {
		for session := range sessions {
			for range copies {
				calls.Add(1)
				go func() {
					defer calls.Done()
					time.Sleep(time.Duration(index) * 100 * time.Millisecond)
					body, err := json.Marshal(map[string]any{
						"session_id":      fmt.Sprintf("flood-session-%d", session),
						"transcript_path": filepath.Join(cwd, "transcript.jsonl"),
						"cwd":             cwd, "permission_mode": "default", "hook_event_name": "PreToolUse",
						"tool_name": "Bash", "tool_use_id": fmt.Sprintf("toolu_%06d", index),
						"tool_input": map[string]any{"command": "echo ok", "description": "Print ok"},
					})
					if err != nil {
						t.Error(err)
						return
					}
					rec := httptest.NewRecorder()
					api.handleAgentHook("claudecode").ServeHTTP(rec,
						httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
					var answer map[string]any
					_ = json.Unmarshal(rec.Body.Bytes(), &answer)
					mu.Lock()
					answers[fmt.Sprintf("%d/%v", rec.Code, answer["action"])]++
					mu.Unlock()
				}()
			}
		}
	}
	calls.Wait()
	if total := sessions * toolIDs * copies; answers["200/allow"] != total {
		t.Fatalf("answers = %v, want %d benign allows", answers, total)
	}
	db, err := sql.Open("sqlite", "file:"+fixture.path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var operations, sessionsSeen int
	if err := db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT session_id) FROM correlation_pending_operations
		WHERE session_id LIKE 'flood-session-%'`).Scan(&operations, &sessionsSeen); err != nil {
		t.Fatal(err)
	}
	if operations != sessions*toolIDs || sessionsSeen != sessions {
		t.Fatalf("pending operations = %d over %d sessions, want %d over %d (one per session and tool id)",
			operations, sessionsSeen, sessions*toolIDs, sessions)
	}
}
