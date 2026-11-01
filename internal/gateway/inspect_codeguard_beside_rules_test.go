// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A write tool call's CodeGuard scan runs while the rule dispatch runs, so a
// large benign Write is answered in the longer of the two, not their sum
// (GAP-2284). The dispatch waits until CodeGuard has started; one after the
// other, it would wait out its bound instead. The verdict is unchanged.
func TestWriteCallCodeGuardRunsBesideTheRuleDispatch(t *testing.T) {
	const bound = 3 * time.Second
	codeGuardStarted := make(chan struct{})
	var overlapped bool
	priorCodeGuard, priorDispatch := inspectCodeGuardArgs, inspectDispatchTrustedAction
	t.Cleanup(func() { inspectCodeGuardArgs, inspectDispatchTrustedAction = priorCodeGuard, priorDispatch })
	inspectCodeGuardArgs = func(a *APIServer, ctx context.Context, req *ToolInspectRequest) codeGuardArgsScan {
		close(codeGuardStarted)
		return priorCodeGuard(a, ctx, req)
	}
	inspectDispatchTrustedAction = func(ctx context.Context, request trustedActionRequest) []RuleFinding {
		select {
		case <-codeGuardStarted:
			overlapped = true
		case <-time.After(bound):
		}
		return priorDispatch(ctx, request)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	store, logger := testStoreAndLogger(t)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
	body, _ := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "s-beside", "tool_name": "Write",
		"tool_input": map[string]any{
			"file_path": filepath.Join(t.TempDir(), "big.js"),
			"content":   strings.Repeat("function helper(a, b) { return a + b; }\n", 2000),
		},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	reply := httptest.NewRecorder()
	started := time.Now()
	api.handleAgentHook("claudecode").ServeHTTP(reply, request)
	var answer struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(reply.Body.Bytes(), &answer); err != nil {
		t.Fatalf("status=%d body=%.300s", reply.Code, reply.Body.String())
	}
	if answer.Action != "allow" {
		t.Fatalf("action = %q, want allow (body %.300s)", answer.Action, reply.Body.String())
	}
	if !overlapped {
		t.Fatalf("the rule dispatch waited %s for a CodeGuard scan that starts only after it (call took %s)", bound, time.Since(started))
	}
}

// The CodeGuard verdict of a write call is the same whether or not the scan
// ran beside the dispatch: a CodeGuard finding still reaches the answer.
func TestWriteCallCodeGuardFindingStillDecidesBesideTheRuleDispatch(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	store, logger := testStoreAndLogger(t)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
	req := &ToolInspectRequest{Tool: "Write", Args: json.RawMessage(`{"file_path":"/tmp/app.py","content":"import os\nos.system(user_input)\n"}`)}
	direct := api.runCodeGuardOnArgsWithProvenance(context.Background(), req)
	beside := api.startCodeGuardOnArgs(context.Background(), req)()
	if len(direct.findings) == 0 {
		t.Fatal("fixture has no CodeGuard finding")
	}
	if len(beside.findings) != len(direct.findings) || beside.complete != direct.complete {
		t.Fatalf("beside = %+v, direct = %+v", beside, direct)
	}
	for i := range direct.findings {
		if beside.findings[i].RuleID != direct.findings[i].RuleID {
			t.Fatalf("finding %d: %s vs %s", i, beside.findings[i].RuleID, direct.findings[i].RuleID)
		}
	}
}

// A panic in the CodeGuard scan is raised on the caller's goroutine, where
// the hook's panic recovery handles it as before.
func TestWriteCallCodeGuardPanicReachesTheCaller(t *testing.T) {
	prior := inspectCodeGuardArgs
	t.Cleanup(func() { inspectCodeGuardArgs = prior })
	inspectCodeGuardArgs = func(*APIServer, context.Context, *ToolInspectRequest) codeGuardArgsScan { panic("codeguard boom") }
	wait := (&APIServer{}).startCodeGuardOnArgs(context.Background(), &ToolInspectRequest{})
	defer func() {
		if r := recover(); r != "codeguard boom" {
			t.Fatalf("recovered %v", r)
		}
	}()
	wait()
	t.Fatal("no panic")
}
