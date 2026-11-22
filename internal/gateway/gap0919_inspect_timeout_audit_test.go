// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// gap0919Rows returns the audit rows whose action starts with prefix.
func gap0919Rows(t *testing.T, store *audit.Store, prefix string) []audit.Event {
	t.Helper()
	events, err := store.ListEvents(200)
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Event
	for _, event := range events {
		if strings.HasPrefix(event.Action, prefix) {
			out = append(out, event)
		}
	}
	return out
}

func gap0919ConnectorHealth(api *APIServer, name string) *ConnectorHealth {
	snap := api.health.Snapshot()
	for i := range snap.Connectors {
		if snap.Connectors[i].Name == name {
			return &snap.Connectors[i]
		}
	}
	if snap.Connector != nil && snap.Connector.Name == name {
		return snap.Connector
	}
	return nil
}

// A /api/v1/inspect/tool call that answers 504 past the scan budget writes
// one audit row (its own action, no verdict, reason scan_timeout and the
// elapsed time) and counts the check on /health, so a call the OpenClaw
// plugin then blocks by its fail mode is not unaudited (GAP-0919). The
// gateway records no block or allow for it, and a verdict the worker
// reaches after the 504 writes no second row.
func TestInspectToolScanTimeoutWritesOneAuditRowAndCountsTheCheck(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	api.scannerCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	api.inspectToolScanTimeout = 100 * time.Millisecond
	stub := &cancelGatedAIDInspector{
		started:  make(chan struct{}),
		canceled: make(chan struct{}),
		release:  make(chan struct{}),
	}
	api.SetCiscoInspector(stub)
	workerDone := make(chan struct{})
	api.inspectToolWorkerDone = func() { close(workerDone) }
	released := false
	t.Cleanup(func() {
		if !released {
			close(stub.release)
		}
	})

	request := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool",
		bytes.NewBufferString(`{"tool":"exec","args":{"command":"echo gap0919"}}`))
	request = request.WithContext(withAuthenticatedInspectConnector(request.Context(), "openclaw"))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.handleInspectTool(response, request)
	if response.Code != http.StatusGatewayTimeout || !strings.Contains(response.Body.String(), "scan timeout") {
		t.Fatalf("status %d body %s, want 504 scan timeout", response.Code, response.Body.String())
	}

	rows := gap0919Rows(t, store, "inspect-tool")
	if len(rows) != 1 {
		t.Fatalf("inspect-tool audit rows after the 504 = %d (%+v), want exactly one", len(rows), rows)
	}
	row := rows[0]
	if row.Action != "inspect-tool-timeout" {
		t.Fatalf("timeout row action = %q, want inspect-tool-timeout (never a block or allow the gateway did not decide)", row.Action)
	}
	for _, want := range []string{"verdict=none", "reason=scan_timeout", "elapsed_ms=", "budget_ms=100"} {
		if !strings.Contains(row.Details, want) {
			t.Fatalf("timeout row details %q lack %q", row.Details, want)
		}
	}
	if row.Severity != "MEDIUM" || row.Target != "exec" || row.Connector != "openclaw" {
		t.Fatalf("timeout row severity=%q target=%q connector=%q, want MEDIUM exec openclaw", row.Severity, row.Target, row.Connector)
	}
	health := gap0919ConnectorHealth(api, "openclaw")
	if health == nil || health.ToolInspections != 1 || health.ToolBlocks != 0 {
		t.Fatalf("openclaw /health after the 504 = %+v, want tool_inspections 1, tool_blocks 0", health)
	}

	close(stub.release)
	released = true
	select {
	case <-workerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed-out worker did not finish")
	}
	if rows := gap0919Rows(t, store, "inspect-tool"); len(rows) != 1 {
		t.Fatalf("inspect-tool audit rows after the late worker verdict = %d (%+v), want still one", len(rows), rows)
	}
	if health := gap0919ConnectorHealth(api, "openclaw"); health == nil || health.ToolInspections != 1 || health.ToolBlocks != 0 {
		t.Fatalf("openclaw /health after the late worker verdict = %+v", health)
	}
}

// The content routes answer 504 past the scan budget too; each writes its
// own timeout row (GAP-0919).
func TestInspectContentRoutesScanTimeoutWritesOneAuditRow(t *testing.T) {
	// The scan waits for the budget: with only a 1 ns budget, a Windows timer
	// tick can come after the scan and the route answers 200.
	inspectScanHoldForTest = func(ctx context.Context) { <-ctx.Done() }
	t.Cleanup(func() { inspectScanHoldForTest = nil })
	big := strings.Repeat("hello world ", maxInspectContentLen/12)
	output, _ := json.Marshal(big)
	for _, tc := range []struct {
		route, action, target string
		handler               func(*APIServer) http.HandlerFunc
		body                  any
	}{
		{"/api/v1/inspect/request", "inspect-request-timeout", "pre-request",
			func(a *APIServer) http.HandlerFunc { return a.handleInspectRequest }, RequestInspectRequest{Content: big}},
		{"/api/v1/inspect/response", "inspect-response-timeout", "post-response",
			func(a *APIServer) http.HandlerFunc { return a.handleInspectResponse }, ResponseInspectRequest{Content: big}},
		{"/api/v1/inspect/tool-response", "inspect-tool-response-timeout", "read_file",
			func(a *APIServer) http.HandlerFunc { return a.handleInspectToolResponse },
			ToolResponseInspectRequest{Tool: "read_file", Output: output}},
	} {
		t.Run(tc.route, func(t *testing.T) {
			store, logger := testStoreAndLogger(t)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
			api.inspectToolScanTimeout = time.Nanosecond
			raw, _ := json.Marshal(tc.body)
			rec := httptest.NewRecorder()
			tc.handler(api)(rec, httptest.NewRequest(http.MethodPost, tc.route, bytes.NewReader(raw)))
			if rec.Code != http.StatusGatewayTimeout {
				t.Fatalf("status %d body %s, want 504", rec.Code, rec.Body.String())
			}
			rows := gap0919Rows(t, store, "inspect-")
			if len(rows) != 1 || rows[0].Action != tc.action || rows[0].Target != tc.target ||
				!strings.Contains(rows[0].Details, "reason=scan_timeout") || !strings.Contains(rows[0].Details, "elapsed_ms=") {
				t.Fatalf("audit rows after the 504 = %+v, want one %s row target %s with reason=scan_timeout", rows, tc.action, tc.target)
			}
		})
	}
}

// A caller that goes away before the budget (its own timeout is shorter)
// also gets the call's one row, with its own reason; the write outlives the
// cancelled request instead of being dropped with it (GAP-0919 review).
func TestInspectToolCallerCancelStillWritesTheTimeoutRow(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	api.scannerCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	api.inspectToolScanTimeout = 30 * time.Second
	stub := &cancelGatedAIDInspector{
		started:  make(chan struct{}),
		canceled: make(chan struct{}),
		release:  make(chan struct{}),
	}
	api.SetCiscoInspector(stub)
	workerDone := make(chan struct{})
	api.inspectToolWorkerDone = func() { close(workerDone) }
	defer func() {
		close(stub.release)
		<-workerDone
	}()
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool",
		bytes.NewBufferString(`{"tool":"exec","args":{"command":"echo gap0919"}}`)).WithContext(parent)
	request = request.WithContext(withAuthenticatedInspectConnector(request.Context(), "openclaw"))
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		api.handleInspectTool(response, request)
	}()
	select {
	case <-stub.started:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached the inspector")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled handler did not return")
	}
	if response.Code != http.StatusGatewayTimeout {
		t.Fatalf("status %d, want 504", response.Code)
	}
	rows := gap0919Rows(t, store, "inspect-tool")
	if len(rows) != 1 || rows[0].Action != "inspect-tool-timeout" || !strings.Contains(rows[0].Details, "reason=caller_canceled") {
		t.Fatalf("rows after a caller cancel = %+v, want one inspect-tool-timeout row with reason=caller_canceled", rows)
	}
}
