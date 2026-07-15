// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestParseCorrelationQueryRequiresOneTypedAnchor(t *testing.T) {
	semantic, err := audit.NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		values url.Values
		ok     bool
	}{
		{"semantic", url.Values{"semantic_event_id": {string(semantic)}, "limit": {"25"}}, true},
		{"lifecycle", url.Values{"lifecycle_id": {"lifecycle-1"}}, true},
		{"execution", url.Values{"execution_id": {"execution-1"}}, true},
		{"trace and span", url.Values{"trace_id": {strings.Repeat("a", 32)}, "span_id": {strings.Repeat("b", 16)}}, true},
		{"none", url.Values{}, false},
		{"two", url.Values{"session_id": {"s"}, "turn_id": {"t"}}, false},
		{"scope only", url.Values{"connector_instance_id": {string(semantic)}}, false},
		{"span only", url.Values{"span_id": {strings.Repeat("b", 16)}}, false},
		{"bad UUID", url.Values{"semantic_event_id": {"not-a-uuid"}}, false},
		{"bad trace case", url.Values{"trace_id": {strings.Repeat("A", 32)}}, false},
		{"unknown", url.Values{"session_id": {"s"}, "guess": {"x"}}, false},
		{"repeated", url.Values{"session_id": {"s", "s"}}, false},
		{"whitespace", url.Values{"session_id": {" s"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCorrelationQuery(tc.values)
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v ok=%v", err, tc.ok)
			}
		})
	}
}

func TestCorrelationReadAPIIsNoStoreAndFailClosed(t *testing.T) {
	installCorrelationHMACForTest()
	server, store := newHookCorrelationServer(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close() //nolint:errcheck
	profile := server.hookProfileForConnector("codex")
	payload := map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "api-session", "turn_id": "api-turn",
		"event_id": "api-event", "tool_use_id": "api-tool", "tool_name": "Read",
	}
	req := normalizeAgentHookRequestWithProfile("codex", payload, profile)
	_, req, err := server.correlateHookOccurrence(t.Context(), profile, req,
		[]byte(`{"event_id":"api-event","hook_event_name":"PreToolUse","session_id":"api-session","tool_name":"Read","tool_use_id":"api-tool","turn_id":"api-turn"}`))
	if err != nil {
		t.Fatal(err)
	}
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.RecordObservation(t.Context(), audit.CorrelationObservation{
		RecordID: "api-lifecycle-observation", SemanticEventID: audit.SemanticEventID(req.SemanticEventID),
		Signal: audit.CorrelationSignalLogs, Bucket: "agent_lifecycle", EventName: "tool.started",
		ObservedAt: time.Now().UTC(), LifecycleID: "api-lifecycle", ExecutionID: "api-execution",
		Status: audit.CorrelationObservationExportEligible,
	}); err != nil {
		t.Fatal(err)
	}

	httpReq := httptest.NewRequest(http.MethodGet, "/api/v1/correlation/explain?semantic_event_id="+url.QueryEscape(req.SemanticEventID), nil)
	recorder := httptest.NewRecorder()
	server.handleCorrelationExplainV8(recorder, httpReq)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache=%q body=%s", recorder.Code, recorder.Header().Get("Cache-Control"), recorder.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 {
		t.Fatal("empty correlation response")
	}
	for parameter, value := range map[string]string{
		"lifecycle_id": "api-lifecycle",
		"execution_id": "api-execution",
	} {
		anchored := httptest.NewRequest(http.MethodGet,
			"/api/v1/correlation/graph?"+parameter+"="+url.QueryEscape(value), nil)
		recorder = httptest.NewRecorder()
		server.handleCorrelationGraphV8(recorder, anchored)
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), req.SemanticEventID) {
			t.Fatalf("%s status=%d body=%s", parameter, recorder.Code, recorder.Body.String())
		}
	}

	bad := httptest.NewRequest(http.MethodGet, "/api/v1/correlation/graph?semantic_event_id=bad", nil)
	recorder = httptest.NewRecorder()
	server.handleCorrelationGraphV8(recorder, bad)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid query status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	post := httptest.NewRequest(http.MethodPost, "/api/v1/correlation/graph?semantic_event_id="+url.QueryEscape(req.SemanticEventID), nil)
	recorder = httptest.NewRecorder()
	server.handleCorrelationGraphV8(recorder, post)
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("method status=%d allow=%q", recorder.Code, recorder.Header().Get("Allow"))
	}

	unavailable := &APIServer{}
	recorder = httptest.NewRecorder()
	unavailable.handleCorrelationGraphV8(recorder, httpReq)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable status=%d", recorder.Code)
	}
}
