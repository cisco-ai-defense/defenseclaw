// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

func TestCLIObservabilityV8RequestBoundary(t *testing.T) {
	valid := `{"kind":"action","run_id":"run-1","action":{"name":"policy-reload","target":"default","details":"changed"}}`
	tests := []struct {
		name       string
		method     string
		body       string
		wantStatus int
	}{
		{name: "method", method: http.MethodGet, body: valid, wantStatus: http.StatusMethodNotAllowed},
		{name: "missing runtime", method: http.MethodPost, body: valid, wantStatus: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, cliObservabilityV8Path, strings.NewReader(test.body))
			response := httptest.NewRecorder()
			(&APIServer{}).handleCLIObservabilityV8(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}

	fixture, api, _ := newCLIObservabilityV8Fixture(t)
	_ = fixture
	for _, body := range []string{
		``,
		`{`,
		`{"kind":"action","secret":"value","action":{"name":"policy-reload","target":"default","details":"changed"}}`,
		`{"kind":"action","kind":"alert","action":{"name":"policy-reload","target":"default","details":"changed"}}`,
		`{"kind":"action","action":{"name":"policy-reload","name":"config-update","target":"default","details":"changed"}}`,
		`{"kind":"action","action":{"name":"not-registered","target":"default","details":"changed"}}`,
		`{"kind":"action","action":{"name":"policy-reload","target":"default","details":"changed"},"alert":{"source":"scanner","summary":"bad"}}`,
		`{"kind":"scan","scan":{"scanner":"skill","target":"demo","timestamp":"2026-07-06T00:00:00Z","findings":[],"duration_ms":-1}}`,
		valid + `{}`,
	} {
		request := httptest.NewRequest(http.MethodPost, cliObservabilityV8Path, strings.NewReader(body))
		response := httptest.NewRecorder()
		api.handleCLIObservabilityV8(response, request)
		if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "secret") {
			t.Errorf("body=%q status=%d response=%q", body, response.Code, response.Body.String())
		}
	}
}

func TestCLIObservabilityV8SkillFindingScannerContract(t *testing.T) {
	fixture, api, capture := newCLIObservabilityV8Fixture(t)
	const target = `C:\disposable-codex-home\skills\dc-test-benign`
	const canonical = `{"kind":"scan","run_id":"skill-python-run","scan":{"scanner":"skill-scanner","target":"C:\\disposable-codex-home\\skills\\dc-test-benign","timestamp":"2026-07-24T16:00:00Z","findings":[{"id":"MANIFEST_MISSING_LICENSE_c5ae9be793","severity":"INFO","title":"Skill does not specify a license","description":"","location":"SKILL.md","remediation":"","scanner":"skill-scanner","tags":["analyzer:static"]}],"duration_ms":125}}`
	const leakedAnalyzer = `{"kind":"scan","run_id":"malformed-skill-run","scan":{"scanner":"skill-scanner","target":"C:\\disposable-codex-home\\skills\\dc-test-benign","timestamp":"2026-07-24T16:00:00Z","findings":[{"id":"MANIFEST_MISSING_LICENSE_c5ae9be793","severity":"INFO","title":"Skill does not specify a license","description":"","location":"SKILL.md","remediation":"","scanner":"static","tags":[]}],"duration_ms":125}}`

	request := httptest.NewRequest(http.MethodPost, cliObservabilityV8Path, strings.NewReader(canonical))
	response := httptest.NewRecorder()
	api.handleCLIObservabilityV8(response, request)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("canonical skill payload status=%d response=%q", response.Code, response.Body.String())
	}

	database, err := sql.Open("sqlite", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, check := range []struct {
		query string
		args  []any
		want  int
	}{
		{
			query: `SELECT COUNT(*) FROM scan_results WHERE run_id = 'skill-python-run' AND scanner = 'skill-scanner' AND target = ?`,
			args:  []any{target},
			want:  1,
		},
		{
			query: `SELECT COUNT(*) FROM scan_findings WHERE run_id = 'skill-python-run' AND scanner = 'skill-scanner'`,
			want:  1,
		},
		{
			query: `SELECT COUNT(*) FROM audit_events WHERE run_id = 'skill-python-run' AND action IN ('scan', 'scan-finding')`,
			want:  2,
		},
	} {
		var count int
		if err := database.QueryRow(check.query, check.args...).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != check.want {
			t.Fatalf("query=%q rows=%d want=%d", check.query, count, check.want)
		}
	}
	if len(capture.traces) != 1 {
		t.Fatalf("asset scan traces=%d, want one", len(capture.traces))
	}

	request = httptest.NewRequest(http.MethodPost, cliObservabilityV8Path, strings.NewReader(leakedAnalyzer))
	response = httptest.NewRecorder()
	api.handleCLIObservabilityV8(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed skill payload status=%d response=%q", response.Code, response.Body.String())
	}
	for _, table := range []string{"scan_results", "scan_findings", "audit_events"} {
		var count int
		query := "SELECT COUNT(*) FROM " + table + " WHERE run_id = 'malformed-skill-run'"
		if err := database.QueryRow(query).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s rows=%d after rejected skill payload", table, count)
		}
	}
}

func TestCLIObservabilityV8RejectsMalformedScanBeforeForensicPersistence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(scan, finding map[string]any)
	}{
		{name: "missing timestamp", mutate: func(scan, _ map[string]any) { delete(scan, "timestamp") }},
		{name: "zero timestamp", mutate: func(scan, _ map[string]any) {
			scan["timestamp"] = "0001-01-01T00:00:00Z"
		}},
		{name: "negative duration", mutate: func(scan, _ map[string]any) { scan["duration_ms"] = -1 }},
		{name: "duration overflow", mutate: func(scan, _ map[string]any) {
			scan["duration_ms"] = int64(9223372036855)
		}},
		{name: "invalid scanner", mutate: func(scan, _ map[string]any) { scan["scanner"] = "Skill Scanner" }},
		{name: "empty target", mutate: func(scan, _ map[string]any) { scan["target"] = " " }},
		{name: "oversized target", mutate: func(scan, _ map[string]any) {
			scan["target"] = strings.Repeat("t", cliObservabilityV8MaxTargetBytes+1)
		}},
		{name: "too many findings", mutate: func(scan, _ map[string]any) {
			findings := make([]any, cliObservabilityV8MaxFindings+1)
			for i := range findings {
				findings[i] = map[string]any{"id": "f", "severity": "INFO", "title": "x"}
			}
			scan["findings"] = findings
		}},
		{name: "invalid finding id", mutate: func(_ map[string]any, finding map[string]any) {
			finding["id"] = "finding with spaces"
		}},
		{name: "unknown severity", mutate: func(_ map[string]any, finding map[string]any) {
			finding["severity"] = "WARN"
		}},
		{name: "empty title", mutate: func(_ map[string]any, finding map[string]any) {
			finding["title"] = ""
		}},
		{name: "oversized title", mutate: func(_ map[string]any, finding map[string]any) {
			finding["title"] = strings.Repeat("x", cliObservabilityV8MaxTitleBytes+1)
		}},
		{name: "oversized description", mutate: func(_ map[string]any, finding map[string]any) {
			finding["description"] = strings.Repeat("x", cliObservabilityV8MaxEvidenceBytes+1)
		}},
		{name: "oversized location", mutate: func(_ map[string]any, finding map[string]any) {
			finding["location"] = strings.Repeat("x", cliObservabilityV8MaxLocationBytes+1)
		}},
		{name: "oversized remediation", mutate: func(_ map[string]any, finding map[string]any) {
			finding["remediation"] = strings.Repeat("x", cliObservabilityV8MaxEvidenceBytes+1)
		}},
		{name: "invalid rule id", mutate: func(_ map[string]any, finding map[string]any) {
			finding["rule_id"] = "rule with spaces"
		}},
		{name: "zero line number", mutate: func(_ map[string]any, finding map[string]any) {
			finding["line_number"] = 0
		}},
		{name: "scanner mismatch", mutate: func(_ map[string]any, finding map[string]any) {
			finding["scanner"] = "other-scanner"
		}},
		{name: "too many tags", mutate: func(_ map[string]any, finding map[string]any) {
			finding["tags"] = make([]string, cliObservabilityV8MaxTags+1)
		}},
		{name: "oversized tag", mutate: func(_ map[string]any, finding map[string]any) {
			finding["tags"] = []string{strings.Repeat("x", cliObservabilityV8MaxTagBytes+1)}
		}},
		{name: "internal confidence field", mutate: func(_ map[string]any, finding map[string]any) {
			finding["confidence"] = 0.75
		}},
		{name: "internal decision path", mutate: func(_ map[string]any, finding map[string]any) {
			finding["decision_path"] = map[string]any{"stage": "caller-controlled"}
		}},
		{name: "caller occurrence id", mutate: func(_ map[string]any, finding map[string]any) {
			finding["finding_occurrence_id"] = "caller-controlled"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, api, capture := newCLIObservabilityV8Fixture(t)
			finding := map[string]any{
				"id": "rule-1", "severity": "HIGH", "title": "Unsafe instruction",
				"description": "evidence", "location": "SKILL.md:1",
				"remediation": "remove it", "scanner": "skill-scanner",
				"tags": []string{"prompt-injection"}, "rule_id": "skill.rule-1",
				"line_number": 1,
			}
			scan := map[string]any{
				"scanner": "skill-scanner", "target": "skill://demo",
				"timestamp": "2026-07-06T00:00:00Z", "duration_ms": 1250,
				"findings": []any{finding},
			}
			test.mutate(scan, finding)
			body, err := json.Marshal(map[string]any{
				"kind": "scan", "run_id": "python-run", "scan": scan,
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, cliObservabilityV8Path, bytes.NewReader(body))
			response := httptest.NewRecorder()
			api.handleCLIObservabilityV8(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d response=%q", response.Code, response.Body.String())
			}

			database, err := sql.Open("sqlite", fixture.path)
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			for _, table := range []string{"scan_results", "scan_findings"} {
				var count int
				if err := database.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Fatalf("%s rows=%d after rejected request", table, count)
				}
			}
			if len(capture.traces) != 0 {
				t.Fatalf("asset scan traces=%d after rejected request", len(capture.traces))
			}
		})
	}
}

func TestCLIObservabilityV8EmitsCanonicalFamiliesWithRawSourceFacts(t *testing.T) {
	fixture, api, capture := newCLIObservabilityV8Fixture(t)
	requests := []string{
		`{"kind":"action","run_id":"python-run","action":{"name":"policy-reload","target":"default","details":"owner=alice@example.com"}}`,
		`{"kind":"activity","run_id":"python-run","activity":{"actor":"cli:alice","action":"policy-reload","target_type":"policy","target_id":"default","before":{"owner":"alice@example.com","mode":"warn"},"after":{"owner":"alice@example.com","mode":"block"},"diff":[{"path":"mode","op":"replace","before":"warn","after":"block"}],"severity":"INFO"}}`,
		`{"kind":"alert","run_id":"python-run","alert":{"source":"scanner","severity":"HIGH","summary":"contact alice@example.com","details":{"duration_ms":30000}}}`,
		`{"kind":"scan","run_id":"python-run","scan":{"scanner":"skill-scanner","target":"skill://demo","timestamp":"2026-07-06T00:00:00Z","duration_ms":1250,"findings":[{"id":"rule-1","severity":"HIGH","title":"Unsafe instruction","description":"contact alice@example.com","location":"SKILL.md:1","remediation":"remove it","scanner":"skill-scanner","tags":[],"rule_id":"skill.rule-1","line_number":1}]}}`,
	}
	for _, body := range requests {
		request := httptest.NewRequest(http.MethodPost, cliObservabilityV8Path, bytes.NewBufferString(body))
		response := httptest.NewRecorder()
		api.handleCLIObservabilityV8(response, request)
		if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
			t.Fatalf("status=%d response=%q request=%s", response.Code, response.Body.String(), body)
		}
	}

	database, err := sql.Open("sqlite", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT action, bucket, signal, event_name, source, COALESCE(run_id,''),
		COALESCE(redaction_profile,''), payload_json
		FROM audit_events WHERE run_id = 'python-run' ORDER BY timestamp, id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	seen := map[string]bool{}
	for rows.Next() {
		var action, bucket, signal, eventName, source, runID, profile, payload string
		if err := rows.Scan(
			&action, &bucket, &signal, &eventName, &source, &runID, &profile, &payload,
		); err != nil {
			t.Fatal(err)
		}
		count++
		seen[signal+"/"+bucket+"/"+eventName] = true
		if runID != "python-run" {
			t.Errorf("run_id=%q", runID)
		}
		if profile != "none" {
			t.Errorf("profile=%q for %s/%s", profile, bucket, eventName)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 5 || !seen["logs/compliance.activity/policy.updated"] ||
		!seen["logs/platform.health/subsystem.degraded"] ||
		!seen["logs/asset.scan/scan.completed"] ||
		!seen["logs/security.finding/finding.observed"] {
		t.Fatalf("count=%d families=%v", count, seen)
	}
	if len(capture.traces) != 1 {
		t.Fatalf("asset scan traces=%d, want one generated span", len(capture.traces))
	}
	trace := capture.traces[0]
	scannerName, scannerPresent := trace.DefenseClawScanScanner.Get()
	if !scannerPresent || scannerName != "skill-scanner" || trace.Kind != "INTERNAL" ||
		trace.Envelope.Correlation.RunID != "python-run" || trace.Outcome != observability.OutcomeCompleted {
		t.Fatalf("asset scan trace=%#v", trace)
	}
}

func TestCLIObservabilityV8GeneratesModelAndWebhookSignalsWithoutPythonSDKOwnership(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"traces", "metrics"})
	requests := []string{
		`{"kind":"llm_bridge","run_id":"python-run","llm_bridge":{"model":"openai/gpt-5","provider":"openai","status":"success","duration_ms":125.5,"input_tokens":21,"output_tokens":8,"response_model":"gpt-5","response_id":"response-1","finish_reasons":["stop"]}}`,
		`{"kind":"webhook_delivery","run_id":"python-run","webhook_delivery":{"webhook_kind":"slack","target_url":"https://hooks.example.test/private/path","status_code":204,"duration_ms":17.25,"succeeded":true}}`,
	}
	for _, body := range requests {
		request := httptest.NewRequest(http.MethodPost, cliObservabilityV8Path, strings.NewReader(body))
		response := httptest.NewRecorder()
		api.handleCLIObservabilityV8(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("status=%d body=%q request=%s", response.Code, response.Body.String(), body)
		}
	}

	var spans []*tracepb.Span
	metricNames := map[string]struct{}{}
	var metricRequests []*collectormetricspb.ExportMetricsServiceRequest
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		traceRequests, metrics := capture.snapshot()
		spans = hookModelV8CapturedSpans(traceRequests)
		metricRequests = metrics
		metricNames = hookModelV8CapturedMetricNames(metrics)
		_, bridge := metricNames[observability.TelemetryInstrumentDefenseClawLLMBridgeLatency]
		_, webhookLatency := metricNames[observability.TelemetryInstrumentDefenseClawWebhookLatency]
		_, webhookDispatch := metricNames[observability.TelemetryInstrumentDefenseClawWebhookDispatches]
		if len(spans) == 1 && bridge && webhookLatency && webhookDispatch {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(spans) != 1 || gatewayProtoAttribute(spans[0].Attributes, "defenseclaw.span.family") != observability.TelemetryFamilyModelChat ||
		spans[0].Name != "chat openai/gpt-5" {
		t.Fatalf("generated model spans=%+v", spans)
	}
	for _, name := range []string{
		observability.TelemetryInstrumentDefenseClawLLMBridgeLatency,
		observability.TelemetryInstrumentDefenseClawWebhookLatency,
		observability.TelemetryInstrumentDefenseClawWebhookDispatches,
	} {
		if _, found := metricNames[name]; !found {
			t.Errorf("missing metric %q from %v", name, metricNames)
		}
	}
	for _, request := range metricRequests {
		encoded, err := proto.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte("hooks.example.test")) || bytes.Contains(encoded, []byte("private/path")) {
			t.Fatal("raw webhook target escaped the gateway HMAC boundary")
		}
	}
}

type cliObservabilityV8Capture struct {
	*sidecarOwnedObservabilityV8Runtime
	traces []observability.SpanAssetScanInput
}

func (capture *cliObservabilityV8Capture) EmitRuntimeV8AssetScanTrace(
	ctx context.Context,
	input observability.SpanAssetScanInput,
) error {
	capture.traces = append(capture.traces, input)
	return capture.sidecarOwnedObservabilityV8Runtime.EmitRuntimeV8AssetScanTrace(ctx, input)
}

func newCLIObservabilityV8Fixture(
	t *testing.T,
) (sidecarRuntimeFixture, *APIServer, *cliObservabilityV8Capture) {
	t.Helper()
	fixture := newSidecarRuntimeFixture(t, true)
	logger := audit.NewLogger(fixture.store)
	owner := &sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime}
	capture := &cliObservabilityV8Capture{sidecarOwnedObservabilityV8Runtime: owner}
	logger.SetRuntimeV8Emitter(capture)
	t.Cleanup(logger.Close)
	api := &APIServer{store: fixture.store, logger: logger}
	api.bindObservabilityV8Runtimes(owner, owner, nil, owner)
	return fixture, api, capture
}
