// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/audit/sinks"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// Correlation and identity constants used across v7 e2e so every surface agrees.
const (
	e2eRunID             = "e2e-run-correlation"
	e2eSessionID         = "sess-e2e"
	e2eTraceID           = "0af7651916cd43dd8448eb211c80319c"
	e2eAgentID           = "e2e-agent"
	e2eAgentInstanceID   = "11111111-1111-1111-1111-111111111111"
	e2eSidecarInstanceID = "22222222-2222-2222-2222-222222222222"
)

// observabilityHarness wires SQLite + gateway.jsonl + OTel logs/metrics + audit sinks
// the same way the sidecar does, for cross-surface assertions.
type observabilityHarness struct {
	Store   *audit.Store
	Logger  *audit.Logger
	GW      *gatewaylog.Writer
	gwBuf   *[]gatewaylog.Event
	gwJSONL *[][]byte // marshaled gateway events (export / sink analogue)
	Tel     *telemetry.Provider
	Reader  *sdkmetric.ManualReader
	SpanExp *tracetest.InMemoryExporter
	Sink    *recordingSink
}

type recordingSink struct {
	name string
	mu   sync.Mutex
	evs  []sinks.Event
}

func newRecordingSink(name string) *recordingSink {
	return &recordingSink{name: name}
}

func (r *recordingSink) Name() string { return r.name }
func (r *recordingSink) Kind() string { return "recording" }

func (r *recordingSink) Forward(_ context.Context, e sinks.Event) error {
	r.mu.Lock()
	r.evs = append(r.evs, e)
	r.mu.Unlock()
	return nil
}

func (r *recordingSink) Flush(_ context.Context) error { return nil }
func (r *recordingSink) Close() error                  { return nil }

func (r *recordingSink) snapshot() []sinks.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]sinks.Event, len(r.evs))
	copy(out, r.evs)
	return out
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	// test/e2e/v7_test_helpers.go -> repo root
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func validateAgainstSchema(t *testing.T, jsonBytes []byte, schemaRel string) {
	t.Helper()
	root := moduleRoot(t)
	schemaPath := filepath.Join(root, schemaRel)
	py := filepath.Join(root, ".venv", "bin", "python3")
	if _, err := os.Stat(py); err != nil {
		py = "python3"
	}
	cmd := exec.Command(py, "-c", `
import json, sys
from pathlib import Path
from referencing import Registry, Resource
from jsonschema import Draft202012Validator

schema_path = Path(sys.argv[1])
root = schema_path.parent
schema_doc = json.loads(schema_path.read_text())
doc = json.loads(sys.argv[2])

if schema_path.name == 'gateway-event-envelope.json':
    resources = []
    for name in ['scan-event.json', 'scan-finding-event.json', 'activity-event.json']:
        uri = 'https://defenseclaw.io/schemas/' + name
        p = root / name
        if p.exists():
            resources.append((uri, Resource.from_contents(json.loads(p.read_text()))))
    registry = Registry().with_resources(resources)
    Draft202012Validator(schema_doc, registry=registry).validate(doc)
else:
    Draft202012Validator(schema_doc).validate(doc)
`, schemaPath, string(jsonBytes))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("jsonschema %s: %v\n%s", schemaRel, err, stderr.String())
	}
}

func resetProvenance(t *testing.T) {
	t.Helper()
	version.ResetForTesting()
	version.SetBinaryVersion("e2e-v7")
	if err := version.SetContentHashCanonicalJSON(map[string]any{"e2e": true}); err != nil {
		t.Fatalf("SetContentHashCanonicalJSON: %v", err)
	}
	version.BumpGeneration()
}

// triggerViaSidecarHTTP runs fn inside an httptest.Server handler and issues one GET.
// Correlation headers are set so tests exercise the same shape as HTTP-driven sidecar work.
func triggerViaSidecarHTTP(t *testing.T, fn func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fn()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v7/e2e", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Defenseclaw-Run-ID", e2eRunID)
	req.Header.Set("X-Defenseclaw-Session-ID", e2eSessionID)
	req.Header.Set("X-Defenseclaw-Trace-ID", e2eTraceID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func envelopeBase() gatewaylog.Event {
	// v7 clean break: AgentInstanceID is the per-session UUID (not
	// the process UUID); SidecarInstanceID is what used to be
	// audit.ProcessAgentInstanceID() in v6. Tests pin deterministic
	// values so cross-surface assertions stay stable.
	return gatewaylog.Event{
		RunID:             e2eRunID,
		SessionID:         e2eSessionID,
		TraceID:           e2eTraceID,
		AgentID:           e2eAgentID,
		AgentInstanceID:   e2eAgentInstanceID,
		SidecarInstanceID: e2eSidecarInstanceID,
	}
}

func newObservabilityHarness(t *testing.T) *observabilityHarness {
	t.Helper()
	resetProvenance(t)
	_ = os.Setenv("DEFENSECLAW_RUN_ID", e2eRunID)
	t.Cleanup(func() { _ = os.Unsetenv("DEFENSECLAW_RUN_ID") })
	// Pin the process-wide sidecar instance id so auto-fills
	// (Logger.LogEvent, logActivityImpl) yield exactly what
	// envelopeBase() expects on the SidecarInstanceID axis.
	audit.SetProcessAgentInstanceID(e2eSidecarInstanceID)

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	st, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := st.Init(); err != nil {
		st.Close()
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	reader := sdkmetric.NewManualReader()
	exp := tracetest.NewInMemoryExporter()
	tp, err := telemetry.NewProviderForTraceTest(reader, exp)
	if err != nil {
		t.Fatalf("NewProviderForTraceTest: %v", err)
	}

	log := audit.NewLogger(st)
	log.SetOTelProvider(tp)

	rs := newRecordingSink("rec")
	mgr := sinks.NewManager()
	mgr.Register(rs)
	log.SetSinks(mgr)

	gw, err := gatewaylog.New(gatewaylog.Config{})
	if err != nil {
		t.Fatalf("gatewaylog.New: %v", err)
	}
	buf := &[]gatewaylog.Event{}
	jsonl := &[][]byte{}
	var mu sync.Mutex
	gw.WithFanout(func(ev gatewaylog.Event) {
		mu.Lock()
		*buf = append(*buf, ev)
		b, err := json.Marshal(ev)
		if err == nil {
			*jsonl = append(*jsonl, b)
		}
		mu.Unlock()
		tp.EmitGatewayEvent(ev)
	})
	log.SetGatewayLogWriter(gw)
	log.SetStructuredEmitter(structuredEmitter{w: gw})

	h := &observabilityHarness{
		Store:   st,
		Logger:  log,
		GW:      gw,
		gwBuf:   buf,
		gwJSONL: jsonl,
		Tel:     tp,
		Reader:  reader,
		SpanExp: exp,
		Sink:    rs,
	}
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	return h
}

// structuredEmitter forwards LogActivity / LogAlert gateway events to the same
// JSONL writer used by LogScan (mirrors sidecar wiring).
type structuredEmitter struct {
	w *gatewaylog.Writer
}

func (s structuredEmitter) EmitAudit(_ audit.Event) {}

func (s structuredEmitter) EmitGatewayEvent(ev gatewaylog.Event) {
	if s.w != nil {
		s.w.Emit(ev)
	}
}

func findGatewayEvents(h *observabilityHarness, typ gatewaylog.EventType) []gatewaylog.Event {
	var out []gatewaylog.Event
	for _, e := range *h.gwBuf {
		if e.EventType == typ {
			out = append(out, e)
		}
	}
	return out
}

func collectMetrics(t *testing.T, r *sdkmetric.ManualReader) metricdata.ResourceMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := r.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rm
}

func hasMetricName(rm metricdata.ResourceMetrics, name string) bool {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return true
			}
		}
	}
	return false
}

func findMetric(rm metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	for _, sm := range rm.ScopeMetrics {
		for i := range sm.Metrics {
			if sm.Metrics[i].Name == name {
				return &sm.Metrics[i]
			}
		}
	}
	return nil
}

func sumInt64Counter(rm metricdata.ResourceMetrics, name string) int64 {
	m := findMetric(rm, name)
	if m == nil {
		return 0
	}
	sum, ok := m.Data.(metricdata.Sum[int64])
	if !ok {
		return 0
	}
	var n int64
	for _, dp := range sum.DataPoints {
		n += dp.Value
	}
	return n
}

func metricHasAttrKeyValue(rm metricdata.ResourceMetrics, metricName, attrKey, attrVal string) bool {
	m := findMetric(rm, metricName)
	if m == nil {
		return false
	}
	sum, ok := m.Data.(metricdata.Sum[int64])
	if !ok {
		return false
	}
	for _, dp := range sum.DataPoints {
		v, found := dp.Attributes.Value(attribute.Key(attrKey))
		if found && v.AsString() == attrVal && dp.Value > 0 {
			return true
		}
	}
	return false
}

func assertCorrelationTriplet(t *testing.T, ev gatewaylog.Event) {
	t.Helper()
	if ev.RunID != e2eRunID || ev.SessionID != e2eSessionID || ev.TraceID != e2eTraceID {
		t.Fatalf("correlation mismatch: run_id=%q session_id=%q trace_id=%q want %q %q %q",
			ev.RunID, ev.SessionID, ev.TraceID, e2eRunID, e2eSessionID, e2eTraceID)
	}
}

func assertThreeTierIdentity(t *testing.T, ev gatewaylog.Event) {
	t.Helper()
	// Plan §"Three-tier agent identity":
	//   agent_id           → logical agent (e.g. "openclaw"): always present
	//   agent_instance_id  → per-SESSION UUID: present on session-anchored events
	//   sidecar_instance_id → per-PROCESS UUID: present on any event stamped
	//                         by the running sidecar
	// The v6 behavior (agent_instance_id == process UUID) is specifically
	// disallowed; if this assertion fails it means a call site regressed
	// back to the old semantics.
	if ev.AgentID != e2eAgentID {
		t.Fatalf("agent_id=%q want %q", ev.AgentID, e2eAgentID)
	}
	if ev.AgentInstanceID != e2eAgentInstanceID {
		t.Fatalf("agent_instance_id=%q want %q (must be per-session, not process UUID)",
			ev.AgentInstanceID, e2eAgentInstanceID)
	}
	if ev.SidecarInstanceID != e2eSidecarInstanceID {
		t.Fatalf("sidecar_instance_id=%q want %q", ev.SidecarInstanceID, e2eSidecarInstanceID)
	}
	if ev.AgentInstanceID == ev.SidecarInstanceID {
		t.Fatalf("agent_instance_id must not equal sidecar_instance_id (v6 regression)")
	}
}

func lastGatewayExportJSON(t *testing.T, h *observabilityHarness) []byte {
	t.Helper()
	lines := *h.gwJSONL
	if len(lines) == 0 {
		t.Fatal("no gateway export lines")
	}
	return lines[len(lines)-1]
}

func validateGatewayEnvelope(t *testing.T, raw []byte) {
	t.Helper()
	validateAgainstSchema(t, raw, "schemas/gateway-event-envelope.json")
}

func mustMarshalEvent(t *testing.T, ev gatewaylog.Event) []byte {
	t.Helper()
	ev.Timestamp = ev.Timestamp.UTC()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// minimalScanResult returns a tiny scan result usable for golden / e2e.
func minimalScanResult(findings []scanner.Finding) *scanner.ScanResult {
	return &scanner.ScanResult{
		Scanner:    "skill",
		Target:     "/tmp/e2e",
		TargetType: "skill",
		Timestamp:  time.Unix(1700000000, 0).UTC(),
		Duration:   1,
		Findings:   findings,
	}
}

// stripVolatileGatewayJSON normalizes JSON for golden comparison.
func stripVolatileGatewayJSON(t *testing.T, raw []byte) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m["ts"] = "2000-01-01T00:00:00Z"
	for _, k := range []string{"run_id", "request_id", "session_id", "trace_id", "content_hash", "binary_version"} {
		if _, ok := m[k]; ok {
			m[k] = "<stripped>"
		}
	}
	if _, ok := m["generation"]; ok {
		m["generation"] = 1
	}
	// nested payloads that often carry ids
	stripMap := func(key string) {
		sub, ok := m[key].(map[string]any)
		if !ok || sub == nil {
			return
		}
		for _, kk := range []string{"scan_id", "finding_id", "activity_id"} {
			if _, ok := sub[kk]; ok {
				sub[kk] = "<stripped>"
			}
		}
		m[key] = sub
	}
	for _, k := range []string{"scan", "scan_finding", "activity", "verdict", "judge", "lifecycle", "error", "diagnostic"} {
		stripMap(k)
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

var updateGolden bool

func goldenPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(moduleRoot(t), "test", "e2e", "testdata", "v7", "golden", name)
}

func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := goldenPath(t, name)
	if updateGolden {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote %s", p)
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read golden %s: %v", p, err)
	}
	if strings.TrimSpace(string(want)) != strings.TrimSpace(string(got)) {
		t.Fatalf("golden mismatch %s\n--- want ---\n%s\n--- got ---\n%s\n", name, string(want), string(got))
	}
}
