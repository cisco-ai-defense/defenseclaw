// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinationtest"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const destinationTestGatewayToken = "destination-test-gateway-token"

type fakeDestinationTestLocalEmitter struct {
	calls atomic.Int64
	emit  func(context.Context, router.Metadata, observabilityruntime.EmitBuilder) (pipeline.LocalLogOutcome, error)
}

func (emitter *fakeDestinationTestLocalEmitter) EmitLocalOnly(
	ctx context.Context,
	metadata router.Metadata,
	builder observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	emitter.calls.Add(1)
	return emitter.emit(ctx, metadata, builder)
}

func TestObservabilityDestinationTestActivityRejectsInvalidRequestBoundary(t *testing.T) {
	valid := destinationTestActivityJSON(t, destinationtest.Activity{
		Phase: "attempt", Destination: "soc", ProbeID: "probe-1",
		Mode: "handshake", Result: "attempted",
	})
	tests := []struct {
		name       string
		method     string
		remote     string
		client     string
		body       string
		wantStatus int
		wantAllow  string
	}{
		{name: "method", method: http.MethodGet, remote: "127.0.0.1:1234", client: destinationTestClient, body: valid, wantStatus: http.StatusMethodNotAllowed, wantAllow: http.MethodPost},
		{name: "non-loopback", method: http.MethodPost, remote: "192.0.2.4:1234", client: destinationTestClient, body: valid, wantStatus: http.StatusForbidden},
		{name: "hostname remote", method: http.MethodPost, remote: "localhost:1234", client: destinationTestClient, body: valid, wantStatus: http.StatusForbidden},
		{name: "missing client", method: http.MethodPost, remote: "127.0.0.1:1234", body: valid, wantStatus: http.StatusForbidden},
		{name: "wrong client", method: http.MethodPost, remote: "127.0.0.1:1234", client: "openclaw-plugin", body: valid, wantStatus: http.StatusForbidden},
		{name: "empty", method: http.MethodPost, remote: "127.0.0.1:1234", client: destinationTestClient, wantStatus: http.StatusBadRequest},
		{name: "malformed", method: http.MethodPost, remote: "127.0.0.1:1234", client: destinationTestClient, body: `{`, wantStatus: http.StatusBadRequest},
		{name: "unknown field", method: http.MethodPost, remote: "127.0.0.1:1234", client: destinationTestClient, body: strings.TrimSuffix(valid, "}") + `,"secret":"must-not-enter"}`, wantStatus: http.StatusBadRequest},
		{name: "duplicate field", method: http.MethodPost, remote: "127.0.0.1:1234", client: destinationTestClient, body: `{"phase":"attempt","phase":"outcome","destination":"soc","probe_id":"probe-1","mode":"handshake","result":"attempted"}`, wantStatus: http.StatusBadRequest},
		{name: "trailing value", method: http.MethodPost, remote: "127.0.0.1:1234", client: destinationTestClient, body: valid + `{}`, wantStatus: http.StatusBadRequest},
		{name: "invalid contract", method: http.MethodPost, remote: "127.0.0.1:1234", client: destinationTestClient, body: `{"phase":"attempt","destination":"soc","probe_id":"probe-1","mode":"handshake","result":"failed","failure_class":"timeout"}`, wantStatus: http.StatusBadRequest},
		{name: "oversize", method: http.MethodPost, remote: "127.0.0.1:1234", client: destinationTestClient, body: strings.Repeat(" ", destinationtest.MaxEncodedBytes+1), wantStatus: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := &APIServer{}
			request := httptest.NewRequest(test.method, destinationtest.EndpointPath, strings.NewReader(test.body))
			request.RemoteAddr = test.remote
			request.Header.Set("Content-Type", "application/json")
			if test.client != "" {
				request.Header.Set("X-DefenseClaw-Client", test.client)
			}
			recorder := httptest.NewRecorder()
			api.handleObservabilityDestinationTestActivity(recorder, request)
			if recorder.Code != test.wantStatus || recorder.Header().Get("Allow") != test.wantAllow {
				t.Fatalf("status=%d allow=%q body=%s", recorder.Code, recorder.Header().Get("Allow"), recorder.Body.String())
			}
		})
	}
	t.Run("duplicate client header", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, destinationtest.EndpointPath, strings.NewReader(valid))
		request.RemoteAddr = "127.0.0.1:1234"
		request.Header.Set("Content-Type", "application/json")
		request.Header.Add("X-DefenseClaw-Client", destinationTestClient)
		request.Header.Add("X-DefenseClaw-Client", "openclaw-plugin")
		recorder := httptest.NewRecorder()
		(&APIServer{}).handleObservabilityDestinationTestActivity(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})
}

func TestObservabilityDestinationTestActivityUsesGlobalBearerAndCSRFMiddleware(t *testing.T) {
	activity := destinationTestActivityJSON(t, destinationtest.Activity{
		Phase: "attempt", Destination: "soc", ProbeID: "probe-1",
		Mode: "handshake", Result: "attempted",
	})
	api := &APIServer{scannerCfg: &config.Config{Gateway: config.GatewayConfig{Token: destinationTestGatewayToken}}}
	handler := api.tokenAuth(api.apiCSRFProtect(http.HandlerFunc(api.handleObservabilityDestinationTestActivity)))
	for _, test := range []struct {
		name       string
		token      string
		client     string
		wantStatus int
	}{
		{name: "missing bearer", client: destinationTestClient, wantStatus: http.StatusUnauthorized},
		{name: "wrong bearer", token: "wrong", client: destinationTestClient, wantStatus: http.StatusUnauthorized},
		{name: "missing csrf client", token: destinationTestGatewayToken, wantStatus: http.StatusForbidden},
		{name: "authenticated reaches fail-closed runtime check", token: destinationTestGatewayToken, client: destinationTestClient, wantStatus: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := destinationTestHTTPRequest(t, activity)
			if test.token != "" {
				request.Header.Set("Authorization", "Bearer "+test.token)
			}
			if test.client == "" {
				request.Header.Del("X-DefenseClaw-Client")
			} else {
				request.Header.Set("X-DefenseClaw-Client", test.client)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
		})
	}
}

func TestObservabilityDestinationTestActivityFailsClosedWithoutConfirmedPersistence(t *testing.T) {
	activity := destinationTestActivityJSON(t, destinationtest.Activity{
		Phase: "attempt", Destination: "soc", ProbeID: "probe-1",
		Mode: "handshake", Result: "attempted",
	})
	for _, test := range []struct {
		name    string
		emitter *fakeDestinationTestLocalEmitter
	}{
		{name: "missing emitter"},
		{name: "persistence error", emitter: &fakeDestinationTestLocalEmitter{emit: func(
			context.Context, router.Metadata, observabilityruntime.EmitBuilder,
		) (pipeline.LocalLogOutcome, error) {
			return pipeline.LocalLogOutcome{}, errors.New("secret sqlite path and backend detail")
		}}},
		{name: "ambiguous non-persisted outcome", emitter: &fakeDestinationTestLocalEmitter{emit: func(
			context.Context, router.Metadata, observabilityruntime.EmitBuilder,
		) (pipeline.LocalLogOutcome, error) {
			return pipeline.LocalLogOutcome{}, nil
		}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &APIServer{}
			if test.emitter != nil {
				api.observabilityV8LocalOnly = test.emitter
			}
			recorder := httptest.NewRecorder()
			api.handleObservabilityDestinationTestActivity(recorder, destinationTestHTTPRequest(t, activity))
			if recorder.Code != http.StatusServiceUnavailable ||
				strings.Contains(recorder.Body.String(), "sqlite") || strings.Contains(recorder.Body.String(), "secret") {
				t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
			}
			wantCalls := int64(0)
			if test.emitter != nil {
				wantCalls = 1
			}
			if test.emitter != nil && test.emitter.calls.Load() != wantCalls {
				t.Fatalf("emitter calls=%d want=%d", test.emitter.calls.Load(), wantCalls)
			}
		})
	}
}

func TestObservabilityDestinationTestActivityPersistsGeneratedFamiliesExactlyOnceAndLocally(t *testing.T) {
	fixture := newDestinationTestRuntimeFixture(t, true, true)
	api := &APIServer{
		scannerCfg:               &config.Config{Gateway: config.GatewayConfig{Token: destinationTestGatewayToken}},
		observabilityV8LocalOnly: fixture.runtime,
	}
	handler := api.tokenAuth(api.apiCSRFProtect(http.HandlerFunc(api.handleObservabilityDestinationTestActivity)))
	activities := []destinationtest.Activity{
		{Phase: "attempt", Destination: "soc", ProbeID: "probe-1", Mode: "handshake", Result: "attempted"},
		{Phase: "outcome", Destination: "soc", ProbeID: "probe-1", Mode: "handshake", Result: "succeeded"},
		{Phase: "outcome", Destination: "archive", ProbeID: "probe-2", Mode: "write_probe", Result: "failed", FailureClass: "timeout"},
	}
	for _, activity := range activities {
		request := destinationTestHTTPRequest(t, destinationTestActivityJSON(t, activity))
		request.Header.Set("Authorization", "Bearer "+destinationTestGatewayToken)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNoContent || recorder.Body.Len() != 0 {
			t.Fatalf("activity=%+v status=%d body=%q", activity, recorder.Code, recorder.Body.String())
		}
	}

	rows := readDestinationTestRows(t, fixture.path)
	if len(rows) != len(activities) {
		t.Fatalf("rows=%d want=%d: %#v", len(rows), len(activities), rows)
	}
	wantEvents := []string{"destination.test.attempted", "destination.test.completed", "destination.test.completed"}
	wantOutcomes := []string{"attempted", "completed", "failed"}
	for index, row := range rows {
		if row.action != destinationTestAction || row.bucket != string(observability.BucketComplianceActivity) ||
			row.eventName != wantEvents[index] || row.source != string(observability.SourceCLI) ||
			row.signal != string(observability.SignalLogs) || row.connector != destinationTestClient ||
			row.mandatory != 1 || row.generation != 1 || row.outcome() != wantOutcomes[index] {
			t.Errorf("row[%d]=%#v", index, row)
		}
		payload := row.payload(t)
		wantPayload := map[string]any{
			"defenseclaw.admin.operation":           destinationTestAction,
			"defenseclaw.admin.origin":              "cli",
			"defenseclaw.destination.id":            activities[index].Destination,
			"defenseclaw.destination.test.probe_id": activities[index].ProbeID,
			"defenseclaw.destination.test.mode":     activities[index].Mode,
			"defenseclaw.destination.test.result":   activities[index].Result,
		}
		if activities[index].FailureClass != "" {
			wantPayload["defenseclaw.destination.test.failure_class"] = activities[index].FailureClass
		}
		if !reflect.DeepEqual(payload, wantPayload) {
			t.Errorf("payload[%d]=%v want=%v", index, payload, wantPayload)
		}
		for key := range payload {
			if strings.Contains(key, "secret") || strings.Contains(key, "content") ||
				strings.Contains(key, "header") || strings.Contains(key, "endpoint") {
				t.Fatalf("payload contains forbidden field %q", key)
			}
		}
	}
	if fixture.optionalAdapter == nil {
		t.Fatal("optional adapter was not prepared")
	}
	select {
	case <-fixture.optionalAdapter.delivered:
		t.Fatalf("local-only compliance deliveries=%d", fixture.optionalAdapter.deliveries.Load())
	case <-time.After(100 * time.Millisecond):
	}
}

func TestObservabilityDestinationTestActivityUsesMandatoryFloorWhenCollectionDisabled(t *testing.T) {
	fixture := newDestinationTestRuntimeFixture(t, false, false)
	api := &APIServer{observabilityV8LocalOnly: fixture.runtime}
	activities := []destinationtest.Activity{
		{Phase: "attempt", Destination: "soc", ProbeID: "probe-floor", Mode: "handshake", Result: "attempted"},
		{Phase: "outcome", Destination: "soc", ProbeID: "probe-floor", Mode: "handshake", Result: "failed", FailureClass: "timeout"},
	}
	for _, activity := range activities {
		recorder := httptest.NewRecorder()
		api.handleObservabilityDestinationTestActivity(
			recorder,
			destinationTestHTTPRequest(t, destinationTestActivityJSON(t, activity)),
		)
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("activity=%+v status=%d body=%s", activity, recorder.Code, recorder.Body.String())
		}
	}
	rows := readDestinationTestRows(t, fixture.path)
	if len(rows) != 2 {
		t.Fatalf("floor rows=%d want=2: %#v", len(rows), rows)
	}
	wantEvents := []string{"destination.test.attempted", "destination.test.completed"}
	wantOutcomes := []string{"attempted", "failed"}
	wantPayload := map[string]any{"detail_state": "omitted", "floor_only": true}
	for index, row := range rows {
		if row.eventName != wantEvents[index] || row.outcome() != wantOutcomes[index] ||
			row.mandatory != 1 || !reflect.DeepEqual(row.payload(t), wantPayload) {
			t.Errorf("floor row[%d]=%#v payload=%v", index, row, row.payload(t))
		}
	}
}

type destinationTestRuntimeFixture struct {
	runtime         *observabilityruntime.Runtime
	path            string
	optionalAdapter *destinationTestRecordingAdapter
}

func newDestinationTestRuntimeFixture(
	t *testing.T,
	collectCompliance bool,
	withOptional bool,
) destinationTestRuntimeFixture {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.db")
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	retentionDays := 0
	source := &config.ObservabilityV8Source{Local: config.ObservabilityV8LocalSource{
		Path: path, JudgeBodiesPath: filepath.Join(directory, "judge-bodies.db"),
		RetentionDays: &retentionDays,
	}}
	if !collectCompliance {
		disabled := false
		source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketComplianceActivity: {
				Collect: config.ObservabilityV8CollectSource{Logs: &disabled},
			},
		}
	}
	if withOptional {
		source.Destinations = []config.ObservabilityV8DestinationSource{{
			Name: "must-not-export", Kind: config.ObservabilityV8DestinationJSONL,
			Path: filepath.Join(directory, "must-not-export.jsonl"),
		}}
	}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	var failureIDs atomic.Uint64
	failureBuilder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("destination-test-failure-%d", failureIDs.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	reaper, err := audit.NewRetentionReaper(store, nil, 0, audit.RetentionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	retention, err := observabilityruntime.NewRetentionController(
		reaper, observabilityruntime.RetentionControllerOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	options := observabilityruntime.Options{
		Store: store, Engine: engine, RecordBuilder: failureBuilder,
		Reporter: &discardSidecarGraphReporter{}, RetentionController: retention,
	}
	var optionalAdapter *destinationTestRecordingAdapter
	if withOptional {
		optionalAdapter = &destinationTestRecordingAdapter{delivered: make(chan struct{})}
		options.DestinationAdapterFactory = destinationTestAdapterFactoryFunc(func(
			context.Context,
			config.ObservabilityV8EffectiveDestination,
			telemetry.V8ResourceContext,
		) (delivery.Adapter, observabilityruntime.DestinationAdapterCleanup, error) {
			return optionalAdapter, func(context.Context) error { return nil }, nil
		})
	}
	runtime, err := observabilityruntime.New(
		t.Context(), runtimegraph.ConfigFromPlan(plan, false),
		options,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close destination-test runtime: %v", err)
		}
	})
	return destinationTestRuntimeFixture{runtime: runtime, path: path, optionalAdapter: optionalAdapter}
}

type destinationTestAdapterFactoryFunc func(
	context.Context,
	config.ObservabilityV8EffectiveDestination,
	telemetry.V8ResourceContext,
) (delivery.Adapter, observabilityruntime.DestinationAdapterCleanup, error)

func (function destinationTestAdapterFactoryFunc) PrepareDestination(
	ctx context.Context,
	destination config.ObservabilityV8EffectiveDestination,
	resource telemetry.V8ResourceContext,
) (delivery.Adapter, observabilityruntime.DestinationAdapterCleanup, error) {
	return function(ctx, destination, resource)
}

type destinationTestRecordingAdapter struct {
	deliveries atomic.Int64
	delivered  chan struct{}
	once       sync.Once
}

func (*destinationTestRecordingAdapter) EncodedSize(sizes []int) (int, bool) {
	return delivery.DelimitedEncodedSize(sizes, 0, 1, 1)
}

func (adapter *destinationTestRecordingAdapter) Deliver(
	context.Context,
	delivery.Batch,
) delivery.DeliveryResult {
	adapter.deliveries.Add(1)
	adapter.once.Do(func() { close(adapter.delivered) })
	return delivery.DeliveryResult{Outcome: delivery.OutcomeDelivered}
}

type storedDestinationTestRow struct {
	action, bucket, eventName, source, signal, connector string
	payloadJSON, projectedJSON                           string
	mandatory, generation                                int64
}

func readDestinationTestRows(t *testing.T, path string) []storedDestinationTestRow {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT action, COALESCE(bucket,''), COALESCE(event_name,''),
		COALESCE(source,''), COALESCE(signal,''), COALESCE(connector,''),
		COALESCE(payload_json,''), COALESCE(projected_record_json,''),
		COALESCE(mandatory,0), COALESCE(generation,0)
		FROM audit_events WHERE action = ? ORDER BY rowid`, destinationTestAction)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := make([]storedDestinationTestRow, 0)
	for rows.Next() {
		var row storedDestinationTestRow
		if err := rows.Scan(
			&row.action, &row.bucket, &row.eventName, &row.source, &row.signal, &row.connector,
			&row.payloadJSON, &row.projectedJSON, &row.mandatory, &row.generation,
		); err != nil {
			t.Fatal(err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func (row storedDestinationTestRow) payload(t *testing.T) map[string]any {
	t.Helper()
	result := make(map[string]any)
	if err := json.Unmarshal([]byte(row.payloadJSON), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func (row storedDestinationTestRow) outcome() string {
	var envelope struct {
		Outcome string `json:"outcome"`
	}
	_ = json.Unmarshal([]byte(row.projectedJSON), &envelope)
	return envelope.Outcome
}

func destinationTestActivityJSON(t *testing.T, activity destinationtest.Activity) string {
	t.Helper()
	encoded, err := json.Marshal(activity)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func destinationTestHTTPRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, destinationtest.EndpointPath, bytes.NewBufferString(body))
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DefenseClaw-Client", destinationTestClient)
	return request
}

var _ sidecarRuntimeLocalOnlyEmitter = (*fakeDestinationTestLocalEmitter)(nil)
