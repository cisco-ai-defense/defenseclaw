// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	collectorlogpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/proto"
)

const (
	e2e2FindingID = "e2e2-high-finding"
	e2e2BlockID   = "e2e2-enforcement-block"
	e2e2RawEmail  = "security-operator@example.test"
)

type e2e2RequestCapture struct {
	mu     sync.Mutex
	bodies map[string][][]byte
}

func (capture *e2e2RequestCapture) handler(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	capture.mu.Lock()
	capture.bodies[request.URL.Path] = append(capture.bodies[request.URL.Path], append([]byte(nil), body...))
	capture.mu.Unlock()
	if request.URL.Path == "/splunk" {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, `{"text":"Success","code":0}`)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (capture *e2e2RequestCapture) snapshot(path string) [][]byte {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	result := make([][]byte, len(capture.bodies[path]))
	for index, body := range capture.bodies[path] {
		result[index] = append([]byte(nil), body...)
	}
	return result
}

func TestE2E2HighFindingAndAppliedBlockFanOutExactlyOnce(t *testing.T) {
	directory := t.TempDir()
	storePath := filepath.Join(directory, "audit.db")
	judgePath := filepath.Join(directory, "judge-bodies.db")
	jsonlPath := filepath.Join(directory, "security.jsonl")
	caPath := filepath.Join(directory, "collector-ca.pem")

	store, err := audit.NewStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	reader, err := sql.Open("sqlite", storePath)
	if err != nil {
		t.Fatal(err)
	}
	reader.SetMaxOpenConns(1)
	reader.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = reader.Close() })
	if err := reader.PingContext(t.Context()); err != nil {
		t.Fatal(err)
	}

	capture := &e2e2RequestCapture{bodies: make(map[string][][]byte)}
	server := httptest.NewTLSServer(http.HandlerFunc(capture.handler))
	t.Cleanup(server.Close)
	certificate := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: server.Certificate().Raw,
	})
	secrets := &integrationSecrets{
		values: map[string]string{"E2E2_SPLUNK_TOKEN": "e2e2-splunk-secret"},
		calls:  map[string]int{},
	}
	caLoader := &integrationCALoader{path: caPath, bundle: certificate}
	warnings := &integrationWarnings{}

	logs := []observability.Signal{observability.SignalLogs}
	buckets := []observability.Bucket{
		observability.BucketSecurityFinding,
		observability.BucketEnforcementAction,
	}
	pushBatch := config.ObservabilityV8BatchSource{
		MaxQueueSize: 8, MaxExportBatchSize: 1, ScheduledDelayMS: 1,
	}
	retentionDays := 0
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path: storePath, JudgeBodiesPath: judgePath, RetentionDays: &retentionDays,
		},
		Destinations: []config.ObservabilityV8DestinationSource{
			{
				Name: "security-jsonl", Kind: config.ObservabilityV8DestinationJSONL, Path: jsonlPath,
				Send: &config.ObservabilityV8SendSource{
					Signals: logs, Buckets: buckets, RedactionProfile: "none",
				},
				Batch: config.ObservabilityV8BatchSource{MaxQueueSize: 8},
			},
			{
				Name: "security-splunk", Kind: config.ObservabilityV8DestinationSplunkHEC,
				Endpoint: server.URL + "/splunk", TokenEnv: "E2E2_SPLUNK_TOKEN",
				Source: "defenseclaw", SourceType: "defenseclaw:event",
				Send: &config.ObservabilityV8SendSource{
					Signals: logs, Buckets: buckets, RedactionProfile: "strict",
				},
				TLS: config.ObservabilityV8TLSSource{CACert: caPath},
				NetworkSafety: config.ObservabilityV8NetworkSafetySource{
					AllowPrivateNetworks: true,
				},
				Batch: pushBatch,
			},
			{
				Name: "security-otlp", Kind: config.ObservabilityV8DestinationOTLP,
				Protocol: "http/protobuf", Endpoint: server.URL, LoggerName: "defenseclaw.e2e2",
				Send: &config.ObservabilityV8SendSource{
					Signals: logs, Buckets: buckets, RedactionProfile: "sensitive",
				},
				TLS: config.ObservabilityV8TLSSource{CACert: caPath},
				NetworkSafety: config.ObservabilityV8NetworkSafetySource{
					AllowPrivateNetworks: true,
				},
				Batch: pushBatch,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x72}, 32))
	if err != nil {
		t.Fatal(err)
	}
	factory, err := destinations.NewFactory(destinations.Options{
		ConsoleStream: destinations.ConsoleStderr,
		Stdout:        io.Discard, Stderr: io.Discard,
		Secrets: secrets, CALoader: caLoader,
		Resolver: net.DefaultResolver, Dialer: &net.Dialer{}, Warnings: warnings,
	})
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
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "e2e2", Environment: "test",
		ServiceInstanceID: "e2e2-service", DefenseClawInstanceID: "e2e2-instance",
	})
	runtime, err := observabilityruntime.New(
		t.Context(), runtimegraph.ConfigFromPlan(plan, false),
		observabilityruntime.Options{
			Store: store, Engine: engine, RecordBuilder: mustRecordBuilder(t, "e2e2-runtime-failure"),
			Reporter: &discardReporter{}, RetentionController: retention,
			DestinationAdapterFactory: factory, TelemetryProviderFactory: providerFactory,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	runtimeClosed := false
	t.Cleanup(func() {
		if runtimeClosed {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = runtime.Close(ctx)
	})

	correlation := observability.Correlation{
		RunID: "e2e2-run", RequestID: "e2e2-request", SessionID: "e2e2-session",
		TraceID: "0123456789abcdef0123456789abcdef", SpanID: "0123456789abcdef",
		EvaluationID: "e2e2-evaluation", FindingOccurrenceID: "e2e2-finding-occurrence",
		EnforcementActionID: "e2e2-enforcement-action",
	}
	e2e2EmitSecurityOperation(t, runtime, e2e2FindingID, e2e2SecurityFindingInput(correlation))
	e2e2EmitSecurityOperation(t, runtime, e2e2BlockID, e2e2AppliedBlockInput(correlation))

	waitFor(t, func() bool {
		file, readErr := os.ReadFile(jsonlPath)
		return readErr == nil && bytes.Count(file, []byte{'\n'}) == 2 &&
			len(capture.snapshot("/splunk")) == 2 && len(capture.snapshot("/v1/logs")) == 2
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := runtime.Close(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	runtimeClosed = true

	expected := map[string]e2e2ExpectedProjection{
		e2e2FindingID: {
			bucket: observability.BucketSecurityFinding, eventName: "legacy.audit.scan.finding",
			action: "scan-finding", severity: "HIGH", outcome: observability.OutcomeCompleted,
		},
		e2e2BlockID: {
			bucket: observability.BucketEnforcementAction, eventName: "enforcement.block.applied",
			action: "block", severity: "HIGH", outcome: observability.OutcomeBlocked,
		},
	}
	local := e2e2ReadSQLiteProjections(t, reader)
	e2e2AssertProjectionSet(t, "sqlite", local, expected, correlation, "none", true)

	jsonlBytes, err := os.ReadFile(jsonlPath)
	if err != nil {
		t.Fatal(err)
	}
	jsonl := make([][]byte, 0, 2)
	for _, line := range bytes.Split(bytes.TrimSpace(jsonlBytes), []byte{'\n'}) {
		jsonl = append(jsonl, append([]byte(nil), line...))
	}
	e2e2AssertProjectionSet(t, "jsonl", jsonl, expected, correlation, "none", true)

	splunk := make([][]byte, 0, 2)
	for _, body := range capture.snapshot("/splunk") {
		projection, _, _ := readSplunkProjection(t, body)
		splunk = append(splunk, projection)
	}
	e2e2AssertProjectionSet(t, "splunk", splunk, expected, correlation, "strict", false)

	otlp := make([][]byte, 0, 2)
	for _, body := range capture.snapshot("/v1/logs") {
		var request collectorlogpb.ExportLogsServiceRequest
		if err := proto.Unmarshal(body, &request); err != nil {
			t.Fatal(err)
		}
		otlp = append(otlp, readOTLPLogRequest(t, &request, "defenseclaw.e2e2"))
	}
	e2e2AssertProjectionSet(t, "otlp", otlp, expected, correlation, "sensitive", false)

	if secrets.Calls("E2E2_SPLUNK_TOKEN") != 1 || caLoader.Calls() != 2 {
		t.Fatalf("secret/CA resolution calls=%d/%d", secrets.Calls("E2E2_SPLUNK_TOKEN"), caLoader.Calls())
	}
}

type e2e2RecordInput struct {
	kind        observability.ProducerKind
	key         observability.ProducerKey
	context     observability.ClassificationContext
	source      observability.Source
	connector   string
	action      string
	outcome     observability.Outcome
	correlation observability.Correlation
	body        map[string]any
	classes     map[string]observability.FieldClass
}

func e2e2SecurityFindingInput(correlation observability.Correlation) e2e2RecordInput {
	return e2e2RecordInput{
		kind: observability.ProducerAuditAction, key: "scan-finding",
		context: observability.ClassificationContext{RawSeverity: "HIGH"},
		source:  observability.SourceCodeGuard, connector: "codeguard", action: "scan-finding",
		outcome: observability.OutcomeCompleted, correlation: correlation,
		body: map[string]any{
			"message": "high severity finding for " + e2e2RawEmail,
			"rule_id": "E2E2-001",
		},
		classes: map[string]observability.FieldClass{
			"/message": observability.FieldClassContent,
			"/rule_id": observability.FieldClassIdentifier,
		},
	}
}

func e2e2AppliedBlockInput(correlation observability.Correlation) e2e2RecordInput {
	return e2e2RecordInput{
		kind: observability.ProducerAuditAction, key: "block",
		context: observability.ClassificationContext{
			Bucket: observability.BucketEnforcementAction, EventName: "enforcement.block.applied",
			RawSeverity: "HIGH", Enforced: true,
			MandatoryFacts: observability.MandatoryFacts{EnforcedOutcome: true},
		},
		source: observability.SourceGateway, connector: "codex", action: "block",
		outcome: observability.OutcomeBlocked, correlation: correlation,
		body: map[string]any{
			"defenseclaw.enforcement.effective_action": "block",
			"defenseclaw.enforcement.id":               correlation.EnforcementActionID,
			"message":                                  "successfully blocked request for " + e2e2RawEmail,
		},
		classes: map[string]observability.FieldClass{
			"/defenseclaw.enforcement.effective_action": observability.FieldClassMetadata,
			"/defenseclaw.enforcement.id":               observability.FieldClassIdentifier,
			"/message":                                  observability.FieldClassContent,
		},
	}
}

func e2e2EmitSecurityOperation(
	t *testing.T,
	runtime *observabilityruntime.Runtime,
	recordID string,
	input e2e2RecordInput,
) {
	t.Helper()
	metadata, err := router.NewClassifiedLogMetadata(
		input.kind, input.key, input.context, input.source, input.connector, input.key,
	)
	if err != nil {
		t.Fatal(err)
	}
	builder := mustRecordBuilder(t, recordID)
	outcome, err := runtime.Emit(t.Context(), metadata,
		func(snapshot observabilityruntime.EmitContext, admission router.Admission) (observability.Record, error) {
			if admission != router.AdmissionOrdinary {
				return observability.Record{}, fmt.Errorf("record %s admission=%s", recordID, admission)
			}
			return builder.BuildClassifiedLog(observability.ClassifiedLogInput{
				ProducerKind: input.kind, ProducerKey: input.key, ClassificationContext: input.context,
				Source: input.source, Connector: input.connector, Action: input.action,
				Outcome: input.outcome, Correlation: input.correlation,
				Provenance: observability.Provenance{
					Producer: "e2e2", BinaryVersion: "test",
					RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
					ConfigGeneration:      int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
				},
				Body: input.body, FieldClasses: input.classes,
			})
		},
	)
	if err != nil || !outcome.LocalPersisted() || outcome.Admission() != router.AdmissionOrdinary {
		t.Fatalf("record %s persisted=%t admission=%s error=%v",
			recordID, outcome.LocalPersisted(), outcome.Admission(), err)
	}
}

type e2e2ExpectedProjection struct {
	bucket    observability.Bucket
	eventName string
	action    string
	severity  string
	outcome   observability.Outcome
}

func e2e2ReadSQLiteProjections(t *testing.T, reader *sql.DB) [][]byte {
	t.Helper()
	rows, err := reader.QueryContext(t.Context(), `
		SELECT projected_record_json, redaction_profile FROM audit_events
		WHERE id IN (?, ?) ORDER BY id`, e2e2FindingID, e2e2BlockID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close() //nolint:errcheck
	var result [][]byte
	for rows.Next() {
		var projected []byte
		var profile string
		if err := rows.Scan(&projected, &profile); err != nil {
			t.Fatal(err)
		}
		if profile != "none" {
			t.Fatalf("SQLite profile=%q want none", profile)
		}
		result = append(result, append([]byte(nil), projected...))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func e2e2AssertProjectionSet(
	t *testing.T,
	destination string,
	projections [][]byte,
	expected map[string]e2e2ExpectedProjection,
	correlation observability.Correlation,
	profile string,
	wantRawEmail bool,
) {
	t.Helper()
	counts := make(map[string]int, len(expected))
	for _, projected := range projections {
		var record struct {
			RecordID    string                `json:"record_id"`
			Bucket      observability.Bucket  `json:"bucket"`
			EventName   string                `json:"event_name"`
			Action      string                `json:"action"`
			Severity    string                `json:"severity"`
			Outcome     observability.Outcome `json:"outcome"`
			Correlation map[string]any        `json:"correlation"`
			Projection  map[string]any        `json:"projection"`
		}
		if err := json.Unmarshal(projected, &record); err != nil {
			t.Fatalf("%s projection: %v", destination, err)
		}
		want, ok := expected[record.RecordID]
		if !ok {
			t.Fatalf("%s unexpected record %q", destination, record.RecordID)
		}
		counts[record.RecordID]++
		if record.Bucket != want.bucket || record.EventName != want.eventName ||
			record.Action != want.action || record.Severity != want.severity || record.Outcome != want.outcome {
			t.Errorf("%s record %s identity=%+v want=%+v", destination, record.RecordID, record, want)
		}
		wantCorrelation := map[string]any{
			"run_id": correlation.RunID, "request_id": correlation.RequestID,
			"session_id": correlation.SessionID, "trace_id": correlation.TraceID,
			"span_id": correlation.SpanID, "evaluation_id": correlation.EvaluationID,
			"finding_occurrence_id": correlation.FindingOccurrenceID,
			"enforcement_action_id": correlation.EnforcementActionID,
		}
		for key, value := range wantCorrelation {
			if record.Correlation[key] != value {
				t.Errorf("%s record %s correlation[%s]=%v want=%v",
					destination, record.RecordID, key, record.Correlation[key], value)
			}
		}
		if record.Projection["redaction_profile"] != profile {
			t.Errorf("%s record %s profile=%v want=%s",
				destination, record.RecordID, record.Projection["redaction_profile"], profile)
		}
		hasRawEmail := bytes.Contains(projected, []byte(e2e2RawEmail))
		if hasRawEmail != wantRawEmail {
			t.Errorf("%s record %s raw-email=%t want=%t", destination, record.RecordID, hasRawEmail, wantRawEmail)
		}
	}
	if len(projections) != len(expected) {
		t.Errorf("%s projections=%d want=%d", destination, len(projections), len(expected))
	}
	for recordID := range expected {
		if counts[recordID] != 1 {
			t.Errorf("%s record %s deliveries=%d want=1", destination, recordID, counts[recordID])
		}
	}
	if !reflect.DeepEqual(counts, map[string]int{e2e2FindingID: 1, e2e2BlockID: 1}) {
		t.Errorf("%s delivery counts=%v", destination, counts)
	}
}
