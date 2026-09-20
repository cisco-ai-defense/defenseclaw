// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

func TestE2E3AIDefenseSourceFilteringPreservesBothFindingsLocally(t *testing.T) {
	const (
		aiDefenseID = "e2e3-ai-defense-finding"
		codeGuardID = "e2e3-codeguard-finding"
	)

	requests := make(chan []byte, 4)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		requests <- body
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	directory := t.TempDir()
	storePath := filepath.Join(directory, "audit.db")
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
	if err := reader.PingContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	retentionDays := 0
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path: storePath, JudgeBodiesPath: filepath.Join(directory, "judge-bodies.db"),
			RetentionDays: &retentionDays,
		},
		Destinations: []config.ObservabilityV8DestinationSource{{
			Name: "ai-defense-findings", Kind: config.ObservabilityV8DestinationOTLP,
			Protocol: "http/protobuf", Endpoint: server.URL,
			LoggerName: "defenseclaw.e2e3",
			TLS:        config.ObservabilityV8TLSSource{Insecure: true},
			Routes: []config.ObservabilityV8RouteSource{{
				Name: "ai-defense-only", Signals: []observability.Signal{observability.SignalLogs},
				Selector: &config.ObservabilityV8SelectorSource{
					Buckets: []observability.Bucket{observability.BucketSecurityFinding},
					Sources: []observability.Source{observability.SourceAIDefense},
				},
				Action: config.ObservabilityV8RouteSend, RedactionProfile: "none",
			}},
			NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
			Batch: config.ObservabilityV8BatchSource{
				MaxQueueSize: 8, MaxExportBatchSize: 8, ScheduledDelayMS: 1,
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x33}, 32))
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
	factory, err := destinations.NewFactory(destinations.Options{
		ConsoleStream: destinations.ConsoleStderr,
		Stdout:        io.Discard,
		Stderr:        io.Discard,
		Secrets:       &integrationSecrets{values: map[string]string{}, calls: map[string]int{}},
		CALoader:      &integrationCALoader{},
		Resolver:      net.DefaultResolver,
		Dialer:        &net.Dialer{},
		Warnings:      &integrationWarnings{},
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := observabilityruntime.New(
		context.Background(), runtimegraph.ConfigFromPlan(plan, false),
		observabilityruntime.Options{
			Store: store, Engine: engine,
			RecordBuilder: mustRecordBuilder(t, "e2e3-runtime-failure"),
			Reporter:      &discardReporter{}, RetentionController: retention,
			DestinationAdapterFactory: factory,
			TelemetryProviderFactory: telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
				Version: "integration-test", Environment: "test",
				ServiceInstanceID: "e2e3-service", DefenseClawInstanceID: "e2e3-instance",
			}),
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

	emitE2E3Finding(t, runtime, aiDefenseID, observability.SourceAIDefense)
	emitE2E3Finding(t, runtime, codeGuardID, observability.SourceCodeGuard)

	local := readE2E3LocalFindings(t, reader, aiDefenseID, codeGuardID)
	if local[aiDefenseID] != observability.SourceAIDefense || local[codeGuardID] != observability.SourceCodeGuard {
		t.Fatalf("local findings=%v", local)
	}

	remote := receiveRequest(t, requests)
	var request collectorlogpb.ExportLogsServiceRequest
	if err := proto.Unmarshal(remote, &request); err != nil {
		t.Fatal(err)
	}
	projected := readOTLPLogRequest(t, &request, "defenseclaw.e2e3")
	var record struct {
		RecordID string               `json:"record_id"`
		Bucket   observability.Bucket `json:"bucket"`
		Source   observability.Source `json:"source"`
	}
	if err := json.Unmarshal(projected, &record); err != nil {
		t.Fatal(err)
	}
	if record.RecordID != aiDefenseID || record.Bucket != observability.BucketSecurityFinding || record.Source != observability.SourceAIDefense {
		t.Fatalf("remote finding=%+v", record)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := runtime.Close(ctx); err != nil {
		t.Fatal(err)
	}
	runtimeClosed = true
	select {
	case unexpected := <-requests:
		t.Fatalf("CodeGuard finding escaped source filter: %d-byte OTLP request", len(unexpected))
	default:
	}
}

func emitE2E3Finding(
	t *testing.T,
	runtime *observabilityruntime.Runtime,
	recordID string,
	source observability.Source,
) {
	t.Helper()
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction,
		"scan-finding",
		observability.ClassificationContext{RawSeverity: "HIGH"},
		source,
		"scanner",
		"scan-finding",
	)
	if err != nil {
		t.Fatal(err)
	}
	builder := mustRecordBuilder(t, recordID)
	outcome, err := runtime.Emit(t.Context(), metadata,
		func(snapshot observabilityruntime.EmitContext, admission router.Admission) (observability.Record, error) {
			if admission != router.AdmissionOrdinary {
				return observability.Record{}, fmt.Errorf("unexpected admission %s", admission)
			}
			return builder.BuildClassifiedLog(observability.ClassifiedLogInput{
				ProducerKind:          observability.ProducerAuditAction,
				ProducerKey:           "scan-finding",
				ClassificationContext: observability.ClassificationContext{RawSeverity: "HIGH"},
				Source:                source, Connector: "scanner", Action: "scan-finding",
				Outcome: observability.OutcomeCompleted,
				Correlation: observability.Correlation{
					RunID: "e2e3-run", FindingOccurrenceID: recordID + "-occurrence",
				},
				Provenance: observability.Provenance{
					Producer: "e2e3", BinaryVersion: "test",
					RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
					ConfigGeneration:      int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
				},
				Body: map[string]any{
					"message": "equivalent dangerous command finding",
					"rule_id": "E2E3-001",
				},
				FieldClasses: map[string]observability.FieldClass{
					"/message": observability.FieldClassContent,
					"/rule_id": observability.FieldClassIdentifier,
				},
			})
		},
	)
	if err != nil || !outcome.LocalPersisted() || outcome.Admission() != router.AdmissionOrdinary {
		t.Fatalf("emit %s persisted=%t admission=%s error=%v", source, outcome.LocalPersisted(), outcome.Admission(), err)
	}
}

func readE2E3LocalFindings(
	t *testing.T,
	reader *sql.DB,
	recordIDs ...string,
) map[string]observability.Source {
	t.Helper()
	rows, err := reader.QueryContext(t.Context(), `
		SELECT id, source FROM audit_events
		WHERE id IN (?, ?)
		ORDER BY id`, recordIDs[0], recordIDs[1])
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close() //nolint:errcheck
	result := make(map[string]observability.Source, len(recordIDs))
	for rows.Next() {
		var recordID string
		var source observability.Source
		if err := rows.Scan(&recordID, &source); err != nil {
			t.Fatal(err)
		}
		result[recordID] = source
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(result) != len(recordIDs) {
		t.Fatalf("local finding count=%d want=%d", len(result), len(recordIDs))
	}
	return result
}
