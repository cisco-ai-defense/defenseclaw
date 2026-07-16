// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type e2e1NoOptionalAdapterFactory struct {
	calls atomic.Int64
}

func (factory *e2e1NoOptionalAdapterFactory) PrepareDestination(
	context.Context,
	config.ObservabilityV8EffectiveDestination,
	telemetry.V8ResourceContext,
) (delivery.Adapter, DestinationAdapterCleanup, error) {
	factory.calls.Add(1)
	return nil, func(context.Context) error { return nil }, errors.New("empty config attempted optional adapter construction")
}

type e2e1DefaultLogCase struct {
	bucket  observability.Bucket
	kind    observability.ProducerKind
	key     observability.ProducerKey
	context observability.ClassificationContext
}

func TestE2E1EmptyConfigRuntimeCollectsAllSignalsLocallyWithoutExporters(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	compiled, err := config.ParseCompileObservabilityV8(
		"config.yaml",
		[]byte(fmt.Sprintf(
			"config_version: 8\ndata_dir: %q\nobservability: {}\n",
			filepath.Dir(dependencies.storePath),
		)),
		config.ObservabilityV8CompileOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	plan := compiled.Plan
	if plan.Snapshot().Local.Path != dependencies.storePath {
		t.Fatalf("empty-config local path=%q want=%q", plan.Snapshot().Local.Path, dependencies.storePath)
	}

	adapterFactory := &e2e1NoOptionalAdapterFactory{}
	var pipelineAssemblyCalls atomic.Int64
	var optionalNetworkCandidates atomic.Int64
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "e2e1", Environment: "test",
		ServiceInstanceID: "e2e1-service", DefenseClawInstanceID: "e2e1-instance",
		GenerationPipelines: func(
			_ context.Context,
			candidate *config.ObservabilityV8Plan,
			_ uint64,
			_ telemetry.V8MetricReaderSpec,
		) (telemetry.V8GenerationPipelines, error) {
			pipelineAssemblyCalls.Add(1)
			for _, destination := range candidate.Destinations() {
				if destination.Kind != config.ObservabilityV8DestinationLocalSQLite && destination.Enabled {
					optionalNetworkCandidates.Add(1)
				}
			}
			return telemetry.V8GenerationPipelines{}, nil
		},
	})
	options := dependencies.options()
	options.DestinationAdapterFactory = adapterFactory
	options.TelemetryProviderFactory = providerFactory
	runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(plan, false), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if closeErr := runtime.Close(ctx); closeErr != nil {
			t.Errorf("close empty-config runtime: %v", closeErr)
		}
	})

	lease, graphErr := runtime.manager.Acquire(t.Context())
	if graphErr != nil {
		t.Fatalf("acquire empty-config graph code=%s generation=%d: %v", graphErr.Code(), runtime.Active().Generation(), graphErr)
	}
	providerValue, ok := lease.Component(telemetry.V8ProviderComponentName)
	if !ok {
		lease.Release()
		t.Fatal("empty-config runtime has no telemetry provider")
	}
	providerComponent, ok := providerValue.(*telemetry.V8ProviderComponent)
	if !ok || providerComponent == nil {
		lease.Release()
		t.Fatalf("empty-config provider=%T", providerValue)
	}
	provider, ok := providerComponent.Provider()
	if !ok || provider == nil {
		lease.Release()
		t.Fatal("empty-config provider component is not active")
	}
	dispatchValue, ok := lease.Component(DestinationDispatchComponentName)
	if !ok {
		lease.Release()
		t.Fatal("empty-config runtime has no destination dispatch component")
	}
	dispatch, ok := dispatchValue.(*destinationDispatchComponent)
	if !ok || dispatch == nil || len(dispatch.byName) != 0 {
		lease.Release()
		t.Fatalf("empty-config optional dispatchers=%T/%v", dispatchValue, dispatch)
	}
	for _, bucket := range observability.Buckets() {
		policy, present := lease.Graph().Plan().Bucket(bucket)
		if !present || !policy.Collect.Logs || !policy.Collect.Traces || !policy.Collect.Metrics ||
			policy.RedactionProfile != "none" {
			lease.Release()
			t.Fatalf("empty-config bucket %s policy=%+v present=%t", bucket, policy, present)
		}
		if !provider.TraceBucketEnabled(bucket) || !provider.MetricBucketEnabled(bucket) {
			lease.Release()
			t.Fatalf("empty-config provider did not collect traces/metrics for %s", bucket)
		}
	}
	lease.Release()

	cases := e2e1DefaultLogCases()
	if len(cases) != len(observability.Buckets()) {
		t.Fatalf("E2E-1 cases=%d buckets=%d", len(cases), len(observability.Buckets()))
	}
	seenBuckets := make(map[observability.Bucket]bool, len(cases))
	markers := make(map[string]string, len(cases))
	for index, test := range cases {
		if seenBuckets[test.bucket] {
			t.Fatalf("duplicate E2E-1 bucket %s", test.bucket)
		}
		seenBuckets[test.bucket] = true
		recordID := fmt.Sprintf("e2e1-default-%02d", index)
		marker := "unredacted-" + recordID + "@example.test"
		markers[recordID] = marker
		metadata, metadataErr := router.NewClassifiedLogMetadata(
			test.kind, test.key, test.context,
			observability.SourceSystem, "", test.key,
		)
		if metadataErr != nil {
			t.Fatalf("metadata for %s: %v", test.bucket, metadataErr)
		}
		builder := e2e1RecordBuilder(t, recordID)
		outcome, emitErr := runtime.Emit(t.Context(), metadata,
			func(snapshot EmitContext, admission router.Admission) (observability.Record, error) {
				if admission != router.AdmissionOrdinary {
					return observability.Record{}, fmt.Errorf("bucket %s admission=%s", test.bucket, admission)
				}
				return builder.BuildClassifiedLog(observability.ClassifiedLogInput{
					ProducerKind: test.kind, ProducerKey: test.key, ClassificationContext: test.context,
					Source: observability.SourceSystem, Action: string(test.key),
					Correlation: observability.Correlation{RunID: "e2e1-default-run"},
					Provenance: observability.Provenance{
						Producer: "e2e1", BinaryVersion: "test",
						RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
						ConfigGeneration:      int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
					},
					Body: map[string]any{"content": marker},
					FieldClasses: map[string]observability.FieldClass{
						"/content": observability.FieldClassContent,
					},
				})
			},
		)
		if emitErr != nil || !outcome.LocalPersisted() || len(outcome.OptionalWork()) != 0 ||
			len(outcome.OptionalFailures()) != 0 {
			t.Fatalf("bucket %s persisted=%t optional=%d failures=%d error=%v",
				test.bucket, outcome.LocalPersisted(), len(outcome.OptionalWork()),
				len(outcome.OptionalFailures()), emitErr)
		}
	}

	reader, err := sql.Open("sqlite", dependencies.storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	rows, err := reader.QueryContext(t.Context(), `
		SELECT id, projected_record_json, redaction_profile
		FROM audit_events WHERE id LIKE 'e2e1-default-%' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close() //nolint:errcheck
	counts := make(map[string]int, len(markers))
	for rows.Next() {
		var recordID, projected, profile string
		if scanErr := rows.Scan(&recordID, &projected, &profile); scanErr != nil {
			t.Fatal(scanErr)
		}
		counts[recordID]++
		if profile != "none" {
			t.Errorf("record %s local profile=%q", recordID, profile)
		}
		var record struct {
			RecordID string         `json:"record_id"`
			Body     map[string]any `json:"body"`
		}
		if unmarshalErr := json.Unmarshal([]byte(projected), &record); unmarshalErr != nil {
			t.Fatal(unmarshalErr)
		}
		if record.RecordID != recordID || record.Body["content"] != markers[recordID] {
			t.Errorf("record %s lost unredacted local body: %+v", recordID, record)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for recordID := range markers {
		if counts[recordID] != 1 {
			t.Errorf("record %s SQLite count=%d, want one", recordID, counts[recordID])
		}
	}
	if pipelineAssemblyCalls.Load() != 1 || optionalNetworkCandidates.Load() != 0 ||
		adapterFactory.calls.Load() != 0 {
		t.Fatalf("empty-config assembly=%d optional-candidates=%d adapter-constructions=%d",
			pipelineAssemblyCalls.Load(), optionalNetworkCandidates.Load(), adapterFactory.calls.Load())
	}
}

func e2e1RecordBuilder(t *testing.T, recordID string) *observability.RecordBuilder {
	t.Helper()
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time {
			return time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
		}),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return recordID, nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	return builder
}

func e2e1DefaultLogCases() []e2e1DefaultLogCase {
	auditCase := func(bucket observability.Bucket, key observability.ProducerKey, severity string) e2e1DefaultLogCase {
		return e2e1DefaultLogCase{
			bucket: bucket, kind: observability.ProducerAuditAction, key: key,
			context: observability.ClassificationContext{RawSeverity: severity},
		}
	}
	return []e2e1DefaultLogCase{
		auditCase(observability.BucketComplianceActivity, "config-update", "INFO"),
		auditCase(observability.BucketSecurityFinding, "scan-finding", "HIGH"),
		auditCase(observability.BucketGuardrailEvaluation, "guardrail-allow", "NONE"),
		auditCase(observability.BucketEnforcementAction, "quarantine", "INFO"),
		auditCase(observability.BucketModelIO, "gateway-session-message", "INFO"),
		auditCase(observability.BucketToolActivity, "tool-call", "INFO"),
		auditCase(observability.BucketAssetScan, "scan", "INFO"),
		auditCase(observability.BucketAssetLifecycle, "deploy", "INFO"),
		auditCase(observability.BucketNetworkEgress, "network-egress-allowed", "INFO"),
		auditCase(observability.BucketAgentLifecycle, "gateway-agent-start", "INFO"),
		{
			bucket: observability.BucketAIDiscovery, kind: observability.ProducerGatewayEvent, key: "ai_discovery",
			context: observability.ClassificationContext{
				Bucket: observability.BucketAIDiscovery, EventName: "ai_component.discovered", RawSeverity: "INFO",
			},
		},
		auditCase(observability.BucketTelemetryIngest, "otel.ingest.logs", "INFO"),
		auditCase(observability.BucketPlatformHealth, "webhook-delivered", "INFO"),
		{
			bucket: observability.BucketDiagnostic, kind: observability.ProducerGatewayEvent, key: "diagnostic",
			context: observability.ClassificationContext{RawSeverity: "INFO"},
		},
	}
}

var _ DestinationAdapterFactory = (*e2e1NoOptionalAdapterFactory)(nil)
