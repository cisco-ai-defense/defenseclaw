// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

type capacityHealthRuntime struct {
	*observabilityruntime.Runtime
	snapshot      observabilityruntime.DestinationHealthSnapshot
	snapshotCalls int
}

func (runtime *capacityHealthRuntime) DestinationHealthSnapshot(
	context.Context,
) (observabilityruntime.DestinationHealthSnapshot, error) {
	runtime.snapshotCalls++
	return runtime.snapshot, nil
}

func TestCapacityMetricsUseCompleteGeneratedV8Families(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	sidecar := &Sidecar{startedAt: time.Now().Add(-time.Minute), store: capture.store}
	items := sidecar.capacityMetricBatch(t.Context(), time.Now().UTC())
	results, err := runtime.RecordGeneratedMetricBatch(t.Context(), items)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 11 || len(results) != len(items) {
		t.Fatalf("capacity batch items/results=%d/%d", len(items), len(results))
	}

	want := map[string]bool{
		observability.TelemetryInstrumentDefenseClawRuntimeGoroutines:        false,
		observability.TelemetryInstrumentDefenseClawRuntimeHeapAlloc:         false,
		observability.TelemetryInstrumentDefenseClawRuntimeHeapObjects:       false,
		observability.TelemetryInstrumentDefenseClawRuntimeFdInUse:           false,
		observability.TelemetryInstrumentDefenseClawRuntimeGcPause:           false,
		observability.TelemetryInstrumentDefenseClawProcessUptimeSeconds:     false,
		observability.TelemetryInstrumentDefenseClawSqliteDBBytes:            false,
		observability.TelemetryInstrumentDefenseClawSqliteWalBytes:           false,
		observability.TelemetryInstrumentDefenseClawSqlitePageCount:          false,
		observability.TelemetryInstrumentDefenseClawSqliteFreelistCount:      false,
		observability.TelemetryInstrumentDefenseClawSqliteCheckpointDuration: false,
	}
	metrics := capture.metricSnapshot()
	if len(metrics) != len(want) {
		t.Fatalf("capacity metrics=%d want=%d", len(metrics), len(want))
	}
	for _, metric := range metrics {
		name := metric.Descriptor().Name
		if _, ok := want[name]; !ok {
			t.Fatalf("unexpected capacity family %q", name)
		}
		want[name] = true
		record := metric.CanonicalRecord()
		if record.Bucket() != observability.BucketPlatformHealth ||
			record.Source() != observability.SourceSystem ||
			record.Provenance().Producer != sidecarCapacityV8Producer {
			t.Fatalf("capacity metric %q identity=%s/%s provenance=%+v", name, record.Bucket(), record.Source(), record.Provenance())
		}
		if integer, ok := metric.Value().Int64(); ok && integer < 0 &&
			name != observability.TelemetryInstrumentDefenseClawRuntimeFdInUse {
			t.Fatalf("capacity metric %q negative integer=%d", name, integer)
		}
		if value, ok := metric.Value().Double(); ok && value < 0 {
			t.Fatalf("capacity metric %q negative double=%f", name, value)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("capacity family %q not recorded", name)
		}
	}
}

func TestCapacityCollectionDisabledSkipsAllSnapshotWork(t *testing.T) {
	disabled := false
	runtime, capture := newProxyGeneratedTraceRuntimeWithPolicies(
		t, "always_on", config.ObservabilityV8BucketPolicySource{},
		map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketPlatformHealth: {
				Collect: config.ObservabilityV8CollectSource{Metrics: &disabled},
			},
		},
	)
	// A nil store would make the SQLite snapshot fail if any generated builder
	// ran. Successful admission-drop therefore proves collection precedes both
	// SQLite and Go-runtime snapshot construction.
	sidecar := &Sidecar{startedAt: time.Now().Add(-time.Minute)}
	items := sidecar.capacityMetricBatch(t.Context(), time.Now().UTC())
	results, err := runtime.RecordGeneratedMetricBatch(t.Context(), items)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(items) || len(capture.metricSnapshot()) != 0 {
		t.Fatalf("disabled capacity results/exported=%d/%d", len(results), len(capture.metricSnapshot()))
	}
}

func TestExporterHealthMetricsUseMonotonicFailureDeltasAndPerSignalSuccess(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	graph := runtime.Active()
	if graph == nil {
		t.Fatal("generated runtime has no active graph")
	}
	lastSuccess := time.Unix(1_700_000_000, 125_000_000).UTC()
	wrapper := &capacityHealthRuntime{Runtime: runtime}
	wrapper.snapshot = observabilityruntime.DestinationHealthSnapshot{
		Generation: graph.Generation(), PlanDigest: graph.Digest(),
		Destinations: []observabilityruntime.DestinationHealth{{
			Name: "capture", Enabled: true, Signals: []observability.Signal{observability.SignalMetrics},
			Sources: []delivery.HealthSnapshot{{
				Destination: "capture", Generation: graph.Generation(), Signal: string(observability.SignalMetrics),
				State: delivery.HealthDegraded, Reason: string(delivery.HealthReasonRetryable),
				Counters: delivery.Counters{Failed: 2}, LastSuccess: lastSuccess,
			}},
		}},
	}
	sidecar := &Sidecar{}
	observedAt := time.Now().UTC()
	sidecar.recordExporterHealthMetricsV8(t.Context(), observedAt, wrapper)
	sidecar.recordExporterHealthMetricsV8(t.Context(), observedAt.Add(time.Second), wrapper)
	wrapper.snapshot.Destinations[0].Sources[0].Counters.Failed = 5
	sidecar.recordExporterHealthMetricsV8(t.Context(), observedAt.Add(2*time.Second), wrapper)

	metrics := capture.metricSnapshot()
	errors := generatedMetricByName(
		metrics, observability.TelemetryInstrumentDefenseClawTelemetryExporterErrors,
	)
	if len(errors) != 2 {
		t.Fatalf("exporter error observations=%d metrics=%v", len(errors), metrics)
	}
	for index, want := range []int64{2, 3} {
		value, ok := errors[index].Value().Int64()
		if !ok || value != want {
			t.Fatalf("exporter error[%d] value=%d/%v want=%d", index, value, ok, want)
		}
		attributes := errors[index].Attributes()
		if attributes["defenseclaw.metric.exporter"] != "capture" ||
			attributes["defenseclaw.metric.reason"] != string(delivery.HealthReasonRetryable) ||
			attributes["defenseclaw.telemetry.signal"] != "metrics" {
			t.Fatalf("exporter error[%d] attributes=%v", index, attributes)
		}
	}
	successes := generatedMetricByName(
		metrics, observability.TelemetryInstrumentDefenseClawTelemetryExporterLastExportTs,
	)
	if len(successes) != 3 {
		t.Fatalf("exporter last-success observations=%d", len(successes))
	}
	wantSuccess := float64(lastSuccess.UnixNano()) / float64(time.Second)
	for index, metric := range successes {
		value, ok := metric.Value().Double()
		if !ok || value != wantSuccess {
			t.Fatalf("last-success[%d] value=%f/%v want=%f", index, value, ok, wantSuccess)
		}
	}
	if wrapper.snapshotCalls != 3 {
		t.Fatalf("destination snapshots=%d want=3", wrapper.snapshotCalls)
	}
}

func TestExporterHealthCollectionGatePrecedesDestinationSnapshot(t *testing.T) {
	disabled := false
	runtime, _ := newProxyGeneratedTraceRuntimeWithPolicies(
		t, "always_on", config.ObservabilityV8BucketPolicySource{},
		map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketPlatformHealth: {
				Collect: config.ObservabilityV8CollectSource{Metrics: &disabled},
			},
		},
	)
	wrapper := &capacityHealthRuntime{Runtime: runtime}
	(&Sidecar{}).recordExporterHealthMetricsV8(t.Context(), time.Now().UTC(), wrapper)
	if wrapper.snapshotCalls != 0 {
		t.Fatalf("disabled exporter health took %d destination snapshots", wrapper.snapshotCalls)
	}
}
