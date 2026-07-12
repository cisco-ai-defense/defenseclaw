// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const (
	sidecarCapacityInterval    = 15 * time.Second
	sidecarSQLiteHealthTimeout = 10 * time.Second
	sidecarCapacityV8Producer  = "gateway.capacity"
)

type capacityInt64FamilyBuilder func(
	*observability.FamilyBuilder,
	observability.FamilyEnvelopeInput,
	int64,
) (observability.Record, error)

type capacityDoubleFamilyBuilder func(
	*observability.FamilyBuilder,
	observability.FamilyEnvelopeInput,
	float64,
) (observability.Record, error)

type exporterHealthMetricKey struct {
	destination string
	signal      observability.Signal
}

type exporterHealthMetricV8Runtime interface {
	hookLifecycleMetricV8Runtime
	GeneratedMetricFamilyEnabled(context.Context, observability.EventName) (bool, error)
	DestinationHealthSnapshot(context.Context) (observabilityruntime.DestinationHealthSnapshot, error)
}

func (s *Sidecar) runCapacityObservabilityV8(ctx context.Context, interval time.Duration) {
	if s == nil || ctx == nil || interval <= 0 {
		return
	}
	s.recordCapacityObservabilityV8(ctx, time.Now().UTC())
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case observedAt := <-ticker.C:
			s.recordCapacityObservabilityV8(ctx, observedAt.UTC())
		}
	}
}

func (s *Sidecar) recordCapacityObservabilityV8(ctx context.Context, observedAt time.Time) {
	if s == nil || ctx == nil || observedAt.IsZero() {
		return
	}
	lifecycle := s.observabilityV8LifecycleRuntime()
	runtimeOwner, _ := lifecycle.(hookLifecycleMetricV8Runtime)
	if runtimeOwner == nil {
		return
	}
	_, _ = runtimeOwner.RecordGeneratedMetricBatch(ctx, s.capacityMetricBatch(ctx, observedAt))
	if healthRuntime, ok := lifecycle.(exporterHealthMetricV8Runtime); ok {
		s.recordExporterHealthMetricsV8(ctx, observedAt, healthRuntime)
	}
}

func (s *Sidecar) recordExporterHealthMetricsV8(
	ctx context.Context,
	observedAt time.Time,
	runtime exporterHealthMetricV8Runtime,
) {
	if s == nil || ctx == nil || observedAt.IsZero() || runtime == nil {
		return
	}
	// Exporter health has dynamic cardinality. Consult the exact family gate
	// before taking a destination snapshot so disabling platform.health metrics
	// avoids this work entirely.
	enabled, err := runtime.GeneratedMetricFamilyEnabled(
		ctx, observability.EventName(observability.TelemetryInstrumentDefenseClawTelemetryExporterErrors),
	)
	if err != nil || !enabled {
		return
	}
	health, err := runtime.DestinationHealthSnapshot(ctx)
	if err != nil || health.Generation == 0 || health.PlanDigest == "" {
		return
	}

	s.exporterHealthMetricMu.Lock()
	defer s.exporterHealthMetricMu.Unlock()
	if s.exporterHealthMetricGeneration != health.Generation {
		s.exporterHealthMetricGeneration = health.Generation
		s.exporterHealthMetricCounters = make(map[exporterHealthMetricKey]uint64)
	}
	if s.exporterHealthMetricCounters == nil {
		s.exporterHealthMetricCounters = make(map[exporterHealthMetricKey]uint64)
	}

	for _, destination := range health.Destinations {
		if !destination.Enabled || !observability.IsStableToken(destination.Name) {
			continue
		}
		for _, source := range destination.Sources {
			signal := observability.Signal(source.Signal)
			if source.Generation != health.Generation || source.Destination != destination.Name ||
				!observability.IsSignal(signal) {
				continue
			}
			key := exporterHealthMetricKey{destination: destination.Name, signal: signal}
			previous := s.exporterHealthMetricCounters[key]
			current := source.Counters.Failed
			if current < previous {
				// Counters must be monotonic within one generation. Treat an
				// unexpected reset as a new local baseline without synthesizing a
				// huge wrapped delta.
				previous = 0
			}
			if delta := current - previous; delta > 0 {
				if delta > math.MaxInt64 {
					delta = math.MaxInt64
				}
				reason := source.Reason
				if reason == "" {
					reason = "delivery_failed"
				}
				item := exporterErrorMetricItem(
					ctx, observedAt, health.Generation, destination.Name, signal, reason, int64(delta),
				)
				if _, recordErr := runtime.RecordGeneratedMetricBatch(
					ctx, []observabilityruntime.GeneratedMetricBatchItem{item},
				); recordErr == nil {
					s.exporterHealthMetricCounters[key] = previous + delta
				}
			} else {
				s.exporterHealthMetricCounters[key] = current
			}
			if source.LastSuccess.IsZero() {
				continue
			}
			item := exporterLastSuccessMetricItem(
				ctx, observedAt, health.Generation, destination.Name, signal, source.LastSuccess,
			)
			_, _ = runtime.RecordGeneratedMetricBatch(
				ctx, []observabilityruntime.GeneratedMetricBatchItem{item},
			)
		}
	}
}

func exporterErrorMetricItem(
	ctx context.Context,
	observedAt time.Time,
	generation uint64,
	destination string,
	signal observability.Signal,
	reason string,
	value int64,
) observabilityruntime.GeneratedMetricBatchItem {
	return newGatewayGeneratedMetricItem(
		ctx, observedAt, observability.SourceSystem, "", sidecarCapacityV8Producer,
		observability.EventName(observability.TelemetryInstrumentDefenseClawTelemetryExporterErrors),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			if envelope.Provenance.ConfigGeneration < 0 ||
				uint64(envelope.Provenance.ConfigGeneration) != generation {
				return observability.Record{}, fmt.Errorf("gateway: exporter health generation changed")
			}
			return builder.BuildMetricDefenseClawTelemetryExporterErrors(
				observability.MetricDefenseClawTelemetryExporterErrorsInput{
					Envelope: envelope, Value: value,
					DefenseClawMetricExporter:  observability.Present(destination),
					DefenseClawMetricReason:    observability.Present(reason),
					DefenseClawTelemetrySignal: observability.Present(string(signal)),
				},
			)
		},
	)
}

func exporterLastSuccessMetricItem(
	ctx context.Context,
	observedAt time.Time,
	generation uint64,
	destination string,
	signal observability.Signal,
	lastSuccess time.Time,
) observabilityruntime.GeneratedMetricBatchItem {
	return newGatewayGeneratedMetricItem(
		ctx, observedAt, observability.SourceSystem, "", sidecarCapacityV8Producer,
		observability.EventName(observability.TelemetryInstrumentDefenseClawTelemetryExporterLastExportTs),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			if envelope.Provenance.ConfigGeneration < 0 ||
				uint64(envelope.Provenance.ConfigGeneration) != generation {
				return observability.Record{}, fmt.Errorf("gateway: exporter health generation changed")
			}
			return builder.BuildMetricDefenseClawTelemetryExporterLastExportTs(
				observability.MetricDefenseClawTelemetryExporterLastExportTsInput{
					Envelope:                   envelope,
					Value:                      float64(lastSuccess.UTC().UnixNano()) / float64(time.Second),
					DefenseClawMetricExporter:  observability.Present(destination),
					DefenseClawTelemetrySignal: observability.Present(string(signal)),
				},
			)
		},
	)
}

func (s *Sidecar) capacityMetricBatch(
	ctx context.Context,
	observedAt time.Time,
) []observabilityruntime.GeneratedMetricBatchItem {
	var (
		runtimeOnce     sync.Once
		runtimeSnapshot telemetry.RuntimeMetrics
		sqliteOnce      sync.Once
		sqliteSnapshot  audit.SQLiteHealthSnapshot
		sqliteErr       error
	)
	runtimeValue := func() telemetry.RuntimeMetrics {
		runtimeOnce.Do(func() {
			runtimeSnapshot = telemetry.CollectRuntimeMetrics(s.startedAt)
		})
		return runtimeSnapshot
	}
	sqliteValue := func() (audit.SQLiteHealthSnapshot, error) {
		sqliteOnce.Do(func() {
			if s.store == nil {
				sqliteErr = fmt.Errorf("gateway: mandatory SQLite health store is unavailable")
				return
			}
			snapshotCtx, cancel := context.WithTimeout(ctx, sidecarSQLiteHealthTimeout)
			defer cancel()
			sqliteSnapshot, sqliteErr = s.store.CollectSQLiteHealth(snapshotCtx)
		})
		return sqliteSnapshot, sqliteErr
	}

	items := make([]observabilityruntime.GeneratedMetricBatchItem, 0, 11)
	items = append(items,
		capacityInt64MetricItem(ctx, observedAt, observability.TelemetryInstrumentDefenseClawRuntimeGoroutines,
			func() (int64, error) { return runtimeValue().Goroutines, nil },
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput, value int64) (observability.Record, error) {
				return builder.BuildMetricDefenseClawRuntimeGoroutines(observability.MetricDefenseClawRuntimeGoroutinesInput{Envelope: envelope, Value: value})
			}),
		capacityInt64MetricItem(ctx, observedAt, observability.TelemetryInstrumentDefenseClawRuntimeHeapAlloc,
			func() (int64, error) { return runtimeValue().HeapAllocBytes, nil },
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput, value int64) (observability.Record, error) {
				return builder.BuildMetricDefenseClawRuntimeHeapAlloc(observability.MetricDefenseClawRuntimeHeapAllocInput{Envelope: envelope, Value: value})
			}),
		capacityInt64MetricItem(ctx, observedAt, observability.TelemetryInstrumentDefenseClawRuntimeHeapObjects,
			func() (int64, error) { return runtimeValue().HeapObjects, nil },
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput, value int64) (observability.Record, error) {
				return builder.BuildMetricDefenseClawRuntimeHeapObjects(observability.MetricDefenseClawRuntimeHeapObjectsInput{Envelope: envelope, Value: value})
			}),
		capacityInt64MetricItem(ctx, observedAt, observability.TelemetryInstrumentDefenseClawRuntimeFdInUse,
			func() (int64, error) { return runtimeValue().FDsOpen, nil },
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput, value int64) (observability.Record, error) {
				return builder.BuildMetricDefenseClawRuntimeFdInUse(observability.MetricDefenseClawRuntimeFdInUseInput{Envelope: envelope, Value: value})
			}),
		capacityDoubleMetricItem(ctx, observedAt, observability.TelemetryInstrumentDefenseClawProcessUptimeSeconds,
			func() (float64, error) { return runtimeValue().UptimeSeconds, nil },
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput, value float64) (observability.Record, error) {
				return builder.BuildMetricDefenseClawProcessUptimeSeconds(observability.MetricDefenseClawProcessUptimeSecondsInput{Envelope: envelope, Value: value})
			}),
		capacityInt64MetricItem(ctx, observedAt, observability.TelemetryInstrumentDefenseClawRuntimeGcPause,
			func() (int64, error) { return runtimeValue().GCPauseP99Ns, nil },
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput, value int64) (observability.Record, error) {
				return builder.BuildMetricDefenseClawRuntimeGcPause(observability.MetricDefenseClawRuntimeGcPauseInput{Envelope: envelope, Value: value})
			}),
		capacityInt64MetricItem(ctx, observedAt, observability.TelemetryInstrumentDefenseClawSqliteDBBytes,
			func() (int64, error) { snapshot, err := sqliteValue(); return snapshot.DBSizeBytes, err },
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput, value int64) (observability.Record, error) {
				return builder.BuildMetricDefenseClawSqliteDBBytes(observability.MetricDefenseClawSqliteDBBytesInput{Envelope: envelope, Value: value})
			}),
		capacityInt64MetricItem(ctx, observedAt, observability.TelemetryInstrumentDefenseClawSqliteWalBytes,
			func() (int64, error) { snapshot, err := sqliteValue(); return snapshot.WALSizeBytes, err },
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput, value int64) (observability.Record, error) {
				return builder.BuildMetricDefenseClawSqliteWalBytes(observability.MetricDefenseClawSqliteWalBytesInput{Envelope: envelope, Value: value})
			}),
		capacityInt64MetricItem(ctx, observedAt, observability.TelemetryInstrumentDefenseClawSqlitePageCount,
			func() (int64, error) { snapshot, err := sqliteValue(); return snapshot.PageCount, err },
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput, value int64) (observability.Record, error) {
				return builder.BuildMetricDefenseClawSqlitePageCount(observability.MetricDefenseClawSqlitePageCountInput{Envelope: envelope, Value: value})
			}),
		capacityInt64MetricItem(ctx, observedAt, observability.TelemetryInstrumentDefenseClawSqliteFreelistCount,
			func() (int64, error) { snapshot, err := sqliteValue(); return snapshot.FreelistCount, err },
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput, value int64) (observability.Record, error) {
				return builder.BuildMetricDefenseClawSqliteFreelistCount(observability.MetricDefenseClawSqliteFreelistCountInput{Envelope: envelope, Value: value})
			}),
		capacityDoubleMetricItem(ctx, observedAt, observability.TelemetryInstrumentDefenseClawSqliteCheckpointDuration,
			func() (float64, error) { snapshot, err := sqliteValue(); return snapshot.CheckpointMs, err },
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput, value float64) (observability.Record, error) {
				return builder.BuildMetricDefenseClawSqliteCheckpointDuration(observability.MetricDefenseClawSqliteCheckpointDurationInput{Envelope: envelope, Value: value})
			}),
	)
	return items
}

func capacityInt64MetricItem(
	ctx context.Context,
	observedAt time.Time,
	family string,
	value func() (int64, error),
	build capacityInt64FamilyBuilder,
) observabilityruntime.GeneratedMetricBatchItem {
	return newGatewayGeneratedMetricItem(
		ctx, observedAt, observability.SourceSystem, "", sidecarCapacityV8Producer,
		observability.EventName(family),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			if value == nil || build == nil {
				return observability.Record{}, fmt.Errorf("gateway: invalid capacity metric builder")
			}
			point, err := value()
			if err != nil {
				return observability.Record{}, err
			}
			return build(builder, envelope, point)
		},
	)
}

func capacityDoubleMetricItem(
	ctx context.Context,
	observedAt time.Time,
	family string,
	value func() (float64, error),
	build capacityDoubleFamilyBuilder,
) observabilityruntime.GeneratedMetricBatchItem {
	return newGatewayGeneratedMetricItem(
		ctx, observedAt, observability.SourceSystem, "", sidecarCapacityV8Producer,
		observability.EventName(family),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			if value == nil || build == nil {
				return observability.Record{}, fmt.Errorf("gateway: invalid capacity metric builder")
			}
			point, err := value()
			if err != nil {
				return observability.Record{}, err
			}
			return build(builder, envelope, point)
		},
	)
}
