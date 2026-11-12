// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

// RejectedRecordComponentName is the generation-owned writer of the opt-in
// rejected-record store (observability.local.keep_rejected_records, #1442).
// While the key is off a generation gets an inert component: no queue, no
// goroutine, no timer and no sink, so a refused record is only counted, as
// before.
const RejectedRecordComponentName = "rejected-records"

const (
	// rejectedRecordQueueItems bounds the records waiting for the writer. A
	// full queue drops and counts the record; the producer never waits.
	rejectedRecordQueueItems = 256
	// rejectedRecordWriteTimeout bounds one batch write.
	rejectedRecordWriteTimeout = 5 * time.Second
	// rejectedRecordLogInterval spaces the drop and failure log lines.
	rejectedRecordLogInterval = time.Minute
)

// RejectedRecordStats are the process totals of the rejected-record store.
// DroppedRunCap counts records past the per-run cap: a gateway run writes at
// most rejected_records_max_rows rows, so a flood of refused records cannot
// keep rewriting the table.
type RejectedRecordStats struct {
	Stored          uint64 `json:"stored"`
	DroppedQueue    uint64 `json:"dropped_queue_full"`
	DroppedRunCap   uint64 `json:"dropped_run_cap"`
	DroppedStopping uint64 `json:"dropped_stopping"`
	WriteFailed     uint64 `json:"write_failed"`
}

type rejectedRecordCounters struct {
	offered, stored, droppedQueue, droppedRunCap, droppedStopping, writeFailed atomic.Uint64
}

func (counters *rejectedRecordCounters) snapshot() RejectedRecordStats {
	return RejectedRecordStats{
		Stored: counters.stored.Load(), DroppedQueue: counters.droppedQueue.Load(),
		DroppedRunCap: counters.droppedRunCap.Load(), DroppedStopping: counters.droppedStopping.Load(),
		WriteFailed: counters.writeFailed.Load(),
	}
}

type rejectedRecordError struct{}

func (*rejectedRecordError) Error() string {
	return "observability rejected-record store initialization failed"
}

// rejectedRecordFactory is process-stable: its counters, the per-run cap
// included, span reloads.
type rejectedRecordFactory struct {
	store        *audit.Store
	engine       *redaction.Engine
	log          io.Writer
	secureClient bool
	counters     rejectedRecordCounters
}

func (factory *rejectedRecordFactory) Name() string { return RejectedRecordComponentName }

func (factory *rejectedRecordFactory) Prepare(
	ctx context.Context,
	input runtimegraph.BuildInput,
	acquisitions *runtimegraph.Acquisitions,
) (runtimegraph.Component, error) {
	if factory == nil || ctx == nil || acquisitions == nil || input.Config.Plan == nil {
		return nil, &rejectedRecordError{}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	local := input.Config.Plan.Snapshot().Local
	// Secure Client keeps main's behavior: the store is never on there.
	if !local.KeepRejectedRecords || factory.secureClient {
		return &rejectedRecordsOff{generation: input.Generation}, nil
	}
	maxRows := local.RejectedRecordsMaxRows
	if maxRows < audit.RejectedRecordsMinRows || maxRows > audit.RejectedRecordsMaxRows ||
		factory.store == nil || factory.engine == nil {
		return nil, &rejectedRecordError{}
	}
	profile, ok := redaction.BuiltInProfile(redaction.ProfileSensitive)
	if !ok {
		return nil, &rejectedRecordError{}
	}
	return &rejectedRecordWriter{
		factory: factory, profile: profile, maxRows: maxRows,
		queue: make(chan observability.RejectedRecord, rejectedRecordQueueItems),
		stop:  make(chan struct{}), done: make(chan struct{}),
		now: time.Now,
	}, nil
}

// rejectedRecordsOff is the component of a generation with the store off.
// The graph owns components by pointer identity, so each generation gets
// its own non-zero-size value.
type rejectedRecordsOff struct{ generation uint64 }

// Activate takes the sink from the generation this one replaces, which
// retires in the background.
func (*rejectedRecordsOff) Activate()                        { observability.ClearRejectedRecordSink() }
func (*rejectedRecordsOff) StopIntake(context.Context) error { return nil }
func (*rejectedRecordsOff) Drain(context.Context) error      { return nil }
func (*rejectedRecordsOff) Close(context.Context) error      { return nil }

// rejectedRecordWriter owns one generation's queue and its one writer
// goroutine, started at Activate. It redacts each record with the sensitive
// profile at the projection boundary (redaction.Engine.ProjectFields), so
// audit.db never holds a raw refused payload.
type rejectedRecordWriter struct {
	factory *rejectedRecordFactory
	profile redaction.Profile
	maxRows int
	queue   chan observability.RejectedRecord
	now     func() time.Time

	lifecycleMu sync.Mutex
	accepting   atomic.Bool
	started     bool
	stopOnce    sync.Once
	stop        chan struct{}
	done        chan struct{}
	uninstall   func()

	// Touched by the writer goroutine only.
	lastLog      time.Time
	loggedDrops  uint64
	loggedFailed uint64
}

// OfferRejectedRecord never blocks: it queues, or drops and counts.
func (writer *rejectedRecordWriter) OfferRejectedRecord(record observability.RejectedRecord) {
	counters := &writer.factory.counters
	if !writer.accepting.Load() {
		counters.droppedStopping.Add(1)
		return
	}
	if counters.offered.Add(1) > uint64(writer.maxRows) {
		counters.droppedRunCap.Add(1)
		return
	}
	select {
	case writer.queue <- record:
	default:
		counters.droppedQueue.Add(1)
	}
}

func (writer *rejectedRecordWriter) Activate() {
	writer.lifecycleMu.Lock()
	defer writer.lifecycleMu.Unlock()
	if writer.started {
		return
	}
	writer.started = true
	go writer.run()
	writer.accepting.Store(true)
	writer.uninstall = observability.InstallRejectedRecordSink(writer)
}

func (writer *rejectedRecordWriter) StopIntake(context.Context) error {
	writer.lifecycleMu.Lock()
	defer writer.lifecycleMu.Unlock()
	writer.accepting.Store(false)
	if writer.uninstall != nil {
		writer.uninstall()
		writer.uninstall = nil
	}
	return nil
}

// Drain writes what is queued and stops the writer goroutine.
func (writer *rejectedRecordWriter) Drain(ctx context.Context) error {
	if err := writer.StopIntake(ctx); err != nil {
		return err
	}
	writer.lifecycleMu.Lock()
	started := writer.started
	writer.lifecycleMu.Unlock()
	if !started {
		return nil
	}
	writer.stopOnce.Do(func() { close(writer.stop) })
	select {
	case <-writer.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (writer *rejectedRecordWriter) Close(ctx context.Context) error {
	return writer.Drain(ctx)
}

func (writer *rejectedRecordWriter) run() {
	defer close(writer.done)
	batch := make([]observability.RejectedRecord, 0, audit.RejectedRecordMaxBatch)
	for {
		select {
		case record := <-writer.queue:
			batch = append(batch[:0], record)
			batch = writer.fill(batch)
			writer.write(batch)
		case <-writer.stop:
			for {
				batch = writer.fill(batch[:0])
				if len(batch) == 0 {
					writer.logCounters(true)
					return
				}
				writer.write(batch)
			}
		}
	}
}

// fill takes queued records without waiting, up to one batch.
func (writer *rejectedRecordWriter) fill(batch []observability.RejectedRecord) []observability.RejectedRecord {
	for len(batch) < audit.RejectedRecordMaxBatch {
		select {
		case record := <-writer.queue:
			batch = append(batch, record)
		default:
			return batch
		}
	}
	return batch
}

func (writer *rejectedRecordWriter) write(batch []observability.RejectedRecord) {
	rows := make([]audit.RejectedRecordRow, 0, len(batch))
	stored := writer.now().UTC()
	for _, record := range batch {
		rows = append(rows, writer.row(record, stored))
	}
	ctx, cancel := context.WithTimeout(context.Background(), rejectedRecordWriteTimeout)
	err := writer.factory.store.InsertRejectedRecords(ctx, rows, writer.maxRows)
	cancel()
	counters := &writer.factory.counters
	if err != nil {
		counters.writeFailed.Add(uint64(len(rows)))
		writer.logFailure(err)
	} else {
		counters.stored.Add(uint64(len(rows)))
	}
	writer.logCounters(false)
}

// row redacts one record. A payload the profile cannot project, or one over
// audit.RejectedRecordMaxPayloadBytes, is not kept: the row keeps the
// metadata and lists the field keys.
func (writer *rejectedRecordWriter) row(record observability.RejectedRecord, stored time.Time) audit.RejectedRecordRow {
	row := audit.RejectedRecordRow{
		StoredAt: stored, ObservedAt: record.ObservedAt,
		Signal: string(record.Signal), Bucket: string(record.Bucket), EventName: string(record.EventName),
		Family: record.Family, FamilySchemaVersion: int64(record.FamilySchemaVersion),
		Source: string(record.Source), Connector: record.Connector,
		ReasonCode: string(record.Reason), Field: record.Field, ErrorText: record.ErrorText(),
		PayloadState:  audit.RejectedPayloadRedacted,
		OmittedFields: append([]string(nil), record.OmittedFields...),
	}
	projected, err := writer.factory.engine.ProjectFields(record.Body, record.FieldClasses, writer.profile)
	var encoded []byte
	if err == nil {
		encoded, err = json.Marshal(projected)
	}
	switch {
	case err != nil:
		row.PayloadState = audit.RejectedPayloadRedactionFailed
		row.Payload = json.RawMessage(`{}`)
		row.OmittedFields = rejectedBodyKeys(record.Body, row.OmittedFields)
	case len(encoded) > audit.RejectedRecordMaxPayloadBytes:
		row.PayloadState = audit.RejectedPayloadOmittedOversize
		row.Payload = json.RawMessage(`{}`)
		row.OmittedFields = rejectedBodyKeys(record.Body, row.OmittedFields)
	default:
		row.Payload = encoded
	}
	return row
}

func rejectedBodyKeys(body map[string]any, omitted []string) []string {
	keys := append([]string(nil), omitted...)
	for key := range body {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (writer *rejectedRecordWriter) logFailure(err error) {
	log := writer.factory.log
	now := writer.now()
	if log == nil || (!writer.lastLog.IsZero() && now.Sub(writer.lastLog) < rejectedRecordLogInterval) {
		return
	}
	writer.lastLog = now
	fmt.Fprintf(log, "[sidecar] rejected-record store: write failed (%s): %v; refused records are counted only until a write succeeds\n",
		gatewaylog.ErrCodeRejectedRecordStoreFailed, err)
}

// logCounters writes one line when records were dropped since the last line,
// at most once a minute, or at the end of a generation.
func (writer *rejectedRecordWriter) logCounters(final bool) {
	log := writer.factory.log
	if log == nil {
		return
	}
	stats := writer.factory.counters.snapshot()
	drops := stats.DroppedQueue + stats.DroppedRunCap + stats.DroppedStopping
	if drops == writer.loggedDrops && stats.WriteFailed == writer.loggedFailed {
		return
	}
	now := writer.now()
	if !final && !writer.lastLog.IsZero() && now.Sub(writer.lastLog) < rejectedRecordLogInterval {
		return
	}
	writer.lastLog = now
	writer.loggedDrops, writer.loggedFailed = drops, stats.WriteFailed
	fmt.Fprintf(log, "[sidecar] rejected-record store (%s): stored %d, dropped %d (queue full %d, run cap %d, stopping %d), write failed %d\n",
		gatewaylog.ErrCodeRejectedRecordDropped, stats.Stored, drops, stats.DroppedQueue, stats.DroppedRunCap,
		stats.DroppedStopping, stats.WriteFailed)
}

// RejectedRecordStats returns the process totals of the rejected-record
// store; all zero while it was never on.
func (runtime *Runtime) RejectedRecordStats() RejectedRecordStats {
	if runtime == nil || runtime.rejected == nil {
		return RejectedRecordStats{}
	}
	return runtime.rejected.counters.snapshot()
}

var _ runtimegraph.ComponentFactory = (*rejectedRecordFactory)(nil)
var _ runtimegraph.Component = (*rejectedRecordsOff)(nil)
var _ runtimegraph.Component = (*rejectedRecordWriter)(nil)
var _ observability.RejectedRecordSink = (*rejectedRecordWriter)(nil)
