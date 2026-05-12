// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// Async judge-persistence queue tuning. The defaults are picked so a
// single-writer worker can serve the realistic burst rate
// (~100 RPS of tool-call inspections during an MCP-heavy session)
// without ever entering the BUSY retry loop on audit.db. See
// docs/OBSERVABILITY.md for the operator-facing tuning guide.
const (
	// defaultJudgePersistQueueDepth is the fallback when neither the
	// config field nor the env override supplies a positive value.
	// Sized to absorb a ~10-second burst at 100 RPS while bounding
	// memory to MaxJudgeRawBytes * 1024 ≈ 64 MiB worst case.
	defaultJudgePersistQueueDepth = 1024

	// judgePersistBatchMax is the upper bound on rows committed in a
	// single transaction. SQLite's write cost is dominated by the
	// per-tx fsync, so amortizing 32 INSERTs over one tx is ~32x
	// cheaper than the synchronous one-write-per-judge baseline.
	judgePersistBatchMax = 32

	// judgePersistFlushInterval bounds how long the worker waits
	// before flushing a partial batch. Picked so an idle-after-burst
	// row never sits in the queue longer than a TUI refresh tick.
	judgePersistFlushInterval = 100 * time.Millisecond

	// judgePersistShutdownTimeout caps how long Shutdown waits for
	// the worker to drain. If we exceed this, drops are recorded
	// for the remainder so dashboards reflect data loss honestly.
	judgePersistShutdownTimeout = 5 * time.Second
)

// JudgeBodyInserter is the minimal surface a JudgeStore needs from
// its backing SQLite store. Defining it as an interface lets Phase 4
// swap audit.Store for a dedicated audit.JudgeBodyStore without
// touching the queue/worker — and lets unit tests inject a counting
// fake.
type JudgeBodyInserter interface {
	InsertJudgeResponse(audit.JudgeResponse) error
	// BeginJudgeBatch starts a transaction that the worker
	// uses to commit a batch of rows atomically. Returning a
	// concrete handle keeps the interface tight; callers that
	// can't batch (e.g. tests) return a single-row helper.
	BeginJudgeBatch(ctx context.Context) (JudgeBatch, error)
}

// JudgeBatch is the per-transaction write handle returned from
// JudgeBodyInserter.BeginJudgeBatch. Commit and Rollback are mutually
// exclusive terminal calls.
type JudgeBatch interface {
	InsertJudgeResponse(audit.JudgeResponse) error
	Commit() error
	Rollback() error
}

// judgePersistJob is the unit of work queued by Enqueue. We keep
// just the inputs to BuildJudgeRow so the worker — not the proxy
// goroutine — does the SHA-256 + provenance work.
type judgePersistJob struct {
	ctx        context.Context
	dir        gatewaylog.Direction
	payload    gatewaylog.JudgePayload
	toolName   string
	toolID     string
	policyID   string
	destApp    string
	identity   AgentIdentity
	requestID  string
	traceID    string
	sessionID  string
	runID      string
	enqueuedAt time.Time
}

// JudgeStore persists LLM judge bodies asynchronously through a
// bounded buffered channel + single-writer goroutine.
//
// Why async: the legacy synchronous path fired two SQLite writes
// (judge_responses INSERT, then audit_events INSERT via
// logger.LogEvent) inline with the proxy hot path. Under burst
// load the two writes serialized on SQLite's write lock,
// surfaced as SQLITE_BUSY (`database is locked`), and dropped
// judge rows entirely. The async path:
//
//   - lets the proxy return as soon as the row is queued,
//   - amortizes fsync cost by batching up to judgePersistBatchMax
//     rows per transaction,
//   - drops with telemetry instead of blocking when the queue is
//     full, so the proxy SLO is always respected.
type JudgeStore struct {
	store  JudgeBodyInserter
	logger *audit.Logger // fan-out for redacted summary; may be nil in tests

	queue chan judgePersistJob

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}

	// shutdownRequested flips to non-zero the first time Shutdown is
	// called. Enqueue checks it so post-shutdown calls are accounted
	// for as drops instead of being silently sent into a doomed
	// channel.
	shutdownRequested atomic.Bool
}

// NewJudgeStore wires the async queue on top of the supplied audit
// store. queueDepth <= 0 falls back to defaultJudgePersistQueueDepth.
//
// logger may be nil when the caller does not want the redacted
// audit fan-out (e.g. unit tests). Passing a real *audit.Logger
// ensures every retained body also produces an `llm-judge-response`
// audit event that flows through the normal sink pipeline (Splunk,
// OTLP, webhooks).
func NewJudgeStore(store JudgeBodyInserter, logger *audit.Logger, queueDepth int) *JudgeStore {
	if store == nil {
		return nil
	}
	if queueDepth <= 0 {
		queueDepth = defaultJudgePersistQueueDepth
	}
	js := &JudgeStore{
		store:  store,
		logger: logger,
		queue:  make(chan judgePersistJob, queueDepth),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	go js.run()
	return js
}

// NewJudgeStoreFromAudit is the legacy constructor preserved for
// callers (and tests) that still pass an *audit.Store directly. It
// adapts the store to the new JudgeBodyInserter contract via
// auditStoreInserter and defaults the queue depth.
//
// Production code should prefer NewJudgeStore with the explicit
// JudgeBodyStore (Phase 4) so judge bodies write to their own DB.
func NewJudgeStoreFromAudit(s *audit.Store) *JudgeStore {
	if s == nil {
		return nil
	}
	return NewJudgeStore(&auditStoreInserter{s: s}, nil, defaultJudgePersistQueueDepth)
}

// NewJudgeStoreFromBodyStore constructs a JudgeStore that writes
// judge bodies to the Phase 4 dedicated *audit.JudgeBodyStore. This
// is the production-shape constructor exposed for end-to-end tests
// that need to bypass NewSidecar (which depends on a full config +
// gateway client + connector wiring).
func NewJudgeStoreFromBodyStore(s *audit.JudgeBodyStore, logger *audit.Logger, queueDepth int) *JudgeStore {
	if s == nil {
		return nil
	}
	return NewJudgeStore(&judgeBodyStoreInserter{s: s}, logger, queueDepth)
}

// PersistJudgeEvent is the public API the gateway emit paths use. It
// performs the cheap, per-call work synchronously (capture the
// request-scoped identifiers off ctx) and hands the rest of the
// build + INSERT to the background worker. RawResponse == "" is the
// "retention off / no-op" guard, identical to the synchronous path.
func (j *JudgeStore) PersistJudgeEvent(ctx context.Context, dir gatewaylog.Direction, p gatewaylog.JudgePayload, toolName, toolID, policyID, destinationApp string) error {
	if j == nil || j.store == nil || p.RawResponse == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	job := judgePersistJob{
		ctx:        ctx,
		dir:        dir,
		payload:    p,
		toolName:   toolName,
		toolID:     toolID,
		policyID:   policyID,
		destApp:    destinationApp,
		identity:   AgentIdentityFromContext(ctx),
		requestID:  RequestIDFromContext(ctx),
		traceID:    TraceIDFromContext(ctx),
		sessionID:  SessionIDFromContext(ctx),
		runID:      gatewaylog.ProcessRunID(),
		enqueuedAt: time.Now(),
	}
	return j.enqueue(job)
}

// enqueue is the non-blocking submit. We choose drop-on-full over
// block-on-full because the proxy hot path must never wait on the
// audit DB — a wedged DB would otherwise wedge the proxy.
func (j *JudgeStore) enqueue(job judgePersistJob) error {
	if j.shutdownRequested.Load() {
		telemetry.RecordJudgePersistDrop(job.ctx, "shutdown")
		return nil
	}
	select {
	case j.queue <- job:
		telemetry.RecordJudgePersistQueueDepth(job.ctx, int64(len(j.queue)))
		return nil
	default:
		telemetry.RecordJudgePersistDrop(job.ctx, "queue_full")
		return nil
	}
}

// run is the single-writer worker goroutine. It loops on three
// channels: the work queue (build a batch), a flush timer (commit a
// partial batch on idle), and the stop signal (drain + exit).
//
// We deliberately use a single goroutine — multiple workers would
// race for SQLite's write lock and undo the very contention fix
// this rewrite is supposed to deliver.
func (j *JudgeStore) run() {
	defer close(j.doneCh)

	batch := make([]judgePersistJob, 0, judgePersistBatchMax)
	timer := time.NewTimer(judgePersistFlushInterval)
	timer.Stop()
	timerRunning := false

	stopTimer := func() {
		if timerRunning {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timerRunning = false
		}
	}
	armTimer := func() {
		if !timerRunning {
			timer.Reset(judgePersistFlushInterval)
			timerRunning = true
		}
	}

	flush := func() {
		if len(batch) == 0 {
			return
		}
		j.flushBatch(batch)
		batch = batch[:0]
		stopTimer()
	}

	for {
		select {
		case <-j.stopCh:
			// Drain remaining work non-blockingly so Shutdown
			// honors the bounded timeout. We accept a tail of
			// drops if the queue is still being fed.
			for {
				select {
				case job := <-j.queue:
					batch = append(batch, job)
					if len(batch) >= judgePersistBatchMax {
						flush()
					}
				default:
					flush()
					return
				}
			}

		case job := <-j.queue:
			batch = append(batch, job)
			telemetry.RecordJudgePersistQueueDepth(job.ctx, int64(len(j.queue)))
			if len(batch) == 1 {
				armTimer()
			}
			if len(batch) >= judgePersistBatchMax {
				flush()
			}

		case <-timer.C:
			timerRunning = false
			flush()
		}
	}
}

// flushBatch commits the buffered jobs in a single SQLite
// transaction. Errors are logged and dropped — we never re-queue,
// because a stuck DB would otherwise reload the same poison batch
// forever and starve the queue.
func (j *JudgeStore) flushBatch(jobs []judgePersistJob) {
	ctx := context.Background()
	tx, err := j.store.BeginJudgeBatch(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[judge_store] begin batch (size=%d): %v\n", len(jobs), err)
		for _, jb := range jobs {
			telemetry.RecordJudgePersistDrop(jb.ctx, "tx_begin_failed")
		}
		return
	}
	inserted := 0
	for _, jb := range jobs {
		row := buildJudgeRow(jb)
		if err := tx.InsertJudgeResponse(row); err != nil {
			fmt.Fprintf(os.Stderr, "[judge_store] insert (kind=%s): %v\n", jb.payload.Kind, err)
			continue
		}
		inserted++
	}
	if err := tx.Commit(); err != nil {
		// Best-effort rollback; ignore secondary error so we don't
		// shadow the commit failure for the operator.
		_ = tx.Rollback()
		fmt.Fprintf(os.Stderr, "[judge_store] commit batch (size=%d): %v\n", len(jobs), err)
		// Treat every job in the failed batch as a drop so dashboards
		// reflect reality.
		for _, jb := range jobs {
			telemetry.RecordJudgePersistDrop(jb.ctx, "tx_commit_failed")
		}
		return
	}
	telemetry.RecordJudgePersistBatchSize(ctx, int64(inserted))

	// Fan out the redacted summary AFTER the body commit succeeds so
	// SIEM rows never out-race the local forensic copy. The fan-out
	// runs on the worker goroutine (still off the proxy hot path)
	// and tolerates a nil logger so tests don't need the full audit
	// pipeline.
	if j.logger != nil {
		for _, jb := range jobs {
			j.fanoutAudit(jb)
		}
	}
}

// fanoutAudit emits the redacted audit event for one job. Mirrors
// the historical sidecar closure (sidecar.go:354-374) so existing
// sink consumers see no behavioral change.
func (j *JudgeStore) fanoutAudit(jb judgePersistJob) {
	env := audit.MergeEnvelope(audit.EnvelopeFromContext(jb.ctx), audit.CorrelationEnvelope{
		ToolName:       jb.toolName,
		ToolID:         jb.toolID,
		PolicyID:       jb.policyID,
		DestinationApp: jb.destApp,
	})
	evt := audit.Event{
		Action:   "llm-judge-response",
		Target:   jb.payload.Model,
		Actor:    "defenseclaw-gateway",
		Severity: string(jb.payload.Severity),
		Details: fmt.Sprintf(
			"kind=%s direction=%s action=%s latency_ms=%d input_bytes=%d parse_error=%q",
			jb.payload.Kind, jb.dir, jb.payload.Action, jb.payload.LatencyMs, jb.payload.InputBytes, jb.payload.ParseError,
		),
	}
	audit.ApplyEnvelope(&evt, env)
	_ = j.logger.LogEvent(evt)
}

// buildJudgeRow assembles the audit.JudgeResponse from the queued
// job. Pulled out for testability and so the SHA-256 cost of the
// raw body runs on the worker goroutine instead of the proxy
// goroutine.
func buildJudgeRow(jb judgePersistJob) audit.JudgeResponse {
	prov := version.Current()
	body := jb.payload.RawResponse
	h := sha256.Sum256([]byte(body))
	return audit.JudgeResponse{
		Kind:              jb.payload.Kind,
		Direction:         string(jb.dir),
		Model:             jb.payload.Model,
		Action:            jb.payload.Action,
		Severity:          string(jb.payload.Severity),
		LatencyMs:         jb.payload.LatencyMs,
		ParseError:        jb.payload.ParseError,
		Raw:               body,
		RequestID:         jb.requestID,
		TraceID:           jb.traceID,
		RunID:             jb.runID,
		SessionID:         jb.sessionID,
		InputHash:         "sha256:" + hex.EncodeToString(h[:]),
		InspectedModel:    jb.payload.Model,
		SchemaVersion:     prov.SchemaVersion,
		ContentHash:       prov.ContentHash,
		Generation:        prov.Generation,
		BinaryVersion:     prov.BinaryVersion,
		AgentID:           jb.identity.AgentID,
		AgentInstanceID:   jb.identity.AgentInstanceID,
		SidecarInstanceID: jb.identity.SidecarInstanceID,
		PolicyID:          jb.policyID,
		DestinationApp:    jb.destApp,
		ToolName:          jb.toolName,
		ToolID:            jb.toolID,
	}
}

// Shutdown signals the worker to drain and exit, blocking up to
// judgePersistShutdownTimeout for the drain to complete. Sidecar
// stop wires this in front of the audit.Store close so every
// queued body lands on disk before the DB handle is released.
func (j *JudgeStore) Shutdown(ctx context.Context) error {
	if j == nil {
		return nil
	}
	if !j.shutdownRequested.CompareAndSwap(false, true) {
		// Already shutting down — wait on the existing drain.
		return j.waitForDrain(ctx)
	}
	j.stopOnce.Do(func() { close(j.stopCh) })
	return j.waitForDrain(ctx)
}

func (j *JudgeStore) waitForDrain(ctx context.Context) error {
	// Default budget if the caller passes a bare Background.
	deadlineCh := time.After(judgePersistShutdownTimeout)
	if ctx != nil {
		if dl, ok := ctx.Deadline(); ok {
			if d := time.Until(dl); d > 0 {
				deadlineCh = time.After(d)
			}
		}
	}
	select {
	case <-j.doneCh:
		return nil
	case <-deadlineCh:
		return fmt.Errorf("judge_store: shutdown timed out after %s", judgePersistShutdownTimeout)
	}
}

// QueueDepth is an introspection helper for tests.
func (j *JudgeStore) QueueDepth() int {
	if j == nil || j.queue == nil {
		return 0
	}
	return len(j.queue)
}

// ---------------------------------------------------------------------------
// audit.Store adapter
// ---------------------------------------------------------------------------

// auditStoreInserter adapts the existing *audit.Store to the
// JudgeBodyInserter contract. The synchronous single-row helper is
// the fallback when a transaction cannot be opened (e.g. a future
// store backend that does not expose BeginTx); for audit.Store
// proper we route through the real *sql.Tx via BeginJudgeBatch.
type auditStoreInserter struct {
	s *audit.Store
}

func (a *auditStoreInserter) InsertJudgeResponse(row audit.JudgeResponse) error {
	return a.s.InsertJudgeResponse(row)
}

func (a *auditStoreInserter) BeginJudgeBatch(ctx context.Context) (JudgeBatch, error) {
	batch, err := a.s.BeginJudgeBatch(ctx)
	if err != nil {
		return nil, err
	}
	// *audit.JudgeBatch satisfies the local JudgeBatch interface
	// (InsertJudgeResponse + Commit + Rollback) — the explicit
	// nil-error path keeps the cast crisp instead of relying on
	// implicit conversion semantics.
	return batch, nil
}

// ---------------------------------------------------------------------------
// audit.JudgeBodyStore adapter (Phase 4)
// ---------------------------------------------------------------------------

// judgeBodyStoreInserter adapts the Phase 4 dedicated
// *audit.JudgeBodyStore (judge_bodies.db) to the JudgeBodyInserter
// contract. The semantics match auditStoreInserter exactly — the
// only difference is the underlying SQLite file. Routing through
// this adapter is what isolates the highest-volume write path
// (judge_responses) from audit_events / activity_events writers
// on audit.db.
type judgeBodyStoreInserter struct {
	s *audit.JudgeBodyStore
}

func (a *judgeBodyStoreInserter) InsertJudgeResponse(row audit.JudgeResponse) error {
	return a.s.InsertJudgeResponse(row)
}

func (a *judgeBodyStoreInserter) BeginJudgeBatch(ctx context.Context) (JudgeBatch, error) {
	batch, err := a.s.BeginJudgeBatch(ctx)
	if err != nil {
		return nil, err
	}
	return batch, nil
}
